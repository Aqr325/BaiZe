// Command baizesvc wraps baize.exe as a Windows service: 开机自启、崩溃自动重启.
//
// 守护语义与 start.bat 完全一致：
//
//	退出码 0  -> 用户正常停止，守护循环结束（交给 SCM 的恢复策略兜底）
//	退出码 75 -> 程序请求重启（页面"一键更新/回滚"已换装），立即重跑
//	其他      -> 崩溃，退避后重跑（1->2->4…最多 60 秒）
//
// 子命令（install/remove/start/stop 需管理员权限）：
//
//	baizesvc install   注册 BaiZe 服务（自动启动 + SCM 崩溃恢复策略 + 依赖 PostgreSQL）
//	baizesvc remove    注销服务
//	baizesvc start     启动服务
//	baizesvc stop      停止服务
//	baizesvc run       控制台调试模式（守护逻辑与服务内一致）
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	svcName        = "BAIZE"
	svcDisplayName = "BaiZe 后端服务"
	svcDescription = "BaiZe 后端（开机自启、崩溃自动重启）。包装器复刻 start.bat 的守护语义：退出码 75 立即重跑（自更新），其他异常退避重跑。"

	// restartCode 是 selfupdate.ExitRestart：程序请求守护者重拉（应用新版本）。
	restartCode = 75

	maxBackoff = 60 * time.Second
	stopGrace  = 8 * time.Second
	logMaxSize = 20 << 20 // 20MB 超限轮转为 .old
)

// defaultDSN 在宿主环境未提供 ARTEX_PG_DSN 时的兜底：本机 Windows 服务版 PostgreSQL。
// 迁移完成后正式数据在 5432（服务版，开机自启）。
const defaultDSN = "postgres://artex:artex_local_2026@127.0.0.1:5432/artex?sslmode=disable"

func main() {
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "install":
			install()
			return
		case "remove":
			remove()
			return
		case "start":
			start()
			return
		case "stop":
			stop()
			return
		case "run":
			stopped := make(chan struct{})
			go supervise(make(chan struct{}), stopped)
			<-stopped
			return
		}
	}

	isService, _ := svc.IsWindowsService()
	if !isService {
		fmt.Println("用法: baizesvc <install|remove|start|stop|run>")
		fmt.Println("  install  注册 Windows 服务（需管理员；自动启动 + SCM 崩溃恢复）")
		fmt.Println("  run      控制台调试模式（守护逻辑与服务内一致）")
		os.Exit(2)
	}
	if err := svc.Run(svcName, &baizeService{}); err != nil {
		log.Fatalf("service run: %v", err)
	}
}

// baizeService 实现 svc.Handler。
type baizeService struct{}

func (m *baizeService) Execute(args []string, reqs <-chan svc.ChangeRequest, status chan<- svc.Status) (svcSpecificEC bool, exitCode uint32) {
	status <- svc.Status{State: svc.StartPending}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	stop := make(chan struct{})
	stopped := make(chan struct{})
	go supervise(stop, stopped)

	for {
		select {
		case cr := <-reqs:
			switch cr.Cmd {
			case svc.Interrogate:
				status <- cr.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: uint32(stopGrace/time.Millisecond) + 5000}
				close(stop)
				<-stopped
				status <- svc.Status{State: svc.Stopped}
				return false, 0 // 正常停止（NO_ERROR）
			}
		case <-stopped:
			// 子进程异常路径退出（启动失败 / code 0 但无停止请求）：
			// 报非零退出码，让 SCM 恢复策略自动重启本服务。
			status <- svc.Status{State: svc.Stopped}
			return false, 1
		}
	}
}

// supervise 是守护主循环，语义与 start.bat 一致。
func supervise(stop <-chan struct{}, stopped chan<- struct{}) {
	defer close(stopped)

	dir := exeDir()
	logger := openLog(dir)
	logger.Printf("baizesvc 启动（dir=%s）", dir)

	backoff := time.Second
	for {
		cmd := child(dir, logger)
		if err := cmd.Start(); err != nil {
			logger.Printf("[baizesvc] 启动 baize 失败: %v — 交给 SCM 恢复策略", err)
			return
		}
		go pinToJob(cmd.Process.Pid)

		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()

		select {
		case <-stop:
			// 优雅停止：先 Interrupt，失败或超时再 Kill。
			interruptOrKill(cmd, exited, logger)
			logger.Printf("[baizesvc] 服务停止")
			return
		case err := <-exited:
			code := exitCode(err)
			switch code {
			case 0:
				logger.Printf("[baizesvc] baize 正常退出（code=0）")
				return
			case restartCode:
				logger.Printf("[baizesvc] baize 请求重启（code=75，应用新版本）— 立即重跑")
				backoff = time.Second
			default:
				logger.Printf("[baizesvc] baize 异常退出（code=%d），%s 后重跑", code, backoff)
				select {
				case <-stop:
					return
				case <-time.After(backoff):
				}
				if backoff < maxBackoff {
					backoff *= 2
				}
			}
		}
	}
}

// child 组装 baize 子进程：工作目录与日志重定向到包装器同目录。
func child(dir string, logger *log.Logger) *exec.Cmd {
	bin := filepath.Join(dir, "baize.exe")
	cmd := exec.Command(bin)
	cmd.Dir = dir
	env := os.Environ()
	if os.Getenv("ARTEX_PG_DSN") == "" {
		env = append(env, "ARTEX_PG_DSN="+defaultDSN)
	}
	cmd.Env = env
	cmd.Stdout = logger.Writer()
	cmd.Stderr = logger.Writer()
	return cmd
}

func interruptOrKill(cmd *exec.Cmd, exited <-chan error, logger *log.Logger) {
	if cmd.Process == nil {
		return
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		logger.Printf("[baizesvc] interrupt 失败（%v），直接终止", err)
		_ = cmd.Process.Kill()
		<-exited
		return
	}
	select {
	case <-exited:
	case <-time.After(stopGrace):
		logger.Printf("[baizesvc] 优雅停止超时（%s），强制终止", stopGrace)
		_ = cmd.Process.Kill()
		<-exited
	}
}

// pinToJob 把子进程挂到 kill-on-close 的 Job Object 上：包装器一旦被强杀
// （SCM 强制停止 / 崩溃），子进程随之终止，避免孤儿 baize 占住 8787 端口、
// 导致 SCM 重启后的新包装器起不来。
func pinToJob(pid int) {
	const processAllAccess = 0x1F0FFF
	h, err := windows.OpenProcess(processAllAccess, false, uint32(pid))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	j, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return
	}
	var li windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	li.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(j, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&li)), uint32(unsafe.Sizeof(li))); err != nil {
		windows.CloseHandle(j)
		return
	}
	_ = windows.AssignProcessToJobObject(j, h)
	// 故意不 CloseHandle(j)：包装器存活期间保持"job 关闭即杀子进程"语义。
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode()
	}
	return -1
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// openLog 打开包装器日志（baizesvc.log），超限轮转为 .old。
func openLog(dir string) *log.Logger {
	path := filepath.Join(dir, "baizesvc.log")
	if fi, err := os.Stat(path); err == nil && fi.Size() > logMaxSize {
		_ = os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return log.New(os.Stderr, "", log.LstdFlags)
	}
	return log.New(f, "", log.LstdFlags)
}

func connect() (*mgr.Mgr, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, fmt.Errorf("连接服务管理器失败（需要管理员权限）: %v", err)
	}
	return m, nil
}

func install() {
	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("定位自身失败: %v", err)
	}
	m, err := connect()
	if err != nil {
		log.Fatal(err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(svcName); err == nil {
		s.Close()
		log.Fatalf("服务 %s 已存在（先运行 baizesvc remove 再注册）", svcName)
	}

	cfg := mgr.Config{
		DisplayName:  svcDisplayName,
		Description:  svcDescription,
		StartType:    mgr.StartAutomatic,
		Dependencies: []string{"postgresql-x64-18"}, // 确保数据库先于本服务启动
	}
	s, err := m.CreateService(svcName, exe, cfg)
	if err != nil {
		log.Fatalf("创建服务失败: %v", err)
	}
	defer s.Close()

	// SCM 恢复策略：包装器自身崩溃时由服务管理器重启（双保险）。
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
	if err := s.SetRecoveryActions(actions, 86400); err != nil {
		log.Printf("设置崩溃恢复策略失败（不影响服务注册）: %v", err)
	}
	fmt.Printf("[baizesvc] 服务 %s 注册成功（自动启动，依赖 postgresql-x64-18）\n", svcName)
}

func remove() {
	m, err := connect()
	if err != nil {
		log.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		log.Fatalf("服务 %s 不存在: %v", svcName, err)
	}
	defer s.Close()
	if err := s.Delete(); err != nil {
		log.Fatalf("删除服务失败: %v", err)
	}
	fmt.Printf("[baizesvc] 服务 %s 已注销（重启后彻底移除）\n", svcName)
}

func start() {
	m, err := connect()
	if err != nil {
		log.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		log.Fatalf("服务 %s 不存在: %v", svcName, err)
	}
	defer s.Close()
	if err := s.Start(); err != nil {
		log.Fatalf("启动服务失败: %v", err)
	}
	fmt.Printf("[baizesvc] 服务 %s 已启动\n", svcName)
}

func stop() {
	m, err := connect()
	if err != nil {
		log.Fatal(err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(svcName)
	if err != nil {
		log.Fatalf("服务 %s 不存在: %v", svcName, err)
	}
	defer s.Close()
	if _, err := s.Control(svc.Stop); err != nil {
		log.Fatalf("停止服务失败: %v", err)
	}
	fmt.Printf("[baizesvc] 服务 %s 停止中\n", svcName)
}
