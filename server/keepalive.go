package server

import (
	"log"
	"runtime/debug"
)

// keepalive runs fn and turns a panic into a log line, so a periodic loop
// survives to its next tick instead of taking down the whole process. A
// goroutine panic without a recover kills the process; for unattended runs the
// loop must degrade to a logged error and keep ticking.
func keepalive(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[%s] panic recovered, loop survives: %v\n%s", name, r, debug.Stack())
		}
	}()
	fn()
}
