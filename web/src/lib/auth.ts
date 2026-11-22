const TOKEN_KEY = "artex_token";
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60; // 7 天（秒）

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const auth = {
  getToken(): string | null {
    if (typeof window === "undefined") return null;
    // Mock demo：无真实登录，返回一个假 token 让路由守卫放行、直接进主界面。
    return localStorage.getItem(TOKEN_KEY) ?? (process.env.NEXT_PUBLIC_MOCK === "1" ? "mock-demo" : null);
  },

  setToken(token: string): void {
    localStorage.setItem(TOKEN_KEY, token);
    // 同步写 cookie，供 Next.js middleware 服务端读取。
    // SameSite=Lax 限制跨站携带；HTTPS 下追加 Secure，避免明文链路泄露。
    // 暂不加 HttpOnly：前端仍需读取该 token，HttpOnly 需后端配合改造。
    const secure = typeof window !== "undefined" && window.location?.protocol === "https:" ? "; Secure" : "";
    document.cookie = `${TOKEN_KEY}=${encodeURIComponent(token)}; path=/; max-age=${COOKIE_MAX_AGE}; SameSite=Lax${secure}`;
  },

  clearToken(): void {
    localStorage.removeItem(TOKEN_KEY);
    document.cookie = `${TOKEN_KEY}=; path=/; max-age=0`;
  },

  // 从 JWT payload 的 sub 字段解析当前用户，仅用于展示，不做签名验证。
  getCurrentUser(): CurrentUser | null {
    const token = this.getToken();
    if (!token) return null;
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return null;
      // base64url → base64
      const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
      // 显示名固定为「白泽」（品牌名）；JWT sub 仅作为真实登录用户名保留，
      // 不参与展示——旧 token 的 sub=ARTEX 不影响右上角显示名。
      const username: string = payload.sub ?? "ARTEX";
      return {
        id: "1",
        name: "白泽",
        username,
        email: "",
        avatar: "/logo.png",
        role: "operator",
      };
    } catch {
      return null;
    }
  },
};
