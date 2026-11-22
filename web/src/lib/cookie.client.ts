// Client-side cookie utilities.
// These functions manage cookies in the browser only.
// Server actions handle cookie updates on the server side.

function writeClientCookie(serializedCookie: string) {
  // biome-ignore lint/suspicious/noDocumentCookie: This project still uses document.cookie for broad browser support.
  document.cookie = serializedCookie;
}

export function setClientCookie(key: string, value: string, days = 7) {
  const expires = new Date(Date.now() + days * 864e5).toUTCString();
  // 限制跨站携带；HTTPS 下追加 Secure 避免明文链路泄露。
  // 认证 cookie 仍可被前端读取，故本次不加 HttpOnly（需后端配合）。
  const secure = typeof window !== "undefined" && window.location?.protocol === "https:" ? "; Secure" : "";
  writeClientCookie(`${key}=${value}; expires=${expires}; path=/; SameSite=Lax${secure}`);
}

export function getClientCookie(key: string) {
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith(`${key}=`))
    ?.split("=")[1];
}

export function deleteClientCookie(key: string) {
  writeClientCookie(`${key}=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/`);
}
