// Закрывает весь сайт Basic Auth. В репозитории хранится только SHA-256 от "логин:пароль".
const HASH = "4e96c0b04acc6f8afba3bae9020094d9f62fcc0213d5c34b1da5402963225e38";

async function sha256(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function onRequest({ request, next }) {
  const auth = request.headers.get("Authorization") || "";
  if (auth.startsWith("Basic ")) {
    try {
      if ((await sha256(atob(auth.slice(6)))) === HASH) {
        const res = await next();
        const out = new Response(res.body, res);
        out.headers.set("X-Robots-Tag", "noindex, nofollow");
        out.headers.set("Cache-Control", "private, no-store");
        return out;
      }
    } catch (_) {}
  }
  return new Response("Доступ закрыт", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="uzum-ar", charset="UTF-8"',
      "X-Robots-Tag": "noindex, nofollow",
      "Cache-Control": "no-store",
    },
  });
}
