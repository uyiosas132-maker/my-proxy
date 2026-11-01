// Basic server-side web proxy for Deno Deploy.
// Usage: GET /proxy?url=https://example.com
// Entrypoint: main.ts

// Refuse requests to local and private network addresses (basic SSRF protection).
const BLOCKED =
  /^(localhost|.*\.local|.*\.internal|0\.0\.0\.0|127\..*|10\..*|192\.168\..*|169\.254\..*|172\.(1[6-9]|2\d|3[01])\..*|\[?::1?\]?|metadata.*)$/i;

// Headers removed from upstream responses so pages can load inside an iframe.
const STRIP = [
  "x-frame-options",
  "content-security-policy",
  "content-security-policy-report-only",
  "strict-transport-security",
  "content-encoding",
  "content-length",
  "set-cookie",
];

const proxify = (url: string) => "/proxy?url=" + encodeURIComponent(url);

function resolve(value: string, base: string): string {
  const v = value.trim();
  if (!v || /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i.test(v)) return value;
  try {
    return proxify(new URL(v, base).href);
  } catch {
    return value;
  }
}

function rewriteHtml(html: string, base: string): string {
  return html
    // Drop CSP set through <meta> tags.
    .replace(/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*>/gi, "")
    // Route links, images, scripts, forms and media back through the proxy.
    .replace(
      /(\s(?:href|src|action|poster)\s*=\s*)(["'])(.*?)\2/gis,
      (_m, attr, quote, val) => `${attr}${quote}${resolve(val, base)}${quote}`,
    );
}

function rewriteCss(css: string, base: string): string {
  return css.replace(
    /url\(\s*(["']?)(.*?)\1\s*\)/gi,
    (_m, quote, val) => `url(${quote}${resolve(val, base)}${quote})`,
  );
}

Deno.serve(async (req) => {
  const here = new URL(req.url);

  // Health check: open the root URL to confirm the backend is running.
  if (here.pathname === "/") return new Response("ok");
  if (here.pathname !== "/proxy") return new Response("Not found", { status: 404 });

  const target = here.searchParams.get("url");
  if (!target) return new Response("Missing url parameter", { status: 400 });

  let t: URL;
  try {
    t = new URL(target);
  } catch {
    return new Response("Invalid url", { status: 400 });
  }
  if (!/^https?:$/.test(t.protocol) || BLOCKED.test(t.hostname)) {
    return new Response("Blocked", { status: 403 });
  }

  const headers = new Headers();
  for (const h of ["accept", "accept-language", "content-type", "user-agent"]) {
    const v = req.headers.get(h);
    if (v) headers.set(h, v);
  }

  let upstream: Response;
  try {
    upstream = await fetch(t, {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
      redirect: "manual",
    });
  } catch {
    return new Response("Could not reach that site", { status: 502 });
  }

  const out = new Headers(upstream.headers);
  for (const h of STRIP) out.delete(h);

  // Keep redirects inside the proxy.
  const loc = upstream.headers.get("location");
  if (loc) {
    try {
      out.set("location", proxify(new URL(loc, t).href));
    } catch { /* leave as is */ }
  }

  const type = upstream.headers.get("content-type") ?? "";
  if (type.includes("text/html")) {
    return new Response(rewriteHtml(await upstream.text(), t.href), {
      status: upstream.status,
      headers: out,
    });
  }
  if (type.includes("text/css")) {
    return new Response(rewriteCss(await upstream.text(), t.href), {
      status: upstream.status,
      headers: out,
    });
  }
  return new Response(upstream.body, { status: upstream.status, headers: out });
});
