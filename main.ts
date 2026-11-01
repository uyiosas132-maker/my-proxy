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
  "cross-origin-embedder-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
];

const PREFIX = "/proxy?url=";
const SKIP = /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i;

const proxify = (url: string) => PREFIX + encodeURIComponent(url);

function resolve(value: string, base: string): string {
  const v = value.trim();
  if (!v || SKIP.test(v) || v.startsWith(PREFIX)) return value;
  try {
    return proxify(new URL(v, base).href);
  } catch {
    return value;
  }
}

function rewriteCss(css: string, base: string): string {
  return css
    .replace(
      /url\(\s*(["']?)(.*?)\1\s*\)/gi,
      (_m, quote, val) => `url(${quote}${resolve(val, base)}${quote})`,
    )
    .replace(
      /@import\s+(["'])(.*?)\1/gi,
      (_m, quote, val) => `@import ${quote}${resolve(val, base)}${quote}`,
    );
}

// Runtime patch so images, fetch and XHR created by page scripts also go through the proxy.
function runtimePatch(base: string): string {
  return `<script>(()=>{const R=${JSON.stringify(base)},P=${JSON.stringify(PREFIX)};
const w=u=>{try{u=String(u);if(!u||/^(data:|blob:|javascript:|#|about:)/i.test(u)||u.startsWith(P))return u;return P+encodeURIComponent(new URL(u,R).href)}catch{return u}};
const of=window.fetch;window.fetch=(i,o)=>of(typeof i==="string"?w(i):i,o);
const ox=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u,...a){return ox.call(this,m,w(u),...a)};
const sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){if(/^(src|href|poster)$/i.test(n))v=w(v);return sa.call(this,n,v)};
for(const [C,p] of [[HTMLImageElement,"src"],[HTMLScriptElement,"src"],[HTMLSourceElement,"src"],[HTMLLinkElement,"href"]]){
const d=Object.getOwnPropertyDescriptor(C.prototype,p);if(d&&d.set)Object.defineProperty(C.prototype,p,{get:d.get,set(v){d.set.call(this,w(v))}})}
})();</script>`;
}

function rewriteHtml(html: string, base: string): string {
  html = html
    // Drop CSP set through <meta> tags.
    .replace(/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*>/gi, "")
    // Integrity/nonce/crossorigin attributes break once URLs are rewritten.
    .replace(/\s(integrity|nonce|crossorigin)\s*=\s*("[^"]*"|'[^']*')/gi, "")
    // Route links, images, scripts, forms, media and lazy-load attributes back through the proxy.
    .replace(
      /(\s(?:href|src|action|poster|data-src|data-original|data-lazy-src)\s*=\s*)(["'])(.*?)\2/gis,
      (_m, attr, quote, val) =>
        `${attr}${quote}${resolve(val.replace(/&amp;/g, "&"), base).replace(/"/g, "&quot;")}${quote}`,
    )
    // Responsive images: srcset and data-srcset hold several URLs separated by commas.
    .replace(
      /(\s(?:srcset|data-srcset)\s*=\s*)(["'])(.*?)\2/gis,
      (_m, attr, quote, val) => {
        const rewritten = val
          .split(",")
          .map((part: string) => {
            const [u, ...rest] = part.trim().split(/\s+/);
            return [resolve(u, base), ...rest].join(" ");
          })
          .join(", ");
        return `${attr}${quote}${rewritten.replace(/"/g, "&quot;")}${quote}`;
      },
    )
    // Inline style="" attributes with background images.
    .replace(
      /(\sstyle\s*=\s*)"([^"]*)"/gi,
      (_m, attr, css) => `${attr}"${rewriteCss(css, base).replace(/"/g, "&quot;")}"`,
    )
    // <style> blocks.
    .replace(
      /<style([^>]*)>([\s\S]*?)<\/style>/gi,
      (_m, attrs, css) => `<style${attrs}>${rewriteCss(css, base)}</style>`,
    );

  const inject = runtimePatch(base);
  return /<head[^>]*>/i.test(html)
    ? html.replace(/<head[^>]*>/i, (m) => m + inject)
    : inject + html;
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
  // Many image hosts reject requests without a same-site referer (hotlink protection).
  headers.set("referer", t.origin + "/");

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
  out.set("access-control-allow-origin", "*");

  // Keep redirects inside the proxy.
  const loc = upstream.headers.get("location");
  if (loc) {
    try {
      out.set("location", proxify(new URL(loc, t).href));
    } catch { /* leave as is */ }
  }

  const type = upstream.headers.get("content-type") ?? "";
  if (type.includes("text/html")) {
    out.set("content-type", "text/html; charset=utf-8");
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
  // Images, fonts, video, JS and JSON stream through untouched.
  return new Response(upstream.body, { status: upstream.status, headers: out });
});
