// Basic server-side web proxy for Deno Deploy.
// Usage: GET /proxy?url=https://example.com
// Entrypoint: main.ts

// Refuse requests to local and private network addresses (basic SSRF protection).
const BLOCKED =
  /^(localhost|.*\.local|.*\.internal|0\.0\.0\.0|127\..*|10\..*|192\.168\..*|169\.254\..*|172\.(1[6-9]|2\d|3[01])\..*|\[?::1?\]?|metadata.*)$/i;

// Headers removed from upstream responses so pages can load inside an iframe.
// content-length is handled separately below (it must be kept for video seeking).
const STRIP = [
  "x-frame-options",
  "content-security-policy",
  "content-security-policy-report-only",
  "strict-transport-security",
  "content-encoding",
  "set-cookie",
  "cross-origin-embedder-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "x-content-type-options",
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
const sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){if(/^(src|href|poster|data-src)$/i.test(n))v=w(v);return sa.call(this,n,v)};
for(const [C,p] of [[HTMLImageElement,"src"],[HTMLScriptElement,"src"],[HTMLSourceElement,"src"],[HTMLMediaElement,"src"],[HTMLVideoElement,"poster"],[HTMLLinkElement,"href"]]){
const d=Object.getOwnPropertyDescriptor(C.prototype,p);if(d&&d.set)Object.defineProperty(C.prototype,p,{configurable:true,enumerable:d.enumerable,get:d.get,set(v){d.set.call(this,w(v))}})}
})();</script>`;
}

// Attributes that hold a single URL (including common lazy-load variants).
const URL_ATTRS =
  "(?:xlink:)?href|src|action|poster|data-[\\w-]*(?:src|url|image|original|lazy|poster)[\\w-]*";

function rewriteHtml(html: string, base: string): string {
  html = html
    // Drop CSP set through <meta> tags.
    .replace(/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*>/gi, "")
    // <base> tags change how relative URLs resolve and break the rewriting.
    .replace(/<base\b[^>]*>/gi, "")
    // Integrity/nonce/crossorigin attributes break once URLs are rewritten.
    .replace(/\s(integrity|nonce|crossorigin)\s*=\s*("[^"]*"|'[^']*')/gi, "")
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
    // Quoted single-URL attributes.
    .replace(
      new RegExp(`(\\s(?:${URL_ATTRS})\\s*=\\s*)(["'])(.*?)\\2`, "gis"),
      (m, attr, quote, val) => {
        if (/[{<]/.test(val) || /srcset/i.test(attr)) return m;
        return `${attr}${quote}${resolve(val.replace(/&amp;/g, "&"), base).replace(/"/g, "&quot;")}${quote}`;
      },
    )
    // Unquoted attributes such as <img src=photo.jpg>.
    .replace(
      /(\s(?:href|src|poster)\s*=\s*)([^\s"'>][^\s>]*)/gi,
      (_m, attr, val) => `${attr}"${resolve(val, base)}"`,
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

  // CORS preflight for requests made by proxied pages.
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST, HEAD, OPTIONS",
        "access-control-allow-headers": "*",
      },
    });
  }

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
  // range and if-range are required for video/audio playback and seeking.
  for (const h of ["accept", "accept-language", "content-type", "user-agent", "range", "if-range"]) {
    const v = req.headers.get(h);
    if (v) headers.set(h, v);
  }
  // Ask for an uncompressed body so ranges and content-length stay valid.
  headers.set("accept-encoding", "identity");

  // Hotlink protection usually checks that the referer is the *page's* site, not the image host.
  // The browser sends our own /proxy?url=<page> as the referer, so recover the original page from it.
  let referer = t.origin + "/";
  const inRef = req.headers.get("referer");
  if (inRef) {
    try {
      const r = new URL(inRef);
      const page = r.origin === here.origin && r.pathname === "/proxy"
        ? r.searchParams.get("url")
        : null;
      if (page) referer = new URL(page).href;
    } catch { /* keep default */ }
  }
  headers.set("referer", referer);

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
  const wasEncoded = upstream.headers.has("content-encoding");
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
    out.delete("content-length");
    out.set("content-type", "text/html; charset=utf-8");
    return new Response(rewriteHtml(await upstream.text(), t.href), {
      status: upstream.status,
      headers: out,
    });
  }
  if (type.includes("text/css")) {
    out.delete("content-length");
    return new Response(rewriteCss(await upstream.text(), t.href), {
      status: upstream.status,
      headers: out,
    });
  }

  // Images, GIFs, video, audio, fonts, JS and JSON stream through untouched.
  // content-length, content-range and accept-ranges are kept so video can buffer and seek.
  if (wasEncoded) out.delete("content-length");
  return new Response(upstream.body, { status: upstream.status, headers: out });
});
