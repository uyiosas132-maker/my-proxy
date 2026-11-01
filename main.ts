// Basic server-side web proxy for Deno Deploy.
// Usage: GET /proxy?url=https://example.com
// Diagnose: GET /status?url=https://example.com/image.png  (shows what the upstream site returned)
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
  // hop-by-hop headers must not be copied through
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "te",
  "trailer",
  "proxy-authenticate",
  "proxy-authorization",
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

// Runs inside every proxied page. Sends URLs that page scripts create (images, fetch, XHR,
// links, window.open) and form submissions back through the proxy, and stops pages from
// rewriting the address bar to a URL that only exists on the original site.
function runtimePatch(base: string): string {
  return `<script>(()=>{const R=${JSON.stringify(base)},P=${JSON.stringify(PREFIX)};
const w=u=>{try{u=String(u);if(!u||/^(data:|blob:|javascript:|#|about:)/i.test(u)||u.startsWith(P))return u;
const a=new URL(u,R);if(a.origin===location.origin&&a.pathname==="/proxy")return a.pathname+a.search;
return P+encodeURIComponent(a.href)}catch{return u}};
const of=window.fetch;window.fetch=(i,o)=>{try{if(typeof i==="string")i=w(i);else if(i instanceof URL)i=w(i.href);else if(i instanceof Request)i=new Request(w(i.url),i)}catch{}return of.call(window,i,o)};
const ox=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u,...a){return ox.call(this,m,w(u),...a)};
const sa=Element.prototype.setAttribute;Element.prototype.setAttribute=function(n,v){if(/^(src|href|poster|data-src)$/i.test(n))v=w(v);return sa.call(this,n,v)};
for(const [C,p] of [[HTMLImageElement,"src"],[HTMLScriptElement,"src"],[HTMLSourceElement,"src"],[HTMLMediaElement,"src"],[HTMLVideoElement,"poster"],[HTMLLinkElement,"href"],[HTMLAnchorElement,"href"],[HTMLIFrameElement,"src"]]){
const d=Object.getOwnPropertyDescriptor(C.prototype,p);if(d&&d.set)Object.defineProperty(C.prototype,p,{configurable:true,enumerable:d.enumerable,get:d.get,set(v){d.set.call(this,w(v))}})}
const wo=window.open;window.open=function(u,...r){return wo.call(window,u?w(u):u,...r)};
for(const k of ["pushState","replaceState"]){const o=history[k];history[k]=function(s,t){return o.call(history,s,t)}}
document.addEventListener("submit",e=>{const f=e.target;if(!f||f.tagName!=="FORM"||e.defaultPrevented)return;
try{const raw=f.getAttribute("action")||"";if(raw.startsWith(P))return;const a=new URL(raw||R,R);
if((f.getAttribute("method")||"get").toLowerCase()==="get"){e.preventDefault();const fd=new FormData(f);
if(e.submitter&&e.submitter.name)fd.append(e.submitter.name,e.submitter.value);
const q=new URLSearchParams();fd.forEach((v,k)=>{if(typeof v==="string")q.append(k,v)});a.search=q.toString();
location.href=P+encodeURIComponent(a.href)}else{f.setAttribute("action",P+encodeURIComponent(a.href))}}catch{}},false);
})();</script>`;
}

// Attributes that hold a single URL (including common lazy-load variants).
// "action" is deliberately left out: the runtime patch handles forms, because a GET form
// would otherwise throw away the ?url= part of the proxy address when it submits.
const URL_ATTRS =
  "(?:xlink:)?href|src|poster|data-[\\w-]*(?:src|url|image|original|lazy|poster)[\\w-]*";

// Rewrites URL attributes in markup. Never called on the inside of <script> blocks,
// because those contain JavaScript strings that look like attributes and would be corrupted.
function rewriteMarkup(html: string, base: string): string {
  return html
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
    );
}

function rewriteHtml(html: string, base: string): string {
  // Splitting on a capturing group puts every <script>...</script> block at an odd index.
  const parts = html.split(/(<script\b[^>]*>[\s\S]*?<\/script\s*>)/gi);
  html = parts
    .map((part, i) => {
      if (i % 2 === 1) {
        // Only the opening tag (its src attribute) is rewritten; the JavaScript is left alone.
        const m = part.match(/^(<script\b[^>]*>)([\s\S]*)(<\/script\s*>)$/i);
        return m ? rewriteMarkup(m[1], base) + m[2] + m[3] : part;
      }
      return rewriteMarkup(part, base).replace(
        /<style([^>]*)>([\s\S]*?)<\/style>/gi,
        (_m, attrs, css) => `<style${attrs}>${rewriteCss(css, base)}</style>`,
      );
    })
    .join("");

  // meta charset first, because the injected script is longer than the 1024 bytes browsers scan.
  const inject = `<meta charset="utf-8">` + runtimePatch(base);
  return /<head[^>]*>/i.test(html)
    ? html.replace(/<head[^>]*>/i, (m) => m + inject)
    : inject + html;
}

// Validates the target URL. Unwraps URLs that were already proxied, and refuses to fetch
// this server itself (which would loop forever).
function parseTarget(raw: string | null, here: URL): URL | Response {
  if (!raw) return new Response("Missing url parameter", { status: 400 });
  let t: URL;
  try {
    t = new URL(raw);
  } catch {
    return new Response("Invalid url", { status: 400 });
  }
  for (let i = 0; i < 3 && t.host === here.host && t.pathname === "/proxy"; i++) {
    const inner = t.searchParams.get("url");
    if (!inner) break;
    try {
      t = new URL(inner);
    } catch {
      return new Response("Invalid url", { status: 400 });
    }
  }
  if (!/^https?:$/.test(t.protocol) || BLOCKED.test(t.hostname) || t.host === here.host) {
    return new Response("Blocked", { status: 403 });
  }
  return t;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Retries when the upstream site drops the connection or briefly rate-limits us.
async function fetchUpstream(t: URL, init: RequestInit): Promise<Response> {
  const safe = init.method === "GET" || init.method === "HEAD";
  const tries = safe ? 3 : 1;
  let lastError: unknown;
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(t, init);
      if (safe && i < tries - 1 && [429, 502, 503, 504].includes(r.status)) {
        await r.body?.cancel();
        await sleep(300 * (i + 1));
        continue;
      }
      return r;
    } catch (e) {
      lastError = e;
      console.error("fetch failed:", t.href, String(e));
      if (i < tries - 1) await sleep(300 * (i + 1));
    }
  }
  throw lastError;
}

Deno.serve(async (req) => {
  const here = new URL(req.url);

  // Health check: open the root URL to confirm the backend is running.
  if (here.pathname === "/") return new Response("ok");

  // Diagnostics: shows exactly what the target site answered to this server.
  if (here.pathname === "/status") {
    const t = parseTarget(here.searchParams.get("url"), here);
    if (t instanceof Response) return t;
    try {
      const r = await fetch(t, {
        headers: {
          "user-agent": req.headers.get("user-agent") ?? "Mozilla/5.0",
          "accept": "*/*",
          "referer": t.origin + "/",
        },
        redirect: "manual",
      });
      await r.body?.cancel();
      return Response.json({
        url: t.href,
        status: r.status,
        contentType: r.headers.get("content-type"),
        contentLength: r.headers.get("content-length"),
        location: r.headers.get("location"),
      });
    } catch (e) {
      return Response.json({ url: t.href, error: String(e) }, { status: 502 });
    }
  }

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

  const t = parseTarget(here.searchParams.get("url"), here);
  if (t instanceof Response) return t;

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
    upstream = await fetchUpstream(t, {
      method: req.method,
      headers,
      body: req.method === "GET" || req.method === "HEAD" ? undefined : req.body,
      redirect: "manual",
    });
  } catch {
    return new Response("Could not reach that site", { status: 502 });
  }

  if (upstream.status >= 400) console.error("upstream", upstream.status, t.href);

  const out = new Headers(upstream.headers);
  const wasEncoded = upstream.headers.has("content-encoding");
  for (const h of STRIP) out.delete(h);
  out.set("access-control-allow-origin", "*");

  // Redirects stay inside the proxy. The body of a redirect is irrelevant, so drop it.
  const loc = upstream.headers.get("location");
  if (loc && upstream.status >= 300 && upstream.status < 400) {
    try {
      out.set("location", proxify(new URL(loc, t).href));
    } catch { /* leave as is */ }
    out.delete("content-length");
    out.delete("content-type");
    await upstream.body?.cancel();
    return new Response(null, { status: upstream.status, headers: out });
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
