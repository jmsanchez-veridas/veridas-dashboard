// Google sign-in for the Veridas dashboard.
// Vercel runs this file before serving any page or CSV.
// Only accounts from the allowed domain (or individually listed emails) get through.
//
// Environment variables (Vercel → Settings → Environment Variables):
//   GOOGLE_CLIENT_ID      Google Cloud OAuth client ID
//   GOOGLE_CLIENT_SECRET  That client's secret
//   SESSION_SECRET        Long random text (at least 32 characters)
//   ALLOWED_DOMAIN        Allowed domain, e.g. veridas.com
//   ALLOWED_EMAILS        (optional) comma-separated emails from outside the domain

export const config = { matcher: '/:path*' };

const COOKIE = 'vd_session';
const STATE_COOKIE = 'vd_state';
const SESSION_DAYS = 7;
const enc = new TextEncoder();

const pass = () => new Response(null, { headers: { 'x-middleware-next': '1' } });

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function fromB64url(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}
async function hmacKey(secret) {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}
async function sign(payload, secret) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(body)));
  return body + '.' + b64url(sig);
}
async function verify(token, secret) {
  if (!token || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  try {
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(secret), fromB64url(sig), enc.encode(body));
    if (!ok) return null;
    const data = JSON.parse(new TextDecoder().decode(fromB64url(body)));
    return data.exp > Date.now() ? data : null;
  } catch { return null; }
}
function cookies(req) {
  const out = {};
  (req.headers.get('cookie') || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
const setCookie = (name, value, maxAge) => `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const safePath = (p) => (typeof p === 'string' && p.startsWith('/') && !p.startsWith('//') && !p.startsWith('/auth/') ? p : '/');

function page(title, text, button, status = 200) {
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Public+Sans:wght@300;400;600&display=swap" rel="stylesheet">
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#F1F0ED;border-top:4px solid #FF6C72;box-sizing:border-box;font-family:'Public Sans',system-ui,-apple-system,'Segoe UI',sans-serif;color:#000D47}
.box{background:#fff;border:1px solid #E3E1DC;border-radius:8px;padding:40px 36px;max-width:400px;width:calc(100% - 48px)}
.eyebrow{text-transform:uppercase;letter-spacing:.06em;font-size:12px;margin:0 0 6px}
h1{font-size:30px;font-weight:300;letter-spacing:-.02em;margin:0 0 12px}h1:before{content:"/";color:#FF6C72;margin-right:2px}
p{color:#4D5578;font-size:14.5px;line-height:1.5;margin:0 0 24px}
a.btn{display:inline-flex;align-items:center;gap:10px;background:#000D47;color:#fff;text-decoration:none;padding:12px 20px;border-radius:4px;font-weight:600;font-size:14.5px}a.btn:hover{background:#0A1A66}</style></head>
<body><main class="box"><p class="eyebrow">Veridas · Web performance</p><h1>${title}</h1><p>${text}</p>${button || ''}</main></body></html>`;
  return new Response(html, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

export default async function middleware(req) {
  const env = process.env;
  const url = new URL(req.url);
  const { pathname } = url;
  const domain = (env.ALLOWED_DOMAIN || '').toLowerCase();
  const extra = (env.ALLOWED_EMAILS || '').toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);

  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.SESSION_SECRET || env.SESSION_SECRET.length < 32 || !domain) {
    return page('Access not configured', 'Environment variables are missing in Vercel. Until they are added, the page is not shown to anyone.', '', 503);
  }
  const redirectUri = url.origin + '/auth/callback';
  const jar = cookies(req);

  if (pathname === '/auth/login') {
    const state = b64url(crypto.getRandomValues(new Uint8Array(24)));
    const next = safePath(url.searchParams.get('next'));
    const g = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    g.search = new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, redirect_uri: redirectUri, response_type: 'code', scope: 'openid email', state, hd: domain, prompt: 'select_account' }).toString();
    const signedState = await sign({ state, next, exp: Date.now() + 10 * 60 * 1000 }, env.SESSION_SECRET);
    return new Response(null, { status: 302, headers: { location: g.toString(), 'set-cookie': setCookie(STATE_COOKIE, signedState, 600), 'cache-control': 'no-store' } });
  }

  if (pathname === '/auth/callback') {
    const st = await verify(jar[STATE_COOKIE], env.SESSION_SECRET);
    const code = url.searchParams.get('code');
    if (!st || !code || st.state !== url.searchParams.get('state')) {
      return page('Sign-in failed', 'The sign-in session has expired or is not valid. Please try again.', '<a class="btn" href="/auth/login">Try again</a>', 400);
    }
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: redirectUri, grant_type: 'authorization_code' })
    });
    const tok = tokenRes.ok ? await tokenRes.json() : null;
    let claims = null;
    try { claims = tok && tok.id_token ? JSON.parse(new TextDecoder().decode(fromB64url(tok.id_token.split('.')[1]))) : null; } catch { claims = null; }
    // The id_token comes straight from Google over HTTPS in exchange for the code, so checking its audience is enough.
    const okIssuer = claims && ['accounts.google.com', 'https://accounts.google.com'].includes(claims.iss);
    const email = claims && String(claims.email || '').toLowerCase();
    const allowed = okIssuer && claims.aud === env.GOOGLE_CLIENT_ID && claims.email_verified === true && claims.exp * 1000 > Date.now()
      && ((claims.hd || '').toLowerCase() === domain || extra.includes(email));
    if (!allowed) {
      return page('Restricted access', `This dashboard is only available to ${domain} accounts.${email ? ' You signed in as ' + email.replace(/[<>&"]/g, '') + '.' : ''}`, '<a class="btn" href="/auth/login">Use another account</a>', 403);
    }
    const session = await sign({ email, exp: Date.now() + SESSION_DAYS * 864e5 }, env.SESSION_SECRET);
    const headers = new Headers({ location: safePath(st.next), 'cache-control': 'no-store' });
    headers.append('set-cookie', setCookie(COOKIE, session, SESSION_DAYS * 86400));
    headers.append('set-cookie', setCookie(STATE_COOKIE, '', 0));
    return new Response(null, { status: 302, headers });
  }

  if (pathname === '/auth/logout') {
    return new Response(null, { status: 302, headers: { location: '/auth/salir', 'set-cookie': setCookie(COOKIE, '', 0), 'cache-control': 'no-store' } });
  }
  if (pathname === '/auth/salir') {
    return page('You have signed out', 'To return to the dashboard, sign in again with your Google account.', '<a class="btn" href="/auth/login">Sign in with Google</a>');
  }

  const session = await verify(jar[COOKIE], env.SESSION_SECRET);

  if (pathname === '/auth/me') {
    return new Response(JSON.stringify(session ? { email: session.email } : {}), { status: session ? 200 : 401, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  }
  if (session) return pass();

  const wantsHtml = (req.headers.get('accept') || '').includes('text/html');
  if (wantsHtml) {
    return page('Veridas web performance', `Access restricted to ${domain} accounts.`, `<a class="btn" href="/auth/login?next=${encodeURIComponent(pathname)}">Sign in with Google</a>`, 401);
  }
  return new Response('Unauthorized', { status: 401, headers: { 'cache-control': 'no-store' } });
}
