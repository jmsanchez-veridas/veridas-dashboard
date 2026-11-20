// Inicio de sesión con Google para el dashboard de Veridas.
// Vercel ejecuta este fichero antes de servir cualquier página o CSV.
// Solo deja pasar a cuentas del dominio permitido (o a correos sueltos de la lista).
//
// Variables de entorno (Vercel → Settings → Environment Variables):
//   GOOGLE_CLIENT_ID      ID de cliente OAuth de Google Cloud
//   GOOGLE_CLIENT_SECRET  Secreto de ese cliente
//   SESSION_SECRET        Texto aleatorio largo (mínimo 32 caracteres)
//   ALLOWED_DOMAIN        Dominio permitido, por ejemplo veridas.com
//   ALLOWED_EMAILS        (opcional) correos de fuera del dominio, separados por comas

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
  const html = `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title}</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#F7F7F9;font-family:system-ui,-apple-system,'Segoe UI',sans-serif;color:#17171C}
.box{background:#fff;border:1px solid #E9E9EF;border-radius:18px;padding:36px 32px;max-width:380px;width:calc(100% - 48px);text-align:center}
.logo{width:48px;height:48px;border-radius:13px;background:#EF5B5B;color:#fff;font-weight:700;font-size:26px;display:grid;place-items:center;margin:0 auto 18px}
h1{font-size:20px;font-weight:600;margin:0 0 8px}p{color:#6E6E7A;font-size:14.5px;line-height:1.5;margin:0 0 22px}
a.btn{display:inline-flex;align-items:center;gap:10px;background:#3667F0;color:#fff;text-decoration:none;padding:11px 18px;border-radius:10px;font-weight:500;font-size:14.5px}</style></head>
<body><main class="box"><div class="logo">V</div><h1>${title}</h1><p>${text}</p>${button || ''}</main></body></html>`;
  return new Response(html, { status, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

export default async function middleware(req) {
  const env = process.env;
  const url = new URL(req.url);
  const { pathname } = url;
  const domain = (env.ALLOWED_DOMAIN || '').toLowerCase();
  const extra = (env.ALLOWED_EMAILS || '').toLowerCase().split(',').map((s) => s.trim()).filter(Boolean);

  if (!env.GOOGLE_CLIENT_ID || !env.GOOGLE_CLIENT_SECRET || !env.SESSION_SECRET || env.SESSION_SECRET.length < 32 || !domain) {
    return page('Acceso no configurado', 'Faltan variables de entorno en Vercel. Hasta que estén, la página no se muestra a nadie.', '', 503);
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
      return page('No se ha podido iniciar sesión', 'La sesión de acceso ha caducado o no es válida. Vuelve a intentarlo.', '<a class="btn" href="/auth/login">Volver a intentarlo</a>', 400);
    }
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ code, client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: redirectUri, grant_type: 'authorization_code' })
    });
    const tok = tokenRes.ok ? await tokenRes.json() : null;
    let claims = null;
    try { claims = tok && tok.id_token ? JSON.parse(new TextDecoder().decode(fromB64url(tok.id_token.split('.')[1]))) : null; } catch { claims = null; }
    // El id_token llega directamente de Google por HTTPS a cambio del código, así que basta con comprobar a quién va dirigido.
    const okIssuer = claims && ['accounts.google.com', 'https://accounts.google.com'].includes(claims.iss);
    const email = claims && String(claims.email || '').toLowerCase();
    const allowed = okIssuer && claims.aud === env.GOOGLE_CLIENT_ID && claims.email_verified === true && claims.exp * 1000 > Date.now()
      && ((claims.hd || '').toLowerCase() === domain || extra.includes(email));
    if (!allowed) {
      return page('Acceso restringido', `Este panel solo está disponible para cuentas de ${domain}.${email ? ' Has entrado como ' + email.replace(/[<>&"]/g, '') + '.' : ''}`, '<a class="btn" href="/auth/login">Entrar con otra cuenta</a>', 403);
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
    return page('Has cerrado sesión', 'Para volver al panel, entra de nuevo con tu cuenta de Google.', '<a class="btn" href="/auth/login">Entrar con Google</a>');
  }

  const session = await verify(jar[COOKIE], env.SESSION_SECRET);

  if (pathname === '/auth/me') {
    return new Response(JSON.stringify(session ? { email: session.email } : {}), { status: session ? 200 : 401, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
  }
  if (session) return pass();

  const wantsHtml = (req.headers.get('accept') || '').includes('text/html');
  if (wantsHtml) {
    return page('Rendimiento web de Veridas', `Acceso solo para cuentas de ${domain}.`, `<a class="btn" href="/auth/login?next=${encodeURIComponent(pathname)}">Entrar con Google</a>`, 401);
  }
  return new Response('No autorizado', { status: 401, headers: { 'cache-control': 'no-store' } });
}
