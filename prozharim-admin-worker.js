
export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders() });

      if (path === '/login' && request.method === 'GET') return html(renderLoginPage(), 200);
      if (path === '/api/login' && request.method === 'POST') {
        const body = await safeJson(request);
        if (!body.password || body.password !== env.ADMIN_PASSWORD) return json({ error: 'Неверный пароль' }, 401);
        const token = await createSessionToken(env.SESSION_SECRET);
        const headers = new Headers(corsHeaders());
        headers.append('Set-Cookie', buildSessionCookie(token));
        return new Response(JSON.stringify({ ok: true }), { status: 200, headers: withJson(headers) });
      }
      if (path === '/api/logout' && request.method === 'POST') {
        const headers = new Headers(corsHeaders()); headers.append('Set-Cookie', clearSessionCookie());
        return new Response(JSON.stringify({ ok: true }), { status: 200, headers: withJson(headers) });
      }
      if (path === '/api/session' && request.method === 'GET') {
        const ok = await isAuthorized(request, env);
        return ok ? json({ ok: true }) : json({ error: 'Не авторизован' }, 401);
      }

      if (path.startsWith('/api/')) {
        const ok = await isAuthorized(request, env);
        if (!ok) return json({ error: 'Не авторизован' }, 401);

        if (path === '/api/file' && request.method === 'GET') {
          const filePath = url.searchParams.get('path');
          if (!filePath) return json({ error: 'path required' }, 400);
          const content = await readGithubJson(env, filePath);
          return json({ ok: true, path: filePath, content });
        }
        if (path === '/api/file' && request.method === 'POST') {
          const body = await safeJson(request);
          if (!body.path) return json({ error: 'path required' }, 400);
          await writeGithubFile(env, body.path, JSON.stringify(body.content, null, 2), body.message || `Update ${body.path}`);
          return json({ ok: true });
        }
        if (path === '/api/asset' && request.method === 'POST') {
          const body = await safeJson(request);
          if (!body.path || !body.contentBase64) return json({ error: 'path and contentBase64 required' }, 400);
          await writeGithubBinaryBase64(env, body.path, body.contentBase64, body.message || `Upload ${body.path}`);
          return json({ ok: true, path: body.path });
        }
        return json({ error: 'Route not found' }, 404);
      }

      if (path === '/manager' || path === '/manager/' || path.startsWith('/manager/')) {
        const ok = await isAuthorized(request, env);
        if (!ok) return Response.redirect(`${url.origin}/login`, 302);
      }
      if (path === '/login' || path === '/manager' || path === '/manager/' || path.startsWith('/manager/')) {
        return proxyAsset(url, env);
      }
      return fetch(request);
    } catch (err) {
      return json({ error: err?.message || 'Internal error' }, 500);
    }
  }
};

async function proxyAsset(url, env) {
  const assetBase = (env.ASSET_BASE || '').replace(/\/+$/, '');
  if (!assetBase) return new Response('ASSET_BASE is not configured', { status: 500 });
  let p = url.pathname;
  if (p === '/manager' || p === '/manager/') p = '/manager/index.html';
  const target = p === '/login' ? `${assetBase}/__worker_login_passthrough__` : `${assetBase}${p}`;
  if (p === '/login') return html(renderLoginPage(), 200);
  const res = await fetch(target, { cf: { cacheTtl: 60, cacheEverything: true } });
  const headers = new Headers(res.headers);
  headers.set('Cache-Control', 'no-store');
  headers.set('X-Robots-Tag', 'noindex, nofollow');
  return new Response(res.body, { status: res.status, headers });
}

async function readGithubJson(env, filePath) {
  const apiUrl = `https://api.github.com/repos/${env.GH_OWNER}/${env.GH_REPO}/contents/${filePath}?ref=${encodeURIComponent(env.GH_BRANCH)}`;
  const res = await fetch(apiUrl, { headers: githubHeaders(env) });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`GitHub read error: ${await res.text()}`);
  const data = await res.json();
  const content = decodeBase64Unicode((data.content || '').replace(/\n/g, ''));
  return JSON.parse(content);
}
async function writeGithubFile(env, filePath, textContent, message) {
  const apiUrl = `https://api.github.com/repos/${env.GH_OWNER}/${env.GH_REPO}/contents/${filePath}`;
  let sha;
  const currentRes = await fetch(`${apiUrl}?ref=${encodeURIComponent(env.GH_BRANCH)}`, { headers: githubHeaders(env) });
  if (currentRes.ok) sha = (await currentRes.json()).sha;
  else if (currentRes.status !== 404) throw new Error(`GitHub pre-write error: ${await currentRes.text()}`);
  const payload = { message, content: encodeBase64Unicode(textContent), branch: env.GH_BRANCH, ...(sha ? { sha } : {}) };
  const writeRes = await fetch(apiUrl, { method: 'PUT', headers: { ...githubHeaders(env), 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  if (!writeRes.ok) throw new Error(`GitHub write error: ${await writeRes.text()}`);
  return writeRes.json();
}
async function writeGithubBinaryBase64(env, filePath, base64Content, message) {
  const apiUrl = `https://api.github.com/repos/${env.GH_OWNER}/${env.GH_REPO}/contents/${filePath}`;
  let sha;
  const currentRes = await fetch(`${apiUrl}?ref=${encodeURIComponent(env.GH_BRANCH)}`, { headers: githubHeaders(env) });
  if (currentRes.ok) sha = (await currentRes.json()).sha;
  else if (currentRes.status !== 404) throw new Error(`GitHub pre-write error: ${await currentRes.text()}`);
  const payload = { message, content: base64Content, branch: env.GH_BRANCH, ...(sha ? { sha } : {}) };
  const writeRes = await fetch(apiUrl, { method: 'PUT', headers: { ...githubHeaders(env), 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  if (!writeRes.ok) throw new Error(`GitHub asset write error: ${await writeRes.text()}`);
  return writeRes.json();
}
function githubHeaders(env){ return { 'Authorization': `Bearer ${env.GITHUB_TOKEN}`, 'Accept': 'application/vnd.github+json', 'User-Agent': 'prozharim-admin-worker' }; }
async function isAuthorized(request, env) { const cookies = parseCookies(request.headers.get('Cookie') || ''); const token = cookies.pz_admin_session; if (!token) return false; return verifySessionToken(token, env.SESSION_SECRET); }
async function createSessionToken(secret) { const exp = Math.floor(Date.now()/1000)+60*60*24*14; const nonce = crypto.randomUUID().replace(/-/g,''); const payload = `${exp}.${nonce}`; const sig = await hmacHex(secret, payload); return base64urlEncode(`${payload}.${sig}`); }
async function verifySessionToken(token, secret) { try { const raw = base64urlDecode(token); const [expStr, nonce, sig] = raw.split('.'); const exp = Number(expStr); if (!exp || !nonce || !sig || Date.now()/1000 > exp) return false; const expected = await hmacHex(secret, `${exp}.${nonce}`); return timingSafeEqual(sig, expected); } catch { return false; } }
function buildSessionCookie(token) { return [`pz_admin_session=${token}`,'Path=/','HttpOnly','Secure','SameSite=Lax','Max-Age=1209600'].join('; '); }
function clearSessionCookie() { return ['pz_admin_session=','Path=/','HttpOnly','Secure','SameSite=Lax','Max-Age=0'].join('; '); }
function parseCookies(header) { const out={}; header.split(';').forEach(part=>{ const idx=part.indexOf('='); if(idx===-1) return; out[part.slice(0,idx).trim()] = part.slice(idx+1).trim(); }); return out; }
function corsHeaders() { return { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' }; }
function withJson(headers) { headers.set('Content-Type', 'application/json; charset=utf-8'); headers.set('Cache-Control', 'no-store'); return headers; }
function json(data, status=200) { return new Response(JSON.stringify(data), { status, headers: withJson(new Headers(corsHeaders())) }); }
function html(content, status=200) { return new Response(content, { status, headers: { 'Content-Type':'text/html; charset=utf-8', 'Cache-Control':'no-store', 'X-Robots-Tag':'noindex, nofollow' } }); }
async function safeJson(request){ try { return await request.json(); } catch { return {}; } }
async function hmacHex(secret, message) { const enc = new TextEncoder(); const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign']); const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message)); return [...new Uint8Array(sig)].map(b=>b.toString(16).padStart(2,'0')).join(''); }
function timingSafeEqual(a,b){ if(a.length!==b.length) return false; let mismatch=0; for(let i=0;i<a.length;i++) mismatch |= a.charCodeAt(i)^b.charCodeAt(i); return mismatch===0; }
function base64urlEncode(str){ return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,''); }
function base64urlDecode(str){ const pad = str.length % 4 ? '='.repeat(4 - (str.length % 4)) : ''; return atob(str.replace(/-/g,'+').replace(/_/g,'/') + pad); }
function encodeBase64Unicode(str){ return btoa(unescape(encodeURIComponent(str))); }
function decodeBase64Unicode(str){ return decodeURIComponent(escape(atob(str))); }
function renderLoginPage(){ return `<!doctype html><html lang="ru"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Прожарим — Вход</title><link rel="stylesheet" href="${'/manager/css/admin.css'}"></head><body class="login-page"><div class="login-wrap"><section class="login-hero"><div class="brand"><div class="brand-mark">P</div><div><div class="brand-title">Прожарим</div><div class="brand-sub">Панель управления</div></div></div><div><div class="brand-sub" style="letter-spacing:.16em;text-transform:uppercase;margin-bottom:14px;color:#ffb273">Secure Admin Access</div><h1 style="font-size:56px;line-height:.95;margin:0 0 14px">Управляй сайтом<br>в едином<br>интерфейсе</h1><p class="muted" style="max-width:520px;line-height:1.7">Вход проверяется Cloudflare Worker. Пароль хранится в secret, а сохранения идут в GitHub без токенов в браузере.</p></div><div class="row"><div class="btn2">Cloudflare Worker Auth</div><div class="btn2">GitHub Save Proxy</div><div class="btn2">HttpOnly session</div></div></section><section class="login-box"><div class="login-card"><h2>Вход</h2><p>Введите пароль администратора для панели управления Прожарим.</p><form id="loginForm"><div class="field"><label>Пароль</label><input id="password" class="input" type="password" autocomplete="current-password" placeholder="Введите пароль"></div><button class="btn" style="width:100%;margin-top:8px" type="submit">Войти в панель</button><div id="err" class="notice" style="margin-top:12px"></div></form></div></section></div><script>const form=document.getElementById('loginForm');const err=document.getElementById('err');form.addEventListener('submit',async(e)=>{e.preventDefault();err.className='notice';const password=document.getElementById('password').value.trim();if(!password){err.textContent='Введите пароль';err.className='notice err';return;}try{const res=await fetch('/api/login',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({password})});const data=await res.json();if(!res.ok){err.textContent=data.error||'Ошибка входа';err.className='notice err';return;}location.href='/manager/';}catch(e){err.textContent='Сервер недоступен';err.className='notice err';}});</script></body></html>`; }
