import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, mkdirSync } from 'node:fs';
import { randomBytes, scrypt, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';

process.umask(0o077);
const derive = promisify(scrypt);
const dbPath = process.env.MOU_DB || 'data/accounts.sqlite';
mkdirSync(new URL('.', new URL(dbPath, 'file://' + process.cwd() + '/')), {recursive:true});
const db = new DatabaseSync(dbPath);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS accounts (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, phone TEXT UNIQUE NOT NULL,
 code TEXT UNIQUE NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','user')),
 state TEXT NOT NULL CHECK(state IN ('pending','active','blocked')));
CREATE UNIQUE INDEX IF NOT EXISTS single_admin ON accounts(role) WHERE role='admin';
CREATE TABLE IF NOT EXISTS sessions (
 token TEXT PRIMARY KEY, account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 expires INTEGER NOT NULL);`);
const random = () => randomBytes(32).toString('hex');
const hash = value => createHash('sha256').update(value).digest('hex');
const phone = value => String(value ?? '').trim().replace(/[\s()-]/g,'').replace(/^\+66/,'0');
function fields(values) {
 const name = String(values.name ?? '').trim();
 const number = phone(values.phone);
 const code = String(values.code ?? '').trim().toUpperCase();
 const password = String(values.password ?? '');
 if (!name || name.length > 100 || !/^0[0-9]{8,9}$/.test(number) ||
     !/^[A-Z0-9-]{1,40}$/.test(code) || password.length < 12 || password.length > 128) {
   throw new Error('กรุณาตรวจข้อมูลและตั้งรหัสผ่านอย่างน้อย 12 ตัวอักษร');
 }
 return {name, number, code, password};
}
async function add(values, role) {
 const {name,number,code,password} = fields(values);
 const salt = random();
 const passwordHash = (await derive(password,salt,64)).toString('hex');
 db.prepare('INSERT INTO accounts(name,phone,code,salt,hash,role,state) VALUES(?,?,?,?,?,?,?)')
   .run(name,number,code,salt,passwordHash,role,role === 'admin' ? 'active' : 'pending');
}
if (process.argv[2] === 'init-admin') {
 if (db.prepare("SELECT id FROM accounts WHERE role='admin'").get()) throw Error('ตั้งค่าแอดมินแล้ว');
 let password = '';
 for await (const chunk of process.stdin) password += chunk;
 await add({name:process.env.MOU_ADMIN_NAME, phone:process.env.MOU_ADMIN_PHONE,
   code:process.env.MOU_ADMIN_CODE,password:password.replace(/\r?\n$/,'')},'admin');
 console.log('สร้างบัญชีแอดมินแล้ว');
 process.exit(0);
}
if (!db.prepare("SELECT id FROM accounts WHERE role='admin'").get()) throw Error('เรียก init-admin ก่อนเริ่มระบบ');
const origin = new URL(process.env.MOU_ORIGIN || 'http://127.0.0.1:8080');
const local = ['127.0.0.1','localhost','[::1]'].includes(origin.hostname);
if (origin.protocol !== 'https:' && !(local && origin.protocol === 'http:')) throw Error('ต้องกำหนด HTTPS');
const secure = origin.protocol === 'https:';
const cookie = secure ? '__Host-mou' : 'mou_local';
const flags = '; Path=/; HttpOnly; SameSite=Strict' + (secure ? '; Secure' : '');
const template = readFileSync(new URL('./dashboard.html', import.meta.url), 'utf8');
const clientId = process.env.MOU_GOOGLE_CLIENT_ID || 'REPLACE_WITH_GOOGLE_OAUTH_CLIENT_ID';
if (process.env.MOU_GOOGLE_CLIENT_ID && !/^[a-zA-Z0-9-]+\.apps\.googleusercontent\.com$/.test(clientId)) throw Error('Invalid OAuth Client ID');
const dashboard = '<script src="https://accounts.google.com/gsi/client" async defer></script>' +
 template.split('<body>')[1].split('</body>')[0].replace('REPLACE_WITH_GOOGLE_OAUTH_CLIENT_ID',clientId);
const footer = readFileSync(new URL('./footer.html',import.meta.url),'utf8');
const esc = value => String(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const states = {pending:'รออนุมัติ',active:'ใช้งานได้',blocked:'ยกเลิกสิทธิ์'};
const actions = {pending:['active','อนุมัติ'],active:['blocked','ยกเลิกสิทธิ์'],blocked:['active','คืนสิทธิ์']};
const input = (name,label,type='text',extra='') => `<label>${label}<input name="${name}" type="${type}" required ${extra}></label>`;
function page(user, message='', register=false, adminPage=false, deleting=null) {
 let content;
 if (!user) {
   const form = (action,title,extra='') => `<form method="post" action="/${action}"><h2>${title}</h2>
   ${extra}${input('phone','เบอร์โทรศัพท์','tel','maxlength="30" autocomplete="username"')}
   ${input('password','รหัสผ่าน','password', action==='register'?'minlength="12" maxlength="128" autocomplete="new-password"':'maxlength="128" autocomplete="current-password"')}
   <button>${title}</button></form>`;
   content = '<div class="auth-grid">'+form('login','เข้าสู่ระบบ')+form('register','ลงทะเบียน',
     input('name','ชื่อ','text','maxlength="100"')+input('code','รหัสข้าราชการ สตง.','text','maxlength="40"'))+'</div>';
 } else {
   content = `<strong>${esc(user.name)}</strong> <a href="/">แดชบอร์ด</a>
   ${user.role==='admin'?'<a href="/#admin">ผู้อนุมัติ / แอดมิน</a>':''}
   <form method="post" action="/logout" style="display:inline"><button>ออกจากระบบ</button></form>`;
 }
 if (user?.role==='admin') {
   const members = db.prepare("SELECT id,name,phone,code,state FROM accounts WHERE role='user' ORDER BY state='pending' DESC,id").all();
   content += '<h2 id="admin">คำขอและสิทธิ์ใช้งาน</h2>';
   if (deleting) content += `<p>ยืนยันลบบัญชี ${esc(deleting.name)}</p><form method="post" action="/admin/action"><input type="hidden" name="id" value="${deleting.id}"><button name="action" value="delete">ยืนยันลบ</button> <a href="/#admin">ยกเลิก</a></form>`;
   content += members.length ? '<ul>'+members.map(u => {
     const [action,label] = actions[u.state];
     return `<li>${esc(u.name)} · ${esc(u.phone)} · ${esc(u.code)} · ${states[u.state]}
     <form method="post" action="/admin/action" style="display:inline"><input type="hidden" name="id" value="${u.id}"><input type="hidden" name="state" value="${u.state}"><button name="action" value="${action}">${label}</button></form>
     <a href="/?delete=${u.id}#admin">ลบบัญชี</a></li>`;
   }).join('')+'</ul>' : '<p>ยังไม่มีคำขอ</p>';
 }
 return `<!doctype html><html lang="th"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CASHBORAD MOU70</title>
 <style>body{margin:0;font:16px/1.6 system-ui;color:#102653;background:#eff6ff}.access{padding:18px;max-width:960px;margin:auto}label{display:block;margin:8px 0}label input{display:block;max-width:100%;padding:8px;border:1px solid #9fb8d7;border-radius:6px}button{font:inherit;background:#124b92;color:white;border:0;border-radius:6px;padding:6px 12px;margin:4px}a{color:#124b92}li{overflow-wrap:anywhere}.auth-grid{display:grid;gap:20px;grid-template-columns:repeat(auto-fit,minmax(min(100%,260px),1fr))}#mou-digital[hidden]{display:none!important}#connection{padding:14px 20px;background:white}</style>
 <section class="access"><h1>CASHBORAD MOU70</h1>${message?`<p role="status">${esc(message)}</p>`:''}${content}</section>
 ${user ? dashboard : footer}</html>`;
}
function reply(res,status,body,headers={}) {
 res.writeHead(status,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store',
 'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
 'Content-Security-Policy':"default-src 'none'; img-src data:; style-src 'unsafe-inline' https://accounts.google.com; script-src 'unsafe-inline' https://accounts.google.com; connect-src https://sheets.googleapis.com https://accounts.google.com; frame-src https://accounts.google.com; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
 ...(secure?{'Strict-Transport-Security':'max-age=31536000'}:{}),...headers});
 res.end(body);
}
function redirect(res,location,headers={}) { reply(res,303,'',{Location:location,...headers}); }
const limits = new Map();
const windowMs = 15*60*1000;
function allowed(key,limit) {
 const now = Date.now();
 for (const [k,v] of limits) if (v.until <= now) limits.delete(k);
 if (!limits.has(key) && limits.size >= 10000) return false;
 const value = limits.get(key) || {count:0,until:now+windowMs};
 limits.set(key,value);
 return ++value.count <= limit;
}
const dummySalt = random();
const server = createServer(async (req,res) => {
 try {
  const url = new URL(req.url,origin);
  const path = url.pathname;
  const token = (req.headers.cookie || '').split(';').map(x=>x.trim()).find(x=>x.startsWith(cookie+'='))?.slice(cookie.length+1);
  const tokenHash = token && hash(token);
  const user = tokenHash && db.prepare(`SELECT a.id,a.name,a.role FROM sessions s JOIN accounts a ON a.id=s.account_id
    WHERE s.token=? AND s.expires>? AND a.state='active'`).get(tokenHash,Date.now());
  if (req.method === 'GET') {
   if (path === '/') {
    const deleting = user?.role === 'admin' && url.searchParams.has('delete')
      ? db.prepare("SELECT id,name FROM accounts WHERE id=? AND role='user'").get(url.searchParams.get('delete')) : null;
    return reply(res,200,page(user,'',false,false,deleting));
   }
   if (path === '/register' && !user) return reply(res,200,page(null,'',true));
   if (path === '/admin' && user?.role==='admin') {
    const deleting = db.prepare("SELECT id,name FROM accounts WHERE id=? AND role='user'").get(url.searchParams.get('delete'));
    return reply(res,200,page(user,'',false,true,deleting));
   }
   return reply(res,404,page(user,'ไม่พบหน้าที่ขอ'));
  }
  if (req.method!=='POST' || req.headers.origin!==origin.origin ||
      req.headers['content-type']?.split(';')[0]!=='application/x-www-form-urlencoded') return reply(res,403,'Forbidden');
  let body='';
  for await (const chunk of req) {
   body+=chunk;
   if (body.length>8192) return reply(res,413,'Request too large');
  }
  const data = Object.fromEntries(new URLSearchParams(body));
  const ip = req.socket.remoteAddress;
  if (path==='/logout') {
   if (tokenHash) db.prepare('DELETE FROM sessions WHERE token=?').run(tokenHash);
   return redirect(res,'/',{'Set-Cookie':cookie+'='+flags+'; Max-Age=0'});
  }
  if (path==='/register' && !user) {
   if (!allowed('register:'+ip,12)) return reply(res,429,page(null,'กรุณารอสักครู่แล้วลองใหม่',true));
   try { await add(data,'user'); }
   catch (error) {
    const message=String(error.message).startsWith('กรุณา')?error.message:'ส่งคำขอไม่ได้ กรุณาตรวจข้อมูลหรือติดต่อผู้อนุมัติ';
    return reply(res,400,page(null,message,true));
   }
   return reply(res,201,page(null,'ส่งคำขอแล้ว กรุณารออนุมัติ'));
  }
  if (path==='/login' && !user) {
   const number = phone(data.phone);
   if (!allowed('ip:'+ip,60) || !allowed('phone:'+number,10)) return reply(res,429,page(null,'กรุณารอสักครู่แล้วลองใหม่'));
   if (!data.password || data.password.length>128) return reply(res,401,page(null,'ข้อมูลเข้าสู่ระบบไม่ถูกต้อง'));
   const account = db.prepare('SELECT id,salt,hash,state FROM accounts WHERE phone=?').get(number);
   const derived = await derive(data.password,account?.salt || dummySalt,64);
   if (!account || !timingSafeEqual(derived,Buffer.from(account.hash,'hex'))) return reply(res,401,page(null,'ข้อมูลเข้าสู่ระบบไม่ถูกต้อง'));
   const current = db.prepare('SELECT state,salt FROM accounts WHERE id=?').get(account.id);
   if (!current || current.salt!==account.salt || current.state!=='active') return reply(res,403,page(null,current?.state==='pending'?'บัญชีรออนุมัติ':'บัญชีนี้เข้าใช้งานไม่ได้'));
   const fresh = random();
   db.prepare('DELETE FROM sessions WHERE expires<=?').run(Date.now());
   db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(hash(fresh),account.id,Date.now()+8*3600000);
   return redirect(res,'/',{'Set-Cookie':cookie+'='+fresh+flags+'; Max-Age=28800'});
  }
  if (path==='/admin/action' && user?.role==='admin') {
   if (data.action==='delete') db.prepare("DELETE FROM accounts WHERE id=? AND role='user'").run(data.id);
   else if (actions[data.state]?.[0]===data.action && Object.hasOwn(actions,data.state)) {
    db.exec('BEGIN');
    try {
     const changed=db.prepare("UPDATE accounts SET state=? WHERE id=? AND role='user' AND state=?").run(data.action,data.id,data.state);
     if (changed.changes && data.action==='blocked') db.prepare('DELETE FROM sessions WHERE account_id=?').run(data.id);
     db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
   }
   return redirect(res,'/#admin');
  }
  return reply(res,403,'Forbidden');
 } catch (error) {
  console.error(error.code || error.name);
  if (!res.headersSent) reply(res,500,'ระบบขัดข้อง');
 }
});
server.listen(Number(process.env.PORT || 8080),process.env.MOU_BIND || '127.0.0.1');
