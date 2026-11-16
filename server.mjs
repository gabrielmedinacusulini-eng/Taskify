/* Taskify — servidor + banco de dados (SQLite).
   Rode com:  node server.mjs   (precisa do Node 22 ou mais novo)
   O banco (arquivo data.db) é criado sozinho na primeira vez. */
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { exec } from "node:child_process";
import { DatabaseSync } from "node:sqlite";

const DIR = path.dirname(fileURLToPath(import.meta.url));

/* ---------- configuração (.env) ---------- */
try {
  for (const line of fs.readFileSync(path.join(DIR, ".env"), "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, "$2");
  }
} catch { /* sem .env: usa o padrão */ }
const PORT = Number(process.env.PORT) || 3000;
const DB_FILE = process.env.DB_FILE || path.join(DIR, "data.db");
const DEMO = process.env.DEMO_MODE === "1"; // só para testes: mostra o código na tela (NÃO use de verdade)
const EMAILJS_URL = process.env.EMAILJS_URL || "https://api.emailjs.com/api/v1.0/email/send";

/* ---------- banco de dados ---------- */
const db = new DatabaseSync(DB_FILE);
db.exec(`
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, nickname TEXT NOT NULL DEFAULT '',
  email TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, hash TEXT NOT NULL,
  two_fa INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS codes (
  code_key TEXT PRIMARY KEY, hash TEXT NOT NULL, exp INTEGER NOT NULL, sent INTEGER NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS fails (email TEXT PRIMARY KEY, n INTEGER NOT NULL, until INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS friends (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  friend_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (user_id, friend_id));
CREATE TABLE IF NOT EXISTS friend_requests (
  from_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  to_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (from_id, to_id));
CREATE TABLE IF NOT EXISTS lists (
  id TEXT PRIMARY KEY, type TEXT NOT NULL, name TEXT NOT NULL,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS list_members (
  list_id TEXT NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (list_id, user_id));
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, list_id TEXT NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
  text TEXT NOT NULL, descr TEXT NOT NULL DEFAULT '', date TEXT NOT NULL, time TEXT NOT NULL,
  done INTEGER NOT NULL DEFAULT 0, by_id TEXT REFERENCES users(id) ON DELETE SET NULL);
CREATE INDEX IF NOT EXISTS tasks_list ON tasks(list_id);
CREATE INDEX IF NOT EXISTS members_user ON list_members(user_id);
`);
const q = (sql, ...a) => db.prepare(sql).all(...a);
const q1 = (sql, ...a) => db.prepare(sql).get(...a);
const run = (sql, ...a) => db.prepare(sql).run(...a);
const tx = fn => { db.exec("BEGIN"); try { const r = fn(); db.exec("COMMIT"); return r; } catch (e) { db.exec("ROLLBACK"); throw e; } };

/* ---------- utilitários ---------- */
class HttpError extends Error { constructor(status, message) { super(message); this.status = status; } }
const bad = (m, s = 400) => new HttpError(s, m);
const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const rand = n => crypto.randomBytes(n).toString("hex");
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString("hex");
const same = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const norm = e => String(e || "").trim().toLowerCase();
const str = (v, max) => String(v ?? "").trim().slice(0, max);
const now = () => Date.now();
const userByEmail = email => q1("SELECT * FROM users WHERE email = ?", email);
const userById = id => q1("SELECT * FROM users WHERE id = ?", id);

/* ---------- e-mail com código (EmailJS) ---------- */
const MAILS = {
  register: { title: "Código para se registrar", message: "Use este código para se registrar:" },
  password: { title: "Código para trocar sua senha", message: "Use este código para trocar sua senha:" },
  reset: { title: "Código para redefinir sua senha", message: "Use este código para redefinir sua senha:" },
  login: { title: "Código para entrar", message: "Como a sua verificação em duas etapas está ativada, use este código para entrar:" }
};
const mailReady = () => !!(process.env.EMAILJS_SERVICE_ID && process.env.EMAILJS_TEMPLATE_ID && process.env.EMAILJS_PUBLIC_KEY);

async function sendMail(email, name, kind, code) {
  if (!mailReady()) return false; // sem configuração = modo demo (o código aparece na tela)
  const { EMAILJS_SERVICE_ID: s, EMAILJS_TEMPLATE_ID: t, EMAILJS_PUBLIC_KEY: p, EMAILJS_PRIVATE_KEY: k } = process.env;
  const r = await fetch(EMAILJS_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    signal: AbortSignal.timeout(15000),
    body: JSON.stringify({ service_id: s, template_id: t, user_id: p, accessToken: k, template_params: { to_email: email, to_name: name, code, ...MAILS[kind] } })
  }).catch(() => { throw bad("Não foi possível enviar o e-mail. Tente de novo.", 502); });
  if (!r.ok) {
    console.error("EmailJS respondeu", r.status, await r.text().catch(() => ""));
    throw bad("Não foi possível enviar o e-mail (" + r.status + ").", 502);
  }
  return true;
}

async function sendCode(email, name, kind, data) {
  if (!mailReady() && !DEMO) throw bad("O envio de e-mail ainda não foi configurado no servidor. Avise o administrador do site.", 503);
  const key = `${kind}:${email}`;
  const old = q1("SELECT sent FROM codes WHERE code_key = ?", key);
  if (old && now() - old.sent < 30000) throw bad("Aguarde 30 segundos para reenviar.", 429);
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  run("INSERT OR REPLACE INTO codes (code_key, hash, exp, sent, tries, data) VALUES (?, ?, ?, ?, 0, ?)",
    key, sha(code + key), now() + 6e5, now(), JSON.stringify(data || {}));
  try {
    if (await sendMail(email, name, kind, code)) return `Enviamos um código para ${email}. Vale por 10 minutos.`;
  } catch (e) { run("DELETE FROM codes WHERE code_key = ?", key); throw e; }
  return "MODO DEMO (e-mail não configurado). Seu código: " + code;
}

function checkCode(kind, email, code) {
  const key = `${kind}:${email}`;
  const r = q1("SELECT * FROM codes WHERE code_key = ?", key);
  if (!r || now() > r.exp) throw bad("Código expirado. Envie outro.");
  if (r.tries >= 5) { run("DELETE FROM codes WHERE code_key = ?", key); throw bad("Muitas tentativas. Envie outro código.", 429); }
  if (!same(sha(String(code || "").trim() + key), r.hash)) { run("UPDATE codes SET tries = tries + 1 WHERE code_key = ?", key); throw bad("Código incorreto."); }
  run("DELETE FROM codes WHERE code_key = ?", key);
  return JSON.parse(r.data);
}

/* ---------- sessões ---------- */
function newSession(userId) {
  const token = rand(32);
  run("INSERT INTO sessions (token_hash, user_id, exp) VALUES (?, ?, ?)", sha(token), userId, now() + 30 * 864e5);
  return token;
}
function auth(req) {
  const token = (req.headers.authorization || "").replace(/^Bearer /, "");
  if (!token) throw bad("Sessão expirada.", 401);
  const s = q1("SELECT * FROM sessions WHERE token_hash = ?", sha(token));
  if (!s || s.exp < now()) throw bad("Sessão expirada.", 401);
  const u = userById(s.user_id);
  if (!u) throw bad("Sessão expirada.", 401);
  return { u, token };
}

/* ---------- contas ---------- */
function createUser({ name, email, salt, hash }) {
  return tx(() => {
    if (userByEmail(email)) throw bad("Este e-mail já tem uma conta.", 409);
    const id = rand(8), listId = rand(6);
    run("INSERT INTO users (id, name, email, salt, hash, created) VALUES (?, ?, ?, ?, ?, ?)", id, name, email, salt, hash, now());
    run("INSERT INTO lists (id, type, name, owner_id) VALUES (?, 'personal', 'Sua lista privada', ?)", listId, id);
    run("INSERT INTO list_members (list_id, user_id) VALUES (?, ?)", listId, id);
    return id;
  });
}

async function registerStart(b) {
  const name = str(b.name, 40), email = norm(b.email), password = String(b.password || "");
  if (name.length < 2) throw bad("Digite seu nome.");
  if (!/^\S+@\S+\.\S+$/.test(email)) throw bad("E-mail inválido.");
  if (password.length < 8 || password.length > 200) throw bad("A senha precisa de 8 caracteres ou mais.");
  if (userByEmail(email)) throw bad("Este e-mail já tem uma conta.", 409);
  const salt = rand(16);
  return { note: await sendCode(email, name, "register", { name, salt, hash: hashPw(password, salt) }) };
}

function registerConfirm(b) {
  const email = norm(b.email);
  const d = checkCode("register", email, b.code);
  const id = createUser({ name: d.name, email, salt: d.salt, hash: d.hash });
  return { token: newSession(id) };
}

async function login(b) {
  const email = norm(b.email), password = String(b.password || "");
  const f = q1("SELECT * FROM fails WHERE email = ?", email) || { n: 0, until: 0 };
  if (now() < f.until) throw bad("Muitas tentativas. Aguarde 30 segundos.", 429);
  const u = userByEmail(email);
  const ok = u && password.length <= 200 && same(hashPw(password, u.salt), u.hash);
  if (!ok) {
    const n = f.n + 1;
    run("INSERT OR REPLACE INTO fails (email, n, until) VALUES (?, ?, ?)", email, n >= 5 ? 0 : n, n >= 5 ? now() + 3e4 : 0);
    throw bad("E-mail ou senha incorretos.", 401);
  }
  run("DELETE FROM fails WHERE email = ?", email);
  if (u.two_fa) return { twofa: true, note: await sendCode(email, u.name, "login", { id: u.id }) };
  return { token: newSession(u.id) };
}

function loginConfirm(b) {
  const email = norm(b.email);
  const d = checkCode("login", email, b.code);
  return { token: newSession(d.id) };
}

async function resetStart(b) {
  const email = norm(b.email);
  const note = "Se existir uma conta com este e-mail, enviamos um código. Vale por 10 minutos.";
  const u = userByEmail(email);
  if (!u) return { note };
  const n = await sendCode(email, u.name, "reset", { id: u.id });
  return { note: n.startsWith("MODO DEMO") ? n : note };
}

function resetConfirm(b) {
  const email = norm(b.email), password = String(b.password || "");
  if (password.length < 8 || password.length > 200) throw bad("A senha precisa de 8 caracteres ou mais.");
  const d = checkCode("reset", email, b.code);
  const u = userById(d.id);
  if (!u) throw bad("Conta não encontrada.", 404);
  const salt = rand(16);
  tx(() => {
    run("UPDATE users SET salt = ?, hash = ? WHERE id = ?", salt, hashPw(password, salt), u.id);
    run("DELETE FROM sessions WHERE user_id = ?", u.id); // derruba os logins antigos
  });
  return { ok: true };
}

async function passwordStart(u, b) {
  const password = String(b.password || "");
  if (password.length < 8 || password.length > 200) throw bad("A senha precisa de 8 caracteres ou mais.");
  const salt = rand(16);
  return { note: await sendCode(u.email, u.name, "password", { salt, hash: hashPw(password, salt) }) };
}

function passwordConfirm(u, b) {
  const d = checkCode("password", u.email, b.code);
  run("UPDATE users SET salt = ?, hash = ? WHERE id = ?", d.salt, d.hash, u.id);
  return { ok: true };
}

function profile(u, b) {
  if (b.name !== undefined) {
    const n = str(b.name, 40);
    if (n.length < 2) throw bad("Digite um nome.");
    run("UPDATE users SET name = ? WHERE id = ?", n, u.id);
  }
  if (b.nickname !== undefined) run("UPDATE users SET nickname = ? WHERE id = ?", str(b.nickname, 28), u.id);
  if (b.twoFA !== undefined) run("UPDATE users SET two_fa = ? WHERE id = ?", b.twoFA ? 1 : 0, u.id);
  return { ok: true };
}

/* ---------- listas e tarefas (formato que o site espera) ---------- */
function fullList(id) {
  const l = q1("SELECT * FROM lists WHERE id = ?", id);
  if (!l) return null;
  return {
    id: l.id, type: l.type, name: l.name, ownerId: l.owner_id,
    members: q("SELECT user_id FROM list_members WHERE list_id = ? ORDER BY rowid", id).map(r => r.user_id),
    tasks: q("SELECT id, text, descr, date, time, done, by_id FROM tasks WHERE list_id = ? ORDER BY rowid", id)
      .map(t => ({ id: t.id, text: t.text, desc: t.descr, date: t.date, time: t.time, done: !!t.done, by: t.by_id }))
  };
}

function state(u) {
  const lists = q("SELECT list_id FROM list_members WHERE user_id = ? ORDER BY rowid", u.id).map(r => fullList(r.list_id));
  const friendIds = q("SELECT friend_id AS id FROM friends WHERE user_id = ? ORDER BY rowid", u.id).map(r => r.id);
  const reqIds = q("SELECT from_id AS id FROM friend_requests WHERE to_id = ? ORDER BY rowid", u.id).map(r => r.id);
  const ids = new Set([u.id, ...friendIds, ...reqIds, ...lists.flatMap(l => [...l.members, ...l.tasks.map(t => t.by).filter(Boolean)])]);
  const names = {};
  for (const id of ids) { const x = userById(id); if (x) names[id] = x.nickname || x.name; }
  return {
    me: { id: u.id, name: u.name, nickname: u.nickname, email: u.email, twoFA: !!u.two_fa },
    lists, names,
    friends: friendIds.filter(id => names[id]).map(id => ({ id, name: names[id] })),
    requests: reqIds.filter(id => names[id]).map(id => ({ id, name: names[id] }))
  };
}

/* ---------- amigos ---------- */
const makeFriends = (a, b) => tx(() => {
  run("DELETE FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)", a, b, b, a);
  run("INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)", a, b);
  run("INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)", b, a);
});
const areFriends = (a, b) => !!q1("SELECT 1 AS x FROM friends WHERE user_id = ? AND friend_id = ?", a, b);

function friendRequest(u, b) {
  const note = "Se existir uma conta com este e-mail, o pedido foi enviado.";
  const t = userByEmail(norm(b.email));
  if (t && t.id === u.id) throw bad("Esse é o seu próprio e-mail.");
  if (!t) return { note };
  if (areFriends(u.id, t.id)) throw bad("Vocês já são amigos.");
  if (q1("SELECT 1 AS x FROM friend_requests WHERE from_id = ? AND to_id = ?", t.id, u.id)) { makeFriends(u.id, t.id); return { note: "Vocês agora são amigos." }; }
  run("INSERT OR IGNORE INTO friend_requests (from_id, to_id) VALUES (?, ?)", u.id, t.id);
  return { note };
}
function friendAccept(u, b) {
  const id = String(b.id || "");
  if (!q1("SELECT 1 AS x FROM friend_requests WHERE from_id = ? AND to_id = ?", id, u.id)) throw bad("Pedido não encontrado.", 404);
  if (!userById(id)) throw bad("Conta não encontrada.", 404);
  makeFriends(u.id, id);
  return { ok: true };
}
function friendDecline(u, b) { run("DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?", String(b.id || ""), u.id); return { ok: true }; }
function friendRemove(u, b) {
  const id = String(b.id || "");
  run("DELETE FROM friends WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)", u.id, id, id, u.id);
  return { ok: true };
}

/* ---------- listas ---------- */
function getList(id, u) {
  const l = q1("SELECT l.* FROM lists l JOIN list_members m ON m.list_id = l.id WHERE l.id = ? AND m.user_id = ?", String(id), u.id);
  if (!l) throw bad("Lista não encontrada.", 404);
  return l;
}

function createList(u, b) {
  const name = str(b.name, 28);
  if (!name) throw bad("Dê um nome à lista.");
  if (q1("SELECT COUNT(*) AS c FROM list_members WHERE user_id = ?", u.id).c >= 30) throw bad("Limite de listas atingido.");
  const group = b.kind === "group";
  const members = [u.id];
  if (group) for (const id of new Set(Array.isArray(b.members) ? b.members.map(String) : [])) if (areFriends(u.id, id) && !members.includes(id)) members.push(id);
  const id = rand(6);
  tx(() => {
    run("INSERT INTO lists (id, type, name, owner_id) VALUES (?, ?, ?, ?)", id, group ? "group" : "personal", name, u.id);
    for (const m of members) run("INSERT INTO list_members (list_id, user_id) VALUES (?, ?)", id, m);
  });
  return { list: fullList(id) };
}

function deleteList(u, id) {
  const l = getList(id, u);
  if (l.type === "personal") {
    const mine = q1("SELECT COUNT(*) AS c FROM lists l JOIN list_members m ON m.list_id = l.id WHERE m.user_id = ? AND l.type = 'personal'", u.id).c;
    if (mine <= 1) throw bad("Você precisa ter ao menos uma lista pessoal.");
  }
  if (l.owner_id === u.id) run("DELETE FROM lists WHERE id = ?", l.id); // apaga membros e tarefas junto
  else run("DELETE FROM list_members WHERE list_id = ? AND user_id = ?", l.id, u.id);
}

function taskOp(u, id, b) {
  const l = getList(id, u);
  let taskId;
  if (b.op === "add") {
    const text = str(b.text, 80);
    if (!text) throw bad("Digite a tarefa.");
    if (q1("SELECT COUNT(*) AS c FROM tasks WHERE list_id = ?", l.id).c >= 200) throw bad("Esta lista chegou ao limite de tarefas.");
    if (!/^\d{4}-\d{2}-\d{2}$/.test(b.date || "") || !/^\d{2}:\d{2}$/.test(b.time || "")) throw bad("Escolha a data e o horário.");
    taskId = rand(6);
    run("INSERT INTO tasks (id, list_id, text, descr, date, time, done, by_id) VALUES (?, ?, ?, ?, ?, ?, 0, ?)", taskId, l.id, text, str(b.desc, 140), b.date, b.time, u.id);
  } else if (b.op === "toggle") {
    const r = run("UPDATE tasks SET done = ? WHERE id = ? AND list_id = ?", b.done ? 1 : 0, String(b.taskId || ""), l.id);
    if (!r.changes) throw bad("Tarefa não encontrada.", 404);
  } else if (b.op === "remove") {
    run("DELETE FROM tasks WHERE id = ? AND list_id = ?", String(b.taskId || ""), l.id);
  } else if (b.op === "clear") {
    run("DELETE FROM tasks WHERE list_id = ?", l.id);
  } else throw bad("Operação inválida.");
  return { list: fullList(l.id), taskId };
}

/* ---------- rotas da API ---------- */
async function route(req, path, body) {
  const m = req.method;
  const is = (meth, ...p) => m === meth && path.length === p.length && p.every((x, i) => path[i] === x);

  if (is("POST", "register", "start")) return registerStart(body);
  if (is("POST", "register", "confirm")) return registerConfirm(body);
  if (is("POST", "login")) return login(body);
  if (is("POST", "login", "confirm")) return loginConfirm(body);
  if (is("POST", "reset", "start")) return resetStart(body);
  if (is("POST", "reset", "confirm")) return resetConfirm(body);

  const { u, token } = auth(req);
  if (is("GET", "me")) return state(u);
  if (is("POST", "logout")) { run("DELETE FROM sessions WHERE token_hash = ?", sha(token)); return { ok: true }; }
  if (is("PATCH", "profile")) return profile(u, body);
  if (is("POST", "password", "start")) return passwordStart(u, body);
  if (is("POST", "password", "confirm")) return passwordConfirm(u, body);
  if (is("POST", "friends", "request")) return friendRequest(u, body);
  if (is("POST", "friends", "accept")) return friendAccept(u, body);
  if (is("POST", "friends", "decline")) return friendDecline(u, body);
  if (is("POST", "friends", "remove")) return friendRemove(u, body);
  if (is("POST", "lists")) return createList(u, body);
  if (m === "DELETE" && path[0] === "lists" && path.length === 2) { deleteList(u, path[1]); return { ok: true }; }
  if (m === "POST" && path[0] === "lists" && path[2] === "tasks" && path.length === 3) return taskOp(u, path[1], body);
  throw bad("Rota não encontrada.", 404);
}

const CORS = { "access-control-allow-origin": "*", "access-control-allow-headers": "authorization, content-type", "access-control-allow-methods": "GET, POST, PATCH, DELETE, OPTIONS" };
const readBody = req => new Promise((resolve, reject) => {
  let size = 0; const chunks = [];
  req.on("data", c => { size += c.length; if (size > 1e6) { reject(bad("Pedido grande demais.", 413)); req.destroy(); } else chunks.push(c); });
  req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {}); } catch { resolve({}); } });
  req.on("error", reject);
});

async function handleApi(req, res, url) {
  const send = (d, s = 200) => { res.writeHead(s, { "content-type": "application/json", "cache-control": "no-store", ...CORS }); res.end(JSON.stringify(d)); };
  if (req.method === "OPTIONS") { res.writeHead(204, CORS); return res.end(); }
  try {
    const path = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
    const body = req.method === "GET" || req.method === "DELETE" ? {} : await readBody(req);
    send(await route(req, path, body));
  } catch (e) {
    if (e instanceof HttpError) return send({ error: e.message }, e.status);
    console.error(e);
    send({ error: "Erro no servidor. Tente de novo." }, 500);
  }
}

/* ---------- arquivos do site ---------- */
const FILES = {
  "/": ["index.html", "text/html; charset=utf-8"], "/index.html": ["index.html", "text/html; charset=utf-8"],
  "/icon.png": ["icon.png", "image/png"], "/favicon.ico": ["icon.png", "image/png"]
};
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname.startsWith("/api/") || url.pathname === "/api") return handleApi(req, res, url);
  const f = FILES[url.pathname];
  if (!f) { res.writeHead(404, { "content-type": "text/plain; charset=utf-8" }); return res.end("Página não encontrada."); }
  fs.readFile(path.join(DIR, f[0]), (err, data) => {
    if (err) { res.writeHead(404, { "content-type": "text/plain; charset=utf-8" }); return res.end("Arquivo não encontrado: " + f[0]); }
    res.writeHead(200, { "content-type": f[1], "cache-control": "no-cache", "x-content-type-options": "nosniff" });
    res.end(data);
  });
});

/* ---------- limpeza e início ---------- */
const cleanup = () => {
  run("DELETE FROM sessions WHERE exp < ?", now());
  run("DELETE FROM codes WHERE exp < ?", now());
  run("DELETE FROM fails WHERE until < ? AND until > 0", now());
};
cleanup();
setInterval(cleanup, 36e5).unref();
process.on("SIGINT", () => { server.close(); db.close(); process.exit(0); });

/* ---------- teste de e-mail:  npm run testar-email -- seu@email.com ---------- */
const ti = process.argv.indexOf("--test-email");
if (ti > 0) {
  const to = norm(process.argv[ti + 1]);
  if (!/^\S+@\S+\.\S+$/.test(to)) { console.log("\n  Uso: npm run testar-email -- seu@email.com\n"); process.exit(1); }
  if (!mailReady()) { console.log("\n  Falta preencher o arquivo .env (EMAILJS_SERVICE_ID, EMAILJS_TEMPLATE_ID e EMAILJS_PUBLIC_KEY).\n"); process.exit(1); }
  try {
    await sendMail(to, "Teste", "register", String(crypto.randomInt(0, 1000000)).padStart(6, "0"));
    console.log(`\n  OK! O EmailJS aceitou o envio para ${to}. Confira a caixa de entrada (e o spam).\n`);
    process.exit(0);
  } catch (e) { console.log("\n  FALHOU: " + e.message + "\n  (o motivo detalhado do EmailJS aparece logo acima)\n"); process.exit(1); }
}

/* ---------- início ---------- */
const openBrowser = url => exec(process.platform === "win32" ? `start "" "${url}"` : process.platform === "darwin" ? `open "${url}"` : `xdg-open "${url}"`, () => {});
server.on("error", e => {
  if (e.code === "EADDRINUSE") console.log(`\n  A porta ${PORT} já está em uso. Provavelmente o Taskify já está aberto em outra janela. Feche-a e tente de novo.\n`);
  else console.error(e);
  process.exit(1);
});
server.listen(PORT, () => {
  const url = `http://localhost:${PORT}`;
  console.log(`\n  Taskify rodando em  ${url}`);
  console.log(`  Banco de dados:     ${DB_FILE}`);
  if (mailReady()) {
    console.log("  E-mail:             EmailJS configurado: os códigos vão por e-mail");
    if (!process.env.EMAILJS_PRIVATE_KEY) console.log("  Aviso:              EMAILJS_PRIVATE_KEY está vazia. Se o envio falhar com erro 403, preencha no .env");
  } else if (DEMO) console.log("  E-mail:             MODO DEMO (só para testes): o código aparece na tela");
  else console.log("\n  ATENÇÃO: o e-mail NÃO está configurado. Preencha o arquivo .env e reinicie.\n  Até lá, ninguém consegue criar conta nem recuperar senha.");
  console.log("\n  Para desligar: feche esta janela ou aperte Ctrl + C\n");
  if (!process.env.NO_BROWSER) openBrowser(url);
});
