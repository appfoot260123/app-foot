const express = require('express');
const http = require('http');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { Server } = require('socket.io');
const rateLimit = require('express-rate-limit');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('Configure JWT_SECRET avec une longue valeur secrète (32 caractères minimum).');
if (!DATABASE_URL) throw new Error('Configure DATABASE_URL avec l’URL de ta base PostgreSQL.');

const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.PGSSLMODE === 'disable' ? false : { rejectUnauthorized: false } });
const app = express();
const server = http.createServer(app);
const io = new Server(server);
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, limit: 100, standardHeaders: true, legacyHeaders: false }));

async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(20) NOT NULL,
    username_lower VARCHAR(20) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
}
function makeToken(user) { return jwt.sign({ sub: String(user.id), username: user.username }, JWT_SECRET, { expiresIn: '7d' }); }
function publicUser(row) { return { id: String(row.id), username: row.username }; }
function authHttp(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  try { req.auth = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Connecte-toi à nouveau.' }); }
}
app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'FootZone' }));
app.post('/api/register', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim();
    const password = String(req.body?.password || '');
    if (!/^[A-Za-z0-9_-]{3,20}$/.test(username)) return res.status(400).json({ error: 'Le pseudo doit faire 3 à 20 caractères : lettres, chiffres, _ ou -.' });
    if (password.length < 8 || password.length > 72) return res.status(400).json({ error: 'Le mot de passe doit contenir entre 8 et 72 caractères.' });
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query('INSERT INTO users(username, username_lower, password_hash) VALUES($1,$2,$3) RETURNING id, username', [username, username.toLowerCase(), hash]);
    const user = publicUser(rows[0]); res.status(201).json({ user, token: makeToken(rows[0]) });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Ce pseudo est déjà utilisé. Choisis-en un autre.' });
    console.error('register error', err.message); res.status(500).json({ error: 'Impossible de créer le compte pour le moment.' });
  }
});
app.post('/api/login', async (req, res) => {
  try {
    const username = String(req.body?.username || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const { rows } = await pool.query('SELECT id, username, password_hash FROM users WHERE username_lower=$1', [username]);
    if (!rows.length || !(await bcrypt.compare(password, rows[0].password_hash))) return res.status(401).json({ error: 'Pseudo ou mot de passe incorrect.' });
    res.json({ user: publicUser(rows[0]), token: makeToken(rows[0]) });
  } catch (err) { console.error('login error', err.message); res.status(500).json({ error: 'Connexion impossible pour le moment.' }); }
});
app.get('/api/me', authHttp, async (req, res) => {
  try { const { rows } = await pool.query('SELECT id, username FROM users WHERE id=$1', [req.auth.sub]); if (!rows.length) return res.status(401).json({ error: 'Compte introuvable.' }); res.json({ user: publicUser(rows[0]) }); }
  catch { res.status(500).json({ error: 'Impossible de vérifier le compte.' }); }
});

const rooms = new Map();
function roomCode() { const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let s=''; do { s=''; for(let i=0;i<6;i++) s += chars[Math.floor(Math.random()*chars.length)]; } while(rooms.has(s)); return s; }
function snapshot(room) { return { code: room.code, hostId: room.hostId, players: room.players.map(p => ({ id:p.id, username:p.username })), duel: room.duel ? { shot:room.duel.shot, phase:room.duel.phase, shooter:room.duel.shooter, keeper:room.duel.keeper, goals:room.duel.goals, actions:room.duel.actions, finished:room.duel.finished, log:room.duel.log } : null }; }
function broadcast(room) { io.to(room.code).emit('room:state', snapshot(room)); if(room.duel) io.to(room.code).emit('duel:state', snapshot(room)); }
function sendError(socket, message) { socket.emit('room:error', message); }
io.use((socket, next) => { try { const payload = jwt.verify(socket.handshake.auth?.token || '', JWT_SECRET); socket.user = { id:String(payload.sub), username:payload.username }; next(); } catch { next(new Error('Compte non connecté ou session expirée.')); } });
io.on('connection', socket => {
  socket.on('room:create', () => {
    const code = roomCode(); const room = { code, hostId:socket.id, players:[{ id:socket.id, userId:socket.user.id, username:socket.user.username }], duel:null };
    rooms.set(code, room); socket.join(code); socket.emit('room:created', snapshot(room));
  });
  socket.on('room:join', ({ code } = {}) => {
    code = String(code || '').trim().toUpperCase(); const room = rooms.get(code);
    if (!room) return sendError(socket, 'Salle introuvable. Vérifie le code.');
    if (room.players.some(p => p.userId === socket.user.id)) return sendError(socket, 'Ce compte est déjà dans cette salle.');
    if (room.players.length >= 2) return sendError(socket, 'Cette salle est complète.');
    room.players.push({ id:socket.id, userId:socket.user.id, username:socket.user.username }); socket.join(code); broadcast(room);
  });
  socket.on('room:chat', ({ code, text } = {}) => {
    const room = rooms.get(String(code || '').toUpperCase()); const message = String(text || '').trim().slice(0,250);
    if (!room || !room.players.some(p=>p.id===socket.id) || !message) return;
    io.to(room.code).emit('room:chat', { username:socket.user.username, text:message });
  });
  socket.on('duel:start', ({ code } = {}) => {
    const room = rooms.get(String(code || '').toUpperCase());
    if (!room || room.hostId !== socket.id || room.players.length !== 2) return sendError(socket, 'Il faut deux joueurs, et seul le créateur peut lancer le duel.');
    room.duel = { shot:0, phase:'shoot', shooter:room.players[0].id, keeper:room.players[1].id, goals:[0,0], actions:{}, finished:false, log:['Le duel commence !'] }; broadcast(room);
  });
  socket.on('duel:action', ({ code, direction } = {}) => {
    const room = rooms.get(String(code || '').toUpperCase()), d = room?.duel;
    if (!room || !d || d.finished || !['left','center','right'].includes(direction)) return;
    const me = socket.id;
    if (d.phase === 'shoot' && me === d.shooter && !d.actions[me]?.shot) { d.actions[me] = { ...(d.actions[me]||{}), shot:direction }; d.phase='keep'; }
    else if (d.phase === 'keep' && me === d.keeper && !d.actions[me]?.dive) {
      d.actions[me] = { ...(d.actions[me]||{}), dive:direction };
      const shooterIndex = room.players.findIndex(p=>p.id===d.shooter);
      const scored = d.actions[d.shooter]?.shot !== direction;
      if (scored) d.goals[shooterIndex]++;
      const shooterName = room.players[shooterIndex]?.username || 'Joueur';
      d.log.push(`${shooterName} : ${scored ? 'BUT ! ⚽' : 'ARRÊT ! 🧤'}`);
      d.shot++; d.actions={};
      if (d.shot >= 5) { d.finished=true; d.log.push('Fin du duel !'); }
      else { const oldShooter=d.shooter; d.shooter=d.keeper; d.keeper=oldShooter; d.phase='shoot'; }
      broadcast(room); if(d.finished) io.to(room.code).emit('duel:result', snapshot(room)); return;
    } else return;
    broadcast(room);
  });
  socket.on('disconnect', () => {
    for (const [code, room] of rooms) {
      const index = room.players.findIndex(p=>p.id===socket.id); if(index<0) continue;
      room.players.splice(index,1); if(room.players.length===0) rooms.delete(code); else { if(room.hostId===socket.id) room.hostId=room.players[0].id; room.duel=null; io.to(code).emit('room:left'); broadcast(room); }
    }
  });
});
app.get('*', (req,res) => res.sendFile(path.join(__dirname,'index.html')));
initDb().then(()=>server.listen(PORT,'0.0.0.0',()=>console.log(`FootZone démarré sur le port ${PORT}`))).catch(err=>{console.error('Database startup error:',err.message);process.exit(1)});
