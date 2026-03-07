// PalisadeOne Auth & Client Data API
// Deploy to /opt/auth-api.js on 178.156.234.30
// Loaded by wazuh-proxy-ssl.js

const crypto = require('crypto');
const path = require('path');

// SQLite setup
let db;
try {
  const Database = require('better-sqlite3');
  db = new Database('/opt/palisadeone.db');
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
} catch(e) {
  console.error('SQLite init failed:', e.message);
  console.log('Run: npm install better-sqlite3');
}

// ============ SCHEMA ============
function initDB() {
  if (!db) return;
  db.exec(`
    CREATE TABLE IF NOT EXISTS clients (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      industry TEXT DEFAULT 'technology',
      tier TEXT DEFAULT 'monitor' CHECK(tier IN ('monitor','defend','dominate')),
      employees TEXT DEFAULT '1-50',
      contact_email TEXT,
      contact_name TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      client_id TEXT,
      role TEXT DEFAULT 'client' CHECK(role IN ('admin','client')),
      name TEXT,
      active INTEGER DEFAULT 1,
      last_login TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (client_id) REFERENCES clients(id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS assessments (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      frameworks TEXT,
      answers TEXT,
      scores TEXT,
      company_profile TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (client_id) REFERENCES clients(id)
    );

    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      severity TEXT DEFAULT 'medium',
      control TEXT,
      framework TEXT,
      status TEXT DEFAULT 'open' CHECK(status IN ('open','in_progress','done')),
      due_date TEXT,
      assigned_to TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (client_id) REFERENCES clients(id)
    );

    CREATE TABLE IF NOT EXISTS evidence (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      control TEXT NOT NULL,
      filename TEXT NOT NULL,
      uploaded_by TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (client_id) REFERENCES clients(id)
    );

    CREATE TABLE IF NOT EXISTS policies (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      policy_id TEXT NOT NULL,
      status TEXT DEFAULT 'draft' CHECK(status IN ('draft','published')),
      published_at TEXT,
      FOREIGN KEY (client_id) REFERENCES clients(id)
    );

    CREATE TABLE IF NOT EXISTS tickets (
      id TEXT PRIMARY KEY,
      client_id TEXT,
      user_id TEXT NOT NULL,
      subject TEXT NOT NULL,
      description TEXT,
      category TEXT DEFAULT 'general' CHECK(category IN ('general','incident','access','billing','vulnerability','compliance')),
      priority TEXT DEFAULT 'medium' CHECK(priority IN ('low','medium','high','critical')),
      status TEXT DEFAULT 'open' CHECK(status IN ('open','in_progress','waiting','resolved','closed')),
      assigned_to TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now')),
      resolved_at TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS ticket_messages (
      id TEXT PRIMARY KEY,
      ticket_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      message TEXT NOT NULL,
      is_admin INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (ticket_id) REFERENCES tickets(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);

  // Seed admin user if not exists
  const adminExists = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@palisadeone.com');
  if (!adminExists) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPassword('PalisadeOne2026!', salt);
    db.prepare('INSERT INTO users (id, email, password_hash, salt, role, name) VALUES (?, ?, ?, ?, ?, ?)').run(
      genId(), 'admin@palisadeone.com', hash, salt, 'admin', 'PalisadeOne Admin'
    );
    console.log('[AUTH] Admin user seeded');
  }

  console.log('[AUTH] Database initialized');
}

// ============ HELPERS ============
function genId() { return crypto.randomBytes(12).toString('hex'); }

function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function verifyPassword(password, hash, salt) {
  return hashPassword(password, salt) === hash;
}

function genToken() { return crypto.randomBytes(32).toString('hex'); }

function getSession(token) {
  if (!db || !token) return null;
  const session = db.prepare(`
    SELECT s.*, u.email, u.role, u.client_id, u.name as user_name, u.active,
           c.name as client_name, c.tier, c.industry
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    LEFT JOIN clients c ON u.client_id = c.id
    WHERE s.token = ? AND s.expires_at > datetime('now')
  `).get(token);
  return session && session.active ? session : null;
}

function requireAuth(req) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return null;
  return getSession(token);
}

function requireAdmin(req) {
  const session = requireAuth(req);
  return session && session.role === 'admin' ? session : null;
}

function jsonResponse(res, data, status = 200) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

// ============ ROUTE HANDLER ============
function handleAuthRoutes(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname;
  const method = req.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type,Authorization',
      'Access-Control-Max-Age': '86400'
    });
    return res.end();
  }

  // ---- LOGIN ----
  if (path === '/auth/login' && method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { email, password } = JSON.parse(body);
        if (!email || !password) return jsonResponse(res, { error: 'Email and password required' }, 400);

        const user = db.prepare('SELECT * FROM users WHERE email = ? AND active = 1').get(email.toLowerCase().trim());
        if (!user || !verifyPassword(password, user.password_hash, user.salt)) {
          return jsonResponse(res, { error: 'Invalid credentials' }, 401);
        }

        // Create session (7 day expiry)
        const token = genToken();
        db.prepare(`INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, datetime('now', '+7 days'))`).run(token, user.id);
        db.prepare(`UPDATE users SET last_login = datetime('now') WHERE id = ?`).run(user.id);

        // Get client info
        let client = null;
        if (user.client_id) {
          client = db.prepare('SELECT * FROM clients WHERE id = ?').get(user.client_id);
        }

        jsonResponse(res, {
          token,
          user: { id: user.id, email: user.email, name: user.name, role: user.role },
          client: client ? { id: client.id, name: client.name, tier: client.tier, industry: client.industry } : null,
          redirect: user.role === 'admin' ? '/dashboard.html' : '/client-portal.html'
        });
      } catch(e) { console.error('[AUTH] Login error:', e); jsonResponse(res, { error: 'Server error: ' + e.message }, 500); }
    });
    return;
  }

  // ---- LOGOUT ----
  if (path === '/auth/logout' && method === 'POST') {
    const session = requireAuth(req);
    if (session) db.prepare('DELETE FROM sessions WHERE token = ?').run(session.token);
    return jsonResponse(res, { ok: true });
  }

  // ---- ME (current user) ----
  if (path === '/auth/me' && method === 'GET') {
    const session = requireAuth(req);
    if (!session) return jsonResponse(res, { error: 'Not authenticated' }, 401);
    return jsonResponse(res, {
      user: { id: session.user_id, email: session.email, name: session.user_name, role: session.role },
      client: session.client_id ? { id: session.client_id, name: session.client_name, tier: session.tier, industry: session.industry } : null
    });
  }

  // ---- LIST CLIENTS (admin only) ----
  if (path === '/auth/clients' && method === 'GET') {
    const session = requireAdmin(req);
    if (!session) return jsonResponse(res, { error: 'Admin required' }, 403);
    const clients = db.prepare('SELECT * FROM clients ORDER BY created_at DESC').all();
    // Add user count per client
    clients.forEach(c => {
      c.userCount = db.prepare('SELECT COUNT(*) as cnt FROM users WHERE client_id = ?').get(c.id).cnt;
      c.assessmentCount = db.prepare('SELECT COUNT(*) as cnt FROM assessments WHERE client_id = ?').get(c.id).cnt;
    });
    return jsonResponse(res, { clients });
  }

  // ---- CREATE CLIENT (admin only) ----
  if (path === '/auth/clients' && method === 'POST') {
    const session = requireAdmin(req);
    if (!session) return jsonResponse(res, { error: 'Admin required' }, 403);
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { name, industry, tier, employees, contact_email, contact_name } = JSON.parse(body);
        if (!name) return jsonResponse(res, { error: 'Client name required' }, 400);
        const id = genId();
        db.prepare('INSERT INTO clients (id, name, industry, tier, employees, contact_email, contact_name) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
          id, name, industry || 'technology', tier || 'monitor', employees || '1-50', contact_email || '', contact_name || ''
        );
        return jsonResponse(res, { id, name, tier: tier || 'monitor' }, 201);
      } catch(e) { jsonResponse(res, { error: e.message }, 500); }
    });
    return;
  }

  // ---- UPDATE CLIENT (admin only) ----
  if (path.match(/^\/auth\/clients\/[a-f0-9]+$/) && method === 'PUT') {
    const session = requireAdmin(req);
    if (!session) return jsonResponse(res, { error: 'Admin required' }, 403);
    const clientId = path.split('/').pop();
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const fields = [];
        const values = [];
        ['name', 'industry', 'tier', 'employees', 'contact_email', 'contact_name'].forEach(f => {
          if (data[f] !== undefined) { fields.push(`${f} = ?`); values.push(data[f]); }
        });
        if (fields.length) {
          fields.push("updated_at = datetime('now')");
          values.push(clientId);
          db.prepare(`UPDATE clients SET ${fields.join(', ')} WHERE id = ?`).run(...values);
        }
        return jsonResponse(res, { ok: true });
      } catch(e) { jsonResponse(res, { error: e.message }, 500); }
    });
    return;
  }

  // ---- DELETE CLIENT (admin only) ----
  if (path.match(/^\/auth\/clients\/[a-f0-9]+$/) && method === 'DELETE') {
    const session = requireAdmin(req);
    if (!session) return jsonResponse(res, { error: 'Admin required' }, 403);
    const clientId = path.split('/').pop();
    db.prepare('DELETE FROM evidence WHERE client_id = ?').run(clientId);
    db.prepare('DELETE FROM tasks WHERE client_id = ?').run(clientId);
    db.prepare('DELETE FROM assessments WHERE client_id = ?').run(clientId);
    db.prepare('DELETE FROM policies WHERE client_id = ?').run(clientId);
    db.prepare('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE client_id = ?)').run(clientId);
    db.prepare('DELETE FROM users WHERE client_id = ?').run(clientId);
    db.prepare('DELETE FROM clients WHERE id = ?').run(clientId);
    return jsonResponse(res, { ok: true });
  }

  // ---- CREATE USER (admin only) ----
  if (path === '/auth/users' && method === 'POST') {
    const session = requireAdmin(req);
    if (!session) return jsonResponse(res, { error: 'Admin required' }, 403);
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { email, password, client_id, name, role } = JSON.parse(body);
        if (!email || !password) return jsonResponse(res, { error: 'Email and password required' }, 400);

        const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase().trim());
        if (existing) return jsonResponse(res, { error: 'Email already exists' }, 409);

        const id = genId();
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = hashPassword(password, salt);
        db.prepare('INSERT INTO users (id, email, password_hash, salt, client_id, role, name) VALUES (?, ?, ?, ?, ?, ?, ?)').run(
          id, email.toLowerCase().trim(), hash, salt, client_id || null, role || 'client', name || ''
        );
        return jsonResponse(res, { id, email: email.toLowerCase().trim() }, 201);
      } catch(e) { jsonResponse(res, { error: e.message }, 500); }
    });
    return;
  }

  // ---- LIST USERS (admin only) ----
  if (path === '/auth/users' && method === 'GET') {
    const session = requireAdmin(req);
    if (!session) return jsonResponse(res, { error: 'Admin required' }, 403);
    const users = db.prepare(`
      SELECT u.id, u.email, u.name, u.role, u.client_id, u.active, u.last_login, u.created_at,
             c.name as client_name, c.tier
      FROM users u LEFT JOIN clients c ON u.client_id = c.id
      ORDER BY u.created_at DESC
    `).all();
    return jsonResponse(res, { users });
  }

  // ---- SAVE ASSESSMENT ----
  if (path === '/auth/assessments' && method === 'POST') {
    const session = requireAuth(req);
    if (!session) return jsonResponse(res, { error: 'Not authenticated' }, 401);
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { client_id, frameworks, answers, scores, company_profile } = JSON.parse(body);
        const cid = session.role === 'admin' ? (client_id || session.client_id) : session.client_id;
        if (!cid) return jsonResponse(res, { error: 'Client ID required' }, 400);

        // Check access
        if (session.role !== 'admin' && cid !== session.client_id) {
          return jsonResponse(res, { error: 'Access denied' }, 403);
        }

        const id = genId();
        db.prepare('INSERT INTO assessments (id, client_id, frameworks, answers, scores, company_profile) VALUES (?, ?, ?, ?, ?, ?)').run(
          id, cid,
          JSON.stringify(frameworks || []),
          JSON.stringify(answers || {}),
          JSON.stringify(scores || {}),
          JSON.stringify(company_profile || {})
        );
        return jsonResponse(res, { id }, 201);
      } catch(e) { jsonResponse(res, { error: e.message }, 500); }
    });
    return;
  }

  // ---- GET ASSESSMENTS ----
  if (path.match(/^\/auth\/assessments(\/[a-f0-9]+)?$/) && method === 'GET') {
    const session = requireAuth(req);
    if (!session) return jsonResponse(res, { error: 'Not authenticated' }, 401);
    const clientId = path.split('/')[3] || session.client_id;
    if (session.role !== 'admin' && clientId !== session.client_id) {
      return jsonResponse(res, { error: 'Access denied' }, 403);
    }
    const assessments = db.prepare('SELECT * FROM assessments WHERE client_id = ? ORDER BY created_at DESC').all(clientId || '');
    assessments.forEach(a => {
      try { a.frameworks = JSON.parse(a.frameworks); } catch(e) {}
      try { a.answers = JSON.parse(a.answers); } catch(e) {}
      try { a.scores = JSON.parse(a.scores); } catch(e) {}
      try { a.company_profile = JSON.parse(a.company_profile); } catch(e) {}
    });
    return jsonResponse(res, { assessments });
  }

  // ---- GET CLIENT DATA (for client portal) ----
  if (path === '/auth/my-data' && method === 'GET') {
    const session = requireAuth(req);
    if (!session) return jsonResponse(res, { error: 'Not authenticated' }, 401);
    if (!session.client_id) return jsonResponse(res, { error: 'No client assigned' }, 400);

    const client = db.prepare('SELECT * FROM clients WHERE id = ?').get(session.client_id);
    const assessments = db.prepare('SELECT * FROM assessments WHERE client_id = ? ORDER BY created_at DESC LIMIT 1').all(session.client_id);
    const taskCount = db.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN status = 'done' THEN 1 ELSE 0 END) as done FROM tasks WHERE client_id = ?`).get(session.client_id);
    const evidenceCount = db.prepare('SELECT COUNT(DISTINCT control) as cnt FROM evidence WHERE client_id = ?').get(session.client_id).cnt;

    assessments.forEach(a => {
      try { a.frameworks = JSON.parse(a.frameworks); } catch(e) {}
      try { a.scores = JSON.parse(a.scores); } catch(e) {}
      try { a.company_profile = JSON.parse(a.company_profile); } catch(e) {}
    });

    return jsonResponse(res, {
      client,
      latestAssessment: assessments[0] || null,
      taskSummary: taskCount,
      evidenceControls: evidenceCount,
      tier: client ? client.tier : 'monitor'
    });
  }

  // ---- CREATE TICKET ----
  if (path === '/auth/tickets' && method === 'POST') {
    const session = requireAuth(req);
    if (!session) return jsonResponse(res, { error: 'Not authenticated' }, 401);
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { subject, description, category, priority } = JSON.parse(body);
        if (!subject) return jsonResponse(res, { error: 'Subject required' }, 400);
        const clientId = session.client_id;
        if (!clientId && session.role !== 'admin') return jsonResponse(res, { error: 'No client assigned' }, 400);
        const id = genId();
        const cid = clientId || null;
        db.prepare(`INSERT INTO tickets (id, client_id, user_id, subject, description, category, priority) VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
          id, cid, session.user_id, subject, description || '', category || 'general', priority || 'medium'
        );
        // Add initial message if description provided
        if (description) {
          db.prepare(`INSERT INTO ticket_messages (id, ticket_id, user_id, message, is_admin) VALUES (?, ?, ?, ?, ?)`).run(
            genId(), id, session.user_id, description, session.role === 'admin' ? 1 : 0
          );
        }
        // Send email notification
        sendTicketEmail(id, subject, cid, session.email, priority || 'medium');
        return jsonResponse(res, { id, subject }, 201);
      } catch(e) { console.error('[AUTH] Ticket create error:', e); jsonResponse(res, { error: e.message }, 500); }
    });
    return;
  }

  // ---- LIST TICKETS ----
  if (path === '/auth/tickets' && method === 'GET') {
    const session = requireAuth(req);
    if (!session) return jsonResponse(res, { error: 'Not authenticated' }, 401);
    const url2 = new URL(req.url, 'http://localhost');
    const statusFilter = url2.searchParams.get('status');
    let tickets;
    if (session.role === 'admin') {
      // Admin sees all tickets
      let sql = `SELECT t.*, u.email as creator_email, u.name as creator_name, c.name as client_name
        FROM tickets t JOIN users u ON t.user_id = u.id LEFT JOIN clients c ON t.client_id = c.id`;
      if (statusFilter && statusFilter !== 'all') sql += ` WHERE t.status = '${statusFilter.replace(/'/g, '')}'`;
      sql += ' ORDER BY t.created_at DESC';
      tickets = db.prepare(sql).all();
    } else {
      // Client sees only their tickets
      let sql = `SELECT t.*, u.email as creator_email, u.name as creator_name
        FROM tickets t JOIN users u ON t.user_id = u.id WHERE t.client_id = ?`;
      if (statusFilter && statusFilter !== 'all') sql += ` AND t.status = '${statusFilter.replace(/'/g, '')}'`;
      sql += ' ORDER BY t.created_at DESC';
      tickets = db.prepare(sql).all(session.client_id);
    }
    // Get message count per ticket
    tickets.forEach(t => {
      t.messageCount = db.prepare('SELECT COUNT(*) as cnt FROM ticket_messages WHERE ticket_id = ?').get(t.id).cnt;
    });
    return jsonResponse(res, { tickets });
  }

  // ---- TICKET STATS (admin) ----
  if (path === '/auth/tickets/stats' && method === 'GET') {
    const session = requireAdmin(req);
    if (!session) return jsonResponse(res, { error: 'Admin required' }, 403);
    const stats = {
      open: db.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE status = 'open'").get().cnt,
      in_progress: db.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE status = 'in_progress'").get().cnt,
      waiting: db.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE status = 'waiting'").get().cnt,
      resolved: db.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE status = 'resolved'").get().cnt,
      closed: db.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE status = 'closed'").get().cnt,
      total: db.prepare("SELECT COUNT(*) as cnt FROM tickets").get().cnt,
      critical: db.prepare("SELECT COUNT(*) as cnt FROM tickets WHERE priority = 'critical' AND status NOT IN ('resolved','closed')").get().cnt
    };
    return jsonResponse(res, stats);
  }

  // ---- GET SINGLE TICKET + MESSAGES ----
  if (path.match(/^\/auth\/tickets\/[a-f0-9]+$/) && method === 'GET') {
    const session = requireAuth(req);
    if (!session) return jsonResponse(res, { error: 'Not authenticated' }, 401);
    const ticketId = path.split('/').pop();
    const ticket = db.prepare('SELECT t.*, c.name as client_name FROM tickets t LEFT JOIN clients c ON t.client_id = c.id WHERE t.id = ?').get(ticketId);
    if (!ticket) return jsonResponse(res, { error: 'Ticket not found' }, 404);
    // Access check
    if (session.role !== 'admin' && ticket.client_id !== session.client_id) {
      return jsonResponse(res, { error: 'Access denied' }, 403);
    }
    const messages = db.prepare(`SELECT m.*, u.email, u.name as user_name, u.role
      FROM ticket_messages m JOIN users u ON m.user_id = u.id
      WHERE m.ticket_id = ? ORDER BY m.created_at ASC`).all(ticketId);
    return jsonResponse(res, { ticket, messages });
  }

  // ---- ADD MESSAGE TO TICKET ----
  if (path.match(/^\/auth\/tickets\/[a-f0-9]+\/messages$/) && method === 'POST') {
    const session = requireAuth(req);
    if (!session) return jsonResponse(res, { error: 'Not authenticated' }, 401);
    const ticketId = path.split('/')[3];
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { message } = JSON.parse(body);
        if (!message) return jsonResponse(res, { error: 'Message required' }, 400);
        const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
        if (!ticket) return jsonResponse(res, { error: 'Ticket not found' }, 404);
        if (session.role !== 'admin' && ticket.client_id !== session.client_id) {
          return jsonResponse(res, { error: 'Access denied' }, 403);
        }
        const id = genId();
        db.prepare(`INSERT INTO ticket_messages (id, ticket_id, user_id, message, is_admin) VALUES (?, ?, ?, ?, ?)`).run(
          id, ticketId, session.user_id, message, session.role === 'admin' ? 1 : 0
        );
        db.prepare(`UPDATE tickets SET updated_at = datetime('now') WHERE id = ?`).run(ticketId);
        // Email notify the other side
        if (session.role === 'admin') {
          const creator = db.prepare('SELECT email FROM users WHERE id = ?').get(ticket.user_id);
          if (creator) sendReplyEmail(ticketId, ticket.subject, creator.email, 'PalisadeOne Team');
        } else {
          sendReplyEmail(ticketId, ticket.subject, 'camatta@palisadecg.com', session.email);
        }
        return jsonResponse(res, { id }, 201);
      } catch(e) { console.error('[AUTH] Message error:', e); jsonResponse(res, { error: e.message }, 500); }
    });
    return;
  }

  // ---- UPDATE TICKET STATUS (admin) ----
  if (path.match(/^\/auth\/tickets\/[a-f0-9]+$/) && method === 'PUT') {
    const session = requireAuth(req);
    if (!session) return jsonResponse(res, { error: 'Not authenticated' }, 401);
    const ticketId = path.split('/').pop();
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const ticket = db.prepare('SELECT * FROM tickets WHERE id = ?').get(ticketId);
        if (!ticket) return jsonResponse(res, { error: 'Ticket not found' }, 404);
        // Only admin or ticket owner can update
        if (session.role !== 'admin' && ticket.client_id !== session.client_id) {
          return jsonResponse(res, { error: 'Access denied' }, 403);
        }
        const fields = [];
        const values = [];
        ['status', 'priority', 'assigned_to', 'category'].forEach(f => {
          if (data[f] !== undefined) { fields.push(f + ' = ?'); values.push(data[f]); }
        });
        if (data.status === 'resolved' || data.status === 'closed') {
          fields.push("resolved_at = datetime('now')");
        }
        if (fields.length) {
          fields.push("updated_at = datetime('now')");
          values.push(ticketId);
          db.prepare(`UPDATE tickets SET ${fields.join(', ')} WHERE id = ?`).run(...values);
        }
        return jsonResponse(res, { ok: true });
      } catch(e) { jsonResponse(res, { error: e.message }, 500); }
    });
    return;
  }

  // No matching route
  return false;
}

// ============ EMAIL NOTIFICATIONS ============
function sendTicketEmail(ticketId, subject, clientId, fromEmail, priority) {
  try {
    const client = clientId !== 'admin' ? db.prepare('SELECT name FROM clients WHERE id = ?').get(clientId) : null;
    const clientName = client ? client.name : 'Admin';
    const prioLabel = priority === 'critical' ? '[CRITICAL] ' : priority === 'high' ? '[HIGH] ' : '';
    const body = JSON.stringify({
      to: 'camatta@palisadecg.com',
      subject: `${prioLabel}New Ticket: ${subject} — ${clientName}`,
      text: `New support ticket from ${fromEmail} (${clientName}):\n\nSubject: ${subject}\nPriority: ${priority}\nTicket ID: ${ticketId}\n\nView in dashboard: https://palisadeone.com/dashboard.html`
    });
    const req = require('https').request({
      hostname: 'soc.palisadeone.com', port: 5678,
      path: '/webhook/ticket-notify', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      rejectUnauthorized: false
    });
    req.on('error', () => {}); // silent fail
    req.write(body);
    req.end();
    console.log('[AUTH] Ticket email sent for', ticketId);
  } catch(e) { console.error('[AUTH] Email error:', e.message); }
}

function sendReplyEmail(ticketId, subject, toEmail, fromName) {
  try {
    const body = JSON.stringify({
      to: toEmail,
      subject: `Re: ${subject} — PalisadeOne Support`,
      text: `${fromName} replied to your ticket:\n\nSubject: ${subject}\nTicket ID: ${ticketId}\n\nView: https://palisadeone.com/portal.html`
    });
    const req = require('https').request({
      hostname: 'soc.palisadeone.com', port: 5678,
      path: '/webhook/ticket-notify', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      rejectUnauthorized: false
    });
    req.on('error', () => {});
    req.write(body);
    req.end();
  } catch(e) { console.error('[AUTH] Reply email error:', e.message); }
}

// Init on load
initDB();

module.exports = { handleAuthRoutes, requireAuth, requireAdmin };
