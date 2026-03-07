const fs = require('fs');
let c = fs.readFileSync('/opt/wazuh-proxy-ssl.js', 'utf8');

if (c.includes('/rmm/session-log')) {
  console.log('Session routes already present — skipping');
  process.exit(0);
}

const sessionRoutes = `
  // RMM Session Log — POST
  if (urlPath === '/rmm/session-log' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const entry = JSON.parse(body);
        entry.timestamp = new Date().toISOString();
        const file = '/opt/rmm-sessions.json';
        const sessions = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : [];
        sessions.unshift(entry);
        if (sessions.length > 500) sessions.length = 500;
        fs.writeFileSync(file, JSON.stringify(sessions, null, 2));
        res.writeHead(200, corsHeaders); res.end(JSON.stringify({ok:true}));
      } catch(e) { res.writeHead(500, corsHeaders); res.end(JSON.stringify({error:e.message})); }
    });
    return;
  }

  // RMM Sessions — GET (filtered by agentId)
  if (urlPath === '/rmm/sessions' && req.method === 'GET') {
    const agentId = parsedUrl.query ? parsedUrl.query.agentId : null;
    const file = '/opt/rmm-sessions.json';
    const sessions = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : [];
    const filtered = agentId ? sessions.filter(s => s.agentId === agentId) : sessions;
    res.writeHead(200, corsHeaders); res.end(JSON.stringify(filtered.slice(0, 100)));
    return;
  }

`;

c = c.replace('if (urlPath === "/rmm/peers")', sessionRoutes + 'if (urlPath === "/rmm/peers")');
fs.writeFileSync('/opt/wazuh-proxy-ssl.js', c);
console.log('Session log routes added successfully');
