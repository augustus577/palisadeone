const fs = require("fs");
const https = require("https");

const ZT_FILE = "/opt/zt-data.json";
const ADMIN_TOKEN = "P1AdminKey2026!";
const INDEXER_AUTH = "Basic " + Buffer.from("admin:PalisadeOne2026-").toString("base64");

function readZT() {
  try { return JSON.parse(fs.readFileSync(ZT_FILE, "utf8")); }
  catch(e) { return { version:1, settings:{}, policies:[], approvals:[], applications:[], ringfences:[], storagePolicies:[], elevationRules:[], networkRules:[], deviceModes:{}, auditLog:[] }; }
}

function writeZT(data) {
  fs.writeFileSync(ZT_FILE, JSON.stringify(data, null, 2));
}

function addAuditEntry(data, entry) {
  entry.time = new Date().toISOString();
  entry.id = "al_" + Date.now();
  data.auditLog.unshift(entry);
  if (data.auditLog.length > 1000) data.auditLog = data.auditLog.slice(0, 1000);
}

function checkAuth(req) {
  const h = req.headers["authorization"] || "";
  return h === "Bearer " + ADMIN_TOKEN;
}

function queryES(indexPattern, esQuery, size, sourceFields, sortField) {
  return new Promise((resolve) => {
    const body = JSON.stringify({
      query: esQuery, size: size || 200,
      _source: sourceFields || true,
      sort: sortField ? [{ [sortField]: { order: "desc" } }] : [{ timestamp: { order: "desc" } }]
    });
    const esReq = https.request({
      hostname: "127.0.0.1", port: 9200,
      path: "/" + indexPattern + "/_search", method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": INDEXER_AUTH },
      rejectUnauthorized: false
    }, (r) => {
      let d = "";
      r.on("data", c => d += c);
      r.on("end", () => {
        try {
          const parsed = JSON.parse(d);
          resolve((parsed.hits && parsed.hits.hits) || []);
        } catch(e) { resolve([]); }
      });
    });
    esReq.on("error", () => resolve([]));
    esReq.write(body);
    esReq.end();
  });
}

// Wazuh Manager API helper
const MANAGER_USER = "wazuh";
const MANAGER_PASS = "PalisadeOne2026!";

async function getManagerToken() {
  return new Promise((resolve) => {
    const auth = "Basic " + Buffer.from(MANAGER_USER + ":" + MANAGER_PASS).toString("base64");
    const req = https.request({
      hostname: "127.0.0.1", port: 55000,
      path: "/security/user/authenticate", method: "POST",
      headers: { "Authorization": auth }, rejectUnauthorized: false
    }, (r) => {
      let d = "";
      r.on("data", c => d += c);
      r.on("end", () => {
        try { resolve(JSON.parse(d).data.token); } catch(e) { resolve(null); }
      });
    });
    req.on("error", () => resolve(null));
    req.end();
  });
}

async function triggerActiveResponse(agentId, command) {
  const token = await getManagerToken();
  if (!token) return { error: "Could not authenticate with Wazuh manager" };
  return new Promise((resolve) => {
    const body = JSON.stringify({ command, alert: { data: { srcip: "127.0.0.1" } } });
    const req = https.request({
      hostname: "127.0.0.1", port: 55000,
      path: "/active-response?agents_list=" + agentId, method: "PUT",
      headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
      rejectUnauthorized: false
    }, (r) => {
      let d = "";
      r.on("data", c => d += c);
      r.on("end", () => {
        try { resolve(JSON.parse(d)); } catch(e) { resolve({ raw: d }); }
      });
    });
    req.on("error", (e) => resolve({ error: e.message }));
    req.write(body);
    req.end();
  });
}

async function handleZTRoute(req, res, urlPath, readBodyFn) {
  if (!urlPath.startsWith("/zt/")) return false;

  // GET /zt/data
  if (urlPath === "/zt/data" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(readZT()));
    return true;
  }

  // GET /zt/settings
  if (urlPath === "/zt/settings" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(readZT().settings));
    return true;
  }

  // POST /zt/settings
  if (urlPath === "/zt/settings" && req.method === "POST") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const body = await readBodyFn(req);
    const data = readZT();
    data.settings = { ...data.settings, ...JSON.parse(body) };
    addAuditEntry(data, { event:"policy", app:"--", device:"--", user:"admin", detail:"Settings updated" });
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
    return true;
  }

  // GET /zt/policies
  if (urlPath === "/zt/policies" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(readZT().policies));
    return true;
  }

  // POST /zt/policies
  if (urlPath === "/zt/policies" && req.method === "POST") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const body = await readBodyFn(req);
    const policy = JSON.parse(body);
    policy.id = "p_" + Date.now();
    policy.created = new Date().toISOString();
    const data = readZT();
    data.policies.push(policy);
    addAuditEntry(data, { event:"policy", app:policy.name||"--", device:"--", user:"admin", detail:"Policy created: " + (policy.name||"unnamed") });
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(policy));
    return true;
  }

  // DELETE /zt/policies/:id
  if (urlPath.startsWith("/zt/policies/") && req.method === "DELETE") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const id = urlPath.split("/")[3];
    const data = readZT();
    data.policies = data.policies.filter(p => p.id !== id);
    addAuditEntry(data, { event:"policy", app:"--", device:"--", user:"admin", detail:"Policy deleted: " + id });
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
    return true;
  }

  // GET /zt/approvals
  if (urlPath === "/zt/approvals" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(readZT().approvals));
    return true;
  }

  // POST /zt/approvals
  if (urlPath === "/zt/approvals" && req.method === "POST") {
    const body = await readBodyFn(req);
    const approval = JSON.parse(body);
    approval.id = "r_" + Date.now();
    approval.time = new Date().toISOString();
    approval.status = approval.status || "pending";
    const data = readZT();
    data.approvals.push(approval);
    addAuditEntry(data, { event:"block", app:approval.app||"--", device:approval.device||"--", user:approval.user||"--", detail:"Approval requested: " + (approval.app||"unknown") });
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(approval));
    return true;
  }

  // PUT /zt/approvals/:id
  if (urlPath.startsWith("/zt/approvals/") && req.method === "PUT") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const id = urlPath.split("/")[3];
    const body = await readBodyFn(req);
    const update = JSON.parse(body);
    const data = readZT();
    const approval = data.approvals.find(a => a.id === id);
    if (approval) {
      approval.status = update.status || approval.status;
      approval.decidedAt = new Date().toISOString();
      approval.decidedBy = update.decidedBy || "admin";
      addAuditEntry(data, { event: update.status === "approved" ? "approve" : "block", app: approval.app || "--", device: approval.device || "--", user: "admin", detail: (update.status === "approved" ? "Approved" : "Denied") + ": " + (approval.app || "") });
      writeZT(data);
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(approval || { error: "not found" }));
    return true;
  }

  // GET /zt/applications
  if (urlPath === "/zt/applications" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(readZT().applications));
    return true;
  }

  // POST /zt/applications
  if (urlPath === "/zt/applications" && req.method === "POST") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const body = await readBodyFn(req);
    const app = JSON.parse(body);
    const data = readZT();
    const idx = data.applications.findIndex(a => a.id === app.id || a.path === app.path);
    if (idx >= 0) { data.applications[idx] = { ...data.applications[idx], ...app }; }
    else { app.id = app.id || "a_" + Date.now(); app.discovered = new Date().toISOString(); data.applications.push(app); }
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
    return true;
  }

  // PUT /zt/applications/:id — update app status (whitelist/blacklist)
  if (urlPath.match(/^\/zt\/applications\/[\w_]+$/) && req.method === "PUT") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const id = urlPath.split("/")[3];
    const body = await readBodyFn(req);
    const update = JSON.parse(body);
    const data = readZT();
    const app = data.applications.find(a => a.id === id);
    if (app) {
      Object.assign(app, update);
      addAuditEntry(data, { event: update.status === "whitelisted" ? "allow" : "block", app: app.name || app.path || "--", device: "--", user: "admin", detail: "Application " + (update.status || "updated") + ": " + (app.name || app.path) });
      writeZT(data);
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(app || { error: "not found" }));
    return true;
  }

  // GET /zt/devices
  if (urlPath === "/zt/devices" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(readZT().deviceModes));
    return true;
  }

  // POST /zt/devices/:agentId/mode
  if (urlPath.match(/^\/zt\/devices\/\w+\/mode$/) && req.method === "POST") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const agentId = urlPath.split("/")[3];
    const body = await readBodyFn(req);
    const { mode, name } = JSON.parse(body);
    const data = readZT();
    if (!data.deviceModes) data.deviceModes = {};
    data.deviceModes[agentId] = { mode, name: name || agentId, updatedAt: new Date().toISOString() };
    addAuditEntry(data, { event:"policy", app:"--", device: name || agentId, user:"admin", detail:"Device mode set to " + mode });
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, agentId, mode }));
    return true;
  }

  // GET /zt/ringfences
  if (urlPath === "/zt/ringfences" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(readZT().ringfences));
    return true;
  }

  // POST /zt/ringfences
  if (urlPath === "/zt/ringfences" && req.method === "POST") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const body = await readBodyFn(req);
    const rule = JSON.parse(body);
    rule.id = "rf_" + Date.now();
    const data = readZT();
    data.ringfences.push(rule);
    addAuditEntry(data, { event:"policy", app:rule.app||"--", device:"--", user:"admin", detail:"Ringfence created for " + (rule.app||"unknown") });
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(rule));
    return true;
  }

  // GET /zt/storage
  if (urlPath === "/zt/storage" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(readZT().storagePolicies));
    return true;
  }

  // GET /zt/elevation
  if (urlPath === "/zt/elevation" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(readZT().elevationRules));
    return true;
  }

  // GET /zt/network
  if (urlPath === "/zt/network" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(readZT().networkRules));
    return true;
  }

  // GET /zt/audit
  if (urlPath === "/zt/audit" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(readZT().auditLog));
    return true;
  }

  // GET /zt/process-events?hours=24&agentId=001
  if (urlPath === "/zt/process-events" && req.method === "GET") {
    const params = new URLSearchParams(req.url.split("?")[1] || "");
    const hours = parseInt(params.get("hours")) || 24;
    const agentId = params.get("agentId") || null;
    const since = new Date(Date.now() - hours * 3600000).toISOString();
    const q = { bool: { must: [
      { range: { timestamp: { gte: since } } },
      { bool: { should: [
        { exists: { field: "data.win.eventdata.processName" } },
        { exists: { field: "data.win.eventdata.newProcessName" } }
      ]}}
    ]}};
    if (agentId) q.bool.must.push({ term: { "agent.id": agentId } });
    const hits = await queryES("wazuh-alerts-4.x-*", q, 500,
      ["data.win.eventdata.processName","data.win.eventdata.newProcessName","data.win.eventdata.parentProcessName","data.win.eventdata.commandLine","data.win.eventdata.subjectUserName","data.win.eventdata.targetUserName","agent.name","agent.id","timestamp","rule.description","rule.level"]);
    const processes = hits.map(h => {
      const s = h._source;
      const ed = (s.data && s.data.win && s.data.win.eventdata) || {};
      return { process: ed.processName || ed.newProcessName || "", parent: ed.parentProcessName || "", commandLine: ed.commandLine || "", user: ed.subjectUserName || ed.targetUserName || "", agent: s.agent ? s.agent.name : "", agentId: s.agent ? s.agent.id : "", timestamp: s.timestamp, ruleDesc: s.rule ? s.rule.description : "", ruleLevel: s.rule ? s.rule.level : 0 };
    });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ total: processes.length, processes }));
    return true;
  }

  // GET /zt/syscheck?hours=48&agentId=001
  if (urlPath === "/zt/syscheck" && req.method === "GET") {
    const params = new URLSearchParams(req.url.split("?")[1] || "");
    const hours = parseInt(params.get("hours")) || 48;
    const agentId = params.get("agentId") || null;
    const since = new Date(Date.now() - hours * 3600000).toISOString();
    const q = { bool: { must: [
      { range: { timestamp: { gte: since } } },
      { term: { "rule.groups": "syscheck" } }
    ]}};
    if (agentId) q.bool.must.push({ term: { "agent.id": agentId } });
    const hits = await queryES("wazuh-alerts-4.x-*", q, 200,
      ["syscheck.path","syscheck.event","syscheck.md5_after","syscheck.sha256_after","syscheck.size_after","agent.name","agent.id","timestamp","rule.description"]);
    const changes = hits.map(h => {
      const s = h._source;
      return { path: s.syscheck ? s.syscheck.path : "", event: s.syscheck ? s.syscheck.event : "", md5: s.syscheck ? s.syscheck.md5_after : "", sha256: s.syscheck ? s.syscheck.sha256_after : "", agent: s.agent ? s.agent.name : "", agentId: s.agent ? s.agent.id : "", timestamp: s.timestamp };
    });
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ total: changes.length, changes }));
    return true;
  }

  // GET /zt/health
  if (urlPath === "/zt/health" && req.method === "GET") {
    const data = readZT();
    const totalDevices = Math.max(Object.keys(data.deviceModes).length, 1);
    const secured = Object.values(data.deviceModes).filter(d => d.mode === "secured").length;
    const scores = {
      deviceSecurity: Math.round((secured / totalDevices) * 100),
      policyCoverage: Math.min(100, data.policies.length * 10),
      ringfencing: Math.min(100, data.ringfences.length * 15),
      appCategorization: data.applications.length > 0 ? Math.round(data.applications.filter(a => a.status !== "uncategorized").length / data.applications.length * 100) : 0,
      pendingApprovals: data.approvals.filter(a => a.status === "pending").length === 0 ? 100 : Math.max(0, 100 - data.approvals.filter(a => a.status === "pending").length * 20),
      storageControl: data.storagePolicies.filter(s => s.enabled).length > 0 ? 80 : 0,
      elevationControl: data.elevationRules.filter(e => e.enabled).length > 0 ? 80 : 0,
    };
    scores.overall = Math.round(Object.values(scores).reduce((a,b) => a+b, 0) / Object.keys(scores).length);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(scores));
    return true;
  }

  // POST /zt/deploy/sysmon — Trigger Sysmon deployment on an agent
  if (urlPath === "/zt/deploy/sysmon" && req.method === "POST") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const body = await readBodyFn(req);
    const { agentId, agentName } = JSON.parse(body);
    // Trigger via Wazuh API active response
    const result = await triggerActiveResponse(agentId, "deploy-sysmon");
    const data = readZT();
    addAuditEntry(data, { event:"policy", app:"Sysmon", device: agentName || agentId, user:"admin", detail:"Sysmon deployment triggered on " + (agentName || agentId) });
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, agentId, action: "deploy-sysmon", result }));
    return true;
  }

  // POST /zt/deploy/wdac — Trigger WDAC policy deployment
  if (urlPath === "/zt/deploy/wdac" && req.method === "POST") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const body = await readBodyFn(req);
    const { agentId, agentName, mode } = JSON.parse(body);
    const wdacMode = mode || "audit";
    const data = readZT();
    addAuditEntry(data, { event:"policy", app:"WDAC", device: agentName || agentId, user:"admin", detail:"WDAC " + wdacMode + " mode deployment triggered on " + (agentName || agentId) });
    // Update device mode
    if (!data.deviceModes) data.deviceModes = {};
    data.deviceModes[agentId] = { mode: wdacMode === "enforce" ? "secured" : "learning", name: agentName || agentId, updatedAt: new Date().toISOString(), wdacMode };
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, agentId, wdacMode, note: "WDAC policy will be deployed via shared agent config" }));
    return true;
  }

  // GET /zt/sysmon-apps — Aggregate Sysmon process events into application catalog
  if (urlPath === "/zt/sysmon-apps" && req.method === "GET") {
    const params = new URLSearchParams(req.url.split("?")[1] || "");
    const hours = parseInt(params.get("hours")) || 24;
    const since = new Date(Date.now() - hours * 3600000).toISOString();
    const q = { bool: { must: [
      { range: { timestamp: { gte: since } } },
      { bool: { should: [
        { match: { "rule.groups": "sysmon_event1" } },
        { exists: { field: "data.win.eventdata.image" } }
      ]}}
    ]}};
    const hits = await queryES("wazuh-alerts-4.x-*", q, 1000,
      ["data.win.eventdata.image","data.win.eventdata.hashes","data.win.eventdata.company","data.win.eventdata.product","data.win.eventdata.signed","data.win.eventdata.user","agent.name","agent.id","timestamp"]);

    // Aggregate by executable path
    const appMap = {};
    hits.forEach(h => {
      const s = h._source;
      const ed = (s.data && s.data.win && s.data.win.eventdata) || {};
      const image = ed.image || "";
      if (!image) return;
      const key = image.toLowerCase();
      if (!appMap[key]) {
        appMap[key] = {
          path: image,
          name: image.split("\\").pop(),
          publisher: ed.company || "Unknown",
          product: ed.product || "",
          signed: ed.signed === "true",
          hash: (ed.hashes || "").split(",")[0] || "",
          agents: new Set(),
          count: 0,
          lastSeen: s.timestamp
        };
      }
      appMap[key].count++;
      if (s.agent) appMap[key].agents.add(s.agent.name || s.agent.id);
      if (s.timestamp > appMap[key].lastSeen) appMap[key].lastSeen = s.timestamp;
    });

    const apps = Object.values(appMap).map(a => ({
      ...a, agents: [...a.agents], devices: a.agents.size
    })).sort((a, b) => b.count - a.count);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ total: apps.length, apps }));
    return true;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end('{"error":"ZT route not found"}');
  return true;
}

module.exports = { handleZTRoute };
