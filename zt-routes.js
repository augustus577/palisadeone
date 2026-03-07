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

  // POST /zt/deploy/sysmon — Trigger Sysmon deployment via polling
  if (urlPath === "/zt/deploy/sysmon" && req.method === "POST") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const body = await readBodyFn(req);
    const { agentId, agentName } = JSON.parse(body);
    // Queue via polling mechanism (same as dashboard actions)
    if (!global._agentActions) global._agentActions = {};
    global._agentActions[agentId] = { action: "deploy-sysmon", params: null, timestamp: Date.now() };
    const data = readZT();
    addAuditEntry(data, { event:"policy", app:"Sysmon", device: agentName || agentId, user:"admin", detail:"Sysmon deployment triggered on " + (agentName || agentId) });
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, agentId, action: "deploy-sysmon", note: "Queued via polling — agent will pick up within 60s" }));
    return true;
  }

  // POST /zt/deploy/wdac — Trigger WDAC policy deployment via polling
  if (urlPath === "/zt/deploy/wdac" && req.method === "POST") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const body = await readBodyFn(req);
    const { agentId, agentName, mode } = JSON.parse(body);
    const wdacMode = mode || "audit";
    // Queue via polling mechanism
    if (!global._agentActions) global._agentActions = {};
    global._agentActions[agentId] = { action: "deploy-wdac", params: { mode: wdacMode }, timestamp: Date.now() };
    const data = readZT();
    addAuditEntry(data, { event:"policy", app:"WDAC", device: agentName || agentId, user:"admin", detail:"WDAC " + wdacMode + " mode deployment triggered on " + (agentName || agentId) });
    if (!data.deviceModes) data.deviceModes = {};
    data.deviceModes[agentId] = { mode: wdacMode === "enforce" ? "secured" : "learning", name: agentName || agentId, updatedAt: new Date().toISOString(), wdacMode };
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, agentId, wdacMode, note: "Queued via polling — agent will pick up within 60s" }));
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

  // GET /zt/kill-chains?hours=6 — Build real process ancestry trees from Sysmon
  if (urlPath === "/zt/kill-chains" && req.method === "GET") {
    const params = new URLSearchParams(req.url.split("?")[1] || "");
    const hours = parseInt(params.get("hours")) || 6;
    const since = new Date(Date.now() - hours * 3600000).toISOString();
    const hits = await queryES("wazuh-alerts-4.x-*", {
      bool: { must: [
        { range: { timestamp: { gte: since } } },
        { match: { "rule.groups": "sysmon_event1" } }
      ]}
    }, 2000, [
      "data.win.eventdata.image","data.win.eventdata.parentImage",
      "data.win.eventdata.processId","data.win.eventdata.parentProcessId",
      "data.win.eventdata.processGuid","data.win.eventdata.parentProcessGuid",
      "data.win.eventdata.commandLine","data.win.eventdata.user",
      "data.win.eventdata.company","data.win.eventdata.hashes",
      "data.win.eventdata.originalFileName",
      "agent.name","agent.id","timestamp","rule.level"
    ]);

    // Build process map keyed by processGuid
    const procMap = {};
    const children = {};
    hits.forEach(h => {
      const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
      const guid = ed.processGuid || "";
      const parentGuid = ed.parentProcessGuid || "";
      if (!guid) return;
      procMap[guid] = {
        image: ed.image || "",
        name: (ed.image || "").split("\\").pop(),
        pid: ed.processId || "",
        parentImage: ed.parentImage || "",
        parentPid: ed.parentProcessId || "",
        parentGuid,
        commandLine: ed.commandLine || "",
        user: ed.user || "",
        company: ed.company || "",
        hashes: ed.hashes || "",
        agent: h._source.agent ? h._source.agent.name : "",
        agentId: h._source.agent ? h._source.agent.id : "",
        timestamp: h._source.timestamp,
        ruleLevel: h._source.rule ? h._source.rule.level : 0,
        guid
      };
      if (!children[parentGuid]) children[parentGuid] = [];
      children[parentGuid].push(guid);
    });

    // Suspicious patterns
    const suspiciousPatterns = [
      { parent: /outlook\.exe$/i, child: /powershell|cmd\.exe|wscript|cscript|mshta/i, tactic: "Execution", reason: "Office app spawned shell — possible macro attack" },
      { parent: /outlook\.exe$/i, child: /certutil|bitsadmin/i, tactic: "Defense Evasion", reason: "Office app using LOLBin for download" },
      { parent: /powershell/i, child: /cmd\.exe/i, tactic: "Execution", reason: "PowerShell spawned cmd" },
      { parent: /cmd\.exe$/i, child: /powershell/i, tactic: "Execution", reason: "cmd spawned PowerShell — possible staged execution" },
      { parent: /explorer\.exe$/i, child: /powershell|cmd\.exe$/i, tactic: "Execution", reason: "User-initiated shell" },
      { parent: /svchost\.exe$/i, child: /powershell|cmd\.exe/i, tactic: "Persistence", reason: "Service spawned shell — possible service abuse" },
      { parent: /wscript|cscript/i, child: /powershell|cmd/i, tactic: "Execution", reason: "Script host spawned shell — fileless attack pattern" },
      { parent: /winword|excel|powerpnt/i, child: /powershell|cmd|wscript|certutil/i, tactic: "Execution", reason: "Office app spawned suspicious process" },
    ];

    // Build trees: find root processes (whose parentGuid is not in procMap)
    const roots = new Set();
    Object.keys(procMap).forEach(guid => {
      const p = procMap[guid];
      if (!procMap[p.parentGuid]) roots.add(guid);
    });

    function buildTree(guid, depth) {
      const proc = procMap[guid];
      if (!proc || depth > 8) return null;
      const node = { ...proc, depth, children: [], suspicious: false, reason: "", mitre: [] };
      // Check if this node is suspicious
      suspiciousPatterns.forEach(pat => {
        if (pat.parent.test(proc.parentImage) && pat.child.test(proc.image)) {
          node.suspicious = true;
          node.reason = pat.reason;
          node.mitre.push(pat.tactic);
        }
      });
      // Unsigned from user folders
      if (!/^C:\\Windows|^C:\\Program Files/i.test(proc.image) && !proc.company) {
        node.suspicious = true;
        node.reason = node.reason || "Unsigned binary outside system paths";
        if (!node.mitre.includes("Defense Evasion")) node.mitre.push("Defense Evasion");
      }
      // High rule level from Wazuh
      if (proc.ruleLevel >= 7) {
        node.suspicious = true;
        node.reason = node.reason || "High-severity Wazuh alert (level " + proc.ruleLevel + ")";
      }
      const kidGuids = children[guid] || [];
      kidGuids.forEach(cg => {
        const childNode = buildTree(cg, depth + 1);
        if (childNode) node.children.push(childNode);
      });
      return node;
    }

    const chains = [];
    roots.forEach(guid => {
      const tree = buildTree(guid, 0);
      if (tree) {
        // Flatten to determine if chain is suspicious
        function hasSuspicious(node) {
          if (node.suspicious) return true;
          return node.children.some(c => hasSuspicious(c));
        }
        function collectMitre(node) {
          let m = [...node.mitre];
          node.children.forEach(c => m = m.concat(collectMitre(c)));
          return [...new Set(m)];
        }
        function chainLength(node) {
          if (node.children.length === 0) return 1;
          return 1 + Math.max(...node.children.map(c => chainLength(c)));
        }
        const len = chainLength(tree);
        if (len >= 2) { // Only include chains with at least 2 levels
          chains.push({
            root: tree.name,
            agent: tree.agent,
            suspicious: hasSuspicious(tree),
            mitre: collectMitre(tree),
            length: len,
            tree
          });
        }
      }
    });

    // Sort: suspicious first, then by length
    chains.sort((a,b) => (b.suspicious - a.suspicious) || (b.length - a.length));

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      total: chains.length,
      suspicious: chains.filter(c=>c.suspicious).length,
      normal: chains.filter(c=>!c.suspicious).length,
      uniqueProcesses: Object.keys(procMap).length,
      mitreTactics: [...new Set(chains.flatMap(c=>c.mitre))],
      chains: chains.slice(0, 50) // Limit response size
    }));
    return true;
  }

  // GET /zt/app-genome?hours=24 — Per-app behavioral profiles from real Sysmon data
  if (urlPath === "/zt/app-genome" && req.method === "GET") {
    const params = new URLSearchParams(req.url.split("?")[1] || "");
    const hours = parseInt(params.get("hours")) || 24;
    const since = new Date(Date.now() - hours * 3600000).toISOString();

    // Get process create events
    const procHits = await queryES("wazuh-alerts-4.x-*", {
      bool: { must: [
        { range: { timestamp: { gte: since } } },
        { match: { "rule.groups": "sysmon_event1" } }
      ]}
    }, 2000, [
      "data.win.eventdata.image","data.win.eventdata.parentImage",
      "data.win.eventdata.commandLine","data.win.eventdata.company",
      "data.win.eventdata.hashes","data.win.eventdata.user",
      "agent.name","timestamp"
    ]);

    // Get network events
    const netHits = await queryES("wazuh-alerts-4.x-*", {
      bool: { must: [
        { range: { timestamp: { gte: since } } },
        { match: { "rule.groups": "sysmon_event3" } }
      ]}
    }, 2000, [
      "data.win.eventdata.image","data.win.eventdata.destinationIp",
      "data.win.eventdata.destinationPort","data.win.eventdata.destinationHostname",
      "data.win.eventdata.protocol","agent.name","timestamp"
    ]);

    // Aggregate by app
    const appProfiles = {};
    function getOrCreate(image) {
      const name = image.split("\\").pop();
      const key = name.toLowerCase();
      if (!appProfiles[key]) {
        appProfiles[key] = {
          name, path: image, execCount: 0,
          childProcesses: {}, parentProcesses: {},
          networkDests: {}, ports: {},
          users: new Set(), agents: new Set(),
          companies: new Set(), hashes: new Set(),
          firstSeen: null, lastSeen: null
        };
      }
      return appProfiles[key];
    }

    procHits.forEach(h => {
      const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
      if (!ed.image) return;
      const app = getOrCreate(ed.image);
      app.execCount++;
      if (ed.user) app.users.add(ed.user);
      if (ed.company) app.companies.add(ed.company);
      if (ed.hashes) app.hashes.add(ed.hashes.split(",")[0]);
      if (h._source.agent) app.agents.add(h._source.agent.name);
      const ts = h._source.timestamp;
      if (!app.firstSeen || ts < app.firstSeen) app.firstSeen = ts;
      if (!app.lastSeen || ts > app.lastSeen) app.lastSeen = ts;
      // Track parent that spawned this
      if (ed.parentImage) {
        const pname = ed.parentImage.split("\\").pop();
        app.parentProcesses[pname] = (app.parentProcesses[pname] || 0) + 1;
      }
      // Track children this app spawns (by looking at events where this is the parent)
    });

    // Second pass: build child relationships
    procHits.forEach(h => {
      const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
      if (!ed.parentImage || !ed.image) return;
      const parentName = ed.parentImage.split("\\").pop().toLowerCase();
      if (appProfiles[parentName]) {
        const childName = ed.image.split("\\").pop();
        appProfiles[parentName].childProcesses[childName] = (appProfiles[parentName].childProcesses[childName] || 0) + 1;
      }
    });

    // Network behaviors
    netHits.forEach(h => {
      const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
      if (!ed.image) return;
      const name = ed.image.split("\\").pop().toLowerCase();
      if (!appProfiles[name]) return; // Only network data for known apps
      const app = appProfiles[name];
      if (ed.destinationHostname) app.networkDests[ed.destinationHostname] = (app.networkDests[ed.destinationHostname] || 0) + 1;
      else if (ed.destinationIp) app.networkDests[ed.destinationIp] = (app.networkDests[ed.destinationIp] || 0) + 1;
      if (ed.destinationPort) app.ports[ed.destinationPort] = (app.ports[ed.destinationPort] || 0) + 1;
    });

    // Build genome profiles
    const genomes = Object.values(appProfiles).map(app => {
      const behaviors = [];
      const topDests = Object.entries(app.networkDests).sort((a,b)=>b[1]-a[1]).slice(0,5);
      if (topDests.length > 0) behaviors.push("Network: " + topDests.map(([h,c])=>h+" ("+c+"x)").join(", "));
      else behaviors.push("Network: No connections observed");
      const topChildren = Object.entries(app.childProcesses).sort((a,b)=>b[1]-a[1]).slice(0,5);
      if (topChildren.length > 0) behaviors.push("Children: " + topChildren.map(([n,c])=>n+" ("+c+"x)").join(", "));
      else behaviors.push("Children: None spawned");
      const topParents = Object.entries(app.parentProcesses).sort((a,b)=>b[1]-a[1]).slice(0,3);
      if (topParents.length > 0) behaviors.push("Launched by: " + topParents.map(([n,c])=>n+" ("+c+"x)").join(", "));
      const topPorts = Object.entries(app.ports).sort((a,b)=>b[1]-a[1]).slice(0,5);
      if (topPorts.length > 0) behaviors.push("Ports: " + topPorts.map(([p,c])=>p+" ("+c+"x)").join(", "));
      behaviors.push("Executions: " + app.execCount + " | Devices: " + app.agents.size);

      // Compute genome strand (24 segments based on behavioral diversity)
      const strand = [];
      const netDiv = Object.keys(app.networkDests).length;
      const childDiv = Object.keys(app.childProcesses).length;
      const portDiv = Object.keys(app.ports).length;
      for (let i = 0; i < 24; i++) {
        let v = 2; // base
        if (i < 8) v = Math.min(9, Math.ceil(netDiv / 2) + 1);
        else if (i < 16) v = Math.min(9, childDiv * 2 + 1);
        else v = Math.min(9, Math.ceil(app.execCount / 20) + 1);
        // Add some variance
        v = Math.max(1, Math.min(9, v + ((i * 7) % 3) - 1));
        strand.push(v);
      }

      // Deviation score
      let deviation = 0;
      if (!app.companies.size || (app.companies.size === 1 && app.companies.has(""))) deviation += 30; // unsigned
      if (childDiv > 3) deviation += 15; // spawns many children
      if (netDiv > 10) deviation += 10; // connects to many destinations
      if (app.path && !/^C:\\Windows|^C:\\Program Files/i.test(app.path)) deviation += 15; // user-space binary
      deviation = Math.min(100, deviation);

      const status = deviation >= 50 ? "critical" : deviation >= 20 ? "elevated" : "normal";
      return {
        name: app.name, path: app.path,
        company: [...app.companies].filter(c=>c).join(", ") || "Unknown",
        execCount: app.execCount, devices: app.agents.size,
        genome: strand, behaviors, deviation, status,
        users: [...app.users], agents: [...app.agents],
        hashes: [...app.hashes].slice(0,3),
        firstSeen: app.firstSeen, lastSeen: app.lastSeen
      };
    }).filter(g => g.execCount >= 2) // Only show apps seen more than once
      .sort((a,b) => b.deviation - a.deviation || b.execCount - a.execCount);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ total: genomes.length, genomes: genomes.slice(0, 30) }));
    return true;
  }

  // GET /zt/app-relationships?hours=24 — Process parent-child + network relationships
  if (urlPath === "/zt/app-relationships" && req.method === "GET") {
    const params = new URLSearchParams(req.url.split("?")[1] || "");
    const hours = parseInt(params.get("hours")) || 24;
    const type = params.get("type") || "all"; // parent, network, all
    const since = new Date(Date.now() - hours * 3600000).toISOString();

    const relationships = [];

    if (type === "parent" || type === "all") {
      const procHits = await queryES("wazuh-alerts-4.x-*", {
        bool: { must: [
          { range: { timestamp: { gte: since } } },
          { match: { "rule.groups": "sysmon_event1" } }
        ]}
      }, 2000, ["data.win.eventdata.image","data.win.eventdata.parentImage","agent.name"]);

      const parentChildMap = {};
      procHits.forEach(h => {
        const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
        if (!ed.parentImage || !ed.image) return;
        const from = ed.parentImage.split("\\").pop();
        const to = ed.image.split("\\").pop();
        if (from === to) return; // Skip self-spawn (e.g. chrome→chrome)
        const key = from + "→" + to;
        if (!parentChildMap[key]) parentChildMap[key] = { from, to, type: "parent", weight: 0 };
        parentChildMap[key].weight++;
      });
      relationships.push(...Object.values(parentChildMap));
    }

    if (type === "network" || type === "all") {
      const netHits = await queryES("wazuh-alerts-4.x-*", {
        bool: { must: [
          { range: { timestamp: { gte: since } } },
          { match: { "rule.groups": "sysmon_event3" } }
        ]}
      }, 2000, [
        "data.win.eventdata.image","data.win.eventdata.destinationHostname",
        "data.win.eventdata.destinationIp","data.win.eventdata.destinationPort"
      ]);

      const netMap = {};
      netHits.forEach(h => {
        const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
        if (!ed.image) return;
        const from = ed.image.split("\\").pop();
        const to = ed.destinationHostname || ed.destinationIp || "";
        if (!to) return;
        const key = from + "→" + to;
        if (!netMap[key]) netMap[key] = { from, to, type: "network", weight: 0, port: ed.destinationPort };
        netMap[key].weight++;
      });
      relationships.push(...Object.values(netMap));
    }

    // Sort by weight, mark suspicious
    const suspiciousApps = /powershell|cmd\.exe|wscript|cscript|mshta|certutil|bitsadmin/i;
    relationships.forEach(r => {
      r.suspicious = false;
      // Office → shell is suspicious
      if (/outlook|winword|excel/i.test(r.from) && suspiciousApps.test(r.to)) r.suspicious = true;
      // Any unsigned process connecting externally
      if (r.type === "network" && suspiciousApps.test(r.from)) r.suspicious = true;
    });
    relationships.sort((a,b) => (b.suspicious - a.suspicious) || (b.weight - a.weight));

    const nodes = new Set();
    relationships.forEach(r => { nodes.add(r.from); nodes.add(r.to); });

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      total: relationships.length,
      nodes: [...nodes],
      relationships: relationships.slice(0, 100)
    }));
    return true;
  }

  // GET /zt/forensics/:agentId — Live forensic data from Sysmon for a specific agent
  if (urlPath.match(/^\/zt\/forensics\/\w+$/) && req.method === "GET") {
    const agentId = urlPath.split("/")[3];
    const since = new Date(Date.now() - 3600000).toISOString(); // last 1 hour

    // Running processes (from recent Sysmon event 1)
    const procHits = await queryES("wazuh-alerts-4.x-*", {
      bool: { must: [
        { range: { timestamp: { gte: since } } },
        { match: { "rule.groups": "sysmon_event1" } },
        { term: { "agent.id": agentId } }
      ]}
    }, 500, [
      "data.win.eventdata.image","data.win.eventdata.processId",
      "data.win.eventdata.user","data.win.eventdata.commandLine",
      "data.win.eventdata.company","data.win.eventdata.hashes",
      "timestamp"
    ]);

    // Network connections (from recent Sysmon event 3)
    const netHits = await queryES("wazuh-alerts-4.x-*", {
      bool: { must: [
        { range: { timestamp: { gte: since } } },
        { match: { "rule.groups": "sysmon_event3" } },
        { term: { "agent.id": agentId } }
      ]}
    }, 500, [
      "data.win.eventdata.image","data.win.eventdata.sourceIp","data.win.eventdata.sourcePort",
      "data.win.eventdata.destinationIp","data.win.eventdata.destinationPort",
      "data.win.eventdata.destinationHostname","data.win.eventdata.protocol",
      "data.win.eventdata.user","timestamp"
    ]);

    // File creates (Sysmon event 11)
    const fileHits = await queryES("wazuh-alerts-4.x-*", {
      bool: { must: [
        { range: { timestamp: { gte: since } } },
        { match: { "rule.groups": "sysmon_eid11_detections" } },
        { term: { "agent.id": agentId } }
      ]}
    }, 200, [
      "data.win.eventdata.image","data.win.eventdata.targetFilename",
      "data.win.eventdata.creationUtcTime","timestamp"
    ]);

    const processes = {};
    procHits.forEach(h => {
      const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
      const name = (ed.image || "").split("\\").pop();
      if (!processes[name]) {
        processes[name] = { name, path: ed.image, pid: ed.processId, user: ed.user || "", company: ed.company || "", hashes: ed.hashes || "", count: 0 };
      }
      processes[name].count++;
    });

    const connections = netHits.map(h => {
      const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
      return {
        process: (ed.image || "").split("\\").pop(),
        srcIp: ed.sourceIp || "", srcPort: ed.sourcePort || "",
        dstIp: ed.destinationIp || "", dstPort: ed.destinationPort || "",
        dstHost: ed.destinationHostname || "", protocol: ed.protocol || "",
        user: ed.user || "", timestamp: h._source.timestamp
      };
    });

    const fileChanges = fileHits.map(h => {
      const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
      return {
        process: (ed.image || "").split("\\").pop(),
        target: ed.targetFilename || "",
        time: ed.creationUtcTime || h._source.timestamp
      };
    });

    // Unique network destinations
    const uniqueConns = {};
    connections.forEach(c => {
      const key = c.process + "→" + (c.dstHost || c.dstIp) + ":" + c.dstPort;
      if (!uniqueConns[key]) uniqueConns[key] = { ...c, count: 0 };
      uniqueConns[key].count++;
    });

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      agentId,
      capturedAt: new Date().toISOString(),
      processes: Object.values(processes).sort((a,b) => b.count - a.count),
      connections: Object.values(uniqueConns).sort((a,b) => b.count - a.count).slice(0, 50),
      fileChanges: fileChanges.slice(0, 50),
      summary: {
        totalProcesses: Object.keys(processes).length,
        totalConnections: Object.keys(uniqueConns).length,
        totalFileChanges: fileChanges.length,
        unsignedProcesses: Object.values(processes).filter(p => !p.company).length
      }
    }));
    return true;
  }

  // ========== DECEPTION HONEYPOTS ==========

  // GET /zt/decoys — List deployed decoys and check for triggers
  if (urlPath === "/zt/decoys" && req.method === "GET") {
    const data = readZT();
    if (!data.decoys) data.decoys = [];
    if (!data.decoyTriggers) data.decoyTriggers = [];

    // Check Sysmon for any file access to decoy paths (Event 11 = FileCreate, Event 1 = ProcessCreate reading decoy)
    const decoyPaths = data.decoys.map(d => d.path.replace(/\\/g, "\\\\").toLowerCase());
    if (decoyPaths.length > 0) {
      const since = new Date(Date.now() - 24 * 3600000).toISOString();
      // Check Sysmon Event 11 (FileCreate) for decoy file access
      const fileHits = await queryES("wazuh-alerts-4.x-*", {
        bool: { must: [
          { range: { timestamp: { gte: since } } },
          { bool: { should: decoyPaths.map(p => ({ wildcard: { "data.win.eventdata.targetFilename": "*" + p.split("\\\\").pop() + "*" } })) } }
        ]}
      }, 100, [
        "data.win.eventdata.targetFilename", "data.win.eventdata.image",
        "data.win.eventdata.user", "agent.name", "agent.id", "timestamp"
      ]);

      // Check for process creates that reference decoy files in command line
      const cmdHits = await queryES("wazuh-alerts-4.x-*", {
        bool: { must: [
          { range: { timestamp: { gte: since } } },
          { match: { "rule.groups": "sysmon_event1" } },
          { bool: { should: data.decoys.map(d => ({ wildcard: { "data.win.eventdata.commandLine": "*" + d.name + "*" } })) } }
        ]}
      }, 100, [
        "data.win.eventdata.image", "data.win.eventdata.commandLine",
        "data.win.eventdata.user", "agent.name", "agent.id", "timestamp"
      ]);

      const newTriggers = [];
      fileHits.forEach(h => {
        const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
        const matchedDecoy = data.decoys.find(d => (ed.targetFilename || "").toLowerCase().includes(d.name.toLowerCase()));
        if (matchedDecoy) {
          newTriggers.push({
            id: "dt_" + Date.now() + "_" + Math.random().toString(36).substr(2,4),
            decoy: matchedDecoy.name, decoyId: matchedDecoy.id,
            device: h._source.agent ? h._source.agent.name : "Unknown",
            agentId: h._source.agent ? h._source.agent.id : "",
            user: ed.user || "", process: (ed.image || "").split("\\").pop(),
            action: "File Access", time: h._source.timestamp, severity: "critical"
          });
        }
      });
      cmdHits.forEach(h => {
        const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
        const matchedDecoy = data.decoys.find(d => (ed.commandLine || "").toLowerCase().includes(d.name.toLowerCase()));
        if (matchedDecoy) {
          const exists = newTriggers.find(t => t.decoy === matchedDecoy.name && t.device === (h._source.agent ? h._source.agent.name : ""));
          if (!exists) {
            newTriggers.push({
              id: "dt_" + Date.now() + "_" + Math.random().toString(36).substr(2,4),
              decoy: matchedDecoy.name, decoyId: matchedDecoy.id,
              device: h._source.agent ? h._source.agent.name : "Unknown",
              agentId: h._source.agent ? h._source.agent.id : "",
              user: ed.user || "", process: (ed.image || "").split("\\").pop(),
              action: "Process Referenced Decoy", time: h._source.timestamp, severity: "critical"
            });
          }
        }
      });

      // Merge new triggers, avoid duplicates
      if (newTriggers.length > 0) {
        const existingKeys = new Set(data.decoyTriggers.map(t => t.decoy + "|" + t.device + "|" + t.process));
        newTriggers.forEach(t => {
          const key = t.decoy + "|" + t.device + "|" + t.process;
          if (!existingKeys.has(key)) {
            data.decoyTriggers.unshift(t);
            // Mark decoy as triggered
            const d = data.decoys.find(dc => dc.id === t.decoyId);
            if (d) d.triggered = true;
          }
        });
        writeZT(data);
      }
    }

    // Count unique endpoints
    const endpointSet = new Set(data.decoys.flatMap(d => d.deployedTo || []));
    const avgDwell = data.decoyTriggers.length > 0 ? "<2s" : "N/A";

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      decoys: data.decoys,
      triggers: data.decoyTriggers,
      stats: {
        active: data.decoys.length,
        triggered: data.decoyTriggers.length,
        endpoints: endpointSet.size,
        avgDwell
      }
    }));
    return true;
  }

  // POST /zt/decoys — Deploy a new honeypot decoy
  if (urlPath === "/zt/decoys" && req.method === "POST") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const body = await readBodyFn(req);
    const { name, path, type, deployTo } = JSON.parse(body);
    const data = readZT();
    if (!data.decoys) data.decoys = [];
    if (!data.decoyTriggers) data.decoyTriggers = [];

    const decoy = {
      id: "dec_" + Date.now(), name: name || "honeypot_" + Date.now() + ".dat",
      path: path || "C:\\Users\\Public\\" + (name || "honeypot.dat"),
      type: type || "Credential File",
      deployed: new Date().toISOString().split("T")[0],
      deployedTo: deployTo || [], triggered: false,
      icon: type === "Crypto Wallet" ? "&#128176;" : type === "Database Config" ? "&#128190;" : type === "SSH Key" ? "&#128272;" : "&#128274;"
    };
    data.decoys.push(decoy);
    addAuditEntry(data, { event: "policy", app: "Honeypot: " + decoy.name, device: "--", user: "admin", detail: "Deployed honeypot decoy: " + decoy.name });
    writeZT(data);

    // If agents specified, trigger active response to create the file
    if (deployTo && deployTo.length > 0) {
      for (const agentId of deployTo) {
        await triggerActiveResponse(agentId, "deploy-decoy");
      }
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, decoy }));
    return true;
  }

  // DELETE /zt/decoys/:id
  if (urlPath.match(/^\/zt\/decoys\/[\w_]+$/) && req.method === "DELETE") {
    if (!checkAuth(req)) { res.writeHead(401); res.end('{"error":"Unauthorized"}'); return true; }
    const id = urlPath.split("/")[3];
    const data = readZT();
    if (!data.decoys) data.decoys = [];
    data.decoys = data.decoys.filter(d => d.id !== id);
    writeZT(data);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
    return true;
  }

  // ========== THREAT SIMULATOR — Evaluates against REAL policies ==========

  // POST /zt/simulate — Run attack simulation against real policy set
  if (urlPath === "/zt/simulate" && req.method === "POST") {
    const body = await readBodyFn(req);
    const { scenarioId, steps } = JSON.parse(body);
    const data = readZT();
    const policies = data.policies.length > 0 ? data.policies : [];
    const ringfences = data.ringfences.length > 0 ? data.ringfences : [];
    const networkRules = data.networkRules || [];
    const storagePolicies = data.storagePolicies || [];
    const apps = data.applications || [];

    // Evaluate each step against real policies
    const results = (steps || []).map(step => {
      const result = { action: step.action, blocked: false, reason: "No policy matched — PASSED THROUGH (GAP)", matchedPolicy: null };

      // Check if app is blacklisted
      if (step.app) {
        const appLower = step.app.toLowerCase();
        const blacklisted = apps.find(a => a.status === "blacklisted" && (a.name.toLowerCase() === appLower || a.path.toLowerCase().includes(appLower)));
        if (blacklisted) {
          result.blocked = true;
          result.reason = "Application blacklisted: " + blacklisted.name;
          result.matchedPolicy = "Application Catalog";
          return result;
        }

        // Check deny policies
        const denyPolicy = policies.find(p => p.enabled && p.action === "deny" && (
          (p.type === "blacklist" && p.match.toLowerCase().includes(appLower)) ||
          (p.type === "hash" && step.hash && p.match.toLowerCase().includes(step.hash.toLowerCase())) ||
          (p.type === "path" && step.path && p.match.toLowerCase().includes(appLower))
        ));
        if (denyPolicy) {
          result.blocked = true;
          result.reason = "Blocked by policy: " + denyPolicy.name;
          result.matchedPolicy = denyPolicy.name;
          return result;
        }

        // Check if NOT whitelisted (default deny)
        const settings = data.settings || {};
        if (settings.defaultDeny) {
          const whitelisted = apps.find(a => a.status === "whitelisted" && a.name.toLowerCase() === appLower);
          const allowPolicy = policies.find(p => p.enabled && p.action === "allow" && (
            (p.type === "publisher" && step.publisher && p.match.toLowerCase().includes(step.publisher.toLowerCase())) ||
            (p.type === "path" && step.path && p.match.toLowerCase().includes(appLower)) ||
            (p.type === "whitelist" && p.match.toLowerCase().includes(appLower))
          ));
          if (!whitelisted && !allowPolicy) {
            result.blocked = true;
            result.reason = "Default deny — not whitelisted or allowed by policy";
            result.matchedPolicy = "Default Deny";
            return result;
          }
        }
      }

      // Check ringfencing
      if (step.ringfenceCheck && step.app) {
        const rf = ringfences.find(r => r.enabled && r.app.toLowerCase().includes(step.app.toLowerCase()));
        if (rf) {
          if (step.ringfenceCheck === "network" && (rf.network === "None" || rf.network === "Blocked")) {
            result.blocked = true;
            result.reason = "Ringfence blocks network access for " + rf.app;
            result.matchedPolicy = "Ringfence: " + rf.app;
            return result;
          }
          if (step.ringfenceCheck === "filesystem" && (rf.filesystem === "None")) {
            result.blocked = true;
            result.reason = "Ringfence blocks file system access for " + rf.app;
            result.matchedPolicy = "Ringfence: " + rf.app;
            return result;
          }
          if (step.ringfenceCheck === "child" && (rf.ipc === "Blocked")) {
            result.blocked = true;
            result.reason = "Ringfence blocks child process spawning for " + rf.app;
            result.matchedPolicy = "Ringfence: " + rf.app;
            return result;
          }
          if (step.ringfenceCheck === "registry" && (rf.registry === "None")) {
            result.blocked = true;
            result.reason = "Ringfence blocks registry access for " + rf.app;
            result.matchedPolicy = "Ringfence: " + rf.app;
            return result;
          }
        }
      }

      // Check network rules
      if (step.networkCheck && step.app) {
        const netRule = networkRules.find(n => n.enabled && n.app.toLowerCase().includes(step.app.toLowerCase()));
        if (netRule && netRule.rule.toLowerCase().includes("block")) {
          result.blocked = true;
          result.reason = "Network rule blocks: " + netRule.rule;
          result.matchedPolicy = "Network: " + netRule.app;
          return result;
        }
      }

      // Check storage
      if (step.storageCheck) {
        const storageRule = storagePolicies.find(s => s.enabled && s.name.toLowerCase().includes(step.storageCheck.toLowerCase()));
        if (storageRule) {
          result.blocked = true;
          result.reason = "Storage policy: " + storageRule.name;
          result.matchedPolicy = storageRule.name;
          return result;
        }
      }

      return result;
    });

    const blocked = results.filter(r => r.blocked).length;
    const total = results.length;
    const score = total > 0 ? Math.round(blocked / total * 100) : 0;
    const gaps = results.filter(r => !r.blocked);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      scenarioId, score, blocked, total, gaps: gaps.length,
      results,
      policyCount: policies.filter(p => p.enabled).length,
      ringfenceCount: ringfences.filter(r => r.enabled).length,
      evaluatedAt: new Date().toISOString()
    }));
    return true;
  }

  // ========== PEER SHIELD — Real IOC sharing from audit/Sysmon data ==========

  // GET /zt/peer-intel — Aggregated IOCs from all endpoints
  if (urlPath === "/zt/peer-intel" && req.method === "GET") {
    const data = readZT();
    if (!data.iocDatabase) data.iocDatabase = [];

    // Extract IOCs from audit log (blocked events)
    const blockedEvents = (data.auditLog || []).filter(a => a.event === "block");
    const existingIndicators = new Set(data.iocDatabase.map(i => i.indicator));
    let newIOCs = 0;

    blockedEvents.forEach(ev => {
      const indicator = ev.app || "";
      if (!indicator || indicator === "--" || existingIndicators.has(indicator)) return;
      data.iocDatabase.push({
        id: "ioc_" + Date.now() + "_" + Math.random().toString(36).substr(2,4),
        type: indicator.includes(".exe") ? "hash" : "behavior",
        indicator,
        threat: "Blocked application: " + indicator,
        source: "Endpoint: " + (ev.device || "Unknown"),
        time: ev.time || new Date().toISOString(),
        blocked: true,
        detail: ev.detail || ""
      });
      existingIndicators.add(indicator);
      newIOCs++;
    });

    // Extract IOCs from Sysmon — high severity alerts
    const since = new Date(Date.now() - 24 * 3600000).toISOString();
    const highSevHits = await queryES("wazuh-alerts-4.x-*", {
      bool: { must: [
        { range: { timestamp: { gte: since } } },
        { range: { "rule.level": { gte: 7 } } },
        { bool: { should: [
          { match: { "rule.groups": "sysmon_event1" } },
          { match: { "rule.groups": "sysmon_event3" } }
        ]}}
      ]}
    }, 100, [
      "data.win.eventdata.image", "data.win.eventdata.hashes",
      "data.win.eventdata.destinationIp", "data.win.eventdata.destinationHostname",
      "data.win.eventdata.user", "agent.name", "timestamp",
      "rule.description", "rule.level"
    ]);

    highSevHits.forEach(h => {
      const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
      const image = ed.image || "";
      const hash = (ed.hashes || "").split(",")[0] || "";
      const destIp = ed.destinationIp || "";
      const destHost = ed.destinationHostname || "";

      // Add process hash IOC
      if (hash && !existingIndicators.has(hash)) {
        data.iocDatabase.push({
          id: "ioc_" + Date.now() + "_" + Math.random().toString(36).substr(2,4),
          type: "hash", indicator: hash,
          threat: "High-severity process: " + image.split("\\").pop(),
          source: "Sysmon: " + (h._source.agent ? h._source.agent.name : "Unknown"),
          time: h._source.timestamp, blocked: true,
          detail: h._source.rule ? h._source.rule.description : ""
        });
        existingIndicators.add(hash);
        newIOCs++;
      }

      // Add suspicious destination IOC
      if (destIp && !destIp.startsWith("10.") && !destIp.startsWith("192.168.") && !destIp.startsWith("127.") && !destIp.startsWith("::1") && !existingIndicators.has(destIp)) {
        data.iocDatabase.push({
          id: "ioc_" + Date.now() + "_" + Math.random().toString(36).substr(2,4),
          type: "ip", indicator: destIp,
          threat: "Connection from high-severity alert",
          source: "Sysmon: " + (h._source.agent ? h._source.agent.name : "Unknown"),
          time: h._source.timestamp, blocked: false,
          detail: (destHost ? destHost + " " : "") + "via " + image.split("\\").pop()
        });
        existingIndicators.add(destIp);
        newIOCs++;
      }
    });

    // Also extract network destinations from all Sysmon data for intel
    const netAggHits = await queryES("wazuh-alerts-4.x-*", {
      bool: { must: [
        { range: { timestamp: { gte: since } } },
        { match: { "rule.groups": "sysmon_event3" } }
      ]}
    }, 500, [
      "data.win.eventdata.image", "data.win.eventdata.destinationIp",
      "data.win.eventdata.destinationHostname", "data.win.eventdata.destinationPort",
      "agent.name", "timestamp"
    ]);

    // Aggregate unique external destinations
    const destMap = {};
    netAggHits.forEach(h => {
      const ed = (h._source.data && h._source.data.win && h._source.data.win.eventdata) || {};
      const ip = ed.destinationIp || "";
      if (!ip || ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.") || ip.startsWith("::1") || ip.startsWith("0.0.0.0")) return;
      const host = ed.destinationHostname || ip;
      if (!destMap[host]) destMap[host] = { host, ip, port: ed.destinationPort, count: 0, processes: new Set(), agents: new Set() };
      destMap[host].count++;
      destMap[host].processes.add((ed.image || "").split("\\").pop());
      if (h._source.agent) destMap[host].agents.add(h._source.agent.name);
    });

    const topDestinations = Object.values(destMap).map(d => ({
      ...d, processes: [...d.processes], agents: [...d.agents]
    })).sort((a,b) => b.count - a.count).slice(0, 30);

    if (newIOCs > 0) writeZT(data);

    // Stats
    const iocs = data.iocDatabase;
    const byType = { hash: iocs.filter(i=>i.type==="hash").length, ip: iocs.filter(i=>i.type==="ip").length, domain: iocs.filter(i=>i.type==="domain").length, behavior: iocs.filter(i=>i.type==="behavior").length };

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({
      feed: iocs.sort((a,b) => (b.time||"").localeCompare(a.time||"")).slice(0, 50),
      stats: {
        total: iocs.length,
        blockedByPeers: iocs.filter(i=>i.blocked).length,
        byType,
        newToday: iocs.filter(i => i.time && i.time.startsWith(new Date().toISOString().split("T")[0])).length
      },
      topDestinations,
      lastUpdated: new Date().toISOString()
    }));
    return true;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end('{"error":"ZT route not found"}');
  return true;
}

module.exports = { handleZTRoute };
