"use strict";
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const SCANS_DIR = "/opt/scans";
const MAX_CONCURRENT = 2;

// In-memory registry — survives proxy restarts by loading from disk
const scans = {};
let activeCount = 0;
const queue = [];

if (!fs.existsSync(SCANS_DIR)) fs.mkdirSync(SCANS_DIR, { recursive: true });

// Load existing scans from disk on startup
try {
  fs.readdirSync(SCANS_DIR).forEach(id => {
    const rf = path.join(SCANS_DIR, id, "results.json");
    if (fs.existsSync(rf)) {
      try {
        const s = JSON.parse(fs.readFileSync(rf, "utf8"));
        scans[id] = s;
        // If it was running when proxy restarted, mark as error
        if (s.status === "running" || s.status === "queued") {
          s.status = "error";
          s.error = "Interrupted by proxy restart";
          fs.writeFileSync(rf, JSON.stringify(s, null, 2));
        }
      } catch(e) {}
    }
  });
  console.log("[scanner] Loaded", Object.keys(scans).length, "scans from disk");
} catch(e) {}

function generateId() { return crypto.randomBytes(8).toString("hex"); }

function startScan(config) {
  const id = generateId();
  const scan = {
    id,
    status: "queued",
    type: config.type || "external",
    profile: config.profile || "standard",
    targets: config.targets || [],
    exclusions: config.exclusions || [],
    clientName: config.clientName || "",
    startedAt: new Date().toISOString(),
    queuedAt: new Date().toISOString(),
    completedAt: null,
    findings: [],
    stats: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    error: null
  };

  const scanDir = path.join(SCANS_DIR, id);
  fs.mkdirSync(scanDir, { recursive: true });
  fs.writeFileSync(path.join(scanDir, "config.json"), JSON.stringify(config, null, 2));
  fs.writeFileSync(path.join(scanDir, "results.json"), JSON.stringify(scan, null, 2));

  scans[id] = scan;

  if (activeCount < MAX_CONCURRENT) {
    runScan(scan, scanDir);
  } else {
    queue.push({ scan, scanDir });
    console.log("[scanner] Queued scan", id, "— active:", activeCount);
  }

  return scan;
}

function runScan(scan, scanDir) {
  activeCount++;
  scan.status = "running";
  scan.startedAt = new Date().toISOString();
  saveScan(scan, scanDir);
  runNmap(scan, scanDir);
}

function nextInQueue() {
  activeCount--;
  if (queue.length > 0) {
    const { scan, scanDir } = queue.shift();
    runScan(scan, scanDir);
  }
}

function saveScan(scan, scanDir) {
  try {
    fs.writeFileSync(path.join(scanDir, "results.json"), JSON.stringify(scan, null, 2));
  } catch(e) {}
}

// ── NMAP ──────────────────────────────────────────────────────────────────────
function runNmap(scan, scanDir) {
  const xmlOut = path.join(scanDir, "nmap.xml");
  const txtOut = path.join(scanDir, "nmap.txt");

  let args = ["-oX", xmlOut, "-oN", txtOut];

  if (scan.profile === "quick") {
    args = args.concat(["-T4", "-F", "--top-ports", "100", "--open"]);
  } else if (scan.profile === "deep") {
    args = args.concat(["-T3", "-sV", "--version-intensity", "7", "-sC", "-O", "--osscan-guess", "-p-", "--open"]);
  } else {
    // standard
    args = args.concat(["-T4", "-sV", "--version-intensity", "5", "-sC", "--top-ports", "1000", "--open"]);
  }

  if (scan.exclusions.length > 0) {
    args.push("--exclude"); args.push(scan.exclusions.join(","));
  }

  args = args.concat(scan.targets);
  console.log("[scanner] nmap", args.join(" "));

  const proc = spawn("nmap", args, { timeout: 600000 });
  let stderr = "";
  proc.stderr.on("data", d => { stderr += d; });

  proc.on("close", code => {
    console.log("[scanner] nmap done, code:", code);
    try {
      const txt = fs.readFileSync(txtOut, "utf8");
      parseNmap(scan, txt);
    } catch(e) { console.error("[scanner] nmap read error:", e.message); }

    if (code !== 0 && !scan.findings.length) {
      scan.error = "nmap exited " + code + ": " + stderr.slice(0, 300);
    }

    runNuclei(scan, scanDir);
  });

  proc.on("error", e => {
    scan.error = "nmap unavailable: " + e.message;
    finishScan(scan, scanDir);
  });
}

function parseNmap(scan, txt) {
  const blocks = txt.split(/Nmap scan report for /);
  for (const block of blocks.slice(1)) {
    const hostRaw = (block.match(/^([^\n]+)/) || [])[1] || "unknown";
    const host = hostRaw.replace(/\s*\(.*\)/, "").trim();
    const portLines = block.match(/^\d+\/(tcp|udp)\s+open\s+\S+.*$/gm) || [];

    for (const line of portLines) {
      const m = line.match(/^(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$/);
      if (!m) continue;
      const port = parseInt(m[1]);
      const proto = m[2];
      const service = m[3];
      const version = (m[4] || "").trim();

      scan.findings.push({
        id: crypto.randomBytes(4).toString("hex"),
        host,
        port,
        protocol: proto,
        service,
        version,
        source: "nmap",
        severity: "info",
        title: `Open Port ${port}/${proto} (${service})`,
        description: version ? `Service: ${service} ${version}` : `Service: ${service}`,
        cve: null,
        cvss: 0,
        solution: "Verify this port is intentionally exposed. Restrict access with firewall rules if not needed."
      });
    }
  }
}

// ── NUCLEI ────────────────────────────────────────────────────────────────────
function runNuclei(scan, scanDir) {
  const targetsFile = path.join(scanDir, "targets.txt");
  const outFile = path.join(scanDir, "nuclei.jsonl");

  // Build target list from original targets + discovered HTTP ports
  const urls = new Set(scan.targets);
  for (const f of scan.findings) {
    if (f.source === "nmap" && f.port) {
      const httpPorts = [80, 443, 8080, 8443, 8000, 3000, 5000, 5601, 9200, 9443, 4444, 7070, 4000];
      if (httpPorts.includes(f.port)) {
        const proto = [443, 8443, 9443].includes(f.port) ? "https" : "http";
        urls.add(`${proto}://${f.host}:${f.port}`);
      }
    }
  }

  fs.writeFileSync(targetsFile, Array.from(urls).join("\n"));

  const sevMap = { quick: "critical,high", standard: "low,medium,high,critical", deep: "info,low,medium,high,critical" };
  const severity = sevMap[scan.profile] || sevMap.standard;

  let args = [
    "-l", targetsFile,
    "-jsonl", "-o", outFile,
    "-silent",
    "-severity", severity,
    "-rate-limit", "100",
    "-c", "20",
    "-timeout", "10",
    "-retries", "1",
    "-no-color"
  ];

  // Template selection by scan type
  if (scan.type === "webapp") {
    args = args.concat(["-t", "http/", "-t", "cves/", "-t", "vulnerabilities/", "-t", "exposures/"]);
  } else if (scan.type === "network") {
    args = args.concat(["-t", "network/", "-t", "cves/", "-t", "services/"]);
  } else {
    // external — broad coverage
    args = args.concat(["-t", "cves/", "-t", "vulnerabilities/", "-t", "exposures/", "-t", "misconfiguration/", "-t", "default-logins/"]);
  }

  console.log("[scanner] nuclei", args.slice(0, 6).join(" "), "...");
  const proc = spawn("nuclei", args, {
    timeout: 600000,
    env: { ...process.env, HOME: "/root" }
  });

  let stderr = "";
  proc.stderr.on("data", d => { stderr += d; });

  proc.on("close", code => {
    console.log("[scanner] nuclei done, code:", code);
    if (fs.existsSync(outFile)) {
      const lines = fs.readFileSync(outFile, "utf8").split("\n").filter(Boolean);
      for (const line of lines) {
        try {
          const r = JSON.parse(line);
          const info = r.info || {};
          const sev = (info.severity || "info").toLowerCase();
          const cvssMap = { info: 0, low: 2.5, medium: 5.5, high: 7.5, critical: 9.5 };

          // Extract CVEs
          const cves = (info.classification?.cve_id || []).filter(Boolean);

          scan.findings.push({
            id: crypto.randomBytes(4).toString("hex"),
            host: r.host || r.ip || r["matched-at"] || "",
            port: r.port || null,
            protocol: "tcp",
            service: r.type || "http",
            version: "",
            source: "nuclei",
            severity: sev,
            title: info.name || r["template-id"] || "Unknown",
            description: info.description || "",
            cve: cves.length ? cves[0] : null,
            cves: cves,
            cvss: info.classification?.cvss_score || cvssMap[sev] || 0,
            solution: info.remediation || "Refer to vendor advisory for patch information.",
            tags: info.tags || [],
            matched_at: r["matched-at"] || "",
            matcher_name: r["matcher-name"] || "",
            template_id: r["template-id"] || ""
          });
        } catch(e) {}
      }
    }
    finishScan(scan, scanDir);
  });

  proc.on("error", e => {
    if (!scan.error) scan.error = "nuclei unavailable: " + e.message;
    finishScan(scan, scanDir);
  });
}

// ── FINISH ────────────────────────────────────────────────────────────────────
function finishScan(scan, scanDir) {
  // Compute stats
  scan.stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of scan.findings) {
    const sev = f.severity || "info";
    if (scan.stats[sev] !== undefined) scan.stats[sev]++;
    else scan.stats.info++;
  }

  // Deduplicate by title+host
  const seen = new Set();
  scan.findings = scan.findings.filter(f => {
    const key = `${f.host}:${f.port}:${f.title}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });

  // Sort: critical first, then by host
  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  scan.findings.sort((a, b) => (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4));

  scan.status = "completed";
  scan.completedAt = new Date().toISOString();
  saveScan(scan, scanDir);
  console.log("[scanner] Scan", scan.id, "complete —", scan.findings.length, "findings | C:", scan.stats.critical, "H:", scan.stats.high, "M:", scan.stats.medium);
  nextInQueue();
}

// ── PUBLIC API ────────────────────────────────────────────────────────────────
function getScan(id) {
  if (scans[id]) return scans[id];
  const rf = path.join(SCANS_DIR, id, "results.json");
  if (fs.existsSync(rf)) {
    try { return JSON.parse(fs.readFileSync(rf, "utf8")); } catch(e) {}
  }
  return null;
}

function listScans() {
  try {
    const dirs = fs.readdirSync(SCANS_DIR).filter(d => fs.existsSync(path.join(SCANS_DIR, d, "config.json")));
    return dirs.map(d => getScan(d)).filter(Boolean)
      .map(s => ({
        id: s.id, status: s.status, type: s.type, profile: s.profile,
        targets: s.targets, clientName: s.clientName || "",
        startedAt: s.startedAt, completedAt: s.completedAt,
        stats: s.stats || { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        findingCount: s.findings ? s.findings.length : 0,
        error: s.error || null
      }))
      .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
  } catch(e) { return []; }
}

function deleteScan(id) {
  delete scans[id];
  const scanDir = path.join(SCANS_DIR, id);
  try { fs.rmSync(scanDir, { recursive: true, force: true }); } catch(e) {}
}

// ── CYBER EXPOSURE SCORE (CES) ───────────────────────────────────────────────

function getGrade(score) {
  if (score >= 95) return "A+";
  if (score >= 90) return "A";
  if (score >= 85) return "A-";
  if (score >= 80) return "B+";
  if (score >= 75) return "B";
  if (score >= 70) return "B-";
  if (score >= 65) return "C+";
  if (score >= 60) return "C";
  if (score >= 55) return "C-";
  if (score >= 40) return "D";
  return "F";
}

function getClientScans(clientName) {
  try {
    const dirs = fs.readdirSync(SCANS_DIR).filter(d =>
      fs.existsSync(path.join(SCANS_DIR, d, "results.json"))
    );
    const clientScans = [];
    for (const d of dirs) {
      try {
        const s = JSON.parse(fs.readFileSync(path.join(SCANS_DIR, d, "results.json"), "utf8"));
        if (s.status === "completed" && s.clientName && s.clientName.toLowerCase() === clientName.toLowerCase()) {
          clientScans.push(s);
        }
      } catch(e) {}
    }
    return clientScans;
  } catch(e) { return []; }
}

function calculateCES(clientName) {
  const clientScans = getClientScans(clientName);
  if (clientScans.length === 0) return null;

  // Sort scans newest first
  clientScans.sort((a, b) => new Date(b.completedAt) - new Date(a.completedAt));

  // Keep only the most recent scan per unique target set (sorted targets as key)
  const targetMap = new Map();
  for (const s of clientScans) {
    const key = (s.targets || []).slice().sort().join(",");
    if (!targetMap.has(key)) {
      targetMap.set(key, s);
    }
  }
  const latestScans = Array.from(targetMap.values());

  // Aggregate findings from the latest scans
  let critical = 0, high = 0, medium = 0, low = 0, info = 0;
  let totalCVSS = 0, cvssCount = 0;
  let lastScanDate = null;

  for (const s of latestScans) {
    const st = s.stats || {};
    critical += st.critical || 0;
    high += st.high || 0;
    medium += st.medium || 0;
    low += st.low || 0;
    info += st.info || 0;

    // Gather CVSS scores from findings
    if (s.findings) {
      for (const f of s.findings) {
        if (f.cvss && f.cvss > 0 && f.severity !== "info") {
          totalCVSS += f.cvss;
          cvssCount++;
        }
      }
    }

    // Track most recent scan date
    if (s.completedAt && (!lastScanDate || new Date(s.completedAt) > new Date(lastScanDate))) {
      lastScanDate = s.completedAt;
    }
  }

  const totalFindings = critical + high + medium + low + info;
  const avgCVSS = cvssCount > 0 ? Math.round((totalCVSS / cvssCount) * 10) / 10 : 0;

  // Calculate weighted deductions (capped per category)
  const criticalDeduct = Math.min(critical * 10, 40);
  const highDeduct = Math.min(high * 5, 25);
  const mediumDeduct = Math.min(medium * 2, 15);
  const lowDeduct = Math.min(low * 0.5, 10);

  let score = 100 - criticalDeduct - highDeduct - mediumDeduct - lowDeduct;

  // Secondary CVSS factor: if average CVSS is high, apply additional penalty
  // Scale: avgCVSS 0-10 maps to 0-10 bonus penalty
  if (avgCVSS > 0) {
    const cvssPenalty = Math.min((avgCVSS / 10) * 10, 10);
    score -= cvssPenalty;
  }

  // Clamp to 0-100
  score = Math.max(0, Math.min(100, Math.round(score * 10) / 10));

  // Determine trend by comparing to older scans
  let trend = "new";
  if (clientScans.length >= 2) {
    // Compare latest scan stats to the second-latest
    const latest = clientScans[0];
    const previous = clientScans[1];
    const latestTotal = (latest.stats?.critical || 0) * 10 + (latest.stats?.high || 0) * 5 +
                        (latest.stats?.medium || 0) * 2 + (latest.stats?.low || 0) * 0.5;
    const prevTotal = (previous.stats?.critical || 0) * 10 + (previous.stats?.high || 0) * 5 +
                      (previous.stats?.medium || 0) * 2 + (previous.stats?.low || 0) * 0.5;
    if (latestTotal < prevTotal) trend = "improving";
    else if (latestTotal > prevTotal) trend = "declining";
    else trend = "stable";
  }

  return {
    score,
    grade: getGrade(score),
    breakdown: {
      critical,
      high,
      medium,
      low,
      info,
      totalFindings,
      avgCVSS,
      scansAnalyzed: latestScans.length,
      lastScanDate
    },
    trend
  };
}

function getAllCES() {
  // Collect all unique client names from completed scans
  const clientNames = new Set();
  try {
    const dirs = fs.readdirSync(SCANS_DIR).filter(d =>
      fs.existsSync(path.join(SCANS_DIR, d, "results.json"))
    );
    for (const d of dirs) {
      try {
        const s = JSON.parse(fs.readFileSync(path.join(SCANS_DIR, d, "results.json"), "utf8"));
        if (s.status === "completed" && s.clientName) {
          clientNames.add(s.clientName);
        }
      } catch(e) {}
    }
  } catch(e) {}

  const results = {};
  for (const name of clientNames) {
    const ces = calculateCES(name);
    if (ces) results[name] = ces;
  }
  return results;
}

module.exports = { startScan, getScan, listScans, deleteScan, calculateCES, getAllCES };
