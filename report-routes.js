// ============================================================
// REPORT GENERATION ROUTES — Add to wazuh-proxy-ssl.js
// Generates HTML-based security reports that render as PDF via browser print
// ============================================================
// To install: append this to /opt/wazuh-proxy-ssl.js on the server
// then restart: systemctl restart wazuh-proxy

// --- ADD THESE ROUTES TO THE EXISTING SERVER ---

// GET /report/monthly?client=CLIENTNAME&month=YYYY-MM
// Generates a branded monthly security report as downloadable HTML
// The client can print-to-PDF from their browser for a clean report

/*
  Add this route handler inside the existing request handler in wazuh-proxy-ssl.js:

  // Monthly Security Report
  if (req.method === 'GET' && parsedUrl.pathname === '/report/monthly') {
    const params = parsedUrl.searchParams || new URLSearchParams(parsedUrl.search);
    const client = params.get('client') || 'All Clients';
    const month = params.get('month') || new Date().toISOString().slice(0, 7);

    try {
      // Fetch alert data from Wazuh for the month
      const [year, mon] = month.split('-');
      const startDate = `${month}-01T00:00:00Z`;
      const endDate = new Date(parseInt(year), parseInt(mon), 0);
      endDate.setHours(23, 59, 59);
      const endDateStr = endDate.toISOString();

      const alertQuery = {
        size: 0,
        query: {
          bool: {
            must: [
              { range: { timestamp: { gte: startDate, lte: endDateStr } } }
            ]
          }
        },
        aggs: {
          by_level: {
            range: {
              field: 'rule.level',
              ranges: [
                { key: 'Low', from: 0, to: 4 },
                { key: 'Medium', from: 4, to: 7 },
                { key: 'High', from: 7, to: 12 },
                { key: 'Critical', from: 12 }
              ]
            }
          },
          top_rules: {
            terms: { field: 'rule.description.keyword', size: 10 }
          },
          by_agent: {
            terms: { field: 'agent.name.keyword', size: 20 }
          },
          by_mitre: {
            terms: { field: 'rule.mitre.technique.keyword', size: 10 }
          },
          alerts_over_time: {
            date_histogram: {
              field: 'timestamp',
              calendar_interval: 'day'
            }
          }
        }
      };

      const alertRes = await fetch(`https://localhost:9200/wazuh-alerts-*/_search`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + Buffer.from('admin:admin').toString('base64')
        },
        body: JSON.stringify(alertQuery),
        agent: new (require('https').Agent)({ rejectUnauthorized: false })
      });
      const alertData = await alertRes.json();

      // SCA / Compliance data
      const scaQuery = {
        size: 0,
        query: { bool: { must: [{ exists: { field: 'data.sca.policy' } }] } },
        aggs: {
          by_policy: {
            terms: { field: 'data.sca.policy.keyword', size: 20 },
            aggs: {
              results: { terms: { field: 'data.sca.check.result.keyword', size: 5 } }
            }
          }
        }
      };
      const scaRes = await fetch(`https://localhost:9200/wazuh-alerts-*/_search`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Basic ' + Buffer.from('admin:admin').toString('base64')
        },
        body: JSON.stringify(scaQuery),
        agent: new (require('https').Agent)({ rejectUnauthorized: false })
      });
      const scaData = await scaRes.json();

      // Build report HTML
      const totalAlerts = alertData.hits?.total?.value || 0;
      const levels = {};
      (alertData.aggregations?.by_level?.buckets || []).forEach(b => { levels[b.key] = b.doc_count; });
      const topRules = (alertData.aggregations?.top_rules?.buckets || []).slice(0, 8);
      const agents = alertData.aggregations?.by_agent?.buckets || [];
      const mitre = alertData.aggregations?.by_mitre?.buckets || [];
      const timeline = alertData.aggregations?.alerts_over_time?.buckets || [];

      const scaPolicies = scaData.aggregations?.by_policy?.buckets || [];

      const monthName = new Date(parseInt(year), parseInt(mon) - 1).toLocaleString('en-US', { month: 'long', year: 'numeric' });

      const html = generateReportHTML({
        client, monthName, totalAlerts, levels, topRules, agents, mitre, timeline, scaPolicies
      });

      res.writeHead(200, {
        'Content-Type': 'text/html',
        'Content-Disposition': `inline; filename="PalisadeOne-Report-${month}.html"`,
        'Access-Control-Allow-Origin': '*'
      });
      res.end(html);
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ error: err.message }));
    }
    return;
  }


  function generateReportHTML({ client, monthName, totalAlerts, levels, topRules, agents, mitre, timeline, scaPolicies }) {
    const critical = levels['Critical'] || 0;
    const high = levels['High'] || 0;
    const medium = levels['Medium'] || 0;
    const low = levels['Low'] || 0;

    // Calculate health score (100 - weighted penalties)
    const healthScore = Math.max(0, Math.min(100, 100 - (critical * 5) - (high * 2) - (medium * 0.5)));

    // Timeline chart data
    const maxDay = Math.max(...timeline.map(t => t.doc_count), 1);
    const timelineBars = timeline.map(t => {
      const date = new Date(t.key_as_string || t.key);
      const day = date.getDate();
      const pct = Math.round((t.doc_count / maxDay) * 100);
      return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
        <div style="width:100%;background:rgba(0,255,209,0.15);height:120px;position:relative;">
          <div style="position:absolute;bottom:0;width:100%;height:${pct}%;background:linear-gradient(to top,#00FFD1,#0084FF);transition:height 0.3s;"></div>
        </div>
        <span style="font-size:8px;color:#4A6080;">${day}</span>
      </div>`;
    }).join('');

    // Top rules table rows
    const ruleRows = topRules.map((r, i) =>
      `<tr><td style="padding:8px 12px;border-bottom:1px solid #112240;color:#C8D8F0;font-size:12px;">${i + 1}</td>
       <td style="padding:8px 12px;border-bottom:1px solid #112240;color:#C8D8F0;font-size:12px;">${r.key}</td>
       <td style="padding:8px 12px;border-bottom:1px solid #112240;color:#00FFD1;font-size:12px;text-align:right;">${r.doc_count}</td></tr>`
    ).join('');

    // Agent breakdown rows
    const agentRows = agents.slice(0, 10).map(a =>
      `<tr><td style="padding:8px 12px;border-bottom:1px solid #112240;color:#C8D8F0;font-size:12px;">${a.key}</td>
       <td style="padding:8px 12px;border-bottom:1px solid #112240;color:#00FFD1;font-size:12px;text-align:right;">${a.doc_count}</td></tr>`
    ).join('');

    // MITRE ATT&CK tags
    const mitreTags = mitre.slice(0, 8).map(m =>
      `<span style="display:inline-block;padding:4px 10px;margin:3px;background:rgba(0,132,255,0.1);border:1px solid rgba(0,132,255,0.2);color:#0084FF;font-size:10px;letter-spacing:1px;">${m.key} (${m.doc_count})</span>`
    ).join('');

    // SCA compliance rows
    const scaRows = scaPolicies.slice(0, 6).map(p => {
      let pass = 0, fail = 0;
      (p.results?.buckets || []).forEach(r => {
        if (r.key === 'passed') pass = r.doc_count;
        else if (r.key === 'failed') fail = r.doc_count;
      });
      const total = pass + fail || 1;
      const pct = Math.round((pass / total) * 100);
      return `<div style="margin-bottom:16px;">
        <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
          <span style="font-size:12px;color:#C8D8F0;">${p.key}</span>
          <span style="font-size:12px;color:#00FFD1;">${pct}%</span>
        </div>
        <div style="height:6px;background:#112240;border-radius:3px;overflow:hidden;">
          <div style="height:100%;width:${pct}%;background:${pct >= 80 ? '#00FFD1' : pct >= 60 ? '#F5A623' : '#FF3B5C'};border-radius:3px;"></div>
        </div>
        <div style="font-size:10px;color:#4A6080;margin-top:2px;">${pass} passed / ${fail} failed</div>
      </div>`;
    }).join('');

    const generatedDate = new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Security Report — ${monthName} — ${client}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=JetBrains+Mono:wght@400;500&family=Outfit:wght@300;400;500;600&display=swap');
  * { margin:0;padding:0;box-sizing:border-box; }
  body { background:#03050A;color:#C8D8F0;font-family:'Outfit',sans-serif;line-height:1.6; }
  @media print {
    body { background:#fff;color:#1a1a1a; }
    .no-print { display:none !important; }
    .page-break { page-break-before:always; }
    .report-section { border-color:#ddd !important; }
    .stat-value { color:#0066cc !important; }
  }
  .report-container { max-width:900px;margin:0 auto;padding:40px; }
  .report-header { text-align:center;padding:60px 40px;border:1px solid #112240;margin-bottom:40px;position:relative;overflow:hidden; }
  .report-header::before { content:'';position:absolute;inset:0;background:radial-gradient(ellipse 60% 60% at 50% 40%,rgba(0,255,209,0.05) 0%,transparent 60%); }
  .report-logo { font-family:'Bebas Neue',sans-serif;font-size:36px;color:#00FFD1;letter-spacing:6px;position:relative; }
  .report-logo span { color:#0084FF; }
  .report-title { font-family:'Bebas Neue',sans-serif;font-size:42px;color:#F0F6FF;letter-spacing:3px;margin-top:16px;position:relative; }
  .report-meta { font-family:'JetBrains Mono',monospace;font-size:11px;color:#4A6080;letter-spacing:2px;margin-top:12px;position:relative; }
  .report-section { border:1px solid #112240;padding:32px;margin-bottom:24px; }
  .section-head { font-family:'Bebas Neue',sans-serif;font-size:24px;color:#F0F6FF;letter-spacing:2px;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid #112240; }
  .section-label-sm { font-family:'JetBrains Mono',monospace;font-size:10px;color:#00FFD1;letter-spacing:3px;margin-bottom:12px; }
  .stats-row { display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px; }
  .stat-card { background:#070C14;border:1px solid #112240;padding:20px;text-align:center; }
  .stat-value { font-family:'Bebas Neue',sans-serif;font-size:36px;letter-spacing:2px;line-height:1; }
  .stat-name { font-size:10px;color:#4A6080;letter-spacing:2px;text-transform:uppercase;margin-top:6px; }
  .health-ring { width:120px;height:120px;margin:0 auto 16px;position:relative; }
  .health-score { position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-family:'Bebas Neue',sans-serif;font-size:36px;color:#00FFD1; }
  table { width:100%;border-collapse:collapse; }
  th { padding:8px 12px;text-align:left;font-family:'JetBrains Mono',monospace;font-size:10px;color:#4A6080;letter-spacing:2px;border-bottom:2px solid #112240; }
  .print-btn { position:fixed;bottom:24px;right:24px;padding:14px 28px;background:#00FFD1;color:#03050A;font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;letter-spacing:2px;border:none;cursor:pointer;z-index:100; }
  .print-btn:hover { opacity:0.9; }
  .footer { text-align:center;padding:40px;font-size:11px;color:#4A6080;border-top:1px solid #112240;margin-top:40px; }
</style>
</head>
<body>
<button class="print-btn no-print" onclick="window.print()">PRINT / SAVE PDF</button>

<div class="report-container">
  <!-- HEADER -->
  <div class="report-header">
    <div class="report-logo">PALISADE<span>ONE</span></div>
    <div class="report-title">MONTHLY SECURITY REPORT</div>
    <div class="report-meta">${monthName.toUpperCase()} &bull; ${client.toUpperCase()}</div>
    <div style="font-size:11px;color:#4A6080;margin-top:8px;position:relative;">Generated ${generatedDate}</div>
  </div>

  <!-- EXECUTIVE SUMMARY -->
  <div class="report-section">
    <div class="section-head">EXECUTIVE SUMMARY</div>
    <div style="display:grid;grid-template-columns:auto 1fr;gap:40px;align-items:center;">
      <div style="text-align:center;">
        <svg width="120" height="120" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="54" fill="none" stroke="#112240" stroke-width="8"/>
          <circle cx="60" cy="60" r="54" fill="none" stroke="${healthScore >= 80 ? '#00FFD1' : healthScore >= 60 ? '#F5A623' : '#FF3B5C'}" stroke-width="8" stroke-dasharray="${(healthScore / 100) * 339} 339" stroke-linecap="round" transform="rotate(-90 60 60)"/>
        </svg>
        <div style="font-family:'Bebas Neue',sans-serif;font-size:36px;color:#00FFD1;margin-top:-78px;position:relative;">${Math.round(healthScore)}</div>
        <div style="font-size:10px;color:#4A6080;letter-spacing:2px;margin-top:42px;">HEALTH SCORE</div>
      </div>
      <div>
        <p style="font-size:14px;line-height:1.8;margin-bottom:16px;">During ${monthName}, your environment generated <strong style="color:#F0F6FF;">${totalAlerts.toLocaleString()}</strong> security events across <strong style="color:#F0F6FF;">${agents.length}</strong> monitored endpoints. ${critical > 0 ? `<span style="color:#FF3B5C;font-weight:600;">${critical} critical alerts</span> were detected and addressed.` : 'No critical-severity alerts were detected.'}</p>
        <p style="font-size:13px;color:#4A6080;line-height:1.7;">${healthScore >= 80 ? 'Your security posture is strong. Continue maintaining current controls and monitoring for emerging threats.' : healthScore >= 60 ? 'Your security posture needs attention. Review the recommendations below to address identified gaps.' : 'Your security posture requires immediate attention. Critical findings should be remediated as soon as possible.'}</p>
      </div>
    </div>
  </div>

  <!-- ALERT OVERVIEW -->
  <div class="report-section">
    <div class="section-head">ALERT OVERVIEW</div>
    <div class="stats-row">
      <div class="stat-card"><div class="stat-value" style="color:#FF3B5C;">${critical}</div><div class="stat-name">Critical</div></div>
      <div class="stat-card"><div class="stat-value" style="color:#F5A623;">${high}</div><div class="stat-name">High</div></div>
      <div class="stat-card"><div class="stat-value" style="color:#0084FF;">${medium}</div><div class="stat-name">Medium</div></div>
      <div class="stat-card"><div class="stat-value" style="color:#4A6080;">${low}</div><div class="stat-name">Low</div></div>
    </div>

    <!-- Daily Alert Timeline -->
    <div class="section-label-sm">// DAILY ALERT VOLUME</div>
    <div style="display:flex;gap:2px;align-items:flex-end;height:140px;padding-top:20px;">
      ${timelineBars}
    </div>
  </div>

  <!-- TOP DETECTION RULES -->
  <div class="report-section page-break">
    <div class="section-head">TOP DETECTION RULES</div>
    <table>
      <thead><tr><th>#</th><th>Rule Description</th><th style="text-align:right;">Count</th></tr></thead>
      <tbody>${ruleRows}</tbody>
    </table>
  </div>

  <!-- ENDPOINT BREAKDOWN -->
  <div class="report-section">
    <div class="section-head">ENDPOINT ALERT DISTRIBUTION</div>
    <table>
      <thead><tr><th>Agent / Endpoint</th><th style="text-align:right;">Alerts</th></tr></thead>
      <tbody>${agentRows}</tbody>
    </table>
  </div>

  <!-- MITRE ATT&CK -->
  ${mitreTags ? `<div class="report-section">
    <div class="section-head">MITRE ATT&CK TECHNIQUES OBSERVED</div>
    <div style="margin-top:8px;">${mitreTags}</div>
  </div>` : ''}

  <!-- COMPLIANCE STATUS -->
  ${scaRows ? `<div class="report-section page-break">
    <div class="section-head">COMPLIANCE STATUS (SCA)</div>
    <div class="section-label-sm">// SECURITY CONFIGURATION ASSESSMENT</div>
    ${scaRows}
  </div>` : ''}

  <!-- RECOMMENDATIONS -->
  <div class="report-section">
    <div class="section-head">RECOMMENDATIONS</div>
    <div style="display:flex;flex-direction:column;gap:16px;">
      ${critical > 0 ? `<div style="padding:16px;background:rgba(255,59,92,0.08);border-left:3px solid #FF3B5C;">
        <div style="font-size:13px;color:#FF3B5C;font-weight:600;margin-bottom:4px;">Address Critical Alerts</div>
        <p style="font-size:12px;color:#4A6080;">${critical} critical alerts were detected this month. Review each incident and ensure all remediation steps have been completed.</p>
      </div>` : ''}
      ${high > 10 ? `<div style="padding:16px;background:rgba(245,166,35,0.08);border-left:3px solid #F5A623;">
        <div style="font-size:13px;color:#F5A623;font-weight:600;margin-bottom:4px;">Reduce High-Severity Alert Volume</div>
        <p style="font-size:12px;color:#4A6080;">${high} high-severity alerts suggest potential tuning opportunities or unaddressed vulnerabilities. Review top rules for patterns.</p>
      </div>` : ''}
      <div style="padding:16px;background:rgba(0,255,209,0.05);border-left:3px solid #00FFD1;">
        <div style="font-size:13px;color:#00FFD1;font-weight:600;margin-bottom:4px;">Maintain Endpoint Coverage</div>
        <p style="font-size:12px;color:#4A6080;">${agents.length} endpoints are currently reporting. Ensure all company devices have the Wazuh agent installed and reporting.</p>
      </div>
      <div style="padding:16px;background:rgba(0,132,255,0.05);border-left:3px solid #0084FF;">
        <div style="font-size:13px;color:#0084FF;font-weight:600;margin-bottom:4px;">Review Compliance Posture</div>
        <p style="font-size:12px;color:#4A6080;">Review SCA compliance results above and prioritize remediation of failed checks to improve your overall security posture.</p>
      </div>
    </div>
  </div>

  <!-- FOOTER -->
  <div class="footer">
    <div style="font-family:'Bebas Neue',sans-serif;font-size:18px;color:#4A6080;letter-spacing:4px;margin-bottom:8px;">PALISADE<span style="color:#00FFD1;">ONE</span></div>
    <div>This report is confidential and intended for ${client} only.</div>
    <div style="margin-top:4px;">contactus@palisadeone.com &bull; palisadeone.com</div>
  </div>
</div>
</body>
</html>`;
  }
*/

// ============================================================
// CLIENT-SIDE REPORT GENERATION (No server required)
// This version generates reports entirely in the browser
// using data already fetched from the Wazuh proxy
// ============================================================

function generateSecurityReport(alertData, options = {}) {
  const {
    client = 'All Clients',
    month = new Date().toISOString().slice(0, 7),
    scaPolicies = [],
    agentCount = 0
  } = options;

  const [year, mon] = month.split('-');
  const monthName = new Date(parseInt(year), parseInt(mon) - 1).toLocaleString('en-US', { month: 'long', year: 'numeric' });
  const generatedDate = new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  // Process alert data
  let critical = 0, high = 0, medium = 0, low = 0;
  const ruleCounts = {};
  const agentCounts = {};
  const mitreCounts = {};
  const dailyCounts = {};

  (alertData || []).forEach(hit => {
    const src = hit._source || hit;
    const level = src.rule?.level || 0;
    if (level >= 12) critical++;
    else if (level >= 7) high++;
    else if (level >= 4) medium++;
    else low++;

    const ruleDesc = src.rule?.description || 'Unknown';
    ruleCounts[ruleDesc] = (ruleCounts[ruleDesc] || 0) + 1;

    const agentName = src.agent?.name || 'Unknown';
    agentCounts[agentName] = (agentCounts[agentName] || 0) + 1;

    (src.rule?.mitre?.technique || []).forEach(t => {
      mitreCounts[t] = (mitreCounts[t] || 0) + 1;
    });

    const day = (src.timestamp || '').slice(0, 10);
    if (day) dailyCounts[day] = (dailyCounts[day] || 0) + 1;
  });

  const totalAlerts = (alertData || []).length;
  const healthScore = Math.max(0, Math.min(100, 100 - (critical * 5) - (high * 2) - (medium * 0.5)));

  // Sort and slice
  const topRules = Object.entries(ruleCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const topAgents = Object.entries(agentCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
  const topMitre = Object.entries(mitreCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const days = Object.entries(dailyCounts).sort((a, b) => a[0].localeCompare(b[0]));
  const maxDay = Math.max(...days.map(d => d[1]), 1);

  const timelineBars = days.map(([date, count]) => {
    const dayNum = parseInt(date.slice(-2));
    const pct = Math.round((count / maxDay) * 100);
    return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;">
      <div style="width:100%;background:rgba(0,255,209,0.15);height:120px;position:relative;">
        <div style="position:absolute;bottom:0;width:100%;height:${pct}%;background:linear-gradient(to top,#00FFD1,#0084FF);"></div>
      </div>
      <span style="font-size:8px;color:#4A6080;">${dayNum}</span>
    </div>`;
  }).join('');

  const ruleRows = topRules.map(([desc, count], i) =>
    `<tr><td style="padding:8px 12px;border-bottom:1px solid #112240;color:#C8D8F0;font-size:12px;">${i + 1}</td>
     <td style="padding:8px 12px;border-bottom:1px solid #112240;color:#C8D8F0;font-size:12px;">${desc}</td>
     <td style="padding:8px 12px;border-bottom:1px solid #112240;color:#00FFD1;font-size:12px;text-align:right;">${count}</td></tr>`
  ).join('');

  const agentRows = topAgents.map(([name, count]) =>
    `<tr><td style="padding:8px 12px;border-bottom:1px solid #112240;color:#C8D8F0;font-size:12px;">${name}</td>
     <td style="padding:8px 12px;border-bottom:1px solid #112240;color:#00FFD1;font-size:12px;text-align:right;">${count}</td></tr>`
  ).join('');

  const mitreTags = topMitre.map(([tech, count]) =>
    `<span style="display:inline-block;padding:4px 10px;margin:3px;background:rgba(0,132,255,0.1);border:1px solid rgba(0,132,255,0.2);color:#0084FF;font-size:10px;letter-spacing:1px;">${tech} (${count})</span>`
  ).join('');

  const scaRows = (scaPolicies || []).map(p => {
    const pass = p.pass || 0;
    const fail = p.fail || 0;
    const total = pass + fail || 1;
    const pct = Math.round((pass / total) * 100);
    return `<div style="margin-bottom:16px;">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
        <span style="font-size:12px;color:#C8D8F0;">${p.name || p.key || 'Policy'}</span>
        <span style="font-size:12px;color:#00FFD1;">${pct}%</span>
      </div>
      <div style="height:6px;background:#112240;border-radius:3px;overflow:hidden;">
        <div style="height:100%;width:${pct}%;background:${pct >= 80 ? '#00FFD1' : pct >= 60 ? '#F5A623' : '#FF3B5C'};border-radius:3px;"></div>
      </div>
      <div style="font-size:10px;color:#4A6080;margin-top:2px;">${pass} passed / ${fail} failed</div>
    </div>`;
  }).join('');

  const endpointCount = agentCount || Object.keys(agentCounts).length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Security Report - ${monthName} - ${client}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=JetBrains+Mono:wght@400;500&family=Outfit:wght@300;400;500;600&display=swap');
  *{margin:0;padding:0;box-sizing:border-box;}
  body{background:#03050A;color:#C8D8F0;font-family:'Outfit',sans-serif;line-height:1.6;}
  @media print{
    body{background:#fff;color:#1a1a1a;-webkit-print-color-adjust:exact;print-color-adjust:exact;}
    .no-print{display:none!important;}
    .page-break{page-break-before:always;}
  }
  .rc{max-width:900px;margin:0 auto;padding:40px;}
  .rh{text-align:center;padding:60px 40px;border:1px solid #112240;margin-bottom:40px;position:relative;overflow:hidden;}
  .rh::before{content:'';position:absolute;inset:0;background:radial-gradient(ellipse 60% 60% at 50% 40%,rgba(0,255,209,0.05) 0%,transparent 60%);}
  .rh *{position:relative;}
  .rs{border:1px solid #112240;padding:32px;margin-bottom:24px;}
  .sh{font-family:'Bebas Neue',sans-serif;font-size:24px;color:#F0F6FF;letter-spacing:2px;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid #112240;}
  .sl{font-family:'JetBrains Mono',monospace;font-size:10px;color:#00FFD1;letter-spacing:3px;margin-bottom:12px;}
  .sr{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;}
  .sc{background:#070C14;border:1px solid #112240;padding:20px;text-align:center;}
  .sv{font-family:'Bebas Neue',sans-serif;font-size:36px;letter-spacing:2px;line-height:1;}
  .sn{font-size:10px;color:#4A6080;letter-spacing:2px;text-transform:uppercase;margin-top:6px;}
  table{width:100%;border-collapse:collapse;}
  th{padding:8px 12px;text-align:left;font-family:'JetBrains Mono',monospace;font-size:10px;color:#4A6080;letter-spacing:2px;border-bottom:2px solid #112240;}
  .pb{position:fixed;bottom:24px;right:24px;padding:14px 28px;background:#00FFD1;color:#03050A;font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;letter-spacing:2px;border:none;cursor:pointer;z-index:100;}
  .pb:hover{opacity:0.9;}
  .ft{text-align:center;padding:40px;font-size:11px;color:#4A6080;border-top:1px solid #112240;margin-top:40px;}
</style>
</head>
<body>
<button class="pb no-print" onclick="window.print()">PRINT / SAVE PDF</button>
<div class="rc">
  <div class="rh">
    <div style="font-family:'Bebas Neue',sans-serif;font-size:36px;color:#00FFD1;letter-spacing:6px;">PALISADE<span style="color:#0084FF;">ONE</span></div>
    <div style="font-family:'Bebas Neue',sans-serif;font-size:42px;color:#F0F6FF;letter-spacing:3px;margin-top:16px;">MONTHLY SECURITY REPORT</div>
    <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#4A6080;letter-spacing:2px;margin-top:12px;">${monthName.toUpperCase()} &bull; ${client.toUpperCase()}</div>
    <div style="font-size:11px;color:#4A6080;margin-top:8px;">Generated ${generatedDate}</div>
  </div>

  <div class="rs">
    <div class="sh">EXECUTIVE SUMMARY</div>
    <div style="display:grid;grid-template-columns:auto 1fr;gap:40px;align-items:center;">
      <div style="text-align:center;">
        <svg width="120" height="120" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="54" fill="none" stroke="#112240" stroke-width="8"/>
          <circle cx="60" cy="60" r="54" fill="none" stroke="${healthScore >= 80 ? '#00FFD1' : healthScore >= 60 ? '#F5A623' : '#FF3B5C'}" stroke-width="8" stroke-dasharray="${(healthScore / 100) * 339} 339" stroke-linecap="round" transform="rotate(-90 60 60)"/>
        </svg>
        <div style="font-family:'Bebas Neue',sans-serif;font-size:36px;color:#00FFD1;margin-top:-78px;position:relative;">${Math.round(healthScore)}</div>
        <div style="font-size:10px;color:#4A6080;letter-spacing:2px;margin-top:42px;">HEALTH SCORE</div>
      </div>
      <div>
        <p style="font-size:14px;line-height:1.8;margin-bottom:16px;">During ${monthName}, your environment generated <strong style="color:#F0F6FF;">${totalAlerts.toLocaleString()}</strong> security events across <strong style="color:#F0F6FF;">${endpointCount}</strong> monitored endpoints. ${critical > 0 ? `<span style="color:#FF3B5C;font-weight:600;">${critical} critical alerts</span> were detected and addressed.` : 'No critical-severity alerts were detected.'}</p>
        <p style="font-size:13px;color:#4A6080;line-height:1.7;">${healthScore >= 80 ? 'Your security posture is strong. Continue maintaining current controls and monitoring for emerging threats.' : healthScore >= 60 ? 'Your security posture needs attention. Review the recommendations below to address identified gaps.' : 'Your security posture requires immediate attention. Critical findings should be remediated as soon as possible.'}</p>
      </div>
    </div>
  </div>

  <div class="rs">
    <div class="sh">ALERT OVERVIEW</div>
    <div class="sr">
      <div class="sc"><div class="sv" style="color:#FF3B5C;">${critical}</div><div class="sn">Critical</div></div>
      <div class="sc"><div class="sv" style="color:#F5A623;">${high}</div><div class="sn">High</div></div>
      <div class="sc"><div class="sv" style="color:#0084FF;">${medium}</div><div class="sn">Medium</div></div>
      <div class="sc"><div class="sv" style="color:#4A6080;">${low}</div><div class="sn">Low</div></div>
    </div>
    <div class="sl">// DAILY ALERT VOLUME</div>
    <div style="display:flex;gap:2px;align-items:flex-end;height:140px;padding-top:20px;">${timelineBars}</div>
  </div>

  <div class="rs page-break">
    <div class="sh">TOP DETECTION RULES</div>
    <table><thead><tr><th>#</th><th>Rule Description</th><th style="text-align:right;">Count</th></tr></thead><tbody>${ruleRows}</tbody></table>
  </div>

  <div class="rs">
    <div class="sh">ENDPOINT ALERT DISTRIBUTION</div>
    <table><thead><tr><th>Agent / Endpoint</th><th style="text-align:right;">Alerts</th></tr></thead><tbody>${agentRows}</tbody></table>
  </div>

  ${mitreTags ? `<div class="rs"><div class="sh">MITRE ATT&CK TECHNIQUES</div><div style="margin-top:8px;">${mitreTags}</div></div>` : ''}

  ${scaRows ? `<div class="rs page-break"><div class="sh">COMPLIANCE STATUS (SCA)</div><div class="sl">// SECURITY CONFIGURATION ASSESSMENT</div>${scaRows}</div>` : ''}

  <div class="rs">
    <div class="sh">RECOMMENDATIONS</div>
    <div style="display:flex;flex-direction:column;gap:16px;">
      ${critical > 0 ? `<div style="padding:16px;background:rgba(255,59,92,0.08);border-left:3px solid #FF3B5C;">
        <div style="font-size:13px;color:#FF3B5C;font-weight:600;margin-bottom:4px;">Address Critical Alerts</div>
        <p style="font-size:12px;color:#4A6080;">${critical} critical alerts were detected. Review each incident and ensure all remediation steps have been completed.</p>
      </div>` : ''}
      ${high > 10 ? `<div style="padding:16px;background:rgba(245,166,35,0.08);border-left:3px solid #F5A623;">
        <div style="font-size:13px;color:#F5A623;font-weight:600;margin-bottom:4px;">Reduce High-Severity Volume</div>
        <p style="font-size:12px;color:#4A6080;">${high} high-severity alerts may indicate tuning opportunities or unaddressed vulnerabilities.</p>
      </div>` : ''}
      <div style="padding:16px;background:rgba(0,255,209,0.05);border-left:3px solid #00FFD1;">
        <div style="font-size:13px;color:#00FFD1;font-weight:600;margin-bottom:4px;">Maintain Endpoint Coverage</div>
        <p style="font-size:12px;color:#4A6080;">${endpointCount} endpoints currently reporting. Ensure all company devices have agents installed.</p>
      </div>
      <div style="padding:16px;background:rgba(0,132,255,0.05);border-left:3px solid #0084FF;">
        <div style="font-size:13px;color:#0084FF;font-weight:600;margin-bottom:4px;">Review Compliance Posture</div>
        <p style="font-size:12px;color:#4A6080;">Review SCA results and prioritize remediation of failed checks to strengthen your security posture.</p>
      </div>
    </div>
  </div>

  <div class="ft">
    <div style="font-family:'Bebas Neue',sans-serif;font-size:18px;color:#4A6080;letter-spacing:4px;margin-bottom:8px;">PALISADE<span style="color:#00FFD1;">ONE</span></div>
    <div>This report is confidential and intended for ${client} only.</div>
    <div style="margin-top:4px;">contactus@palisadeone.com &bull; palisadeone.com</div>
  </div>
</div>
</body>
</html>`;
}

// Make available globally
if (typeof window !== 'undefined') {
  window.generateSecurityReport = generateSecurityReport;
}
if (typeof module !== 'undefined') {
  module.exports = { generateSecurityReport };
}
