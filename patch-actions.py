import sys
sys.stdout.reconfigure(encoding='utf-8')

path = r'C:\Users\camat\Documents\PALISADEONE\dashboard.html'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

# Replace lines 7007-7097 (the 4 stub functions) with real implementations
# Use unique anchors to find the replacement zone
START = '// ── ENDPOINT ACTIONS ──────────────────────────────────────────\nasync function killSuspiciousProcesses()'
END = "} catch(e) { showToast('Policy push failed — check agent status.', 'error'); }\n}"

start_idx = content.find(START)
end_idx = content.find(END, start_idx) + len(END)

if start_idx == -1:
    print("ERROR: Could not find START anchor")
    sys.exit(1)
if end_idx == -1:
    print("ERROR: Could not find END anchor")
    sys.exit(1)

new_code = r"""// ── ENDPOINT ACTIONS ──────────────────────────────────────────

async function killSuspiciousProcesses() {
  if (!activeAgentId) { showToast('No endpoint selected.', 'warn'); return; }
  const agentName = agentsData[activeAgentId]?.name || activeAgentId;
  const modal = document.createElement('div');
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.82);z-index:700;display:flex;align-items:center;justify-content:center;';
  modal.innerHTML = `
    <div style="background:var(--deep);border:1px solid var(--border2);width:680px;max-width:96vw;max-height:88vh;overflow:hidden;display:flex;flex-direction:column;">
      <div style="padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;">
        <div>
          <div style="font-family:'Bebas Neue',sans-serif;font-size:17px;letter-spacing:2px;color:var(--danger);">KILL PROCESS — ${escH(agentName)}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:2px;">Select a process to terminate. Suspicious processes flagged in red.</div>
        </div>
        <button onclick="this.closest('div[style*=fixed]').remove()" style="background:transparent;border:1px solid var(--border);color:var(--muted);width:28px;height:28px;cursor:pointer;">✕</button>
      </div>
      <div style="padding:10px 20px;border-bottom:1px solid var(--border);flex-shrink:0;">
        <input id="kp-filter" placeholder="Filter by process name..." oninput="filterKpList()" style="width:100%;padding:7px 10px;background:var(--surface);border:1px solid var(--border2);color:var(--text);font-size:12px;font-family:'Outfit',sans-serif;box-sizing:border-box;">
      </div>
      <div id="kp-list" style="flex:1;overflow-y:auto;padding:8px 20px;">
        <div style="color:var(--muted);font-size:12px;padding:20px 0;text-align:center;">Loading processes...</div>
      </div>
    </div>`;
  document.body.appendChild(modal);
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  window._kpAgentId = activeAgentId;
  try {
    const r = await fetch(`${PROXY_URL}/syscollector/${activeAgentId}/processes?limit=200&sort=name`);
    const d = await r.json();
    window._kpProcs = d.data?.affected_items || [];
    renderKpList(window._kpProcs);
  } catch(e) {
    document.getElementById('kp-list').innerHTML = `<div style="color:var(--danger);font-size:12px;padding:16px 0;">Failed to load: ${escH(e.message)}</div>`;
  }
}

function renderKpList(procs) {
  const el = document.getElementById('kp-list');
  if (!el) return;
  if (!procs.length) { el.innerHTML = '<div style="color:var(--muted);font-size:12px;padding:16px 0;text-align:center;">No processes found.</div>'; return; }
  const flagged = ['mimikatz','meterpreter','cobalt','beacon','empire','psexec','procdump','wce.exe','fgdump','pwdump','netcat','nc.exe','lazagne','sharphound','rubeus'];
  el.innerHTML = `<div style="display:grid;grid-template-columns:1fr 70px 110px 60px;gap:0;padding:4px 0 6px;border-bottom:1px solid var(--border);font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--muted);letter-spacing:1px;">
    <span>PROCESS</span><span>PID</span><span>USER</span><span></span></div>` +
  procs.map(p => {
    const plow = (p.name||'').toLowerCase();
    const isSusp = flagged.some(f => plow.includes(f));
    return `<div style="display:grid;grid-template-columns:1fr 70px 110px 60px;align-items:center;padding:4px 0;border-bottom:1px solid var(--border);">
      <span style="color:${isSusp?'var(--danger)':'var(--text)'};font-family:'JetBrains Mono',monospace;font-size:11px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escH(p.name||'')}">${isSusp?'⚠ ':''}${escH(p.name||'?')}</span>
      <span style="color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:10px;">${p.pid||'?'}</span>
      <span style="color:var(--muted);font-family:'JetBrains Mono',monospace;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escH(p.euser||p.ruser||'—')}</span>
      <button onclick="confirmKillProc('${escH(String(p.name||'')).replace(/'/g,String.fromCharCode(92)+String.fromCharCode(39))}',${p.pid||0})"
        style="padding:2px 8px;background:transparent;border:1px solid rgba(255,68,102,0.4);color:var(--danger);font-size:9px;cursor:pointer;font-family:'JetBrains Mono',monospace;">KILL</button>
    </div>`;
  }).join('');
}

function filterKpList() {
  const q = (document.getElementById('kp-filter')?.value||'').toLowerCase();
  renderKpList((window._kpProcs||[]).filter(p=>(p.name||'').toLowerCase().includes(q)));
}

async function confirmKillProc(procName, pid) {
  const agentId = window._kpAgentId || activeAgentId;
  const agentName = agentsData[agentId]?.name || agentId;
  if (!confirm(`Kill "${procName}" (PID ${pid}) on ${agentName}?\n\nThis terminates the process immediately.`)) return;
  try {
    await fetch(`${PROXY_URL}/active-response?agents_list=${agentId}`, {
      method: 'PUT', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ command: 'kill-process', arguments: [procName] })
    });
    showToast(`Kill command sent for "${procName}". Note: requires kill-process AR script — re-run installer to enable.`, 'success');
    document.querySelector('div[style*="z-index:700"]')?.remove();
  } catch(e) { showToast('Kill command failed: ' + e.message, 'error'); }
}

async function collectEvidence() {
  if (!activeAgentId) { showToast('No endpoint selected.', 'warn'); return; }
  const agentName = agentsData[activeAgentId]?.name || activeAgentId;
  showToast('Building evidence package...', 'info');
  const [alertsRes, osRes, pkgRes, procRes, portRes, hwRes] = await Promise.allSettled([
    fetch(`${PROXY_URL}/wazuh-alerts-4.x-*/_search`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ size:200, sort:[{timestamp:{order:'desc'}}],
        query:{bool:{filter:[{term:{'agent.id':activeAgentId}},{range:{timestamp:{gte:'now-7d'}}}]}} })
    }).then(r=>r.json()),
    fetch(`${PROXY_URL}/syscollector/${activeAgentId}/os`).then(r=>r.json()),
    fetch(`${PROXY_URL}/syscollector/${activeAgentId}/packages?limit=500`).then(r=>r.json()),
    fetch(`${PROXY_URL}/syscollector/${activeAgentId}/processes?limit=300`).then(r=>r.json()),
    fetch(`${PROXY_URL}/syscollector/${activeAgentId}/ports?limit=200`).then(r=>r.json()),
    fetch(`${PROXY_URL}/syscollector/${activeAgentId}/hardware`).then(r=>r.json()),
  ]);
  const agent = agentsData[activeAgentId]||{};
  const alerts = alertsRes.value?.hits?.hits?.map(h=>h._source)||[];
  const report = {
    collected_at: new Date().toISOString(),
    collected_by: JSON.parse(sessionStorage.getItem('p1_user')||'{}').email||'admin',
    agent: {id:activeAgentId, name:agent.name, ip:agent.ip, status:agent.status, version:agent.version},
    summary: { alerts:alerts.length, critical:alerts.filter(a=>a.rule?.level>=12).length, high:alerts.filter(a=>a.rule?.level>=7&&a.rule?.level<12).length, medium:alerts.filter(a=>a.rule?.level>=4&&a.rule?.level<7).length },
    hardware: hwRes.value?.data?.affected_items?.[0]||null,
    os: osRes.value?.data?.affected_items?.[0]||null,
    running_processes: procRes.value?.data?.affected_items||[],
    open_ports: portRes.value?.data?.affected_items||[],
    installed_packages: pkgRes.value?.data?.affected_items||[],
    alerts_last_7d: alerts,
  };
  const blob = new Blob([JSON.stringify(report,null,2)],{type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href=url; a.download=`evidence-${agentName.replace(/[^a-z0-9]/gi,'-')}-${new Date().toISOString().slice(0,10)}.json`;
  a.click(); URL.revokeObjectURL(url);
  showToast(`Downloaded — ${report.summary.alerts} alerts, ${report.running_processes.length} processes, ${report.open_ports.length} ports.`, 'success');
}

async function runLiveQuery() {
  if (!activeAgentId) { showToast('No endpoint selected.', 'warn'); return; }
  const agentName = agentsData[activeAgentId]?.name || activeAgentId;
  const queries = [
    { label:'Running Processes', url:`/syscollector/${activeAgentId}/processes?limit=200&sort=name`, cols:['name','pid','euser','state'], heads:['Process','PID','User','State'] },
    { label:'Open Ports', url:`/syscollector/${activeAgentId}/ports?limit=100`, cols:['protocol','local_port','local_ip','remote_ip','state'], heads:['Proto','Port','Local IP','Remote IP','State'] },
    { label:'Installed Packages', url:`/syscollector/${activeAgentId}/packages?limit=300&sort=-install_time`, cols:['name','version','vendor','architecture'], heads:['Package','Version','Vendor','Arch'] },
    { label:'Network Interfaces', url:`/syscollector/${activeAgentId}/netiface`, cols:['name','mac','type','state','mtu'], heads:['Interface','MAC','Type','State','MTU'] },
    { label:'OS Info', url:`/syscollector/${activeAgentId}/os`, cols:['os_name','os_version','hostname','architecture','release'], heads:['OS','Version','Hostname','Arch','Release'] },
    { label:'Hardware', url:`/syscollector/${activeAgentId}/hardware`, cols:['cpu_name','cpu_cores','ram_total','ram_free'], heads:['CPU','Cores','RAM Total','RAM Free'] },
  ];
  window._lqQueries = queries;
  const modal = document.createElement('div');
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.82);z-index:700;display:flex;align-items:center;justify-content:center;';
  modal.innerHTML = `
    <div style="background:var(--deep);border:1px solid var(--border2);width:800px;max-width:96vw;max-height:90vh;overflow:hidden;display:flex;flex-direction:column;">
      <div style="padding:14px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-shrink:0;">
        <div>
          <div style="font-family:'Bebas Neue',sans-serif;font-size:17px;letter-spacing:2px;color:var(--accent2);">LIVE QUERY — ${escH(agentName)}</div>
          <div style="font-size:11px;color:var(--muted);margin-top:2px;">Real-time data from Wazuh syscollector</div>
        </div>
        <button onclick="this.closest('div[style*=fixed]').remove()" style="background:transparent;border:1px solid var(--border);color:var(--muted);width:28px;height:28px;cursor:pointer;">✕</button>
      </div>
      <div style="padding:10px 20px;border-bottom:1px solid var(--border);display:flex;gap:6px;flex-wrap:wrap;flex-shrink:0;">
        ${queries.map((q,i)=>`<button id="lq-tab-${i}" onclick="runLiveQueryFetch(${i})"
          style="padding:5px 12px;background:transparent;border:1px solid var(--border2);color:var(--text);font-size:11px;cursor:pointer;font-family:'Outfit',sans-serif;">${q.label}</button>`).join('')}
      </div>
      <div id="lq-result" style="flex:1;overflow:auto;padding:12px 20px;">
        <div style="color:var(--muted);font-size:12px;">Loading...</div>
      </div>
    </div>`;
  document.body.appendChild(modal);
  modal.addEventListener('click', e => { if (e.target === modal) modal.remove(); });
  runLiveQueryFetch(0);
}

async function runLiveQueryFetch(idx) {
  const q = (window._lqQueries||[])[idx];
  const el = document.getElementById('lq-result');
  if (!el || !q) return;
  (window._lqQueries||[]).forEach((_,i) => {
    const t = document.getElementById('lq-tab-'+i);
    if (!t) return;
    t.style.background = i===idx ? 'rgba(0,132,255,0.15)' : 'transparent';
    t.style.borderColor = i===idx ? 'var(--accent2)' : 'var(--border2)';
    t.style.color = i===idx ? 'var(--accent2)' : 'var(--text)';
  });
  el.innerHTML = '<div style="color:var(--muted);font-size:12px;">Querying agent...</div>';
  try {
    const r = await fetch(`${PROXY_URL}${q.url}`);
    const d = await r.json();
    const items = d.data?.affected_items||(d.data?[d.data]:[]);
    if (!items.length) { el.innerHTML = '<div style="color:var(--muted);font-size:12px;">No data returned.</div>'; return; }
    el.innerHTML = `<div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--muted);margin-bottom:8px;">${items.length} result${items.length!==1?'s':''}</div>
      <div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;">
        <thead><tr>${q.heads.map(h=>`<th style="text-align:left;padding:5px 8px;border-bottom:1px solid var(--border);font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--muted);letter-spacing:1px;white-space:nowrap;">${h}</th>`).join('')}</tr></thead>
        <tbody>${items.map((item,ri)=>`<tr style="border-bottom:1px solid var(--border);${ri%2?'background:rgba(255,255,255,0.02)':''}">
          ${q.cols.map(col=>{
            let val=col.split('.').reduce((o,k)=>o?.[k],item);
            if(col.includes('ram')&&typeof val==='number') val=Math.round(val/1024)+' MB';
            if(col==='install_time'&&typeof val==='number') val=new Date(val*1000).toLocaleDateString();
            return `<td style="padding:4px 8px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:11px;white-space:nowrap;max-width:180px;overflow:hidden;text-overflow:ellipsis;" title="${escH(String(val??''))}">${escH(String(val??'—'))}</td>`;
          }).join('')}
        </tr>`).join('')}</tbody>
      </table></div>`;
  } catch(e) { el.innerHTML = `<div style="color:var(--danger);font-size:12px;">Query failed: ${escH(e.message)}</div>`; }
}

async function pushPolicyUpdate() {
  if (!activeAgentId) { showToast('No endpoint selected.', 'warn'); return; }
  const name = agentsData[activeAgentId]?.name || activeAgentId;
  showToast(`Syncing agent config on ${name}...`, 'info');
  try {
    const [restartRes, syschecksRes] = await Promise.allSettled([
      fetch(`${PROXY_URL}/agents/${activeAgentId}/restart`, { method: 'PUT', headers: {'Content-Type':'application/json'} }),
      fetch(`${PROXY_URL}/syscheck?agents_list=${activeAgentId}`, { method: 'PUT', headers: {'Content-Type':'application/json'} }),
    ]);
    const ok = restartRes.status === 'fulfilled' && restartRes.value?.ok;
    showToast(ok
      ? `Agent config synced on ${name} — Wazuh service restarting, syscheck scan queued.`
      : `Sync attempted on ${name} — verify agent is online.`, ok ? 'success' : 'warn');
  } catch(e) { showToast('Policy sync failed: ' + e.message, 'error'); }
}"""

content = content[:start_idx] + new_code + content[end_idx:]

with open(path, 'w', encoding='utf-8') as f:
    f.write(content)

print("Done. File updated.")
