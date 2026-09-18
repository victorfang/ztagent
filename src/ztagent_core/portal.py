# ZTAgent.ai : Zero Trust Security for AI Agents
# Author: VictorFang.com

"""Dependency-free administration portal."""

ADMIN_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ZTAgent · Admin</title>
  <style>
    :root { color-scheme: dark; --bg:#0b1020; --card:#141b2d; --muted:#9ca8bf;
      --accent:#66e3c4; --danger:#ff718b; --line:#28334b; }
    * { box-sizing:border-box } body { margin:0; font:14px system-ui,sans-serif;
      background:var(--bg); color:#edf3ff } main { max-width:1100px; margin:auto; padding:28px }
    header { display:flex; justify-content:space-between; gap:20px; align-items:center }
    h1 { font-size:22px; margin:0 } p { color:var(--muted) }
    input,button { border:1px solid var(--line); border-radius:7px; padding:9px 11px;
      background:#0f1628; color:inherit } input { width:300px } button { cursor:pointer }
    button:hover { border-color:var(--accent) } .grid { display:grid;
      grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin:24px 0 }
    .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px }
    .value { font-size:24px; font-weight:700; margin-top:7px } .ok { color:var(--accent) }
    .bad { color:var(--danger) } table { width:100%; border-collapse:collapse }
    th,td { text-align:left; border-bottom:1px solid var(--line); padding:10px 7px;
      max-width:440px; overflow-wrap:anywhere } th { color:var(--muted); font-weight:500 }
    code { color:#c6d5f7 } .error { color:var(--danger) }
    footer { margin-top:22px; color:var(--muted) } footer a { color:var(--accent) }
    @media(max-width:650px) { header { align-items:flex-start; flex-direction:column }
      input { width:100% } main { padding:18px } }
  </style>
</head>
<body><main>
  <header><div><h1>ZTAgent</h1><p>Zero Trust Security for AI Agents</p></div>
    <form id="auth"><input id="token" type="password" autocomplete="off"
      placeholder="Admin bearer token" aria-label="Admin bearer token">
      <button>Connect</button></form></header>
  <div id="message"><p>Enter a token with the configured administrator role.</p></div>
  <section class="grid" id="summary"></section>
  <section class="card"><h2>Recent security events</h2>
    <div style="overflow:auto"><table><thead><tr><th>Time</th><th>Type</th><th>Outcome</th>
      <th>Identity</th><th>Details</th></tr></thead><tbody id="events"></tbody></table></div>
  </section>
  <footer><a href="https://ztagent.ai" target="_blank" rel="noopener">ztagent.ai</a>
    · by <a href="https://VictorFang.com" target="_blank" rel="noopener">Victor Fang</a>
    · <a href="https://X.com/vicfcs" target="_blank" rel="noopener">X</a>
    · <a href="https://www.linkedin.com/in/drvictorfang" target="_blank"
      rel="noopener">LinkedIn</a></footer>
</main><script>
const auth = () => ({Authorization: `Bearer ${sessionStorage.getItem("ztagent-token") || ""}`});
const esc = value => String(value ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function load() {
  const [summaryResponse, eventsResponse] = await Promise.all([
    fetch("/admin/api/summary", {headers:auth()}), fetch("/admin/api/events", {headers:auth()})
  ]);
  if (!summaryResponse.ok) throw new Error(`Access denied (${summaryResponse.status})`);
  const summary = await summaryResponse.json(), events = await eventsResponse.json();
  const values = [
    ["Events", summary.events], ["Blocked", summary.blocked_events],
    ["Contained identities", summary.contained_identities],
    ["Audit chain", summary.audit_chain_valid ? "Verified" : "Invalid"],
    ["Provider", `${summary.provider} / ${summary.model}`], ["Environment", summary.environment]
  ];
  document.querySelector("#summary").innerHTML = values.map(([k,v]) =>
    `<div class="card"><span>${esc(k)}</span><div class="value">${esc(v)}</div></div>`).join("");
  document.querySelector("#events").innerHTML = events.reverse().map(row => {
    const e=row.event || {};
    return `<tr><td>${esc(e.timestamp)}</td><td>${esc(e.event_type)}</td>
      <td class="${e.outcome==="blocked"?"bad":""}">${esc(e.outcome)}</td>
      <td><code>${esc(e.subject)}</code></td><td>${esc(JSON.stringify(e.details))}</td></tr>`;
  }).join("");
  document.querySelector("#message").innerHTML = "<p class=ok>Connected</p>";
}
document.querySelector("#auth").addEventListener("submit", event => {
  event.preventDefault();
  sessionStorage.setItem("ztagent-token", document.querySelector("#token").value);
  load().catch(error => document.querySelector("#message").innerHTML =
    `<p class=error>${esc(error.message)}</p>`);
});
if (sessionStorage.getItem("ztagent-token")) load().catch(() => {});
</script></body></html>"""
