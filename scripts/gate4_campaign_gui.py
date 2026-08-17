#!/usr/bin/env python3
"""Read-only localhost dashboard for an active Gate 4 campaign."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Unix-AGB · Gate 4 campaign</title>
<style>
:root{color-scheme:dark;--ink:#061a33;--navy:#062954;--navy2:#0a3d70;--panel:#0d2948cc;--line:#1f6280;--text:#effaff;--muted:#8db0cf;--cyan:#079ab6;--cyan2:#46cada;--ok:#2ac98f;--bad:#ff7684}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 82% -8%,#079ab655 0,transparent 36%),radial-gradient(circle at 0 65%,#0a3d7055 0,transparent 32%),linear-gradient(145deg,#041126,var(--ink) 58%,#041426);background-attachment:fixed;color:var(--text);font:15px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.15;background-image:linear-gradient(#36c6dc22 1px,transparent 1px),linear-gradient(90deg,#36c6dc22 1px,transparent 1px);background-size:46px 46px;mask-image:linear-gradient(to bottom,#000,transparent 72%)}
main{position:relative;max-width:1180px;margin:auto;padding:30px 22px 60px}header{display:flex;justify-content:space-between;gap:24px;align-items:center;margin-bottom:24px;padding:16px 0}.brand{display:flex;align-items:center;gap:16px}.logo{width:66px;height:66px;object-fit:contain;filter:drop-shadow(0 8px 22px #02abc744)}h1{margin:0;font-size:clamp(26px,4vw,43px);letter-spacing:-.045em;font-weight:750}h1 span{color:var(--cyan2)}.eyebrow{color:var(--muted);font:11px ui-monospace,monospace;letter-spacing:.2em;text-transform:uppercase}.badge{padding:9px 14px;border:1px solid #2e7893;border-radius:999px;background:#081b32aa;box-shadow:inset 0 0 18px #0eaec711;font:13px ui-monospace,monospace}.ok{color:var(--ok)}.bad{color:var(--bad)}
.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:13px}.card{position:relative;overflow:hidden;background:linear-gradient(145deg,#0e3153dd,#091f3add);border:1px solid #225d79;border-radius:16px;padding:17px;min-height:108px;box-shadow:0 18px 50px #01081355,inset 0 1px #65dff016}.card:after{content:"";position:absolute;width:80px;height:80px;border-radius:50%;right:-40px;top:-40px;background:#22c1d51a}.wide{grid-column:span 2}.label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.11em}.value{font:650 26px ui-monospace,SFMono-Regular,monospace;margin-top:8px}.bar{height:9px;background:#041326;border:1px solid #1d5f7d;border-radius:9px;overflow:hidden;margin-top:13px}.bar i{display:block;height:100%;width:0;background:linear-gradient(90deg,#087da8,var(--cyan2));box-shadow:0 0 16px var(--cyan);transition:width .4s}
section{margin-top:23px}h2{font-size:15px;margin:0 0 10px;color:#d9f8ff;letter-spacing:.02em}.table{overflow:auto;background:#071a30bb;border:1px solid #205b76;border-radius:16px;box-shadow:0 16px 45px #01081344}table{border-collapse:collapse;width:100%;font:13px ui-monospace,SFMono-Regular,monospace}th,td{text-align:left;padding:11px 13px;border-bottom:1px solid #16415d;white-space:nowrap}th{color:#86b9cc;background:#0b2743;font-weight:500}tbody tr:hover{background:#0c385255}.empty{padding:18px;color:var(--muted)}footer{margin-top:20px;color:#6f9bb0;font:11px ui-monospace,monospace;overflow-wrap:anywhere}@media(max-width:760px){.grid{grid-template-columns:1fr 1fr}.wide{grid-column:span 2}header{align-items:flex-start;flex-direction:column}.logo{width:54px;height:54px}}
</style></head><body><main><header><div class="brand"><img class="logo" src="/assets/logo" alt="Unix-AGB shield"><div><div class="eyebrow">Aletheion Guard Bridge · local observability</div><h1>Gate 4 <span>campaign</span></h1></div></div><div id="health" class="badge">connecting</div></header>
<div class="grid"><div class="card wide"><div class="label">Progress</div><div id="elapsed" class="value">—</div><div class="bar"><i id="progress"></i></div></div><div class="card"><div class="label">Heartbeats</div><div id="samples" class="value">0</div></div><div class="card"><div class="label">Failures</div><div id="failures" class="value">0</div></div><div class="card"><div class="label">Max RSS</div><div id="rss" class="value">0 KiB</div></div><div class="card"><div class="label">Max FDs</div><div id="fds" class="value">0</div></div><div class="card"><div class="label">Load average</div><div id="load" class="value">—</div></div><div class="card"><div class="label">Mode</div><div id="mode" class="value">—</div></div></div>
<section><h2>Supervised workloads</h2><div class="table"><table><thead><tr><th>ID</th><th>Class</th><th>PID</th><th>CPU ticks</th><th>RSS KiB</th><th>FDs</th></tr></thead><tbody id="processes"><tr><td colspan="6" class="empty">Waiting for first heartbeat…</td></tr></tbody></table></div></section>
<section><h2>Probe results</h2><div class="table"><table><thead><tr><th>Command</th><th>Status</th><th>Duration ms</th><th>stdout SHA-256</th></tr></thead><tbody id="probes"><tr><td colspan="4" class="empty">No probe sample yet.</td></tr></tbody></table></div></section>
<footer id="chain">heartbeat chain: —</footer></main>
<script>
const q=id=>document.getElementById(id), esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function rows(items, fields, empty){return items.length?items.map(x=>'<tr>'+fields.map(f=>'<td>'+esc(f(x))+'</td>').join('')+'</tr>').join(''):'<tr><td colspan="'+fields.length+'" class="empty">'+esc(empty)+'</td></tr>'}
async function refresh(){try{let r=await fetch('/api/status',{cache:'no-store'}),s=await r.json(),p=Math.max(0,Math.min(100,100*(s.elapsed_seconds||0)/(s.requested_seconds||1)));q('health').textContent=s.complete?'complete':s.running?'running':'starting';q('health').className='badge '+((s.failures||[]).length?'bad':'ok');q('elapsed').textContent=Math.floor(s.elapsed_seconds||0)+'s / '+(s.requested_seconds||0)+'s';q('progress').style.width=p+'%';q('samples').textContent=s.heartbeat_samples||0;q('failures').textContent=(s.failures||[]).length;q('failures').className='value '+((s.failures||[]).length?'bad':'ok');q('rss').textContent=(s.maxima?.rss_kib||0)+' KiB';q('fds').textContent=s.maxima?.fd_count||0;q('load').textContent=(s.loadavg||[]).map(x=>Number(x).toFixed(2)).join(' · ')||'—';q('mode').textContent=s.mode||'—';q('chain').textContent='heartbeat chain: '+(s.heartbeat_chain_head||'—');q('processes').innerHTML=rows(s.processes||[],[x=>x.id,x=>x.class,x=>x.pid,x=>x.cpu_ticks,x=>x.rss_kib,x=>x.fd_count],'No live workloads.');q('probes').innerHTML=rows(s.probes||[],[x=>(x.argv||[]).join(' '),x=>x.returncode,x=>Number(x.duration_ms||0).toFixed(2),x=>(x.stdout_sha256||'').slice(0,16)+'…'],'No probes configured.')}catch(e){q('health').textContent='disconnected';q('health').className='badge bad'}}
refresh();setInterval(refresh,1000);
</script></body></html>"""


class CampaignGui:
    def __init__(self, output_dir: Path, port: int) -> None:
        self.output_dir = output_dir
        outer = self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path == "/" or self.path == "/index.html":
                    body, kind, code = PAGE.encode(), "text/html; charset=utf-8", 200
                elif self.path == "/assets/logo":
                    logo = Path(__file__).resolve().parents[1] / "assets/Unix_AGB_Logo.png"
                    body, kind, code = logo.read_bytes(), "image/png", 200
                elif self.path.startswith("/api/status"):
                    path = outer.output_dir / "live-status.json"
                    if path.is_file(): body, code = path.read_bytes(), 200
                    else: body, code = b'{"running":false,"failures":[]}', 200
                    kind = "application/json"
                else: body, kind, code = b"not found\n", "text/plain", 404
                self.send_response(code); self.send_header("Content-Type", kind)
                self.send_header("Cache-Control", "no-store"); self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            def log_message(self, _format: str, *_args: object) -> None: pass
        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int: return int(self.server.server_address[1])
    def start(self) -> None: self.thread.start()
    def stop(self) -> None: self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
