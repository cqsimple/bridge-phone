#!/usr/bin/env python3
import sqlite3,socket,json,os,time,threading,requests
from functools import wraps
from flask import Flask,jsonify,render_template_string,request,session,redirect
from werkzeug.security import generate_password_hash,check_password_hash

app=Flask(__name__)
app.secret_key=os.environ.get("SECRET_KEY","vpn-dashboard-secret-change-me")

DB_FILE="/opt/site-dashboard/dashboard.db"
SITES_FILE="/opt/site-dashboard/sites.json"
STATUS_LOG="/var/log/openvpn/openvpn-status.log"
MGMT_HOST="127.0.0.1"
MGMT_PORT=7505
DEVICE_PORT=80
POLL=5

def get_db():
    db=sqlite3.connect(DB_FILE)
    db.row_factory=sqlite3.Row
    return db

def init_db():
    os.makedirs(os.path.dirname(DB_FILE),exist_ok=True)
    db=get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created TEXT DEFAULT(datetime('now')));
        CREATE TABLE IF NOT EXISTS user_sites(
            user_id INTEGER NOT NULL,
            site_name TEXT NOT NULL,
            PRIMARY KEY(user_id,site_name));
        CREATE TABLE IF NOT EXISTS vps_sites(
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT UNIQUE NOT NULL,
            label       TEXT NOT NULL,
            ip          TEXT NOT NULL,
            ssh_user    TEXT NOT NULL DEFAULT 'root',
            ssh_password TEXT NOT NULL,
            web_port    INTEGER NOT NULL DEFAULT 80,
            notes       TEXT,
            created     TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS audit_log(
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            username    TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            site_name   TEXT NOT NULL,
            device_ip   TEXT,
            device_port TEXT,
            vendor      TEXT,
            url_path    TEXT,
            started_at  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            duration_s  INTEGER NOT NULL DEFAULT 0);
    """)
    if not db.execute("SELECT 1 FROM users").fetchone():
        db.execute("INSERT INTO users(username,password,is_admin)VALUES(?,?,1)",
                   ("admin",generate_password_hash("admin")))
        print("[db] Created admin/admin")
    db.commit();db.close()


# ════════════════════════════════════════════════════════════
# AUDIT LOG
# ════════════════════════════════════════════════════════════
import threading as _ath
import queue as _aq
from datetime import datetime as _adt, timezone as _atz, timedelta as _atd

_audit_queue   = _aq.Queue()
_active_visits = {}
_VISIT_IDLE    = 300

def _anow():
    return _adt.now(_atz.utc)

def _aiso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def _afmt_est(iso):
    try:
        dt = _adt.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_atz.utc)
        try:
            from zoneinfo import ZoneInfo
            dt = dt.astimezone(ZoneInfo("America/New_York"))
        except Exception:
            offset = -4 if 3 < dt.month < 11 else -5
            dt = dt + _atd(hours=offset)
        return dt.strftime("%Y-%m-%d %I:%M:%S %p ET")
    except Exception:
        return iso

def _audit_worker():
    import sqlite3 as _sq
    while True:
        try:
            msg = _audit_queue.get(timeout=10)
        except _aq.Empty:
            _flush_stale_visits()
            continue
        if msg is None:
            break
        try:
            conn = _sq.connect(DB_FILE)
            if msg["op"] == "insert":
                cur = conn.execute(
                    "INSERT INTO audit_log(user_id,username,event_type,site_name,"
                    "device_ip,device_port,vendor,url_path,started_at,last_seen,duration_s)"
                    "VALUES(?,?,?,?,?,?,?,?,?,?,0)",
                    (msg["user_id"],msg["username"],msg["event_type"],msg["site_name"],
                     msg["device_ip"],msg["device_port"],msg["vendor"],msg.get("url_path"),
                     msg["started_at"],msg["started_at"]))
                conn.commit()
                _active_visits[msg["visit_key"]] = {
                    "started_at":msg["now"],"last_seen":msg["now"],"audit_id":cur.lastrowid}
            elif msg["op"] == "update":
                conn.execute("UPDATE audit_log SET last_seen=?,duration_s=? WHERE id=?",
                             (msg["last_seen"],msg["duration_s"],msg["audit_id"]))
                conn.commit()
            elif msg["op"] == "purge":
                conn.execute("DELETE FROM audit_log WHERE started_at < ?",(msg["cutoff"],))
                conn.commit()
            conn.close()
        except Exception as e:
            print(f"[audit worker] {e}", flush=True)

def _flush_stale_visits():
    cutoff = _anow() - _atd(seconds=_VISIT_IDLE)
    stale  = [k for k,v in _active_visits.items() if v["last_seen"] < cutoff]
    for k in stale:
        v = _active_visits.pop(k)
        dur = int((v["last_seen"] - v["started_at"]).total_seconds())
        _audit_queue.put({"op":"update","audit_id":v["audit_id"],
                          "last_seen":_aiso(v["last_seen"]),"duration_s":dur})

def record_audit_event(event_type, site_name, device_ip=None, device_port=None,
                       vendor=None, url_path=None):
    try:
        uid      = session.get("user_id")
        username = session.get("username","unknown")
        if not uid:
            return
        sites    = load_sites()
        site_obj = next((s for s in sites if s["name"] == site_name), None)
        site_label = site_obj.get("label", site_name) if site_obj else site_name
        sid       = request.cookies.get("session", str(uid))
        visit_key = (sid, site_label, device_ip or "", device_port or "")
        now       = _anow()
        if visit_key in _active_visits:
            v = _active_visits[visit_key]
            v["last_seen"] = now
            if v.get("audit_id"):
                dur = int((now - v["started_at"]).total_seconds())
                _audit_queue.put({"op":"update","audit_id":v["audit_id"],
                                  "last_seen":_aiso(now),"duration_s":dur})
        else:
            _active_visits[visit_key] = {"started_at":now,"last_seen":now,"audit_id":None}
            _audit_queue.put({"op":"insert","visit_key":visit_key,"now":now,
                              "user_id":uid,"username":username,"event_type":event_type,
                              "site_name":site_label,"device_ip":device_ip,
                              "device_port":device_port,"vendor":vendor,
                              "url_path":url_path,"started_at":_aiso(now)})
    except Exception as e:
        print(f"[audit] {e}", flush=True)

def purge_old_audit():
    cutoff = _aiso(_anow() - _atd(days=183))
    _audit_queue.put({"op":"purge","cutoff":cutoff})

def start_audit_worker():
    t = _ath.Thread(target=_audit_worker, daemon=True, name="audit-worker")
    t.start()

# ════════════════════════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def d(*a,**kw):
        if "user_id" not in session:return redirect("/login")
        return f(*a,**kw)
    return d

def admin_required(f):
    @wraps(f)
    def d(*a,**kw):
        if "user_id" not in session:return redirect("/login")
        if not session.get("is_admin"):return jsonify({"error":"Admin only"}),403
        return f(*a,**kw)
    return d

def cu():
    return{"id":session.get("user_id"),"username":session.get("username"),
           "is_admin":session.get("is_admin",False)}


def update_ansible_inventory():
    """Keep ansible inventory in sync with sites.json"""
    import os as _os
    inventory_path = "/opt/bridge-phone/ansible/inventory.ini"
    if not _os.path.exists(_os.path.dirname(inventory_path)):
        return
    sites = load_sites()
    lines = ["[bridge_phone_sites]\n"]
    for s in sites:
        name = s["name"]
        ip   = s["vpn_ip"]
        lines.append(f"{name} ansible_host={ip} ansible_user=root\n")
    lines.append("\n[bridge_phone_sites:vars]\n")
    lines.append("ansible_ssh_private_key_file=/root/.ssh/id_rsa\n")
    lines.append("ansible_ssh_common_args='-o StrictHostKeyChecking=no'\n")
    with open(inventory_path, "w") as f:
        f.writelines(lines)

def load_sites():
    try:
        with open(SITES_FILE) as f:return json.load(f)
    except:return []

def get_user_site_names(user_id,is_admin):
    if is_admin:return[s["name"]for s in load_sites()]
    db=get_db()
    rows=db.execute("SELECT site_name FROM user_sites WHERE user_id=?",(user_id,)).fetchall()
    db.close()
    return[r["site_name"]for r in rows]

def get_connected_clients():
    clients={}
    try:
        with open(STATUS_LOG) as f:lines=f.readlines()
        in_c=False
        for line in lines:
            line=line.strip()
            if line.startswith("Common Name,"):in_c=True;continue
            if line.startswith("ROUTING TABLE"):in_c=False;continue
            if in_c and "," in line:
                p=line.split(",")
                if len(p)>=5:
                    cn=p[0].strip()
                    if cn:clients[cn]={"vpn_ip":"","connected_since":",".join(p[4:]).strip(),
                                       "bytes_rx":int(p[2])if p[2].isdigit()else 0,
                                       "bytes_tx":int(p[3])if p[3].isdigit()else 0}
        in_r=False
        for line in lines:
            line=line.strip()
            if line.startswith("Virtual Address,"):in_r=True;continue
            if line.startswith("GLOBAL STATS"):in_r=False;continue
            if in_r and "," in line:
                p=line.split(",")
                if len(p)>=2:
                    cn,vpn=p[1].strip(),p[0].strip()
                    if cn in clients:clients[cn]["vpn_ip"]=vpn
    except Exception as e:print(f"[status]{e}")
    return clients

def fmt_bytes(n):
    for u in("B","KB","MB","GB"):
        if n<1024:return f"{n:.0f} {u}"
        n/=1024
    return f"{n:.1f} TB"

def disconnect_client(name):
    try:
        s=socket.socket();s.settimeout(3);s.connect((MGMT_HOST,MGMT_PORT))
        s.recv(4096);s.sendall(f"kill {name}\n".encode())
        time.sleep(0.5);r=s.recv(4096).decode();s.close()
        return"SUCCESS"in r
    except:return False

_cache={}
_lock=threading.Lock()

def refresh_cache():
    connected=get_connected_clients()
    updated={}
    for site in load_sites():
        name,vpn_ip=site["name"],site["vpn_ip"]
        info=connected.get(name)
        e={"name":name,"label":site.get("label",name),"vpn_ip":vpn_ip,
           "online":bool(info),"browser_up":False,"scanning":False,
           "device_count":0,"last_scan":0,"bytes_rx":"","bytes_tx":"","connected_since":""}
        if info:
            e["connected_since"]=info["connected_since"]
            e["bytes_rx"]=fmt_bytes(info["bytes_rx"])
            e["bytes_tx"]=fmt_bytes(info["bytes_tx"])
            if site.get("type") != "freepbx_vps":
                try:
                    r=requests.get(f"http://{vpn_ip}:{DEVICE_PORT}/api/state",timeout=3)
                    st=r.json()
                    e.update(browser_up=True,scanning=st.get("scanning",False),
                             device_count=len(st.get("devices",[])),last_scan=st.get("last_scan",0))
                except:pass
            else:
                e.update(browser_up=True,device_count=1,site_type="freepbx_vps")
        updated[name]=e
    with _lock:
        _cache.clear();_cache.update(updated)

def bg():
    while True:
        try:refresh_cache()
        except Exception as ex:print(f"[refresh]{ex}")
        time.sleep(POLL)

def sites_for_user(user_id,is_admin):
    names=get_user_site_names(user_id,is_admin)
    with _lock:return[_cache[n]for n in names if n in _cache]

LOGIN_HTML="""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Login</title>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;600&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:'Sora',sans-serif;
  min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:36px 32px;width:340px}
.logo{color:#58a6ff;font-size:1.1rem;font-weight:600;margin-bottom:6px}
.logo span{color:#3fb950}
.sub{color:#8b949e;font-size:.82rem;margin-bottom:26px}
.err{color:#f85149;background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);
  padding:8px 12px;border-radius:6px;margin-bottom:14px;font-size:.82rem}
label{display:block;font-size:.72rem;color:#8b949e;margin-bottom:4px;
  text-transform:uppercase;letter-spacing:.04em}
input{width:100%;background:#1c2128;border:1px solid #21262d;border-radius:7px;
  padding:9px 12px;color:#e6edf3;font-size:.9rem;outline:none;margin-bottom:14px}
input:focus{border-color:#58a6ff}
button{width:100%;background:#58a6ff;color:#000;border:none;border-radius:7px;
  padding:10px;font-weight:600;font-size:.9rem;cursor:pointer}
button:hover{opacity:.85}
</style></head><body>
<div class="box">
  <div class="logo"><img src="/static/logo.png" style="height:36px;vertical-align:middle;margin-right:8px"> Bridge_Phone</div>
  <div class="sub">Sign in to your account</div>
  <div style="background:rgba(210,153,34,.1);border:1px solid rgba(210,153,34,.3);border-radius:6px;padding:10px 12px;margin-bottom:18px;font-size:.75rem;color:#d29922;line-height:1.5">
    &#9888; Authorized personnel only. Unauthorized access to this system is prohibited. All activity is monitored and logged.
  </div>
  {% if err %}<div class="err">{{ err }}</div>{% endif %}
  <form method="POST">
    <label>Username</label><input name="username" autofocus required>
    <label>Password</label><input name="password" type="password" required>
    <button type="submit">Sign In</button>
  </form>
</div></body></html>"""

DASH_HTML="""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Bridge_Phone</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Sora:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#13131f;--sf:#1e1e2e;--sf2:#252535;--bd:#21262d;--ac:#F07B10;
  --gn:#3fb950;--rd:#f85149;--tx:#e6edf3;--mu:#8b949e;--r:10px}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:'Sora',sans-serif;min-height:100vh}
header{background:var(--sf);border-bottom:1px solid var(--bd);padding:14px 28px;
  display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:100}
.logo{font-family:'JetBrains Mono',monospace;font-size:1rem;font-weight:600;color:var(--ac)}
.logo span{color:var(--gn)}
.nav{margin-left:auto;display:flex;gap:8px;align-items:center}
.nav a{font-size:.78rem;padding:5px 11px;border-radius:6px;color:var(--mu);
  font-family:'JetBrains Mono',monospace;text-decoration:none;transition:background .15s}
.nav a:hover{background:rgba(255,255,255,.06);color:var(--tx)}
.nu{font-size:.78rem;color:var(--mu);font-family:'JetBrains Mono',monospace}
.sep{color:var(--bd)}
main{max-width:960px;margin:0 auto;padding:28px 20px}
.sb{display:flex;gap:14px;margin-bottom:24px;flex-wrap:wrap}
.sc{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r);
  padding:11px 18px;display:flex;flex-direction:column;gap:2px;min-width:120px}
.sl{font-size:.68rem;color:var(--mu);text-transform:uppercase;letter-spacing:.06em}
.sv{font-size:1.4rem;font-weight:700;color:var(--ac);font-family:'JetBrains Mono',monospace}
.sg{display:flex;flex-direction:column;gap:11px}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r);
  overflow:hidden;animation:fu .25s ease both}
.card.on{border-color:rgba(63,185,80,.3)}.card:hover{border-color:var(--ac)}
@keyframes fu{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.ch{padding:13px 17px;background:var(--sf2);border-bottom:1px solid var(--bd);
  display:flex;align-items:center;gap:11px}
.cb{padding:13px 17px;display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:12px;
  font-size:.7rem;font-weight:600;font-family:'JetBrains Mono',monospace}
.b-gn{background:rgba(63,185,80,.13);color:var(--gn);border:1px solid rgba(63,185,80,.28)}
.b-mu{background:rgba(255,255,255,.05);color:var(--mu);border:1px solid var(--bd)}
.dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.b-gn .dot{animation:glow 2s ease-in-out infinite}
@keyframes glow{0%,100%{opacity:1}50%{opacity:.4}}
.lbl{font-size:.95rem;font-weight:600}
.nm{font-size:.7rem;color:var(--mu);font-family:'JetBrains Mono',monospace}
.vip{font-family:'JetBrains Mono',monospace;font-size:.74rem;color:var(--ac);
  margin-left:auto;background:rgba(88,166,255,.08);padding:3px 9px;border-radius:5px}
.chips{display:flex;gap:6px;flex-wrap:wrap;flex:1}
.chip{display:inline-flex;align-items:center;gap:4px;padding:3px 8px;border-radius:5px;
  font-size:.69rem;font-family:'JetBrains Mono',monospace;
  background:rgba(255,255,255,.04);border:1px solid var(--bd);color:var(--mu)}
.chip.ok{color:var(--gn);border-color:rgba(63,185,80,.22);background:rgba(63,185,80,.05)}
.chip.sc{color:var(--ac);border-color:rgba(88,166,255,.22);animation:pu .9s infinite}
@keyframes pu{0%,100%{opacity:1}50%{opacity:.4}}
.acts{display:flex;gap:6px;flex-shrink:0}
.btn{display:inline-flex;align-items:center;padding:5px 12px;border-radius:6px;border:none;
  font-size:.75rem;font-weight:600;cursor:pointer;font-family:'Sora',sans-serif;
  text-decoration:none;transition:opacity .2s}
.btn:hover{opacity:.82}.btn:disabled{opacity:.35;cursor:not-allowed}
.bp{background:var(--ac);color:#000}
.bsc{background:rgba(88,166,255,.12);color:var(--ac);border:1px solid rgba(88,166,255,.3)}
.bd{background:rgba(248,81,73,.12);color:var(--rd);border:1px solid rgba(248,81,73,.28)}
.off{padding:11px 17px;font-size:.79rem;color:var(--mu);font-family:'JetBrains Mono',monospace}
.empty{text-align:center;padding:60px 20px;color:var(--mu)}
</style></head>
<body>
<header>
  <div class="logo"><img src="/static/logo.png" style="height:36px;vertical-align:middle;margin-right:8px"> Bridge_Phone</div>
  <div class="nav">
    <span class="nu">{{ username }}</span>
    <span class="sep"> | </span>
    {% if is_admin %}<a href="/admin">Admin</a><a href="/admin/new-site">New Site</a><a href="/admin/wg-users">VPN Users</a><a href="/admin/vps-sites">VPS Sites</a><a href="/admin/audit">Audit Log</a>{% endif %}
    <a href="/logout">Sign out</a>
  </div>
</header>
<main>
  <div class="sb">
    <div class="sc"><span class="sl">My Sites</span><span class="sv" id="st">-</span></div>
    <div class="sc"><span class="sl">Online</span><span class="sv" id="so" style="color:var(--gn)">-</span></div>
    <div class="sc"><span class="sl">Offline</span><span class="sv" id="sf" style="color:var(--mu)">-</span></div>
  </div>
  <div class="sg" id="sg"><div class="empty">Loading sites...</div></div>
</main>
<script>
var IS_ADMIN = {{ is_admin_js }};
function ago(ts) {
  if(!ts) return '-';
  var s = Math.round(Date.now()/1000 - ts);
  if(s < 60) return s+'s ago';
  if(s < 3600) return Math.round(s/60)+'m ago';
  return Math.round(s/3600)+'h ago';
}
function load() {
  fetch('/api/my-sites', {credentials:'include'})
  .then(function(r) {
    if(r.status === 302 || r.redirected) { window.location='/login'; return null; }
    return r.json();
  })
  .then(function(r) {
    if(!r) return;
    var sites = r.sites || [];
    var on = 0;
    for(var i=0; i<sites.length; i++) { if(sites[i].online) on++; }
    document.getElementById('st').textContent = sites.length;
    document.getElementById('so').textContent = on;
    document.getElementById('sf').textContent = sites.length - on;
    var g = document.getElementById('sg');
    if(!sites.length) {
      g.innerHTML = '<div class="empty">No sites assigned to your account.</div>';
      return;
    }
    // Only redraw if data changed
    var newHash = JSON.stringify(sites);
    if(window._lastHash === newHash) return;
    window._lastHash = newHash;
    var html = '';
    for(var i=0; i<sites.length; i++) {
      var s = sites[i];
      var chips = '', acts = '';
      var discBtn = IS_ADMIN
        ? '<button class="btn bd" data-n="'+s.name+'" onclick="disc(this.dataset.n)">Disconnect</button>'
        : '';
      if(s.online && s.browser_up) {
        if(s.site_type === 'freepbx_vps') {
          if(s.connected_since) chips += '<span class="chip">up '+s.connected_since+'</span>';
          chips += '<span class="chip ok">&#10003; FreePBX VPS</span>';
          acts = '<a class="btn bp" href="/site/'+s.name+'/" target="_blank">Open FreePBX</a>'
               + ' <button class="btn" style="background:rgba(255,255,255,.06);color:#e6edf3;border:1px solid #21262d" data-n="'+s.name+'" data-l="'+s.label+'" onclick="rename(this.dataset.n,this.dataset.l)" title="Rename">&#9998;</button>'
               + ' ' + discBtn;
        } else {
          chips += s.scanning
            ? '<span class="chip sc">scanning...</span>'
            : '<span class="chip ok">&#10003; '+s.device_count+' device'+(s.device_count!==1?'s':'')+'</span>';
          if(s.last_scan) chips += '<span class="chip">scan '+ago(s.last_scan)+'</span>';
          if(s.connected_since) chips += '<span class="chip">up '+s.connected_since+'</span>';
          acts = '<a class="btn bp" href="/site/'+s.name+'/" target="_blank">Open</a>'
               + ' <button class="btn bsc" data-n="'+s.name+'" onclick="scan(this.dataset.n)">Scan</button>'
               + ' <button class="btn" style="background:rgba(255,255,255,.06);color:#e6edf3;border:1px solid #21262d" data-n="'+s.name+'" data-l="'+s.label+'" onclick="rename(this.dataset.n,this.dataset.l)" title="Rename">&#9998;</button>'
               + ' ' + discBtn;
        }
      } else if(s.online) {
        chips = '<span class="chip">Browser connecting...</span>';
        acts = '<a class="btn bp" href="/site/'+s.name+'/" target="_blank">Open</a>';
      }
      var body = s.online
        ? '<div class="cb"><div class="chips">'+chips+'</div><div class="acts">'+acts+'</div></div>'
        : '<div class="off">Offline - will reconnect automatically.</div>';
      html += '<div class="card '+(s.online?'on':'')+'" style="animation-delay:'+(i*30)+'ms">'
            + '<div class="ch">'
            + '<span class="badge '+(s.online?'b-gn':'b-mu')+'">'
            + '<span class="dot"></span>'+(s.online?'Online':'Offline')+'</span>'
            + '<div><div class="lbl">'+s.label+'</div><div class="nm">'+s.name+'</div></div>'
            + '<div class="vip">'+s.vpn_ip+'</div>'
            + '</div>'+body+'</div>';
    }
    g.innerHTML = html;
  })
  .catch(function(e) { console.error(e); });
}
function rename(n, l) {
  var nl = prompt("New name for "+n+":", l);
  if(!nl || nl.trim() === l) return;
  fetch("/api/sites/"+n+"/rename", {method:"POST", credentials:"include",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({label: nl.trim()})
  }).then(function(r){return r.json();}).then(function(d){
    if(d.status==="ok") load(); else alert("Error: "+(d.error||"unknown"));
  });
}
function scan(n) {
  fetch('/api/sites/'+n+'/scan', {method:'POST', credentials:'include'});
}
function disc(n) {
  if(!confirm('Disconnect '+n+'? It will reconnect automatically.')) return;
  fetch('/api/sites/'+n+'/disconnect', {method:'POST', credentials:'include'})
  .then(function() { load(); });
}
load();
setInterval(load, 5000);
</script>
</body></html>"""

ADMIN_HTML="""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Admin</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Sora:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--bg:#13131f;--sf:#1e1e2e;--sf2:#252535;--bd:#21262d;--ac:#F07B10;
  --gn:#3fb950;--rd:#f85149;--wn:#d29922;--tx:#e6edf3;--mu:#8b949e;--r:10px}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:'Sora',sans-serif;min-height:100vh}
header{background:var(--sf);border-bottom:1px solid var(--bd);padding:14px 28px;
  display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:100}
.logo{font-family:'JetBrains Mono',monospace;font-size:1rem;font-weight:600;color:var(--ac)}
.logo span{color:var(--gn)}
.nav{margin-left:auto;display:flex;gap:8px;align-items:center}
.nav a{font-size:.78rem;padding:5px 11px;border-radius:6px;color:var(--mu);
  font-family:'JetBrains Mono',monospace;text-decoration:none;transition:background .15s}
.nav a:hover{background:rgba(255,255,255,.06);color:var(--tx)}
.nu{font-size:.78rem;color:var(--mu);font-family:'JetBrains Mono',monospace}
.sep{color:var(--bd)}
main{max-width:900px;margin:0 auto;padding:28px 20px}
h2{font-size:1.05rem;font-weight:600;margin-bottom:16px}
.flash{padding:9px 14px;border-radius:7px;margin-bottom:16px;font-size:.82rem}
.ok2{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.28);color:var(--gn)}
.er2{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.28);color:var(--rd)}
.tabs{display:flex;gap:2px;border-bottom:1px solid var(--bd);margin-bottom:22px}
.tab{padding:8px 15px;font-size:.81rem;cursor:pointer;border-radius:7px 7px 0 0;
  color:var(--mu);border:1px solid transparent;border-bottom:none;transition:color .15s}
.tab.act{color:var(--ac);background:var(--sf2);border-color:var(--bd);margin-bottom:-1px}
.tc{display:none}.tc.act{display:block}
.card{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r);
  overflow:hidden;margin-bottom:14px}
.ch{padding:12px 16px;background:var(--sf2);border-bottom:1px solid var(--bd);
  display:flex;align-items:center;gap:10px}
.cb{padding:14px 16px}
table{width:100%;border-collapse:collapse;font-size:.83rem}
th{text-align:left;padding:9px 12px;font-size:.68rem;color:var(--mu);
  text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid var(--bd);font-weight:400}
td{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}
tr:last-child td{border-bottom:none}
label{display:block;font-size:.72rem;color:var(--mu);margin-bottom:4px;
  text-transform:uppercase;letter-spacing:.04em}
input,select{width:100%;background:var(--sf2);border:1px solid var(--bd);border-radius:7px;
  padding:8px 11px;color:var(--tx);font-family:'Sora',sans-serif;font-size:.84rem;outline:none}
input:focus,select:focus{border-color:var(--ac)}
.fi{margin-bottom:12px}.fr{display:flex;gap:10px;align-items:flex-end}
.fr .fi{flex:1;margin-bottom:0}
.btn{display:inline-flex;align-items:center;padding:6px 13px;border-radius:6px;border:none;
  font-size:.76rem;font-weight:600;cursor:pointer;font-family:'Sora',sans-serif}
.btn:hover{opacity:.82}
.bp{background:var(--ac);color:#000}.bs{background:var(--gn);color:#000}
.bd{background:rgba(248,81,73,.12);color:var(--rd);border:1px solid rgba(248,81,73,.28)}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:10px;
  font-size:.7rem;font-weight:600;font-family:'JetBrains Mono',monospace}
.b-ad{background:rgba(210,153,34,.13);color:var(--wn);border:1px solid rgba(210,153,34,.28)}
.b-mu{background:rgba(255,255,255,.05);color:var(--mu);border:1px solid var(--bd)}
.sp{display:flex;flex-direction:column;gap:4px;max-height:240px;overflow-y:auto;
  border:1px solid var(--bd);border-radius:7px;padding:6px}
.sp label{display:flex;align-items:center;gap:8px;padding:6px 8px;border-radius:5px;
  cursor:pointer;font-size:.82rem;font-weight:400;text-transform:none;letter-spacing:0;
  color:var(--tx);margin-bottom:0}
.sp label:hover{background:rgba(255,255,255,.05)}
.sp input[type=checkbox]{width:auto;flex-shrink:0}
.sp-ip{font-family:'JetBrains Mono',monospace;font-size:.69rem;color:var(--mu);margin-left:auto}
</style></head><body>
<header>
  <div class="logo"><img src="/static/logo.png" style="height:36px;vertical-align:middle;margin-right:8px"> Bridge_Phone</div>
  <div class="nav">
    <span class="nu">{{ username }}</span><span class="sep"> | </span>
    <a href="/">Dashboard</a><a href="/admin">Admin</a><a href="/admin/new-site">New Site</a><a href="/admin/wg-users">VPN Users</a><a href="/admin/vps-sites">VPS Sites</a><a href="/admin/audit">Audit Log</a>
    <a href="/logout">Sign out</a>
  </div>
</header>
<main>
  {% for m,c in msgs %}<div class="flash {{ c }}">{{ m }}</div>{% endfor %}
  <div class="tabs">
    <div class="tab act" onclick="sw('users',this)">Users</div>
    <div class="tab" onclick="sw('assign',this)">Site Assignments</div>
    <div class="tab" onclick="sw('pw',this)">Change Password</div>
  </div>
  <div class="tc act" id="tc-users">
    <h2>Users</h2>
    <div class="card" style="margin-bottom:18px">
      <div class="ch"><strong>Add User</strong></div>
      <div class="cb">
        <form method="POST" action="/admin/users/add">
          <div class="fr">
            <div class="fi"><label>Username</label><input name="username" required></div>
            <div class="fi"><label>Password</label><input name="password" type="password" required></div>
            <div class="fi" style="max-width:120px"><label>Role</label>
              <select name="is_admin">
                <option value="0">User</option>
                <option value="1">Admin</option>
              </select></div>
            <div><button class="btn bs" type="submit">Add</button></div>
          </div>
        </form>
      </div>
    </div>
    <div class="card">
      <table>
        <thead><tr><th>Username</th><th>Role</th><th>Sites</th><th>Created</th><th></th></tr></thead>
        <tbody>
        {% for u in users %}
        <tr>
          <td><strong>{{ u.username }}</strong></td>
          <td>{% if u.is_admin %}<span class="badge b-ad">Admin</span>
              {% else %}<span class="badge b-mu">User</span>{% endif %}</td>
          <td style="font-family:'JetBrains Mono',monospace;font-size:.74rem;color:var(--mu)">
            {{ u.site_count }} site{% if u.site_count != 1 %}s{% endif %}</td>
          <td style="font-size:.74rem;color:var(--mu)">{{ u.created[:10] }}</td>
          <td style="text-align:right">
            {% if u.id != uid %}
            <form method="POST" action="/admin/users/{{ u.id }}/toggle-admin" style="display:inline">
              <button class="btn" style="background:rgba(88,166,255,.1);color:#58a6ff;border:1px solid rgba(88,166,255,.28);margin-right:4px">
                {% if u.is_admin %}Remove Admin{% else %}Make Admin{% endif %}
              </button>
            </form>
            <form method="POST" action="/admin/users/{{ u.id }}/delete"
              onsubmit="return confirm('Delete {{ u.username }}?')" style="display:inline">
              <button class="btn bd">Delete</button>
            </form>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
  <div class="tc" id="tc-assign">
    <h2>Site Assignments</h2>
    <p style="color:var(--mu);font-size:.82rem;margin-bottom:18px">
      Admins see all sites. Assign specific sites to regular users here.</p>
    {% for u in users if not u.is_admin %}
    <div class="card" style="margin-bottom:13px">
      <div class="ch"><strong>{{ u.username }}</strong>
        <span style="font-size:.72rem;color:var(--mu);margin-left:8px">
          {{ u.site_count }} assigned</span></div>
      <div class="cb">
        <form method="POST" action="/admin/users/{{ u.id }}/sites">
          <div class="sp">
            {% for s in all_sites %}
            <label>
              <input type="checkbox" name="sites" value="{{ s.name }}"
                {% if s.name in u.assigned_sites %}checked{% endif %}>
              <div>
                <div style="font-weight:500">{{ s.label }}</div>
                <div style="font-size:.7rem;color:var(--mu)">{{ s.name }}</div>
              </div>
              <div class="sp-ip">{{ s.vpn_ip }}</div>
            </label>
            {% endfor %}
          </div>
          <div style="margin-top:10px">
            <button class="btn bp" type="submit">Save</button>
          </div>
        </form>
      </div>
    </div>
    {% else %}
    <p style="color:var(--mu);font-size:.82rem">No regular users yet.</p>
    {% endfor %}
  </div>
  <div class="tc" id="tc-pw">
    <h2>Change Password</h2>
    <div class="card" style="max-width:360px">
      <div class="cb">
        <form method="POST" action="/admin/change-password">
          <div class="fi"><label>Current Password</label>
            <input name="current_pw" type="password" required></div>
          <div class="fi"><label>New Password</label>
            <input name="new_pw" type="password" required minlength="8"></div>
          <div class="fi"><label>Confirm New Password</label>
            <input name="confirm_pw" type="password" required minlength="8"></div>
          <button class="btn bp" type="submit">Update Password</button>
        </form>
      </div>
    </div>
  </div>
</main>
<script>
function sw(n,el){
  document.querySelectorAll('.tab,.tc').forEach(function(e){e.classList.remove('act');});
  document.getElementById('tc-'+n).classList.add('act');
  el.classList.add('act');
}
</script>
</body></html>"""

@app.route("/servlet", methods=["GET","POST","PUT","DELETE","PATCH"])
def servlet_redirect():
    from flask import request as freq, redirect
    # Figure out which site the user came from via referer
    referer = freq.headers.get("Referer", "")
    import re as _re
    m = _re.search(r"/site/([^/]+)/device/([^/]+)/([^/]+)/", referer)
    if m:
        site = m.group(1)
        ip = m.group(2)
        port = m.group(3)
        qs = freq.query_string.decode("utf-8", errors="ignore")
        return redirect(f"/site/{site}/device/{ip}/{port}/servlet?{qs}", 307)
    return "Not found", 404

@app.route("/static/<path:filename>")
def static_files(filename):
    from flask import send_from_directory
    return send_from_directory("/opt/site-dashboard/static", filename)

@app.route("/login",methods=["GET","POST"])
def login_page():
    if "user_id" in session:return redirect("/")
    err=""
    if request.method=="POST":
        u=request.form.get("username","").strip()
        p=request.form.get("password","")
        db=get_db()
        user=db.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone()
        db.close()
        if user and check_password_hash(user["password"],p):
            session.permanent=True
            session.update(user_id=user["id"],username=user["username"],
                           is_admin=bool(user["is_admin"]))
            return redirect("/")
        err="Invalid username or password."
    return render_template_string(LOGIN_HTML,err=err)

@app.route("/logout")
def logout():
    session.clear();return redirect("/login")

@app.route("/")
@login_required
def dashboard():
    user=cu()
    return render_template_string(
        DASH_HTML,
        username=user["username"],
        is_admin=user["is_admin"],
        is_admin_js="true" if user["is_admin"] else "false"
    )

@app.route("/api/my-sites")
@login_required
def api_my_sites():
    user=cu()
    return jsonify({"sites":sites_for_user(user["id"],user["is_admin"])})

@app.route("/api/test")
def api_test():
    return jsonify({"clients":get_connected_clients(),"sites":load_sites(),"cache":list(_cache.keys())})

@app.route("/api/sites/<n>/scan",methods=["POST"])
@login_required
def api_scan(n):
    user=cu()
    if n not in get_user_site_names(user["id"],user["is_admin"]):
        return jsonify({"error":"Access denied"}),403
    site=next((s for s in load_sites() if s["name"]==n),None)
    if not site:return jsonify({"error":"Not found"}),404
    try:
        r=requests.post(f"http://{site['vpn_ip']}:{DEVICE_PORT}/api/scan",timeout=4)
        return jsonify({"status":"started"if r.status_code==200 else"error"})
    except:return jsonify({"error":"RPi not reachable"}),503

@app.route("/api/sites/<n>/disconnect",methods=["POST"])
@admin_required
def api_disconnect(n):
    return jsonify({"status":"ok"if disconnect_client(n)else"error"})

@app.route("/admin")
@admin_required
def admin_page():
    msgs=session.pop("flash",[])
    db=get_db()
    all_sites=load_sites()
    users_raw=db.execute("SELECT * FROM users ORDER BY username").fetchall()
    users=[]
    for u in users_raw:
        assigned=[r["site_name"]for r in db.execute(
            "SELECT site_name FROM user_sites WHERE user_id=?",(u["id"],))]
        users.append({"id":u["id"],"username":u["username"],"is_admin":bool(u["is_admin"]),
                      "created":u["created"],"site_count":len(assigned),"assigned_sites":assigned})
    db.close()
    user=cu()
    return render_template_string(
        ADMIN_HTML,username=user["username"],
        users=users,all_sites=all_sites,uid=session["user_id"],msgs=msgs
    )

@app.route("/admin/users/add",methods=["POST"])
@admin_required
def admin_add_user():
    username=request.form.get("username","").strip()
    password=request.form.get("password","")
    is_admin=int(request.form.get("is_admin",0))
    db=get_db()
    try:
        db.execute("INSERT INTO users(username,password,is_admin)VALUES(?,?,?)",
                   (username,generate_password_hash(password),is_admin))
        db.commit()
        session["flash"]=[(f"User '{username}' created.","ok2")]
    except sqlite3.IntegrityError:
        session["flash"]=[(f"Username '{username}' already exists.","er2")]
    finally:db.close()
    return redirect("/admin")

@app.route("/admin/users/<int:uid>/toggle-admin", methods=["POST"])
@admin_required
def admin_toggle_admin(uid):
    with get_db() as db:
        user = db.execute("SELECT is_admin FROM users WHERE id=?", (uid,)).fetchone()
        if user:
            new_val = 0 if user["is_admin"] else 1
            db.execute("UPDATE users SET is_admin=? WHERE id=?", (new_val, uid))
    return redirect("/admin")

@app.route("/admin/users/<int:uid>/delete",methods=["POST"])
@admin_required
def admin_delete_user(uid):
    if uid==session["user_id"]:
        session["flash"]=[("Cannot delete your own account.","er2")]
        return redirect("/admin")
    db=get_db()
    db.execute("DELETE FROM users WHERE id=?",(uid,))
    db.commit();db.close()
    session["flash"]=[("User deleted.","ok2")]
    return redirect("/admin")

@app.route("/admin/users/<int:uid>/sites",methods=["POST"])
@admin_required
def admin_set_sites(uid):
    selected=request.form.getlist("sites")
    db=get_db()
    db.execute("DELETE FROM user_sites WHERE user_id=?",(uid,))
    for name in selected:
        db.execute("INSERT OR IGNORE INTO user_sites(user_id,site_name)VALUES(?,?)",(uid,name))
    db.commit();db.close()
    session["flash"]=[("Assignments saved.","ok2")]
    return redirect("/admin#assign")

@app.route("/admin/change-password",methods=["POST"])
@admin_required
def admin_change_pw():
    current=request.form.get("current_pw","")
    new_pw=request.form.get("new_pw","")
    confirm=request.form.get("confirm_pw","")
    db=get_db()
    user=db.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
    if not check_password_hash(user["password"],current):
        session["flash"]=[("Current password incorrect.","er2")]
    elif new_pw!=confirm:
        session["flash"]=[("Passwords do not match.","er2")]
    elif len(new_pw)<8:
        session["flash"]=[("Minimum 8 characters.","er2")]
    else:
        db.execute("UPDATE users SET password=? WHERE id=?",(generate_password_hash(new_pw),session["user_id"]))
        db.commit()
        session["flash"]=[("Password updated.","ok2")]
    db.close()
    return redirect("/admin#pw")


@app.route("/site/<site_name>/", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
@app.route("/site/<site_name>/<path:subpath>", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
def proxy_site(site_name, subpath=""):
    # Custom auth check that ignores Authorization header
    # (Authorization is for the downstream device, not our dashboard)
    if "user_id" not in session:
        return redirect("/login")
    user = cu()
    # ── Audit logging ─────────────────────────────────────────
    _skip = (".css",".js",".png",".jpg",".jpeg",".ico",
             ".woff",".woff2",".svg",".gif",".map",".ttf")
    if subpath.startswith("device/"):
        _dp = subpath.strip("/").split("/")
        if len(_dp) >= 2 and (len(_dp) <= 3 or _dp[3:] == [""]):
            record_audit_event("device_open", site_name,
                               device_ip=_dp[1],
                               device_port=_dp[2] if len(_dp) > 2 else "80")
    elif not any(subpath.endswith(x) for x in _skip) and subpath == "":
        record_audit_event("site_open", site_name)
    # ── End audit logging ─────────────────────────────────────
    if site_name not in get_user_site_names(user["id"], user["is_admin"]):
        return "Access denied", 403
    site = next((s for s in load_sites() if s["name"] == site_name), None)
    if not site:
        return "Site not found", 404
    vpn_ip = site["vpn_ip"]
    target = f"http://{vpn_ip}/{subpath}"
    if request.query_string:
        target += "?" + request.query_string.decode()
    try:
        fwd_headers = {k:v for k,v in request.headers
                       if k.lower() not in ("host","content-length","transfer-encoding","referer","origin")}
        # For device requests, only forward device-specific cookies (not dashboard session)
        if subpath.startswith("device/"):
            import re as _rc
            raw_cookie = fwd_headers.get("Cookie","")
            device_cookies = ";".join(c for c in raw_cookie.split(";")
                if not any(x in c.strip() for x in ("session=",)))
            if device_cookies.strip():
                fwd_headers["Cookie"] = device_cookies
            elif "Cookie" in fwd_headers:
                del fwd_headers["Cookie"]
        if "Authorization" in request.headers:
            fwd_headers["Authorization"] = request.headers["Authorization"]
        resp = requests.request(
            method=request.method,
            url=target,
            headers=fwd_headers,
            data=request.get_data(),
            timeout=300,
            allow_redirects=False,
        )
        # Rewrite Location headers so redirects stay in the proxy chain
        if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
            import re as _rloc
            loc = resp.headers.get("Location", "")
            # Rewrite absolute URLs with IP addresses
            loc = _rloc.sub(
                r'https?://(\d+\.\d+\.\d+\.\d+)(?::(\d+))?(/.*)?',
                lambda m: f"/site/{site_name}/device/{m.group(1)}/{m.group(2) or '80'}{m.group(3) or '/'}",
                loc
            )
            # Rewrite absolute paths in Location header
            if loc.startswith("/") and not loc.startswith("/site/"):
                # subpath looks like: device/192.168.0.100/80/something
                parts = subpath.strip("/").split("/")
                if len(parts) >= 3 and parts[0] == "device":
                    # Keep same device ip/port, just update the path
                    dev_ip   = parts[1]
                    dev_port = parts[2]
                    # Only rewrite if loc doesnt already have device in it
                    if not loc.startswith("/device/"):
                        loc = f"/site/{site_name}/device/{dev_ip}/{dev_port}{loc}"
                    else:
                        loc = f"/site/{site_name}{loc}"
            # Update the response headers
            excluded_loc = [k for k in resp.headers if k.lower() != "location"]
            new_headers = {k:v for k,v in resp.headers.items() if k.lower() != "location"}
            new_headers["Location"] = loc
            body = resp.content
            return body, resp.status_code, new_headers

        # Pass 401 responses straight through with auth headers
        if resp.status_code == 401:
            print(f"[proxy] 401 passthrough for {subpath} WWW-Auth={resp.headers.get('WWW-Authenticate','NONE')}", flush=True)
            auth_headers = {k:v for k,v in resp.headers.items()
                           if k.lower() not in ("content-encoding","transfer-encoding","connection")}
            return resp.content, 401, auth_headers

        # Rewrite HTML responses to fix URLs
        content_type = resp.headers.get("Content-Type","") or resp.headers.get("ContentType","")
        print(f"[proxy] {subpath[:50]} ct={repr(content_type)} status={resp.status_code}", flush=True)
        body = resp.content
        if ("text/html" in content_type or "text/html" in resp.headers.get("ContentType","") or "javascript" in content_type or "text/css" in content_type) and subpath.startswith("device/"):
            import re as _re
            # Build correct base path for this device
            dev_parts = subpath.strip("/").split("/")
            if len(dev_parts) >= 3 and dev_parts[0] == "device":
                base_path = f"/site/{site_name}/device/{dev_parts[1]}/{dev_parts[2]}/"
            else:
                base_path = f"/site/{site_name}/"
            base = base_path.encode()
            # Inject single <base> tag for relative URL resolution
            # Rewrite absolute paths in HTML using full device base path
            site_base = f"/site/{site_name}".encode()
            dev_base = base_path.rstrip("/").encode()
            body = body.replace(b'href="/', b'href="' + dev_base + b'/')
            body = body.replace(b'src="/', b'src="' + dev_base + b'/')
            body = body.replace(b"href='/", b"href='" + dev_base + b'/')
            body = body.replace(b"src='/", b"src='" + dev_base + b'/')
            # action= rewrite removed - base tag handles this
            body = body.replace(b'url(/', dev_base + b'/')
            # Rewrite CSS relative ../paths (e.g. Grandstream GXP style.css)
            if b'url("../' in body or b"url('../" in body or b'url(../' in body:
                body = body.replace(b'url("../', b'url("' + dev_base + b'/')
                body = body.replace(b"url('../", b"url('" + dev_base + b"/")
                body = body.replace(b'url(../', b'url(' + dev_base + b'/')
            # Rewrite GWT absolute paths in JavaScript (e.g. Grandstream GXP)
            body = body.replace(b"='/style.css'", b"='" + dev_base + b"/style.css'")
            body = body.replace(b'="/style.css"', b'="' + dev_base + b'/style.css"')
            # Rewrite cgi-bin absolute paths in HTML and JS
            body = body.replace(b"url: '/cgi-bin/", b"url: '" + dev_base + b"/cgi-bin/")
            body = body.replace(b'url: "/cgi-bin/', b'url: "' + dev_base + b'/cgi-bin/')
            body = body.replace(b"url:'/cgi-bin/", b"url:'" + dev_base + b"/cgi-bin/")
            body = body.replace(b'url:"/cgi-bin/', b'url:"' + dev_base + b'/cgi-bin/')
            body = body.replace(b"action: '/cgi-bin/", b"action: '" + dev_base + b"/cgi-bin/")
            body = body.replace(b'action: "/cgi-bin/', b'action: "' + dev_base + b'/cgi-bin/')
            body = body.replace(b'url("/', dev_base + b'/')
            body = body.replace(b'background:url(/', b'background:url(' + dev_base + b'/')
            # Rewrite window.location /device/ absolute paths
            body = body.replace(b'window.location ="/device/', b'window.location ="' + b"/site/" + site_name.encode() + b'/device/')
            body = body.replace(b"window.location ='/device/", b"window.location ='" + b"/site/" + site_name.encode() + b"/device/")
            body = body.replace(b'window.location="/device/', b'window.location="' + b"/site/" + site_name.encode() + b'/device/')
            body = body.replace(b"window.location='/device/", b"window.location='" + b"/site/" + site_name.encode() + b"/device/")
            body = body.replace(b'window.location.href ="/device/', b'window.location.href ="' + b"/site/" + site_name.encode() + b'/device/')
            body = body.replace(b"window.location.href ='/device/", b"window.location.href ='" + b"/site/" + site_name.encode() + b"/device/")
            body = body.replace(b'window.location.href="/device/', b'window.location.href="' + b"/site/" + site_name.encode() + b'/device/')
            body = body.replace(b"window.location.href='/device/", b"window.location.href='" + b"/site/" + site_name.encode() + b"/device/")
            body = _re.sub(
                rb'(get_E|post_E|send)\s*\(["\'](/servlet)',
                lambda m: m.group(1) + b'("' + dev_base + m.group(2),
                body
            )
            # Rewrite JS window.location absolute paths
            body = body.replace(b'window.location.href ="\/', b'window.location.href ="' + dev_base + b'/')
            body = body.replace(b"window.location.href ='/", b"window.location.href ='" + dev_base + b"/")
            body = body.replace(b'window.location.href ="\/', b'window.location.href ="' + dev_base + b'/')
            body = body.replace(b"window.location.href ='/", b"window.location.href ='" + dev_base + b"/")
            # Inject base tag AFTER rewrites to avoid double-rewriting
            # Skip base tag for pbx proxy requests - RPi already handles rewriting
            if "/pbx/" not in subpath:
                import re as _bre
                body = _bre.sub(
                    b'(<head>|<HEAD>)',
                    b'\1<base href="' + base + b'">',
                    body, count=1)
            # Rewrite device endpoint links
            def rewrite_device_url(m):
                ip = m.group(1).decode()
                port = m.group(2).decode() if m.group(2) else "80"
                return f'href="/site/{site_name}/device/{ip}/{port}/"'.encode()
            body = _re.sub(
                rb'href="https?://(\d+\.\d+\.\d+\.\d+)(?::(\d+))?/"',
                rewrite_device_url, body
            )

        # Rewrite API URLs in Device Browser HTML
        if "text/html" in content_type and not subpath.startswith("device/"):
            site_prefix = f"/site/{site_name}".encode()
            body = body.replace(b'fetch("/api/', b'fetch("' + site_prefix + b'/api/')
            body = body.replace(b'fetch("/api/', b'fetch("' + site_prefix + b'/api/')
            body = body.replace(b'"/api/scan"', b'"' + site_prefix + b'/api/scan"')
            body = body.replace(b'"/api/state"', b'"' + site_prefix + b'/api/state"')
        excluded = ("content-encoding","content-length","transfer-encoding","connection")
        headers = {k:v for k,v in resp.headers.items() if k.lower() not in excluded}
        # Pass auth challenge and cookies through
        if "WWW-Authenticate" in resp.headers:
            headers["WWW-Authenticate"] = resp.headers["WWW-Authenticate"]
        if "Set-Cookie" in resp.headers:
            headers["Set-Cookie"] = resp.headers["Set-Cookie"]
        headers.pop("Content-Length", None)
        headers.pop("content-length", None)

        # Rewrite device URLs in JSON API responses so they route through the RPi proxy
        if "application/json" in resp.headers.get("Content-Type","") or subpath.startswith("api/"):
            try:
                import json as _json, re as _re
                text = body.decode("utf-8", errors="ignore")
                # Replace http(s)://192.168.x.x:port with /device/ip/port
                def fix_url(m):
                    ip     = m.group(1)
                    port   = m.group(2) if m.group(2) else "80"
                    return f"/site/{site_name}/device/{ip}/{port}/"
                    return f"/site/{site_name}/device/{ip}/{port}"
                text = _re.sub(
                    r'https?://(\d+\.\d+\.\d+\.\d+)(?::(\d+))?',
                    fix_url, text
                )
                body = text.encode("utf-8")
            except Exception as je:
                print(f"[proxy] JSON rewrite error: {je}")

        return body, resp.status_code, headers
    except Exception as e:
        return f"Could not reach {site_name}: {e}", 503


import subprocess as _sp
import smtplib, ssl as _ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders as _enc

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
SMTP_USER = "nimbusmonitor922@gmail.com"
SMTP_PASS = "mnlwteqnxgrocwvp"
SMTP_FROM = "noreply@cqsimple.com"
PORTAL_URL = "http://10.9.0.1:8080"

def _send_email(to_addr, subject, html_body, attachment_path=None, attachment_name=None):
    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"] = f"Bridge_Phone <{SMTP_FROM}>"
    msg["To"] = to_addr
    msg["Reply-To"] = "support@cqsimple.com"
    msg.attach(MIMEText(html_body, "html"))
    if attachment_path:
        with open(attachment_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
        _enc.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{attachment_name}"')
        msg.attach(part)
    ctx = _ssl.create_default_context()
    with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx) as s:
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(SMTP_USER, to_addr, msg.as_string())


@app.route("/admin/wg-users")
@admin_required
def admin_wg_users():
    import json as _json
    try:
        wg_users = _json.load(open("/etc/wireguard/users.json"))
    except:
        wg_users = []
    try:
        wg_out = _sp.check_output(["wg","show","wg0"],stderr=_sp.DEVNULL).decode()
    except:
        wg_out = ""
    msgs = session.pop("flash", [])

    rows = ""
    for u in wg_users:
        connected = u["public_key"] in wg_out
        badge = ('<span style="background:rgba(240,123,16,.13);color:#F07B10;border:1px solid ' +
                 'rgba(63,185,80,.28);border-radius:10px;padding:2px 8px;font-size:.7rem;' +
                 'font-weight:600">Connected</span>' if connected else
                 '<span style="background:rgba(255,255,255,.05);color:#8b949e;border:1px solid ' +
                 '#21262d;border-radius:10px;padding:2px 8px;font-size:.7rem;' +
                 'font-weight:600">Offline</span>')
        rows += (f"<tr>"
            f"<td style='padding:10px 12px;border-bottom:1px solid #21262d;font-weight:600'>{u['name']}</td>"
            f"<td style='padding:10px 12px;border-bottom:1px solid #21262d;font-family:JetBrains Mono,monospace;font-size:.8rem'>{u['ip']}</td>"
            f"<td style='padding:10px 12px;border-bottom:1px solid #21262d'>{badge}</td>"
            f"<td style='padding:10px 12px;border-bottom:1px solid #21262d;font-size:.75rem;color:#8b949e'>{u.get('created','')}</td>"
            f"<td style='padding:10px 12px;border-bottom:1px solid #21262d;text-align:right'>"
            f"<div style='display:flex;flex-direction:column;gap:4px;align-items:flex-end'><div style='display:flex;gap:6px'><a href='/admin/wg-users/{u['name']}/download' style='background:rgba(88,166,255,.12);color:#58a6ff;border:1px solid rgba(88,166,255,.28);border-radius:6px;padding:4px 10px;font-size:.72rem;text-decoration:none'>Download Config</a><a href='/admin/wg-users/{u['name']}/send-credentials' style='background:rgba(63,185,80,.12);color:#3fb950;border:1px solid rgba(63,185,80,.28);border-radius:6px;padding:4px 10px;font-size:.72rem;text-decoration:none'>Send Credentials</a><a href='/admin/wg-users/{u['name']}/send-password' style='background:rgba(240,123,16,.12);color:#F07B10;border:1px solid rgba(240,123,16,.28);border-radius:6px;padding:4px 10px;font-size:.72rem;text-decoration:none'>Send Password</a></div></div>"
            f"<form method='POST' action='/admin/wg-users/{u['name']}/delete' onsubmit='return confirm(\"Remove {u['name']}?\")' style='display:inline'>"
            f"<button style='background:rgba(248,81,73,.12);color:#f85149;border:1px solid rgba(248,81,73,.28);border-radius:6px;padding:4px 10px;font-size:.72rem;cursor:pointer'>Remove</button>"
            f"</form></td></tr>")

    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>VPN Users</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Sora:wght@400;600&display=swap" rel="stylesheet">
    <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#0d1117;color:#e6edf3;font-family:'Sora',sans-serif;min-height:100vh}}
    header{{background:#161b22;border-bottom:1px solid #21262d;padding:14px 28px;display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:100}}
    .logo{{font-family:'JetBrains Mono',monospace;font-size:1rem;font-weight:600;color:#58a6ff}}
    .logo span{{color:#3fb950}}
    .nav{{margin-left:auto;display:flex;gap:8px}}
    .nav a{{font-size:.78rem;padding:5px 11px;border-radius:6px;color:#8b949e;font-family:'JetBrains Mono',monospace;text-decoration:none}}
    .nav a:hover{{background:rgba(255,255,255,.06);color:#e6edf3}}
    main{{max-width:900px;margin:0 auto;padding:28px 20px}}
    h2{{font-size:1.05rem;font-weight:600;margin-bottom:16px}}
    .flash{{padding:9px 14px;border-radius:7px;margin-bottom:16px;font-size:.82rem}}
    .ok2{{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.28);color:#3fb950}}
    .er2{{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.28);color:#f85149}}
    .card{{background:#161b22;border:1px solid #21262d;border-radius:10px;overflow:hidden;margin-bottom:18px}}
    .ch{{padding:12px 16px;background:#1c2128;border-bottom:1px solid #21262d}}
    .cb{{padding:14px 16px}}
    label{{display:block;font-size:.72rem;color:#8b949e;margin-bottom:4px;text-transform:uppercase;letter-spacing:.04em}}
    input{{width:100%;background:#1c2128;border:1px solid #21262d;border-radius:7px;padding:8px 11px;color:#e6edf3;font-size:.84rem;outline:none;margin-bottom:12px}}
    input:focus{{border-color:#58a6ff}}
    .fr{{display:flex;gap:10px;align-items:flex-end}}
    .fi{{flex:1}}
    .btn{{display:inline-flex;align-items:center;padding:8px 16px;border-radius:7px;border:none;font-size:.8rem;font-weight:600;cursor:pointer;font-family:'Sora',sans-serif}}
    .bp{{background:#58a6ff;color:#000}}
    table{{width:100%;border-collapse:collapse;font-size:.83rem}}
    th{{text-align:left;padding:9px 12px;font-size:.68rem;color:#8b949e;text-transform:uppercase;letter-spacing:.06em;border-bottom:1px solid #21262d;font-weight:400}}
    .info{{color:#8b949e;font-size:.82rem;margin-bottom:18px;line-height:1.6}}
    </style></head><body>
    <header>
      <div class="logo"><img src="/static/logo.png" style="height:36px;vertical-align:middle;margin-right:8px"> Bridge_Phone</div>
      <div class="nav">
        <a href="/">Dashboard</a>
        <a href="/admin">Admin</a>
        <a href="/admin/wg-users" style="color:#58a6ff;background:rgba(88,166,255,.1)">VPN Users</a>
        <a href="/logout">Sign out</a>
      </div>
    </header>
    <main>
      {"".join(f'<div class="flash {c}">{m}</div>' for m,c in msgs)}
      <h2>WireGuard VPN Users</h2>
      <p class="info">Each user needs a WireGuard config file to access the dashboard.
        Add them below then send them the downloaded .conf file to import into the
        WireGuard app on Windows, Mac, iOS or Android.</p>
      <div class="card" style="margin-bottom:20px">
        <div class="ch"><strong>Add VPN User</strong></div>
        <div class="cb">
          <form method="POST" action="/admin/wg-users/add">
            <div class="fr">
              <div class="fi"><label>Username</label>
                <input name="username" placeholder="e.g. alice" required></div>
              <div class="fi"><label>Email Address</label>
                <input name="email" type="email" placeholder="user@example.com" required></div>
              <div style="padding-bottom:12px">
                <button class="btn bp" type="submit">Add User</button></div>
            </div>
          </form>
        </div>
      </div>
      <div class="card">
        <table>
          <thead><tr><th>Username</th><th>VPN IP</th><th>Status</th><th>Created</th><th></th></tr></thead>
          <tbody>{rows if rows else '<tr><td colspan="5" style="padding:20px;text-align:center;color:#8b949e">No VPN users yet.</td></tr>'}</tbody>
        </table>
      </div>
    </main></body></html>"""


@app.route("/admin/wg-users/add", methods=["POST"])
@admin_required
def admin_wg_users_add():
    username = request.form.get("username","").strip()
    email    = request.form.get("email","").strip()
    if not username:
        session["flash"] = [("Username required.", "er2")]
        return redirect("/admin/wg-users")
    try:
        result = _sp.check_output(
            ["bash", "/root/Wireguard_setup/02_add_wg_user.sh", username],
            stderr=_sp.STDOUT
        ).decode()
        # Store email and create portal account
        import os as _os, secrets as _sec, string as _str
        from werkzeug.security import generate_password_hash as _gph
        user_dir = f"/etc/wireguard/users/{username}"
        _os.makedirs(user_dir, exist_ok=True)
        email_file = f"{user_dir}/{username}.email"
        if email:
            with open(email_file, "w") as ef:
                ef.write(email)
        passwd_chars = _str.ascii_letters + _str.digits + "!@#$%"
        plain_pw = "".join(_sec.choice(passwd_chars) for _ in range(12))
        passwd_file = f"{user_dir}/{username}.passwd"
        with open(passwd_file, "w") as pf:
            pf.write(plain_pw)
        _os.chmod(passwd_file, 0o600)
        with get_db() as db:
            existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if not existing:
                db.execute("INSERT INTO users(username,password,is_admin) VALUES(?,?,0)",
                           (username, _gph(plain_pw)))
        session["flash"] = [(f"User '{username}' added. Download their config file below.", "ok2")]
    except _sp.CalledProcessError as e:
        session["flash"] = [(f"Error: {e.output.decode()[:300]}", "er2")]
    return redirect("/admin/wg-users")


@app.route("/admin/wg-users/<username>/send-credentials")
@admin_required
def admin_wg_send_credentials(username):
    conf_path = f"/etc/wireguard/users/{username}/{username}.conf"
    email_path = f"/etc/wireguard/users/{username}/{username}.email"
    if not os.path.exists(conf_path):
        session["flash"] = [(f"Config file not found for {username}.", "er2")]
        return redirect("/admin/wg-users")
    if not os.path.exists(email_path):
        session["flash"] = [(f"No email address on file for {username}. Delete and re-add the user with an email.", "er2")]
        return redirect("/admin/wg-users")
    with open(email_path) as ef:
        to_email = ef.read().strip()
    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:30px">
    <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)">
      <div style="background:#1B3A6B;padding:28px 32px;text-align:center">
        <h1 style="color:#F07B10;margin:0;font-size:1.6rem">Bridge_Phone</h1>
        <p style="color:#fff;margin:6px 0 0;font-size:.95rem">Secure Remote Device Management</p>
      </div>
      <div style="padding:32px">
        <h2 style="color:#1B3A6B;margin-top:0">Welcome, {username}!</h2>
        <p style="color:#444;line-height:1.7">Your Bridge_Phone VPN access has been set up. Follow the steps below to get connected.</p>

        <h3 style="color:#1B3A6B">Step 1 &mdash; Install WireGuard</h3>
        <p style="color:#444">Download and install the WireGuard app for your device:</p>
        <ul style="color:#444;line-height:2">
          <li><a href="https://www.wireguard.com/install/" style="color:#F07B10">Windows</a></li>
          <li><a href="https://apps.apple.com/us/app/wireguard/id1441195209" style="color:#F07B10">macOS (Mac App Store)</a></li>
          <li><a href="https://apps.apple.com/us/app/wireguard/id1441195209" style="color:#F07B10">iOS (iPhone / iPad)</a></li>
          <li><a href="https://play.google.com/store/apps/details?id=com.wireguard.android" style="color:#F07B10">Android</a></li>
        </ul>

        <h3 style="color:#1B3A6B">Step 2 &mdash; Import Your Config File</h3>
        <p style="color:#444;line-height:1.7">Your personal WireGuard configuration file is attached to this email (<strong>{username}.conf</strong>). Open WireGuard, click <strong>Import tunnel(s) from file</strong>, select the attached file, then click <strong>Activate</strong>.</p>
        <p style="color:#c0392b;font-size:.88rem"><strong>Important:</strong> Do not share this file with anyone. It is your personal VPN key.</p>

        <h3 style="color:#1B3A6B">Step 3 &mdash; Access the Portal</h3>
        <p style="color:#444;line-height:1.7">Once connected to VPN, open your browser and go to:</p>
        <div style="background:#1B3A6B;border-radius:8px;padding:14px;text-align:center;margin:12px 0">
          <a href="{PORTAL_URL}" style="color:#F07B10;font-size:1.1rem;font-weight:bold;text-decoration:none">{PORTAL_URL}</a>
        </div>
        <p style="color:#444;line-height:1.7">Your login credentials will be sent in a separate email.</p>

        <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
        <p style="color:#888;font-size:.85rem;line-height:1.7;text-align:center">
          Questions? Contact CQ Simple LLC<br>
          <a href="tel:19894927068" style="color:#F07B10">1-989-492-7068</a><br>
          Powered by Bridge_Phone &mdash; &copy; 2026 CQ Simple LLC
        </p>
      </div>
    </div>
    </body></html>
    """
    try:
        _send_email(to_email, "Your Bridge_Phone VPN Access", html,
                    attachment_path=conf_path, attachment_name=f"{username}.conf")
        session["flash"] = [(f"Credentials email sent to {to_email}.", "ok2")]
    except Exception as e:
        session["flash"] = [(f"Email failed: {e}", "er2")]
    return redirect("/admin/wg-users")

@app.route("/admin/wg-users/<username>/send-password")
@admin_required
def admin_wg_send_password(username):
    email_path  = f"/etc/wireguard/users/{username}/{username}.email"
    passwd_path = f"/etc/wireguard/users/{username}/{username}.passwd"
    if not os.path.exists(email_path):
        session["flash"] = [(f"No email address on file for {username}.", "er2")]
        return redirect("/admin/wg-users")
    if not os.path.exists(passwd_path):
        session["flash"] = [(f"No password on file for {username}. Password file not found.", "er2")]
        return redirect("/admin/wg-users")
    with open(email_path) as ef:
        to_email = ef.read().strip()
    with open(passwd_path) as pf:
        password = pf.read().strip()
    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:30px">
    <div style="max-width:600px;margin:0 auto;background:#fff;border-radius:10px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.1)">
      <div style="background:#1B3A6B;padding:28px 32px;text-align:center">
        <h1 style="color:#F07B10;margin:0;font-size:1.6rem">Bridge_Phone</h1>
        <p style="color:#fff;margin:6px 0 0;font-size:.95rem">Secure Remote Device Management</p>
      </div>
      <div style="padding:32px">
        <h2 style="color:#1B3A6B;margin-top:0">Your Portal Login</h2>
        <p style="color:#444;line-height:1.7">Here are your Bridge_Phone portal credentials. Keep these safe and do not share them.</p>
        <div style="background:#f8f8f8;border:1px solid #eee;border-radius:8px;padding:20px;margin:20px 0">
          <p style="margin:0 0 8px;color:#444"><strong>Username:</strong> <span style="font-family:monospace;color:#1B3A6B">{username}</span></p>
          <p style="margin:0;color:#444"><strong>Password:</strong> <span style="font-family:monospace;color:#1B3A6B">{password}</span></p>
        </div>
        <p style="color:#444;line-height:1.7">Visit the portal at <a href="{PORTAL_URL}" style="color:#F07B10">{PORTAL_URL}</a> after connecting to VPN.</p>
        <p style="color:#c0392b;font-size:.88rem"><strong>Security tip:</strong> You will be prompted to change your password on first login. Please do so immediately.</p>
        <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
        <p style="color:#888;font-size:.85rem;line-height:1.7;text-align:center">
          Questions? Contact CQ Simple LLC<br>
          <a href="tel:19894927068" style="color:#F07B10">1-989-492-7068</a><br>
          Powered by Bridge_Phone &mdash; &copy; 2026 CQ Simple LLC
        </p>
      </div>
    </div>
    </body></html>
    """
    try:
        _send_email(to_email, "Your Bridge_Phone Portal Password", html)
        session["flash"] = [(f"Password email sent to {to_email}.", "ok2")]
    except Exception as e:
        session["flash"] = [(f"Email failed: {e}", "er2")]
    return redirect("/admin/wg-users")

@app.route("/admin/wg-users/<username>/download")
@admin_required
def admin_wg_users_download(username):
    from flask import Response
    conf_path = f"/etc/wireguard/users/{username}/{username}.conf"
    if not os.path.exists(conf_path):
        return f"Config not found for {username}", 404
    return Response(
        open(conf_path).read(),
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={username}-vpn.conf"}
    )


@app.route("/admin/wg-users/<username>/delete", methods=["POST"])
@admin_required
def admin_wg_users_delete(username):
    try:
        result = _sp.check_output(
            ["bash", "/root/Wireguard_setup/03_remove_wg_user.sh", username],
            stderr=_sp.STDOUT
        ).decode()
        session["flash"] = [(f"User '{username}' removed.", "ok2")]
    except _sp.CalledProcessError as e:
        session["flash"] = [(f"Error: {e.output.decode()[:300]}", "er2")]
    return redirect("/admin/wg-users")


@app.route("/admin/new-site")
@admin_required
def admin_new_site():
    msgs = session.pop("flash", [])
    sites = load_sites()

    # Calculate what the next VPN IP will be
    existing_ccd = len([s for s in sites])
    site_num = existing_ccd + 1
    next_ip = f"10.8.{site_num // 254}.{(site_num % 254) + 1}"
    next_name = f"rpi-site-{existing_ccd + 1}"

    site_rows = "".join(f"""<tr>
        <td style='padding:9px 12px;border-bottom:1px solid #21262d;
            font-family:JetBrains Mono,monospace;font-size:.8rem'>{s['name']}</td>
        <td style='padding:9px 12px;border-bottom:1px solid #21262d'>{s['label']}</td>
        <td style='padding:9px 12px;border-bottom:1px solid #21262d;
            font-family:JetBrains Mono,monospace;font-size:.8rem;
            color:#58a6ff'>{s['vpn_ip']}</td>
        <td style='padding:9px 12px;border-bottom:1px solid #21262d;text-align:right'>
            <a href='/admin/new-site/{s["name"]}/download-ovpn'
               style='background:rgba(88,166,255,.12);color:#58a6ff;
               border:1px solid rgba(88,166,255,.28);border-radius:6px;
               padding:4px 10px;font-size:.72rem;text-decoration:none;margin-right:6px'>
               Download .ovpn</a>
            <a href='/admin/new-site/{s["name"]}/download-package'
               style='background:rgba(63,185,80,.12);color:#3fb950;
               border:1px solid rgba(63,185,80,.28);border-radius:6px;
               padding:4px 10px;font-size:.72rem;text-decoration:none;margin-right:6px'>
               &#8659; Download Setup Package</a>
            <form method='POST' action='/admin/new-site/{s["name"]}/delete'
               onsubmit="return confirm('Delete this site? This will revoke the VPN certificate and cannot be undone.')"
               style='display:inline'>
               <button style='background:rgba(248,81,73,.12);color:#f85149;
               border:1px solid rgba(248,81,73,.28);border-radius:6px;
               padding:4px 10px;font-size:.72rem;cursor:pointer'>Delete</button>
            </form>
        </td>
    </tr>""" for s in sites)

    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
    <title>New Site — VPN Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Sora:wght@400;600&display=swap" rel="stylesheet">
    <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:#0d1117;color:#e6edf3;font-family:'Sora',sans-serif;min-height:100vh}}
    header{{background:#161b22;border-bottom:1px solid #21262d;padding:14px 28px;
        display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:100}}
    .logo{{font-family:'JetBrains Mono',monospace;font-size:1rem;font-weight:600;color:#58a6ff}}
    .logo span{{color:#3fb950}}
    .nav{{margin-left:auto;display:flex;gap:8px}}
    .nav a{{font-size:.78rem;padding:5px 11px;border-radius:6px;color:#8b949e;
        font-family:'JetBrains Mono',monospace;text-decoration:none}}
    .nav a:hover{{background:rgba(255,255,255,.06);color:#e6edf3}}
    main{{max-width:900px;margin:0 auto;padding:28px 20px}}
    h2{{font-size:1.05rem;font-weight:600;margin-bottom:16px}}
    h3{{font-size:.9rem;font-weight:600;margin-bottom:12px;color:#8b949e}}
    .flash{{padding:9px 14px;border-radius:7px;margin-bottom:16px;font-size:.82rem}}
    .ok2{{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.28);color:#3fb950}}
    .er2{{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.28);color:#f85149}}
    .card{{background:#161b22;border:1px solid #21262d;border-radius:10px;
        overflow:hidden;margin-bottom:20px}}
    .ch{{padding:12px 16px;background:#1c2128;border-bottom:1px solid #21262d;
        display:flex;align-items:center;justify-content:space-between}}
    .cb{{padding:16px}}
    label{{display:block;font-size:.72rem;color:#8b949e;margin-bottom:4px;
        text-transform:uppercase;letter-spacing:.04em}}
    input{{width:100%;background:#1c2128;border:1px solid #21262d;border-radius:7px;
        padding:8px 11px;color:#e6edf3;font-size:.84rem;outline:none;margin-bottom:14px}}
    input:focus{{border-color:#58a6ff}}
    .fr{{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}}
    .fi{{flex:1;min-width:180px}}
    .btn{{display:inline-flex;align-items:center;padding:8px 18px;border-radius:7px;
        border:none;font-size:.82rem;font-weight:600;cursor:pointer;
        font-family:'Sora',sans-serif;text-decoration:none}}
    .bp{{background:#58a6ff;color:#000}}
    .info{{color:#8b949e;font-size:.82rem;margin-bottom:18px;line-height:1.7}}
    .hint{{font-family:'JetBrains Mono',monospace;font-size:.75rem;color:#58a6ff;
        background:rgba(88,166,255,.08);border:1px solid rgba(88,166,255,.2);
        border-radius:6px;padding:3px 8px;display:inline-block;margin-bottom:4px}}
    table{{width:100%;border-collapse:collapse;font-size:.83rem}}
    th{{text-align:left;padding:9px 12px;font-size:.68rem;color:#8b949e;
        text-transform:uppercase;letter-spacing:.06em;
        border-bottom:1px solid #21262d;font-weight:400}}
    .steps{{display:flex;flex-direction:column;gap:10px;margin-top:4px}}
    .step{{display:flex;gap:12px;align-items:flex-start}}
    .step-num{{width:28px;height:28px;border-radius:50%;background:#58a6ff;
        color:#000;font-weight:700;font-size:.82rem;display:flex;align-items:center;
        justify-content:center;flex-shrink:0;margin-top:1px}}
    .step-text{{font-size:.84rem;line-height:1.6;color:#e6edf3;padding-top:3px}}
    </style></head><body>
    <header>
      <div class="logo"><img src="/static/logo.png" style="height:36px;vertical-align:middle;margin-right:8px"> Bridge_Phone</div>
      <div class="nav">
        <a href="/">Dashboard</a>
        <a href="/admin">Admin</a>
        <a href="/admin/new-site" style="color:#58a6ff;background:rgba(88,166,255,.1)">New Site</a>
        <a href="/admin/wg-users">VPN Users</a>
        <a href="/logout">Sign out</a>
      </div>
    </header>
    <main>
      {"".join(f'<div class="flash {c}">{m}</div>' for m,c in msgs)}

      <div style="display:flex;justify-content:flex-end;margin-bottom:16px">
        <button onclick="updateAllSites()" id="update-btn"
            style="background:rgba(63,185,80,.12);color:#3fb950;
            border:1px solid rgba(63,185,80,.28);border-radius:6px;
            padding:8px 16px;font-size:.8rem;cursor:pointer;font-family:inherit">
            &#8635; Update All Sites
        </button>
      </div>
      <div id="update-status" style="display:none;margin-bottom:16px;
          padding:10px 14px;border-radius:6px;font-size:.8rem;
          background:rgba(63,185,80,.09);border:1px solid rgba(63,185,80,.28);color:#3fb950">
      </div>
      <div class="card">
        <div class="ch"><strong>Create New RPi Site</strong></div>
        <div class="cb">
          <p class="info">
            Fill in the site details below. This will generate the VPN certificate
            and create the <code>.ovpn</code> file you need to copy to the new RPi.
          </p>
          <form method="POST" action="/admin/new-site/create">
            <div class="fr">
              <div class="fi">
                <label>Site Name (no spaces)</label>
                <div class="hint">Next suggested: {next_name}</div>
                <input name="site_name" placeholder="{next_name}"
                       value="{next_name}" required
                       pattern="[a-z0-9-]+" title="Lowercase letters, numbers and hyphens only">
              </div>
              <div class="fi">
                <label>Display Label</label>
                <input name="label" placeholder="e.g. Branch Office" required>
              </div>
              <div style="padding-bottom:14px">
                <button class="btn bp" type="submit">Generate Certificate</button>
              </div>
            </div>
          </form>
          <p style="color:#8b949e;font-size:.78rem;margin-top:4px">
            Next VPN IP will be: <span style="color:#58a6ff;font-family:JetBrains Mono,monospace">{next_ip}</span>
          </p>
        </div>
      </div>

      <div class="card">
        <div class="ch">
          <strong>Deployment Steps</strong>
        </div>
        <div class="cb">
          <div class="steps">
            <div class="step">
              <div class="step-num">1</div>
              <div class="step-text">Fill in the form above and click <b>Generate Certificate</b>.
                Download the <code>.ovpn</code> file that appears.</div>
            </div>
            <div class="step">
              <div class="step-num">2</div>
              <div class="step-text">Flash a new Raspberry Pi 3 with
                <b>Raspberry Pi OS Lite 64-bit</b> using Raspberry Pi Imager.
                Enable SSH and set a username and password in the advanced settings.</div>
            </div>
            <div class="step">
              <div class="step-num">3</div>
              <div class="step-text">Using WinSCP, copy the downloaded <code>.ovpn</code>
                file and the <code>rpi_setup.sh</code> script to the RPi.</div>
            </div>
            <div class="step">
              <div class="step-num">4</div>
              <div class="step-text">SSH into the RPi and run:<br>
                <code style="background:#1c2128;padding:4px 8px;border-radius:4px;
                font-family:JetBrains Mono,monospace;font-size:.8rem">
                sudo bash rpi_setup.sh {next_name}.ovpn</code></div>
            </div>
            <div class="step">
              <div class="step-num">5</div>
              <div class="step-text">The RPi will connect automatically.
                Go to <a href="/admin">Admin → Site Assignments</a> to assign
                the new site to users.</div>
            </div>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="ch"><strong>Existing Sites</strong>
          <span style="font-size:.75rem;color:#8b949e">{len(sites)} site{"s" if len(sites)!=1 else ""} registered</span>
        </div>
        <table>
          <thead><tr>
            <th>Site Name</th><th>Label</th><th>VPN IP</th><th></th>
          </tr></thead>
          <tbody>{site_rows if site_rows else
          '<tr><td colspan="4" style="padding:20px;text-align:center;color:#8b949e">No sites yet.</td></tr>'
          }</tbody>
        </table>
      </div>
    </main></body></html>"""


@app.route("/admin/new-site/create", methods=["POST"])
@admin_required
def admin_new_site_create():
    import re as _re
    site_name = request.form.get("site_name","").strip().lower()
    label     = request.form.get("label","").strip()

    if not site_name or not label:
        session["flash"] = [("Site name and label are required.", "er2")]
        return redirect("/admin/new-site")

    if not _re.match(r'^[a-z0-9-]+$', site_name):
        session["flash"] = [("Site name must be lowercase letters, numbers and hyphens only.", "er2")]
        return redirect("/admin/new-site")

    # Check not duplicate
    if any(s["name"] == site_name for s in load_sites()):
        session["flash"] = [(f"Site '{site_name}' already exists.", "er2")]
        return redirect("/admin/new-site")

    server_ip = "207.148.10.72"
    try:
        result = _sp.check_output(
            ["bash", "/root/02_gen_client_cert.sh", site_name, server_ip, label],
            stderr=_sp.STDOUT
        ).decode()
        session["flash"] = [(
            f"Site '{site_name}' created successfully. Download the .ovpn file below.",
            "ok2"
        )]
    except _sp.CalledProcessError as e:
        output = e.output.decode()[:400] if e.output else "Unknown error"
        session["flash"] = [(f"Error creating site: {output}", "er2")]

    return redirect("/admin/new-site")


@app.route("/admin/new-site/<site_name>/download-ovpn")
@admin_required
def admin_download_ovpn(site_name):
    from flask import Response
    ovpn_path = f"/etc/openvpn/clients/{site_name}/{site_name}.ovpn"
    if not os.path.exists(ovpn_path):
        return f"No .ovpn file found for {site_name}. Generate the certificate first.", 404
    return Response(
        open(ovpn_path).read(),
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename={site_name}.ovpn"}
    )


@app.route("/api/sites/<n>/rename", methods=["POST"])
@login_required
def api_rename_site(n):
    user = cu()
    if n not in get_user_site_names(user["id"], user["is_admin"]):
        return jsonify({"error": "Access denied"}), 403
    new_label = request.json.get("label","").strip()
    if not new_label:
        return jsonify({"error": "Label required"}), 400
    try:
        sites = load_sites()
        for s in sites:
            if s["name"] == n:
                s["label"] = new_label
                break
        with open(SITES_FILE, "w") as f:
            import json as _j
            _j.dump(sites, f, indent=2)
        # Update cache
        with _lock:
            if n in _cache:
                _cache[n]["label"] = new_label
        return jsonify({"status": "ok", "label": new_label})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/cgi-bin/<path:subpath>", methods=["GET","POST","PUT","DELETE","PATCH"])
@app.route("/admin/ajax.php", methods=["GET","POST","PUT","DELETE","PATCH"])
@app.route("/admin/assets/<path:subpath>", methods=["GET","POST","PUT","DELETE","PATCH"])
@app.route("/admin/modules/<path:subpath>", methods=["GET","POST","PUT","DELETE","PATCH"])
@app.route("/pbx/<pbx_ip>/cgi-bin/<path:subpath>", methods=["GET","POST","PUT","DELETE","PATCH"])
def device_catchall(subpath="", pbx_ip=None):
    import re as _rc
    referer = request.headers.get("Referer", "")
    print(f"[catchall] path={request.path} referer={referer}", flush=True)

    # Extract site/rpi/port from referer
    m = _rc.search(r'/site/([^/]+)/device/([^/]+)/([^/]+)/', referer)
    if not m:
        return "Cannot determine device from referer", 400

    site_name = m.group(1)
    rpi_ip    = m.group(2)
    rpi_port  = m.group(3)
    qs = ("?" + request.query_string.decode()) if request.query_string else ""

    # Check if request came from a pbx proxy page
    pbx_match = _rc.search(r'/pbx/([^/]+)/', referer)

    if request.path.startswith("/pbx/") and pbx_ip:
        # /pbx/<ip>/cgi-bin/... -> route through pbx proxy
        return redirect(
            f"/site/{site_name}/device/{rpi_ip}/{rpi_port}/pbx/{pbx_ip}/cgi-bin/{subpath}{qs}",
            code=307)

    if request.path.startswith("/cgi-bin/"):
        if pbx_match:
            # cgi-bin call from pbx page
            pbx = pbx_match.group(1)
            return redirect(
                f"/site/{site_name}/device/{rpi_ip}/{rpi_port}/pbx/{pbx}/cgi-bin/{subpath}{qs}",
                code=307)
        else:
            # cgi-bin call from direct device page
            return redirect(
                f"/site/{site_name}/device/{rpi_ip}/{rpi_port}/cgi-bin/{subpath}{qs}",
                code=307)

    if request.path.startswith("/admin/"):
        path_after_admin = request.path[len("/admin/"):]
        if pbx_match:
            pbx = pbx_match.group(1)
            return redirect(
                f"/site/{site_name}/device/{rpi_ip}/{rpi_port}/pbx/{pbx}/admin/{path_after_admin}{qs}",
                code=307)
        else:
            return redirect(
                f"/site/{site_name}/device/{rpi_ip}/{rpi_port}/admin/{path_after_admin}{qs}",
                code=307)

    return "Unhandled path", 400


@app.route("/admin/new-site/<site_name>/download-package")
@admin_required
def admin_download_package(site_name):
    import zipfile as _zf
    import io as _io
    import os as _os

    ovpn_path = f"/etc/openvpn/clients/{site_name}/{site_name}.ovpn"
    setup_path = "/root/rpi_setup.sh"

    if not _os.path.exists(ovpn_path):
        return f"No .ovpn file found for {site_name}. Generate the certificate first.", 404

    # Create zip in memory
    buf = _io.BytesIO()
    with _zf.ZipFile(buf, "w", _zf.ZIP_DEFLATED) as zf:
        zf.write(ovpn_path, f"{site_name}.ovpn")
        if _os.path.exists(setup_path):
            zf.write(setup_path, "rpi_setup.sh")
        else:
            # Fallback - download from GitHub
            try:
                import urllib.request as _ur
                url = "https://raw.githubusercontent.com/cqsimple/bridge-phone/main/scripts/rpi_setup.sh"
                with _ur.urlopen(url, timeout=10) as r:
                    zf.writestr("rpi_setup.sh", r.read())
            except:
                zf.writestr("rpi_setup.sh", "# Setup script not found - download from GitHub\n")

        # Add a README
        readme = f"""Bridge Phone - Site Setup Package
==================================
Site: {site_name}

Files included:
  {site_name}.ovpn  - VPN configuration file
  rpi_setup.sh      - Setup script

Setup Instructions:
1. Copy both files to your Raspberry Pi or Orange Pi Zero 3
2. SSH into the device
3. Run: sudo bash rpi_setup.sh {site_name}.ovpn
4. Wait 5-10 minutes for setup to complete
5. The device will connect to the VPN automatically
6. Assign the site to users in Admin > Site Assignments

Requirements:
- Raspberry Pi 3B/3B+ OR Orange Pi Zero 3
- Raspberry Pi OS Lite 64-bit OR Armbian Ubuntu
- SSH enabled, ethernet connected
"""
        zf.writestr("README.txt", readme)

    buf.seek(0)
    from flask import Response
    return Response(
        buf.getvalue(),
        mimetype="application/zip",
        headers={"Content-Disposition": f"attachment; filename={site_name}-setup.zip"}
    )


@app.route("/admin/new-site/<site_name>/delete", methods=["POST"])
@admin_required
def admin_delete_site(site_name):
    import subprocess as _sp
    import shutil as _sh

    errors = []

    # 1. Remove from sites.json
    try:
        sites = load_sites()
        sites = [s for s in sites if s["name"] != site_name]
        with open(SITES_FILE, "w") as f:
            import json as _j
            _j.dump(sites, f, indent=2)
    except Exception as e:
        errors.append(f"sites.json: {e}")

    # 2. Revoke certificate
    try:
        _sp.run(
            ["bash", "-c", f"cd /etc/openvpn/easy-rsa && ./easyrsa --batch revoke {site_name} && ./easyrsa gen-crl"],
            capture_output=True
        )
    except Exception as e:
        errors.append(f"cert revoke: {e}")

    # 3. Remove CCD entry
    try:
        ccd = f"/etc/openvpn/ccd/{site_name}"
        if os.path.exists(ccd):
            os.remove(ccd)
    except Exception as e:
        errors.append(f"ccd: {e}")

    # 4. Remove client config files
    try:
        client_dir = f"/etc/openvpn/clients/{site_name}"
        if os.path.exists(client_dir):
            _sh.rmtree(client_dir)
    except Exception as e:
        errors.append(f"client dir: {e}")

    # 5. Disconnect VPN if connected
    try:
        disconnect_client(site_name)
    except Exception as e:
        errors.append(f"disconnect: {e}")

    # 6. Remove from cache
    with _lock:
        _cache.pop(site_name, None)

    if errors:
        session["flash"] = [(f"Site deleted with warnings: {', '.join(errors)}", "ok2")]
    else:
        session["flash"] = [(f"Site '{site_name}' deleted successfully.", "ok2")]

    return redirect("/admin/new-site")


@app.route("/api/update-sites", methods=["POST"])
@admin_required
def api_update_sites():
    import subprocess as _sp
    import threading as _t
    def run_update():
        try:
            result = _sp.run(
                ["ansible-playbook",
                 "-i", "/opt/bridge-phone/ansible/inventory.ini",
                 "/opt/bridge-phone/ansible/update-sites.yml"],
                capture_output=True, text=True, timeout=300
            )
            print(f"[ansible] returncode={result.returncode}", flush=True)
            print(f"[ansible] stdout={result.stdout[-500:]}", flush=True)
            if result.stderr:
                print(f"[ansible] stderr={result.stderr[-200:]}", flush=True)
        except Exception as e:
            print(f"[ansible] error={e}", flush=True)
    _t.Thread(target=run_update, daemon=True).start()
    return jsonify({"status": "started", "message": "Update started on all sites"})


@app.route("/admin/audit")
@login_required
def audit_log_page():
    if not session.get("is_admin"):
        return redirect("/")
    import csv, io
    d          = get_db()
    username_f = request.args.get("username", "").strip()
    site_f     = request.args.get("site", "").strip()
    date_from  = request.args.get("date_from", "").strip()
    date_to    = request.args.get("date_to", "").strip()
    export     = request.args.get("export") == "1"

    q = "SELECT * FROM audit_log WHERE 1=1"
    p = []
    if username_f: q += " AND username LIKE ?";  p.append(f"%{username_f}%")
    if site_f:     q += " AND site_name=?";      p.append(site_f)
    if date_from:  q += " AND started_at >= ?";  p.append(date_from+"T00:00:00Z")
    if date_to:    q += " AND started_at <= ?";  p.append(date_to+"T23:59:59Z")
    q += " ORDER BY started_at DESC LIMIT 2000"

    rows      = d.execute(q, p).fetchall()
    all_users = [r[0] for r in d.execute("SELECT DISTINCT username FROM audit_log ORDER BY username").fetchall()]
    all_sites = [r[0] for r in d.execute("SELECT DISTINCT site_name FROM audit_log ORDER BY site_name").fetchall()]
    d.close()

    if export:
        out = io.StringIO()
        w   = csv.writer(out)
        w.writerow(["ID","User","Event","Site","Device IP","Port","Connected","Last Seen","Duration(s)","Duration"])
        for r in rows:
            m,s = divmod(r["duration_s"],60); h,m = divmod(m,60)
            fmt = (f"{h}h {m}m {s}s" if h else f"{m}m {s}s")
            w.writerow([r["id"],r["username"],r["event_type"],r["site_name"],
                        r["device_ip"] or "",r["device_port"] or "",
                        r["started_at"],r["last_seen"],r["duration_s"],fmt])
        from flask import Response
        return Response(out.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition":f"attachment; filename=audit_{_aiso(_anow())[:10]}.csv"})

    def dfmt(s):
        m,sec=divmod(s,60); h,m=divmod(m,60)
        return (f"{h}h {m}m {sec}s" if h else f"{m}m {sec}s") if m else f"{sec}s"

    def dcls(s):
        return "dur-long" if s>=600 else ("dur-mid" if s>=60 else "dur-short")

    rows_html = ""
    for r in rows:
        badge = ('<span class="badge bs">Site</span>' if r["event_type"]=="site_open"
            else '<span class="badge bd">Device</span>')
        ds = r["duration_s"]
        rows_html += (
            f"<tr><td><strong>{r['username']}</strong></td>"
            f"<td>{badge}</td><td>{r['site_name']}</td>"
            f"<td>{r['device_ip'] or '&#8212;'}</td>"
            f"<td>{r['device_port'] or '&#8212;'}</td>"
            f"<td style='white-space:nowrap'>{_afmt_est(r['started_at'])}</td>"
            f"<td style='white-space:nowrap'>{_afmt_est(r['last_seen'])}</td>"
            f"<td class='{dcls(ds)}'>{dfmt(ds)}</td></tr>"
        )

    uf  = "".join(f'<option value="{u}" {"selected" if u==username_f else ""}>{u}</option>' for u in all_users)
    sf  = "".join(f'<option value="{s}" {"selected" if s==site_f else ""}>{s}</option>' for s in all_sites)
    eqs = request.query_string.decode()
    eqs = (eqs+"&export=1") if eqs else "export=1"
    tot = len(rows)
    so  = sum(1 for r in rows if r["event_type"]=="site_open")
    do  = sum(1 for r in rows if r["event_type"]=="device_open")
    uc  = len(set(r["username"] for r in rows))
    sc  = len(set(r["site_name"] for r in rows))
    empty = '<div class="empty"><div style="font-size:48px;opacity:.3">&#128203;</div><div>No records match your filters.</div></div>' if not rows else ""
    tbl   = "" if not rows else (
        '<div class="tw"><table>'
        '<thead><tr><th>User</th><th>Event</th><th>Site</th>'
        '<th>Device IP</th><th>Port</th>'
        '<th>Connected</th><th>Last Seen</th><th>Duration</th></tr></thead>'
        f'<tbody>{rows_html}</tbody></table></div>'
    )

    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Audit Log</title><style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}}
header{{display:flex;align-items:center;justify-content:space-between;padding:0 24px;height:52px;background:#161b22;border-bottom:1px solid #30363d}}
.logo{{font-weight:700;font-size:16px;color:#58a6ff}}
.nav a{{color:#8b949e;text-decoration:none;font-size:13px;margin-left:16px;padding:4px 8px;border-radius:5px}}
.nav a:hover{{color:#e6edf3;background:#21262d}}
.nav a.act{{color:#58a6ff;background:rgba(88,166,255,.1)}}
.wrap{{max-width:1400px;margin:0 auto;padding:28px 20px}}
.ph{{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;flex-wrap:wrap;gap:12px}}
.ph h1{{font-size:20px;font-weight:700;color:#e6edf3}}
.ph .sub{{font-size:12px;color:#8b949e;margin-top:3px}}
.bex{{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:#238636;border:1px solid #2ea043;border-radius:6px;color:#fff;font-size:13px;font-weight:500;text-decoration:none}}
.bex:hover{{background:#2ea043}}
.fb{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:16px 20px;margin-bottom:20px;display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end}}
.fb label{{font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.4px;display:flex;flex-direction:column;gap:5px}}
.fb input,.fb select{{padding:7px 10px;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:13px;min-width:140px}}
.fb input:focus,.fb select:focus{{outline:none;border-color:#58a6ff}}
.bfi{{padding:8px 18px;background:#1f6feb;color:#fff;border:none;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer}}
.bfi:hover{{background:#388bfd}}
.brs{{padding:8px 14px;background:#21262d;color:#8b949e;border:1px solid #30363d;border-radius:6px;font-size:13px;cursor:pointer;text-decoration:none}}
.brs:hover{{background:#30363d;color:#e6edf3}}
.sr{{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap}}
.sc{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 20px;min-width:120px}}
.sc .v{{font-size:22px;font-weight:700;color:#58a6ff}}
.sc .l{{font-size:11px;color:#8b949e;margin-top:2px}}
.tw{{overflow-x:auto;border-radius:10px;border:1px solid #30363d}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
thead th{{background:#1f4080;color:#e6edf3;padding:11px 14px;text-align:left;white-space:nowrap;font-weight:600}}
tbody tr{{border-bottom:1px solid #21262d}}
tbody tr:last-child{{border-bottom:none}}
tbody tr:hover{{background:#161b22}}
tbody td{{padding:10px 14px;vertical-align:middle;color:#c9d1d9}}
.badge{{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.4px}}
.bs{{background:rgba(88,166,255,.15);color:#58a6ff}}
.bd{{background:rgba(63,185,80,.15);color:#3fb950}}
.dur-short{{color:#6e7681}}.dur-mid{{color:#d29922}}.dur-long{{color:#f85149;font-weight:600}}
.empty{{text-align:center;padding:60px 20px;color:#6e7681}}
</style></head><body>
<header>
  <div class="logo">&#127751; Bridge Phone</div>
  <div class="nav">
    <a href="/">Dashboard</a><a href="/admin">Admin</a>
    <a href="/admin/new-site">New Site</a><a href="/admin/wg-users">VPN Users</a>
    <a href="/admin/audit" class="act">Audit Log</a><a href="/logout">Sign out</a>
  </div>
</header>
<div class="wrap">
  <div class="ph">
    <div><h1>Audit Log</h1><div class="sub">Device access history &#8212; last 6 months</div></div>
    <a class="bex" href="/admin/audit?{eqs}">&#11015; Export CSV</a>
  </div>
  <form class="fb" method="get">
    <label>User<select name="username"><option value="">All users</option>{uf}</select></label>
    <label>Site<select name="site"><option value="">All sites</option>{sf}</select></label>
    <label>From<input type="date" name="date_from" value="{date_from}"></label>
    <label>To<input type="date" name="date_to" value="{date_to}"></label>
    <button type="submit" class="bfi">Filter</button>
    <a href="/admin/audit" class="brs">Reset</a>
  </form>
  <div class="sr">
    <div class="sc"><div class="v">{tot}</div><div class="l">Total events</div></div>
    <div class="sc"><div class="v">{uc}</div><div class="l">Users</div></div>
    <div class="sc"><div class="v">{so}</div><div class="l">Site opens</div></div>
    <div class="sc"><div class="v">{do}</div><div class="l">Device opens</div></div>
    <div class="sc"><div class="v">{sc}</div><div class="l">Sites accessed</div></div>
  </div>
  {empty}{tbl}
</div></body></html>"""


# ════════════════════════════════════════════════════════════
# VPS SITES — SSH tunnel management
# ════════════════════════════════════════════════════════════
import subprocess as _sp
import threading as _vth
import time as _vtime

_vps_tunnels = {}   # id -> {proc, local_port, started_at, last_used}
_vps_sessions = {}  # id -> requests.Session()
_vps_lock    = threading.Lock()
_VPS_IDLE_TIMEOUT = 1800  # 30 minutes

def _next_tunnel_port():
    used = {v["local_port"] for v in _vps_tunnels.values()}
    port = 19000
    while port in used:
        port += 1
    return port

def _start_tunnel(site_id, ip, ssh_user, ssh_password, web_port):
    with _vps_lock:
        if site_id in _vps_tunnels:
            t = _vps_tunnels[site_id]
            t["last_used"] = _vtime.time()
            # Check tunnel still alive
            if t.get("tunnel_obj") and t["tunnel_obj"].is_alive:
                return t["local_port"]
            # Tunnel dead - clean up
            try:
                t.get("tunnel_obj") and t["tunnel_obj"].stop()
            except:
                pass
            del _vps_tunnels[site_id]
        local_port = _next_tunnel_port()
        try:
            import shutil as _sh
            sshpass = _sh.which("sshpass")
            from sshtunnel import SSHTunnelForwarder as _SSTF
            tunnel_obj = _SSTF(
                ip,
                ssh_username=ssh_user,
                ssh_password=ssh_password,
                local_bind_address=("127.0.0.1", local_port),
                remote_bind_address=("127.0.0.1", web_port),
                set_keepalive=10,
            )
            tunnel_obj.start()
            _vtime.sleep(2)
            if not tunnel_obj.is_alive:
                tunnel_obj.stop()
                return None
            _vps_tunnels[site_id] = {
                "tunnel_obj": tunnel_obj,
                "proc": type("FakeProc", (), {"poll": lambda self: None, "terminate": lambda self: None})(),
                "local_port": local_port,
                "started_at": _vtime.time(), "last_used": _vtime.time()
            }
            if site_id in _vps_sessions:
                del _vps_sessions[site_id]
            return local_port
            print(f"[vps tunnel] Starting: {cmd}", flush=True)
            proc = _sp.Popen(cmd, stdout=_sp.DEVNULL, stderr=_sp.DEVNULL)
            _vtime.sleep(4)
            if proc.poll() is not None:
                print(f"[vps tunnel] Process died with returncode={proc.returncode}", flush=True)
                return None
            # Verify port is actually listening
            import socket as _sock
            try:
                _s = _sock.create_connection(("127.0.0.1", local_port), timeout=3)
                _s.close()
                print(f"[vps tunnel] Port {local_port} confirmed listening", flush=True)
                # Port is up - register tunnel and return immediately
                _vps_tunnels[site_id] = {
                    "proc": proc, "local_port": local_port,
                    "started_at": _vtime.time(), "last_used": _vtime.time()
                }
                if site_id in _vps_sessions:
                    del _vps_sessions[site_id]
                return local_port
            except Exception as _se:
                print(f"[vps tunnel] Port {local_port} not listening: {_se}", flush=True)
                proc.terminate()
                return None
            _vtime.sleep(3)
            if proc.poll() is not None:
                print(f"[vps tunnel] Process died with returncode={proc.returncode}", flush=True)
                return None
            # Make a test connection to keep tunnel alive
            try:
                import socket as _sock
                _s = _sock.create_connection(("127.0.0.1", local_port), timeout=2)
                _s.close()
            except:
                pass
            _vtime.sleep(2)
            if proc.poll() is not None:
                pass  # process died
                print(f"[vps tunnel] Process died with returncode={proc.returncode}", flush=True)
                return None
            _vps_tunnels[site_id] = {
                "proc": proc, "local_port": local_port,
                "started_at": _vtime.time(), "last_used": _vtime.time()
            }
            # Clear any stale FreePBX session on new connection
            if site_id in _vps_sessions:
                del _vps_sessions[site_id]
            return local_port
        except Exception as e:
            print(f"[vps tunnel] {e}", flush=True)
            return None

def _stop_tunnel(site_id):
    with _vps_lock:
        if site_id in _vps_tunnels:
            try:
                t = _vps_tunnels[site_id]
                if t.get("tunnel_obj"):
                    t["tunnel_obj"].stop()
            except:
                pass
            del _vps_tunnels[site_id]
    if site_id in _vps_sessions:
        del _vps_sessions[site_id]

def _tunnel_watchdog():
    while True:
        _vtime.sleep(30)
        now = _vtime.time()
        # Auto-close idle tunnels
        with _vps_lock:
            stale = [sid for sid, t in _vps_tunnels.items()
                     if now - t["last_used"] > _VPS_IDLE_TIMEOUT]
        for sid in stale:
            print(f"[vps tunnel] auto-closing idle tunnel {sid}", flush=True)
            _stop_tunnel(sid)

threading.Thread(target=_tunnel_watchdog, daemon=True).start()


@app.route("/admin/vps-sites")
@login_required
def vps_sites_page():
    if not session.get("is_admin"):
        return redirect("/")
    d    = get_db()
    rows = d.execute("SELECT * FROM vps_sites ORDER BY label").fetchall()
    d.close()

    with _vps_lock:
        active = dict(_vps_tunnels)

    rows_html = ""
    for r in rows:
        sid      = r["id"]
        tunnel   = active.get(sid)
        if tunnel:
            age     = int(_vtime.time() - tunnel["started_at"])
            m, s    = divmod(age, 60)
            age_str = str(m) + "m " + str(s) + "s"
            status  = '<span class="vs-badge vs-on">&#9679; Connected (' + age_str + ')</span>'
            actions = ('<a class="vb vb-open" href="/vps/' + str(sid) + '/fpbx-login"'
                       ' target="_blank">Open FreePBX</a> '
                       '<button class="vb vb-disc" onclick="vpsDisc(' + str(sid) + ')">Disconnect</button>')
        else:
            status  = '<span class="vs-badge vs-off">&#9679; Offline</span>'
            actions = '<button class="vb vb-conn" onclick="vpsConn(' + str(sid) + ')">Connect</button>'
        ssh_str  = r["ssh_user"] + "@" + r["ip"]
        edit_fn  = ('editVps(' + str(sid) + ',"' + r["name"] + '","' + r["label"] + '","'
                    + r["ip"] + '","' + r["ssh_user"] + '","' + str(r["web_port"]) + '","'
                    + (r["notes"] or "") + '")' )
        del_fn   = 'delVps(' + str(sid) + ',"'  + r["label"].replace('"', '&quot;') + '")'
        rows_html += (
            '<tr><td><strong>' + r["label"] + '</strong><br>'
            '<span class="vsub">' + r["name"] + '</span></td>'
            '<td>' + r["ip"] + '</td><td>' + str(r["web_port"]) + '</td>'
            '<td><code class="vcode">' + ssh_str + '</code></td>'
            '<td>' + status + '</td>'
            '<td>' + actions
            + ' <button class="vb vb-edit" onclick="' + edit_fn + '">Edit</button> '
            + '<button class="vb vb-del" onclick="' + del_fn + '">Delete</button></td></tr>'
        )


    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>VPS Sites</title><style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0d1117;color:#c9d1d9;min-height:100vh}}
header{{display:flex;align-items:center;justify-content:space-between;padding:0 24px;height:52px;background:#161b22;border-bottom:1px solid #30363d}}
.logo{{font-weight:700;font-size:16px;color:#58a6ff}}
.nav a{{color:#8b949e;text-decoration:none;font-size:13px;margin-left:16px;padding:4px 8px;border-radius:5px}}
.nav a:hover,.nav a.act{{color:#e6edf3;background:#21262d}}
.nav a.act{{color:#58a6ff;background:rgba(88,166,255,.1)}}
.wrap{{max-width:1300px;margin:0 auto;padding:28px 20px}}
.ph{{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}}
.ph h1{{font-size:20px;font-weight:700;color:#e6edf3}}
.ph .sub{{font-size:12px;color:#8b949e;margin-top:3px}}
.badd{{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;background:#238636;border:1px solid #2ea043;border-radius:6px;color:#fff;font-size:13px;font-weight:500;cursor:pointer;border:none}}
.badd:hover{{background:#2ea043}}
.tw{{overflow-x:auto;border-radius:10px;border:1px solid #30363d}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
thead th{{background:#1f4080;color:#e6edf3;padding:11px 14px;text-align:left;white-space:nowrap;font-weight:600}}
tbody tr{{border-bottom:1px solid #21262d}}
tbody tr:last-child{{border-bottom:none}}
tbody tr:hover{{background:#161b22}}
tbody td{{padding:10px 14px;vertical-align:middle}}
.vsub{{font-size:11px;color:#6e7681}}
.vcode{{background:#161b22;border:1px solid #30363d;border-radius:4px;padding:2px 6px;font-size:12px;color:#79c0ff}}
.vs-badge{{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}}
.vs-on{{background:rgba(63,185,80,.15);color:#3fb950}}
.vs-off{{background:rgba(139,148,158,.1);color:#6e7681}}
.vb{{padding:5px 12px;border-radius:5px;font-size:12px;font-weight:500;cursor:pointer;border:1px solid transparent;margin-right:4px}}
.vb-conn{{background:#1f6feb;color:#fff;border-color:#1f6feb}}.vb-conn:hover{{background:#388bfd}}
.vb-open{{background:#238636;color:#fff;border-color:#2ea043;text-decoration:none;display:inline-block}}.vb-open:hover{{background:#2ea043}}
.vb-disc{{background:#da3633;color:#fff;border-color:#da3633}}.vb-disc:hover{{background:#f85149}}
.vb-edit{{background:#21262d;color:#c9d1d9;border-color:#30363d}}.vb-edit:hover{{background:#30363d}}
.vb-del{{background:rgba(218,54,51,.1);color:#f85149;border-color:rgba(218,54,51,.3)}}.vb-del:hover{{background:rgba(218,54,51,.2)}}
.empty{{text-align:center;padding:60px;color:#6e7681}}
.modal-bg{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:999;align-items:center;justify-content:center}}
.modal-bg.open{{display:flex}}
.modal{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:28px 32px;width:420px}}
.modal h2{{font-size:16px;font-weight:700;color:#e6edf3;margin-bottom:20px}}
.frow{{margin-bottom:14px}}
.frow label{{display:block;font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.4px;margin-bottom:5px}}
.frow input,.frow textarea{{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:13px;padding:8px 10px;outline:none}}
.frow input:focus,.frow textarea:focus{{border-color:#58a6ff}}
.frow textarea{{height:60px;resize:vertical}}
.fbtn{{display:flex;gap:10px;justify-content:flex-end;margin-top:20px}}
.fbtn button{{padding:8px 18px;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer}}
.fbtn .bsave{{background:#238636;color:#fff;border:1px solid #2ea043}}.fbtn .bsave:hover{{background:#2ea043}}
.fbtn .bcancel{{background:#21262d;color:#c9d1d9;border:1px solid #30363d}}.fbtn .bcancel:hover{{background:#30363d}}
.msg{{padding:10px 14px;border-radius:6px;font-size:13px;margin-bottom:16px;display:none}}
.msg.ok{{background:rgba(63,185,80,.1);border:1px solid rgba(63,185,80,.3);color:#3fb950}}
.msg.err{{background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.3);color:#f85149}}
</style></head><body>
<header>
  <div class="logo">&#127751; Bridge Phone</div>
  <div class="nav">
    <a href="/">Dashboard</a><a href="/admin">Admin</a>
    <a href="/admin/new-site">New Site</a><a href="/admin/wg-users">VPN Users</a>
    <a href="/admin/vps-sites" class="act">VPS Sites</a>
    <a href="/admin/audit">Audit Log</a><a href="/logout">Sign out</a>
  </div>
</header>
<div class="wrap">
  <div class="ph">
    <div><h1>FreePBX VPS Sites</h1><div class="sub">SSH tunnel access to remote FreePBX systems</div></div>
    <button class="badd" onclick="openAdd()">&#43; Add VPS Site</button>
  </div>
  <div id="msg" class="msg"></div>
  {'<div class="empty"><div style="font-size:48px;opacity:.3">&#128268;</div><div style="margin-top:12px">No VPS sites yet. Add one to get started.</div></div>' if not rows else
   '<div class="tw"><table><thead><tr><th>Name</th><th>IP Address</th><th>Port</th><th>SSH</th><th>Status</th><th>Actions</th></tr></thead><tbody>' + rows_html + '</tbody></table></div>'}
</div>

<!-- Add/Edit Modal -->
<div id="modal" class="modal-bg">
  <div class="modal">
    <h2 id="modal-title">Add VPS Site</h2>
    <input type="hidden" id="edit-id" value="">
    <div class="frow"><label>Site Name (no spaces)</label><input id="f-name" placeholder="pbx-clientname"></div>
    <div class="frow"><label>Label (display name)</label><input id="f-label" placeholder="Client Name"></div>
    <div class="frow"><label>IP Address</label><input id="f-ip" placeholder="1.2.3.4"></div>
    <div class="frow"><label>SSH Username</label><input id="f-user" value="root"></div>
    <div class="frow"><label>SSH Password</label><input id="f-pass" type="password"></div>
    <div class="frow"><label>Web Port</label><input id="f-port" value="80" type="number"></div>
    <div class="frow"><label>Notes (optional)</label><textarea id="f-notes"></textarea></div>
    <div class="fbtn">
      <button class="bcancel" onclick="closeModal()">Cancel</button>
      <button class="bsave" onclick="saveVps()">Save</button>
    </div>
  </div>
</div>

<script>
function showMsg(txt, ok) {{
  var m=document.getElementById("msg");
  m.textContent=txt; m.className="msg "+(ok?"ok":"err"); m.style.display="block";
  setTimeout(function(){{m.style.display="none";}}, 4000);
}}
function openAdd() {{
  document.getElementById("modal-title").textContent="Add VPS Site";
  document.getElementById("edit-id").value="";
  ["name","label","ip","pass","notes"].forEach(function(f){{document.getElementById("f-"+f).value="";}});
  document.getElementById("f-user").value="root";
  document.getElementById("f-port").value="80";
  document.getElementById("f-name").disabled=false;
  document.getElementById("modal").classList.add("open");
}}
function editVps(id,name,label,ip,user,port,notes) {{
  document.getElementById("modal-title").textContent="Edit VPS Site";
  document.getElementById("edit-id").value=id;
  document.getElementById("f-name").value=name; document.getElementById("f-name").disabled=true;
  document.getElementById("f-label").value=label;
  document.getElementById("f-ip").value=ip;
  document.getElementById("f-user").value=user;
  document.getElementById("f-pass").value="";
  document.getElementById("f-port").value=port;
  document.getElementById("f-notes").value=notes;
  document.getElementById("modal").classList.add("open");
}}
function closeModal() {{ document.getElementById("modal").classList.remove("open"); }}
function saveVps() {{
  var id=document.getElementById("edit-id").value;
  var data={{name:document.getElementById("f-name").value,
             label:document.getElementById("f-label").value,
             ip:document.getElementById("f-ip").value,
             ssh_user:document.getElementById("f-user").value,
             ssh_password:document.getElementById("f-pass").value,
             web_port:document.getElementById("f-port").value,
             notes:document.getElementById("f-notes").value}};
  var url=id?"/admin/vps-sites/"+id+"/edit":"/admin/vps-sites/add";
  fetch(url,{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify(data)}})
    .then(function(r){{return r.json();}})
    .then(function(d){{
      if(d.ok){{closeModal();showMsg(d.msg||"Saved",true);setTimeout(function(){{location.reload();}},1000);}}
      else showMsg(d.error||"Error",false);
    }});
}}
function delVps(id,label) {{
  if(!confirm("Delete "+label+"?")) return;
  fetch("/admin/vps-sites/"+id+"/delete",{{method:"POST"}})
    .then(function(r){{return r.json();}})
    .then(function(d){{
      if(d.ok){{showMsg("Deleted",true);setTimeout(function(){{location.reload();}},800);}}
      else showMsg(d.error||"Error",false);
    }});
}}
function vpsConn(id) {{
  showMsg("Connecting...",true);
  fetch("/admin/vps-sites/"+id+"/connect",{{method:"POST",credentials:"same-origin"}})
    .then(function(r){{return r.json();}})
    .then(function(d){{
      if(d.ok){{showMsg("Connected!",true);setTimeout(function(){{location.reload();}},800);}}
      else showMsg(d.error||"Connection failed",false);
    }});
}}
function vpsDisc(id) {{
  fetch("/admin/vps-sites/"+id+"/disconnect",{{method:"POST"}})
    .then(function(r){{return r.json();}})
    .then(function(d){{ showMsg("Disconnected",true);setTimeout(function(){{location.reload();}},800); }});
}}
document.getElementById("modal").addEventListener("click",function(e){{if(e.target===this)closeModal();}});
</script>
</body></html>"""


@app.route("/admin/vps-sites/add", methods=["POST"])
@login_required
def vps_sites_add():
    if not session.get("is_admin"):
        return jsonify({"error": "Access denied"}), 403
    from flask import request as _r
    data = _r.get_json()
    name     = (data.get("name") or "").strip()
    label    = (data.get("label") or "").strip()
    ip       = (data.get("ip") or "").strip()
    ssh_user = (data.get("ssh_user") or "root").strip()
    ssh_pass = (data.get("ssh_password") or "").strip()
    web_port = int(data.get("web_port") or 80)
    notes    = (data.get("notes") or "").strip()
    if not name or not label or not ip or not ssh_pass:
        return jsonify({"error": "Name, label, IP and password are required"})
    try:
        d = get_db()
        d.execute("INSERT INTO vps_sites(name,label,ip,ssh_user,ssh_password,web_port,notes) VALUES(?,?,?,?,?,?,?)",
                  (name, label, ip, ssh_user, ssh_pass, web_port, notes))
        d.commit(); d.close()
        return jsonify({"ok": True, "msg": f"Added {label}"})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/admin/vps-sites/<int:sid>/edit", methods=["POST"])
@login_required
def vps_sites_edit(sid):
    if not session.get("is_admin"):
        return jsonify({"error": "Access denied"}), 403
    from flask import request as _r
    data     = _r.get_json()
    label    = (data.get("label") or "").strip()
    ip       = (data.get("ip") or "").strip()
    ssh_user = (data.get("ssh_user") or "root").strip()
    ssh_pass = (data.get("ssh_password") or "").strip()
    web_port = int(data.get("web_port") or 80)
    notes    = (data.get("notes") or "").strip()
    try:
        d = get_db()
        if ssh_pass:
            d.execute("UPDATE vps_sites SET label=?,ip=?,ssh_user=?,ssh_password=?,web_port=?,notes=? WHERE id=?",
                      (label, ip, ssh_user, ssh_pass, web_port, notes, sid))
        else:
            d.execute("UPDATE vps_sites SET label=?,ip=?,ssh_user=?,web_port=?,notes=? WHERE id=?",
                      (label, ip, ssh_user, web_port, notes, sid))
        d.commit(); d.close()
        return jsonify({"ok": True, "msg": "Updated"})
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/admin/vps-sites/<int:sid>/delete", methods=["POST"])
@login_required
def vps_sites_delete(sid):
    if not session.get("is_admin"):
        return jsonify({"error": "Access denied"}), 403
    _stop_tunnel(sid)
    d = get_db()
    d.execute("DELETE FROM vps_sites WHERE id=?", (sid,))
    d.commit(); d.close()
    return jsonify({"ok": True})


@app.route("/admin/vps-sites/<int:sid>/connect", methods=["POST"])
@login_required
def vps_sites_connect(sid):
    if not session.get("is_admin"):
        return jsonify({"error": "Access denied"}), 403
    d    = get_db()
    row  = d.execute("SELECT * FROM vps_sites WHERE id=?", (sid,)).fetchone()
    d.close()
    if not row:
        return jsonify({"error": "Site not found"})
    port = _start_tunnel(sid, row["ip"], row["ssh_user"], row["ssh_password"], row["web_port"])
    if port:
        return jsonify({"ok": True, "local_port": port})
    return jsonify({"error": "Could not establish SSH tunnel — check IP and credentials"})


@app.route("/admin/vps-sites/<int:sid>/disconnect", methods=["POST"])
@login_required
def vps_sites_disconnect(sid):
    _stop_tunnel(sid)
    return jsonify({"ok": True})



@app.route("/vps/<int:sid>/", defaults={"subpath": ""}, methods=["GET","POST","PUT","DELETE","PATCH"])
@app.route("/vps/<int:sid>/<path:subpath>", methods=["GET","POST","PUT","DELETE","PATCH"])
@login_required
def vps_proxy(sid, subpath):
    with _vps_lock:
        tunnel = _vps_tunnels.get(sid)
    if not tunnel:
        return "VPS tunnel not connected. <a href='/admin/vps-sites'>Go to VPS Sites</a> and click Connect.", 503
    tunnel["last_used"] = _vtime.time()
    local_port = tunnel["local_port"]
    import requests as _vr
    # Fix font paths
    if subpath.startswith("fonts/"):
        subpath = "admin/assets/" + subpath
    elif "assets/less/fonts/" in subpath:
        subpath = subpath.replace("assets/less/fonts/", "assets/fonts/")
    elif "assets/css/fonts/" in subpath:
        subpath = subpath.replace("assets/css/fonts/", "assets/fonts/")
    target = f"http://localhost:{local_port}/{subpath}"
    if request.query_string:
        target += "?" + request.query_string.decode()
    try:
        # Build headers - rewrite Referer for FreePBX AJAX and strip dashboard cookies
        import re as _rfre
        _vps_hdrs = {}
        for _hk, _hv in request.headers:
            _hkl = _hk.lower()
            if _hkl in ("host","content-length","transfer-encoding"):
                continue
            elif _hkl == "cookie":
                # Only forward PHPSESSID to FreePBX - strip all dashboard/browser cookies
                _phpsessid = None
                for c in _hv.split(";"):
                    if c.strip().startswith("PHPSESSID="):
                        _phpsessid = c.strip()
                        break
                if _phpsessid:
                    _vps_hdrs[_hk] = _phpsessid
            elif _hkl == "referer":
                _vps_hdrs[_hk] = _rfre.sub(
                    r'http://10\.9\.0\.1:8080/vps/\d+',
                    f'http://localhost:{local_port}',
                    _hv)
            elif _hkl == "origin":
                _vps_hdrs[_hk] = f'http://localhost:{local_port}'
            else:
                _vps_hdrs[_hk] = _hv
        _vps_hdrs["Host"] = f"localhost:{local_port}"
        resp = _vr.request(
            method=request.method,
            url=target,
            headers=_vps_hdrs,
            data=request.get_data(),
            timeout=30,
            allow_redirects=False,
            verify=False,
        )
        excluded = ("content-encoding","content-length","transfer-encoding","connection")
        headers  = {k:v for k,v in resp.headers.items() if k.lower() not in excluded}
        body     = resp.content
        ct       = resp.headers.get("Content-Type", "")
        base     = f"/vps/{sid}/".encode()
        if "text/html" in ct:
            body = body.replace(b'href="/', b'href="' + base)
            body = body.replace(b'src="/',  b'src="'  + base)
            body = body.replace(b'action="/', b'action="' + base)
            import re as _vre
            import re as _vre2
            _vps_id_str = str(sid)
            def _inject_base(m):
                tag = m.group(1)
                import posixpath as _ppx
                _vdir = "/vps/" + _vps_id_str + "/" + (_ppx.dirname(subpath.strip("/")) + "/" if _ppx.dirname(subpath.strip("/")) else "")
                base_tag = tag + b'<base href="' + _vdir.encode() + b'">'
                return base_tag
            body = _vre2.sub(b'(<head[^>]*>)', _inject_base, body, count=1)
        if "javascript" in ct:
            body = body.replace(b"='/style.css'", b"='" + base + b"style.css'")
        if "text/css" in ct:
            import posixpath as _ppx2
            _css_dir = "/vps/" + str(sid) + "/" + (_ppx2.dirname(subpath.strip("/")) + "/" if _ppx2.dirname(subpath.strip("/")) else "")
            _css_base = _css_dir.encode()
            body = body.replace(b'url("../', b'url("' + _css_base)
            body = body.replace(b"url('../", b"url('" + _css_base)
            body = body.replace(b'url(../', b'url(' + _css_base)
        return body, resp.status_code, headers
    except Exception as e:
        return f"Proxy error: {e}", 503


@app.route("/vps/<int:sid>/fpbx-login", methods=["GET","POST"])
@login_required
def vps_fpbx_login(sid):
    from flask import request as _req, Response as _LR
    import requests as _vr2

    with _vps_lock:
        tunnel = _vps_tunnels.get(sid)
    
    # Auto-restart tunnel if dead
    if tunnel and tunnel["proc"].poll() is not None:
        print(f"[vps tunnel] tunnel {sid} dead, restarting...", flush=True)
        _stop_tunnel(sid)
        tunnel = None
    
    if not tunnel:
        # Try to restart tunnel automatically
        d2 = get_db()
        row2 = d2.execute("SELECT ip, ssh_user, ssh_password, web_port FROM vps_sites WHERE id=?", (sid,)).fetchone()
        d2.close()
        if row2:
            local_port2 = _start_tunnel(sid, row2["ip"], row2["ssh_user"], row2["ssh_password"], row2["web_port"])
            if local_port2:
                with _vps_lock:
                    tunnel = _vps_tunnels.get(sid)
        if not tunnel:
            return "VPS tunnel not connected. <a href='/admin/vps-sites'>Go to VPS Sites</a> and click Connect.", 503

    tunnel["last_used"] = _vtime.time()
    local_port = tunnel["local_port"]

    # Get site label
    d = get_db()
    row = d.execute("SELECT label FROM vps_sites WHERE id=?", (sid,)).fetchone()
    d.close()
    label = row["label"] if row else "FreePBX"

    if _req.method == "POST":
        username = _req.form.get("username", "")
        password = _req.form.get("password", "")
        if sid not in _vps_sessions:
            _vps_sessions[sid] = _vr2.Session()
        sess = _vps_sessions[sid]
        try:
            # Retry up to 3 times in case tunnel is restarting
            resp = None
            for _attempt in range(3):
                try:
                    resp = sess.post(
                        f"http://localhost:{local_port}/admin/config.php",
                        data={"username": username, "password": password},
                        allow_redirects=False,
                        timeout=15,
                    )
                    break
                except Exception as _re:
                    if _attempt < 2:
                        _vtime.sleep(2)
                    else:
                        raise
            if resp is None:
                raise Exception("No response after 3 attempts")
            if resp.status_code in (301, 302, 303, 307):
                loc = resp.headers.get("Location", "/admin/config.php")
                if loc.startswith("/"):
                    loc = f"/vps/{sid}" + loc
                elif loc.startswith("http://localhost"):
                    loc = f"/vps/{sid}" + loc[len(f"http://localhost:{local_port}"):]
                return redirect(loc)
            # FreePBX returns 200 with admin page on success (no redirect)
            if resp.status_code == 200 and b"FreePBX" in resp.content and b"login" not in resp.content[:500].lower():
                from flask import Response as _FR2
                flask_redir = _FR2("", status=302)
                flask_redir.headers["Location"] = f"/vps/{sid}/admin/config.php"
                # Forward all Set-Cookie headers from FreePBX to browser
                for k, v in resp.raw.headers.items():
                    if k.lower() == "set-cookie":
                        flask_redir.headers.add("Set-Cookie", v)
                return flask_redir
            # Login failed - show form again with error
            return vps_login_page(sid, label, error="Invalid username or password")
        except Exception as e:
            return vps_login_page(sid, label, error=f"Connection error: {e}")

    # Clear session for fresh login
    if sid in _vps_sessions:
        del _vps_sessions[sid]
    return vps_login_page(sid, label)

def vps_login_page(sid, label, error=""):
    err_html = f'<div style="background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.4);border-radius:6px;padding:10px 14px;font-size:13px;color:#f85149;margin-bottom:16px">{error}</div>' if error else ""
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Login — {label}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}}
.box{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:36px 32px;width:360px;box-shadow:0 16px 48px rgba(0,0,0,.4)}}
.logo{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.logo-icon{{width:36px;height:36px;background:rgba(63,185,80,.15);border:1px solid rgba(63,185,80,.3);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px}}
.logo-text{{font-size:15px;font-weight:700;color:#e6edf3}}
.sub{{font-size:12px;color:#8b949e;margin-bottom:24px}}
label{{display:block;font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.4px;margin-bottom:5px}}
input{{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:14px;padding:9px 12px;outline:none;margin-bottom:14px}}
input:focus{{border-color:#58a6ff}}
button{{width:100%;padding:10px;background:#238636;border:1px solid #2ea043;border-radius:6px;color:#fff;font-size:14px;font-weight:500;cursor:pointer;margin-top:4px}}
button:hover{{background:#2ea043}}
.back{{display:block;text-align:center;margin-top:16px;font-size:12px;color:#8b949e;text-decoration:none}}
.back:hover{{color:#e6edf3}}
</style></head><body>
<div class="box">
  <div class="logo">
    <div class="logo-icon">&#127751;</div>
    <div class="logo-text">Bridge Phone</div>
  </div>
  <div class="sub">FreePBX Admin — {label}</div>
  {err_html}
  <form method="POST">
    <label>Username</label>
    <input name="username" type="text" value="pbxadmin" autocomplete="off" autocorrect="off" autocapitalize="off">
    <label>Password</label>
    <input name="password" type="password" autocomplete="new-password">
    <button type="submit">Sign In to FreePBX</button>
  </form>
  <a class="back" href="/admin/vps-sites">&#8592; Back to VPS Sites</a>
</div>
</body></html>"""

if __name__=="__main__":
    # Release any stale tunnel ports on startup
    import socket as _cs
    for _p in range(19000, 19020):
        try:
            _s = _cs.socket(_cs.AF_INET, _cs.SOCK_STREAM)
            _s.setsockopt(_cs.SOL_SOCKET, _cs.SO_REUSEADDR, 1)
            _s.bind(("127.0.0.1", _p))
            _s.close()
        except:
            pass
    init_db()
    threading.Thread(target=bg,daemon=True).start()
    port=int(os.environ.get("PORT",8080))
    print(f"Site Dashboard on http://0.0.0.0:{port}")
    print("Login: admin / admin")
    app.run(host="10.9.0.1",port=port,threaded=True)
