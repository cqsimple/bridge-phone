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
    """)
    if not db.execute("SELECT 1 FROM users").fetchone():
        db.execute("INSERT INTO users(username,password,is_admin)VALUES(?,?,1)",
                   ("admin",generate_password_hash("admin")))
        print("[db] Created admin/admin")
    db.commit();db.close()

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
            try:
                r=requests.get(f"http://{vpn_ip}:{DEVICE_PORT}/api/state",timeout=3)
                st=r.json()
                e.update(browser_up=True,scanning=st.get("scanning",False),
                         device_count=len(st.get("devices",[])),last_scan=st.get("last_scan",0))
            except:pass
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
    {% if is_admin %}<a href="/admin">Admin</a><a href="/admin/new-site">New Site</a><a href="/admin/wg-users">VPN Users</a>{% endif %}
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
        chips += s.scanning
          ? '<span class="chip sc">scanning...</span>'
          : '<span class="chip ok">&#10003; '+s.device_count+' device'+(s.device_count!==1?'s':'')+'</span>';
        if(s.last_scan) chips += '<span class="chip">scan '+ago(s.last_scan)+'</span>';
        if(s.connected_since) chips += '<span class="chip">up '+s.connected_since+'</span>';
        acts = '<a class="btn bp" href="/site/'+s.name+'/" target="_blank">Open</a>'
             + ' <button class="btn bsc" data-n="'+s.name+'" onclick="scan(this.dataset.n)">Scan</button>'
             + ' <button class="btn" style="background:rgba(255,255,255,.06);color:#e6edf3;border:1px solid #21262d" data-n="'+s.name+'" data-l="'+s.label+'" onclick="rename(this.dataset.n,this.dataset.l)" title="Rename">&#9998;</button>'
             + ' ' + discBtn;
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
    <a href="/">Dashboard</a><a href="/admin">Admin</a><a href="/admin/new-site">New Site</a><a href="/admin/wg-users">VPN Users</a>
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
        if ("text/html" in content_type or "text/html" in resp.headers.get("ContentType","") or "javascript" in content_type) and subpath.startswith("device/"):
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
            # Rewrite cgi-bin absolute paths in HTML and JS
            body = body.replace(b"url: '/cgi-bin/", b"url: '" + dev_base + b"/cgi-bin/")
            body = body.replace(b'url: "/cgi-bin/', b'url: "' + dev_base + b'/cgi-bin/')
            body = body.replace(b"url:'/cgi-bin/", b"url:'" + dev_base + b"/cgi-bin/")
            body = body.replace(b'url:"/cgi-bin/', b'url:"' + dev_base + b'/cgi-bin/')
            body = body.replace(b"action: '/cgi-bin/", b"action: '" + dev_base + b"/cgi-bin/")
            body = body.replace(b'action: "/cgi-bin/', b'action: "' + dev_base + b'/cgi-bin/')
            body = body.replace(b'url("/', dev_base + b'/')
            body = body.replace(b'background:url(/', b'background:url(' + dev_base + b'/')
            body = body.replace(b'window.location.href ="/', dev_base + b'/')
            body = body.replace(b"window.location.href ='/", dev_base + b'/')
            body = body.replace(b'window.location.href ="/', dev_base + b'/')
            body = body.replace(b"window.location.href ='/", dev_base + b'/')
            body = body.replace(b'window.location="/', b'window.location.href="' + dev_base + b'/')
            body = body.replace(b'window.location ="\/', b'window.location.href="' + dev_base + b'/')
            body = body.replace(b'window.location ="/', b'window.location.href="/' + dev_base[1:] + b'/')
            body = body.replace(b'window.location ="/', b'window.location ="' + dev_base + b'/')
            body = body.replace(b"window.location ='/", b"window.location ='" + dev_base + b"/")
            body = body.replace(b'window.location="/', b'window.location="' + dev_base + b'/')
            body = body.replace(b"window.location='/", b"window.location='" + dev_base + b"/")
            # Rewrite Ajax/XHR absolute paths in JS
            import re as _re2
            body = _re2.sub(
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
                body = body.replace(b'<head>', b'<head><base href="' + base + b'">', 1)
                body = body.replace(b'<HEAD>', b'<HEAD><base href="' + base + b'">', 1)
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

if __name__=="__main__":
    init_db()
    threading.Thread(target=bg,daemon=True).start()
    port=int(os.environ.get("PORT",8080))
    print(f"Site Dashboard on http://0.0.0.0:{port}")
    print("Login: admin / admin")
    app.run(host="10.9.0.1",port=port,threaded=True)
