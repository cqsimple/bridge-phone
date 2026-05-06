#!/usr/bin/env python3
"""
Device Browser — RPi Site Landing Page

Scans the local network for HTTP-responding devices whenever the
VPN tunnel is active. Accessed from the main site via the RPi's
fixed VPN IP address (e.g. http://10.8.0.10/).
"""

import subprocess, socket, threading, ipaddress, time, re, os, urllib.request, ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify, render_template_string, request, Response
import netifaces

app = Flask(__name__)

# ── Config ─────────────────────────────────────────────────────────────────────
SCAN_WORKERS  = 50
HTTP_TIMEOUT  = 1.5
HTTP_PORTS    = [80, 8080, 443, 8443, 8888, 7080]
VPN_IFACE     = "tun0"
POLL_INTERVAL = 5    # seconds between tun0 state polls
SCAN_COOLDOWN = 15   # seconds after tunnel-up before auto-scan fires

OUI_FALLBACK = {
    "B8:27:EB": "Raspberry Pi Foundation", "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation", "00:0C:29": "VMware",
    "00:50:56": "VMware",    "00:1A:11": "Google",    "F0:9F:C2": "Ubiquiti",
    "00:17:88": "Philips Hue","EC:FA:BC": "Amazon Echo","FC:65:DE": "Amazon",
    "AC:63:BE": "Apple",     "3C:5A:B4": "Google Chromecast","00:1E:C2": "Apple",
}

_state = {
    "vpn_up": False, "scanning": False, "devices": [],
    "last_scan": 0,  "subnet": "", "vpn_ip": "",
    "local_ip": "",  "tunnel_up_at": 0, "session_scanned": False,
}
_lock = threading.Lock()

# ── Network helpers ─────────────────────────────────────────────────────────────

# ── Vendor profiles ──────────────────────────────────────────
import json as _json
_PROFILES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "profiles.json")

def load_profiles():
    try:
        with open(_PROFILES_PATH) as _f:
            return _json.load(_f)
    except Exception:
        return []

def get_profile(vendor_type):
    for p in load_profiles():
        if p.get("vendor_type") == vendor_type:
            return p
    return None

def is_tunnel_up():
    try:    return netifaces.AF_INET in netifaces.ifaddresses(VPN_IFACE)
    except: return False

def get_tunnel_ip():
    try:    return netifaces.ifaddresses(VPN_IFACE)[netifaces.AF_INET][0].get("addr","")
    except: return ""

def get_local_info():
    for iface in netifaces.interfaces():
        if iface.startswith(("lo","tun","vpn","docker")): continue
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            info = addrs[netifaces.AF_INET][0]
            ip, mask = info.get("addr",""), info.get("netmask","")
            if ip and mask and not ip.startswith("127."):
                net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                return str(net), ip
    return "192.168.1.0/24", ""

# ── Scanning ────────────────────────────────────────────────────────────────────
def arp_scan(subnet):
    results = {}
    try:
        out = subprocess.check_output(
            ["arp-scan","--localnet","--retry=2"],
            stderr=subprocess.DEVNULL, timeout=30).decode()
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                ip, mac = parts[0].strip(), parts[1].strip().upper()
                if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                    results[ip] = mac
    except Exception:
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    cols = line.split()
                    if len(cols) >= 4 and cols[2] != "0x0":
                        raw = cols[3].upper().replace(":","")
                        results[cols[0]] = ":".join(raw[i:i+2] for i in range(0,12,2))
        except Exception: pass
    return results

def oui_lookup(mac):
    if not mac or mac == "(unknown)": return "Unknown"
    prefix = mac[:8].upper()
    if prefix in OUI_FALLBACK: return OUI_FALLBACK[prefix]
    try:
        req = urllib.request.Request(
            f"https://api.macvendors.com/{mac}",
            headers={"User-Agent":"DeviceBrowser/1.0"})
        with urllib.request.urlopen(req, timeout=3) as r:
            v = r.read().decode().strip()
            if v and "errors" not in v.lower():
                OUI_FALLBACK[prefix] = v
                return v
    except Exception: pass
    return "Unknown"

def probe_http(ip, port):
    scheme = "https" if port in (443,8443) else "http"
    url = f"{scheme}://{ip}:{port}"
    ctx = None
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent":"DeviceBrowser/1.0"})
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT, context=ctx) as r:
            body = r.read(4096).decode("utf-8", errors="ignore")
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE|re.DOTALL)
            return url, (m.group(1).strip()[:60] if m else None)
    except urllib.error.HTTPError as e:
        try:
            body = e.read(4096).decode("utf-8", errors="ignore")
            m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE|re.DOTALL)
            title = m.group(1).strip()[:60] if m else f"HTTP {e.code}"
            return url, title
        except Exception:
            return url, f"HTTP {e.code}"
    except Exception:
        return None
def scan_device(ip, mac, self_ip):
    if ip == self_ip: return None
    endpoints = []
    for port in HTTP_PORTS:
        r = probe_http(ip, port)
        if r:
            url, title = r
            endpoints.append({"url":url,"port":port,"title":title})
    if not endpoints: return None
    hostname = ""
    try: hostname = socket.gethostbyaddr(ip)[0]
    except Exception: pass
    vtype = detect_vendor(endpoints, mac)
    return {
        "ip":ip, "mac":mac, "vendor":oui_lookup(mac), "hostname":hostname,
        "endpoints":endpoints, "primary_url":endpoints[0]["url"],
        "primary_title":endpoints[0]["title"] or hostname or ip,
        "vendor_type": vtype,
    }

def detect_vendor(endpoints, mac=""):
    """Detect device vendor from endpoint titles and content."""
    mac_prefix = mac.upper()[:8] if mac else ""
    mac_oui_map = {
        "80:82:87": "atcom",       # Atcom Technology
        "70:B3:D5": "fanvil",      # Clearly IP
        "20:0A:0D": "fanvil",      # Clearly IP (second OUI)
        "00:0B:82": "grandstream", # Grandstream
        "00:15:65": "yealink",     # Yealink
        "24:9A:D8": "yealink",     # Yealink
        "80:5E:C0": "yealink",     # Yealink
        "00:E0:70": "freepbx",     # FreePBX systems
    }
    if mac_prefix in mac_oui_map:
        return mac_oui_map[mac_prefix]
    for e in endpoints:
        title = (e.get("title") or "").lower()
        if "freepbx" in title or "sangoma" in title:
            return "freepbx"
        if "yealink" in title or "enterprise ip phone" in title:
            return "yealink"
        if "grandstream" in title:
            return "grandstream"
        if "atcom" in title or "ip phone web configuration" in title:
            return "atcom"
        if "fanvil" in title or "document error" in title:
            return "fanvil"
    # Check for Fanvil/ClearlyIP by fetching page content
    for e in endpoints:
        try:
            import urllib.request as _ur
            req = _ur.Request(e["url"], headers={"User-Agent":"DeviceBrowser/1.0"})
            with _ur.urlopen(req, timeout=2) as r:
                body = r.read(8192).decode("utf-8", errors="ignore")
                if "jscs" in body or "fanvil" in body.lower():
                    return "fanvil"
        except Exception:
            pass
    return None

def run_scan():
    with _lock:
        if _state["scanning"]: return
        _state["scanning"] = True
    print("[scan] Starting…")
    try:
        subnet, self_ip = get_local_info()
        with _lock:
            _state["subnet"] = subnet
            _state["local_ip"] = self_ip
        mac_map = arp_scan(subnet)
        if not mac_map:
            try:
                subprocess.call(["nmap","-sn","-T4",subnet],
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
                mac_map = arp_scan(subnet)
            except Exception: pass
        if not mac_map:
            for host in ipaddress.IPv4Network(subnet,strict=False).hosts():
                mac_map[str(host)] = "(unknown)"
        devices = []
        with ThreadPoolExecutor(max_workers=SCAN_WORKERS) as ex:
            futures = {ex.submit(scan_device,ip,mac,self_ip):ip
                       for ip,mac in mac_map.items()}
            for f in as_completed(futures):
                with _lock:
                    if not _state["vpn_up"]:
                        print("[scan] Tunnel dropped — aborting.")
                        return
                r = f.result()
                if r: devices.append(r)
        devices.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
        with _lock:
            _state["devices"] = devices
            _state["last_scan"] = time.time()
        print(f"[scan] Done — {len(devices)} HTTP device(s).")
    finally:
        with _lock: _state["scanning"] = False

# ── Tunnel monitor ──────────────────────────────────────────────────────────────
def tunnel_monitor():
    prev_up = False
    while True:
        time.sleep(POLL_INTERVAL)
        now_up = is_tunnel_up()
        if now_up and not prev_up:
            vpn_ip = get_tunnel_ip()
            subnet, local_ip = get_local_info()
            print(f"[monitor] Tunnel UP — VPN:{vpn_ip}  LAN:{local_ip}")
            with _lock:
                _state.update(vpn_up=True, vpn_ip=vpn_ip, local_ip=local_ip,
                              subnet=subnet, tunnel_up_at=time.time(), session_scanned=False)
        elif not now_up and prev_up:
            print("[monitor] Tunnel DOWN")
            with _lock:
                _state.update(vpn_up=False, vpn_ip="", devices=[],
                              last_scan=0, session_scanned=False)
        fire = False
        with _lock:
            if (_state["vpn_up"] and not _state["scanning"]
                    and not _state["session_scanned"]
                    and (time.time()-_state["tunnel_up_at"]) >= SCAN_COOLDOWN):
                _state["session_scanned"] = True
                fire = True
        if fire:
            threading.Thread(target=run_scan, daemon=True).start()
        prev_up = now_up

# ── HTML ────────────────────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Bridge_Phone</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Sora:wght@300;500;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#0d1117;--sf:#161b22;--sf2:#1c2128;--bd:#21262d;--ac:#F07B10;
  --gn:#1B3A6B;--rd:#f85149;--tx:#e6edf3;--mu:#8b949e;--r:10px}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);font-family:'Sora',sans-serif;min-height:100vh}
header{background:var(--sf);border-bottom:1px solid var(--bd);padding:15px 26px;
  display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:100}
.logo{font-family:'JetBrains Mono',monospace;font-size:1rem;font-weight:600;color:var(--ac)}
.logo span{color:var(--gn)}
.hr{margin-left:auto;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.pill{display:inline-flex;align-items:center;gap:6px;padding:4px 11px;border-radius:20px;
  font-size:.73rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;
  font-family:'JetBrains Mono',monospace}
.pill.up  {background:rgba(63,185,80,.14);color:#3fb950;border:1px solid rgba(63,185,80,.28)}
.pill.down{background:rgba(248,81,73,.11);color:var(--rd);border:1px solid rgba(248,81,73,.28)}
.pill.busy{background:rgba(88,166,255,.11);color:var(--ac);border:1px solid rgba(88,166,255,.28)}
.dot{width:7px;height:7px;border-radius:50%;background:currentColor;flex-shrink:0}
.up .dot{animation:glow 2s ease-in-out infinite}
.busy .dot{animation:glow .8s ease-in-out infinite}
@keyframes glow{0%,100%{opacity:1}50%{opacity:.3}}
main{max-width:1060px;margin:0 auto;padding:28px 20px}
.wp{display:none;text-align:center;padding:70px 20px}
.wp.vis{display:block}
.wp-icon{font-size:3.2rem;animation:glow 1.5s ease-in-out infinite;display:inline-block}
.wp h2{font-size:1.15rem;margin:18px 0 10px}
.wp p{color:var(--mu);line-height:1.7;max-width:400px;margin:0 auto}
.lp{display:none}.lp.vis{display:block}
.sb{display:flex;gap:14px;margin-bottom:26px;flex-wrap:wrap}
.sc{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r);
  padding:11px 18px;display:flex;flex-direction:column;gap:2px}
.sl{font-size:.68rem;color:var(--mu);text-transform:uppercase;letter-spacing:.06em}
.sv{font-size:1.35rem;font-weight:700;color:var(--ac);font-family:'JetBrains Mono',monospace}
.sv.sm{font-size:.86rem;padding-top:4px}
.tb{display:flex;gap:9px;margin-bottom:20px;align-items:center;flex-wrap:wrap}
.srch{flex:1;min-width:180px;background:var(--sf);border:1px solid var(--bd);
  border-radius:var(--r);padding:8px 12px;color:var(--tx);
  font-family:'JetBrains Mono',monospace;font-size:.82rem;outline:none;
  transition:border-color .2s}
.srch:focus{border-color:var(--ac)}.srch::placeholder{color:var(--mu)}
.rb{background:var(--sf);border:1px solid var(--bd);color:var(--ac);
  border-radius:var(--r);padding:8px 15px;font-weight:600;font-size:.79rem;
  cursor:pointer;font-family:'Sora',sans-serif;white-space:nowrap;
  transition:border-color .2s,background .2s}
.rb:hover{border-color:var(--ac);background:rgba(88,166,255,.07)}
.rb:disabled{opacity:.38;cursor:not-allowed}
.dg{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:13px}
.dc{background:var(--sf);border:1px solid var(--bd);border-radius:var(--r);
  overflow:hidden;transition:border-color .2s,transform .15s;animation:fu .25s ease both}
.dc:hover{border-color:var(--ac);transform:translateY(-2px)}
@keyframes fu{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}
.dch{padding:12px 15px;background:rgba(88,166,255,.05);
  border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:9px}
.di{width:33px;height:33px;background:rgba(88,166,255,.12);border-radius:7px;
  display:flex;align-items:center;justify-content:center;font-size:.95rem;flex-shrink:0}
.dn{font-weight:600;font-size:.86rem;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis;flex:1}
.dcb{padding:12px 15px;display:flex;flex-direction:column;gap:8px}
.mr{display:flex;gap:7px;align-items:baseline}
.mk{font-family:'JetBrains Mono',monospace;font-size:.67rem;color:var(--mu);
  width:48px;flex-shrink:0}
.mv{font-family:'JetBrains Mono',monospace;font-size:.76rem;word-break:break-all}
.vb{display:inline-block;background:rgba(255,255,255,.08);color:#e6edf3;
  border-radius:4px;padding:1px 6px;font-size:.68rem;font-weight:600}
.eps{display:flex;flex-direction:column;gap:5px;margin-top:2px}
.el{display:flex;align-items:center;gap:6px;background:rgba(88,166,255,.05);
  border:1px solid rgba(88,166,255,.17);border-radius:6px;padding:5px 10px;
  text-decoration:none;color:var(--ac);font-size:.76rem;
  font-family:'JetBrains Mono',monospace;transition:background .15s}
.el:hover{background:rgba(88,166,255,.14)}
.et{color:var(--mu);font-size:.68rem;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis;max-width:130px}
.ea{margin-left:auto;opacity:.42}
.cm{grid-column:1/-1;text-align:center;padding:55px 20px;color:var(--mu)}
.spin{font-size:1.9rem;animation:spin 1.2s linear infinite;
  display:inline-block;margin-bottom:12px}
@keyframes spin{to{transform:rotate(360deg)}}
footer{text-align:center;padding:20px;color:var(--mu);font-size:.71rem;
  border-top:1px solid var(--bd);font-family:'JetBrains Mono',monospace;margin-top:36px}
</style></head><body>
<header>
  <div class="logo"><img src="/static/logo.png" style="height:32px;vertical-align:middle;margin-right:8px"> Bridge_Phone</div>
  <div class="hr">
    <span id="pill" class="pill down"><span class="dot"></span> Connecting…</span>
    <span id="lip" style="font-family:'JetBrains Mono',monospace;font-size:.73rem;color:var(--mu)"></span>
  </div>
</header>
<main>
  <div class="wp" id="wp">
    <span class="wp-icon">📡</span>
    <h2>Waiting for VPN tunnel…</h2>
    <p>The RPi is dialling out to the VPN server. This page updates automatically once the tunnel is up and the local network scan completes.</p>
  </div>
  <div class="lp" id="lp">
    <div class="sb">
      <div class="sc"><span class="sl">HTTP Devices</span><span class="sv" id="sc">—</span></div>
      <div class="sc"><span class="sl">Endpoints</span><span class="sv" id="sep">—</span></div>
      <div class="sc"><span class="sl">VPN IP</span><span class="sv sm" id="svpn">—</span></div>
      <div class="sc"><span class="sl">Subnet</span><span class="sv sm" id="ssub">—</span></div>
      <div class="sc"><span class="sl">Last Scan</span><span class="sv sm" id="sage">—</span></div>
    </div>
    <div class="tb">
      <input class="srch" id="srch" type="search"
        placeholder="Filter by IP, hostname, vendor…" oninput="render()">
      <button class="rb" id="rb" onclick="rescan()">↻ Rescan</button>
    </div>
    <div class="dg" id="dg"></div>
  </div>
</main>
<footer>Device Browser · auto-scans on VPN connect · accessed via VPN tunnel IP</footer>
<script>
let devs=[];
const ico=v=>{v=(v||"").toLowerCase();
  if(v.includes("raspberry"))return"🍓";if(v.includes("apple"))return"🍎";
  if(v.includes("google"))return"🔵";if(v.includes("amazon"))return"📦";
  if(v.includes("philips"))return"💡";if(v.includes("ubiquiti"))return"📡";
  if(v.includes("cisco"))return"🔀";return"🖥";};
const ago=ts=>{if(!ts)return"—";const s=Math.round(Date.now()/1000-ts);
  return s<60?s+"s ago":s<3600?Math.round(s/60)+"m ago":Math.round(s/3600)+"h ago";};
async function poll(){
  const r=await fetch("/api/state").then(r=>r.json()).catch(()=>null);
  if(!r)return;
  const{vpn_up:up,scanning:sc,vpn_ip,local_ip,subnet}=r;
  window._vpnIp=vpn_ip||'';

  // Update VPN status elements always
  document.getElementById("wp").classList.toggle("vis",!up);
  document.getElementById("lp").classList.toggle("vis",up);
  const pill=document.getElementById("pill");
  pill.className=`pill ${!up?"down":sc?"busy":"up"}`;
  pill.innerHTML=`<span class="dot"></span> ${!up?"VPN Connecting…":sc?"Scanning…":"VPN Up · "+vpn_ip}`;
  document.getElementById("lip").textContent=local_ip?"LAN: "+local_ip:"";

  if(up){
    // Always update stats and controls
    document.getElementById("sc").textContent=(r.devices||[]).length;
    document.getElementById("sep").textContent=(r.devices||[]).reduce((a,d)=>a+(d.endpoints||[]).length,0);
    document.getElementById("svpn").textContent=vpn_ip||"—";
    document.getElementById("ssub").textContent=subnet||"—";
    document.getElementById("sage").textContent=ago(r.last_scan);
    const rb=document.getElementById("rb");
    rb.disabled=sc;rb.textContent=sc?"Scanning…":"↻ Rescan";

    // Only rebuild device cards if devices actually changed
    const newHash=JSON.stringify(r.devices);
    if(newHash!==window._devHash||sc!==window._lastSc){
      window._devHash=newHash;
      window._lastSc=sc;
      devs=r.devices||[];
      render(sc);
    }
  }
}
function render(sc=false){
  const q=(document.getElementById("srch").value||"").toLowerCase();
  const g=document.getElementById("dg");
  if(sc&&!devs.length){
    g.innerHTML='<div class="cm"><div class="spin">⟳</div><br>Scanning local network…</div>';return;}
  const lst=devs.filter(d=>!q||d.ip.includes(q)||(d.hostname||"").toLowerCase().includes(q)||
    (d.vendor||"").toLowerCase().includes(q)||(d.mac||"").toLowerCase().includes(q));
  if(!lst.length){
    g.innerHTML='<div class="cm"><p>'+(devs.length?"No matches.":"No HTTP devices found.")+"</p></div>";return;}
  g.innerHTML=lst.map((d,i)=>`
    <div class="dc" style="animation-delay:${i*22}ms">
      <div class="dch"><div class="di">${ico(d.vendor)}</div>
        <div class="dn">${d.hostname||d.ip}</div></div>
      <div class="dcb">
        <div class="mr"><span class="mk">IP</span><span class="mv">${d.ip}</span></div>
        <div class="mr"><span class="mk">MAC</span><span class="mv">${d.mac}</span></div>
        <div class="mr"><span class="mk">Vendor</span>
          <span class="mv"><span class="vb">${d.vendor}</span></span></div>
        <div class="eps">${(d.endpoints||[]).map(e=>`
          <a class="el" href="${e.url}" target="_blank">
            <span>:${e.port}</span>
            <span class="et">${e.title||e.url}</span>
            <span class="ea">↗</span></a>`).join("")}
        ${(()=>{
          const vt=d.vendor_type;
          const labels={"freepbx":"Open Nimbus","yealink":"Open Yealink","grandstream":"Open Grandstream","fanvil":"Open ClearlyIP","atcom":"Open Atcom"};
          const colors={"freepbx":"rgba(63,185,80,.09);border-color:rgba(63,185,80,.3);color:#3fb950","yealink":"rgba(88,166,255,.09);border-color:rgba(88,166,255,.3);color:#58a6ff","grandstream":"rgba(88,166,255,.09);border-color:rgba(88,166,255,.3);color:#58a6ff","fanvil":"rgba(88,166,255,.09);border-color:rgba(88,166,255,.3);color:#58a6ff","atcom":"rgba(210,153,34,.09);border-color:rgba(210,153,34,.3);color:#d29922"};
          if(!vt||!labels[vt]) return "";
          const ob=`<a class="el" href="javascript:void(0)" onclick="openNimbus('${d.ip}','${vt}')" style="background:${colors[vt]};margin-top:4px"><span>&#x260E;</span><span class="et">${labels[vt]}</span><span class="ea">&#x2197;</span></a>`;
          const lb=`<a class="el" href="javascript:void(0)" onclick="showLogin('${d.ip}',${d.port||80},'${vt}')" style="background:rgba(255,165,0,.09);border-color:rgba(255,165,0,.3);color:#d4a017;margin-top:4px"><span>&#x1F511;</span><span class="et">Login</span><span class="ea">&#x2197;</span></a>`;
          return ob+lb;
        })()}
        </div>
      </div>
    </div>`).join("");
}
async function rescan(){
  document.getElementById("rb").disabled=true;
  await fetch("/api/scan",{method:"POST"});
}
function openNimbus(ip, vtype){
  var b=window.location.href;
  if(!b.endsWith('/')) b+='/';
  if(vtype === 'freepbx'){
    window.location.href=b+'device/'+window._vpnIp+'/80/pbx/'+ip+'/';
  } else {
    window.location.href=b+'device/'+ip+'/80/';
  }
}
poll();setInterval(poll,10000);
</script>
<div id="lm" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;align-items:center;justify-content:center">
  <div style="background:#161b22;border:1px solid #30363d;border-radius:12px;padding:28px 32px;width:340px;box-shadow:0 16px 48px rgba(0,0,0,.6)">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px">
      <div><div id="lm-title" style="font-size:15px;font-weight:700;color:#e6edf3"></div>
           <div id="lm-sub" style="font-size:12px;color:#8b949e;margin-top:3px"></div></div>
      <span onclick="closeLM()" style="cursor:pointer;color:#8b949e;font-size:22px;line-height:1">&times;</span>
    </div>
    <div id="lm-urow" style="margin-bottom:12px">
      <div style="font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.4px;margin-bottom:5px">Username</div>
      <input id="lm-u" type="text" autocomplete="off" autocorrect="off" autocapitalize="off" style="width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:14px;padding:8px 10px;outline:none;box-sizing:border-box">
    </div>
    <div style="margin-bottom:16px">
      <div style="font-size:11px;font-weight:600;color:#8b949e;text-transform:uppercase;letter-spacing:.4px;margin-bottom:5px">Password</div>
      <input id="lm-p" type="password" autocomplete="new-password" style="width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:14px;padding:8px 10px;outline:none;box-sizing:border-box">
    </div>
    <div id="lm-err" style="display:none;background:rgba(248,81,73,.1);border:1px solid rgba(248,81,73,.4);border-radius:6px;padding:8px 10px;font-size:12px;color:#f85149;margin-bottom:12px"></div>
    <button id="lm-btn" onclick="doLogin()" style="width:100%;padding:10px;background:#238636;border:1px solid #2ea043;border-radius:6px;color:#fff;font-size:14px;font-weight:500;cursor:pointer">Connect</button>
  </div>
</div>
<script>
var _profs={},_lmip="",_lmport=0,_lmvt="",_lmredir="";
fetch("/api/profiles").then(function(r){return r.json();}).then(function(ps){ps.forEach(function(p){_profs[p.vendor_type]=p;});});

function showLogin(ip,port,vt){
  var p=_profs[vt]||{};
  var b=window.location.href; if(!b.endsWith("/")) b+="/";
  if(p.auth_type==="browser_form"){
    if(vt==="freepbx") window.open(b+"device/"+window._vpnIp+"/80/pbx/"+ip+"/","_blank");
    else window.open(b+"device/"+ip+"/"+((p.protocol==="https")?443:port)+"/","_blank");
    return;
  }
  if(p.auth_type==="digest"){ window.open(b+"device/"+ip+"/"+port+"/","_blank"); return; }
  _lmip=ip; _lmport=port; _lmvt=vt; _lmredir=b+"device/"+ip+"/"+port+"/";
  document.getElementById("lm-title").textContent="Login — "+(p.display_name||vt);
  document.getElementById("lm-sub").textContent=ip+":"+port;
  var ur=document.getElementById("lm-urow");
  if(p.password_only){ ur.style.display="none"; }
  else { ur.style.display="block"; document.getElementById("lm-u").value=p.default_username||""; }
  document.getElementById("lm-p").value=p.default_password||"";
  document.getElementById("lm-err").style.display="none";
  document.getElementById("lm-btn").textContent="Connect";
  document.getElementById("lm-btn").disabled=false;
  var m=document.getElementById("lm"); m.style.display="flex";
  setTimeout(function(){ var f=p.password_only?document.getElementById("lm-p"):document.getElementById("lm-u"); if(f) f.focus(); },50);
}
function closeLM(){ document.getElementById("lm").style.display="none"; }
function doLogin(){
  var p=_profs[_lmvt]||{};
  var btn=document.getElementById("lm-btn");
  var err=document.getElementById("lm-err");
  btn.textContent="Connecting..."; btn.disabled=true; err.style.display="none";
  var fd=new FormData();
  fd.append("vendor_type",_lmvt);
  fd.append("redirect_to",_lmredir);
  if(!p.password_only) fd.append("username",document.getElementById("lm-u").value);
  fd.append("password",document.getElementById("lm-p").value);
  var _b=window.location.href; if(!_b.endsWith("/")) _b+="/";
  fetch(_b+"device-login/"+_lmip+"/"+_lmport,{method:"POST",body:fd})
    .then(function(r){
      closeLM();
      var _b2=window.location.href; if(!_b2.endsWith("/")) _b2+="/";
      window.open(_b2+_lmredir,"_blank");
    })
    .catch(function(ex){
      err.textContent="Error: "+ex; err.style.display="block";
      btn.textContent="Connect"; btn.disabled=false;
    });
}
document.getElementById("lm").addEventListener("click",function(e){ if(e.target===this) closeLM(); });
</script>
</body></html>"""

# ── Routes ──────────────────────────────────────────────────────────────────────
@app.route("/")
def index(): return render_template_string(HTML)

@app.route("/api/state")
def api_state():
    with _lock:
        return jsonify({k:_state[k] for k in
            ("vpn_up","vpn_ip","local_ip","scanning","devices","last_scan","subnet")})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    with _lock:
        if not _state["vpn_up"]: return jsonify({"error":"VPN not up"}),400
        if _state["scanning"]:   return jsonify({"status":"already_scanning"})
    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"status":"started"})

@app.route("/api/vpn/hook/up", methods=["POST"])
def hook_up():
    data=request.get_json(silent=True) or {}
    vpn_ip=data.get("vpn_ip",get_tunnel_ip())
    subnet,local_ip=get_local_info()
    with _lock:
        _state.update(vpn_up=True,vpn_ip=vpn_ip,local_ip=local_ip,
                      subnet=subnet,tunnel_up_at=time.time(),session_scanned=False)
    print(f"[hook] UP — VPN:{vpn_ip}  LAN:{local_ip}")
    return jsonify({"status":"ok"})

@app.route("/api/vpn/hook/down", methods=["POST"])
def hook_down():
    with _lock:
        _state.update(vpn_up=False,vpn_ip="",devices=[],last_scan=0,session_scanned=False)
    print("[hook] DOWN")
    return jsonify({"status":"ok"})




# ── FreePBX Proxy ───────────────────────────────────────────────────────────────
import requests as _req
_PBX_SESSIONS = {}

def _pbx_proxy_request(ip, path, method, req_obj):
    import re as _re
    target = f"http://{ip}/{path}"
    if req_obj.query_string:
        target += "?" + req_obj.query_string.decode("utf-8", errors="ignore")
    prefix = f"/pbx/{ip}"
    if ip not in _PBX_SESSIONS:
        _PBX_SESSIONS[ip] = _req.Session()
    sess = _PBX_SESSIONS[ip]
    headers = {k: v for k, v in req_obj.headers if k.lower() not in
               ("host","content-length","transfer-encoding","connection")}
    headers.update({"Host": ip, "Referer": f"http://{ip}/", "Origin": f"http://{ip}"})
    try:
        resp = sess.request(method=method, url=target, headers=headers,
            data=req_obj.get_data(), allow_redirects=False, timeout=300, verify=False)
    except Exception as e:
        return jsonify({"error": str(e)}), 502
    ct = resp.headers.get("Content-Type", "")
    body = resp.content
    if any(t in ct for t in ("text/html","text/javascript","application/javascript","application/json")):
        try:
            text = body.decode("utf-8", errors="replace")
            text = _re.sub(r'(href|src|action)="/', rf'\1="{prefix}/', text)
            text = _re.sub(r"(href|src|action)='/", rf"\1='{prefix}/", text)
            text = _re.sub(r'(url\s*:\s*["\'])/(?!http)', rf'\1{prefix}/', text)
            body = text.encode("utf-8")
        except Exception:
            pass
    excluded = {"content-encoding","transfer-encoding","connection","content-length"}
    out_headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded}
    if "Location" in out_headers:
        loc = out_headers["Location"]
        if loc.startswith("/"):
            out_headers["Location"] = prefix + loc
        elif loc.startswith(f"http://{ip}"):
            out_headers["Location"] = prefix + loc[len(f"http://{ip}"):]
    return Response(body, status=resp.status_code, headers=out_headers,
                    content_type=ct or "application/octet-stream")

@app.route("/pbx/<ip>/", defaults={"subpath": ""}, methods=["GET","POST","PUT","DELETE","PATCH"])
@app.route("/pbx/<ip>/<path:subpath>", methods=["GET","POST","PUT","DELETE","PATCH"])
def freepbx_proxy(ip, subpath):
    from flask import request as freq
    return _pbx_proxy_request(ip, subpath, freq.method, freq)


@app.route("/device/<ip>/<int:port>/", defaults={"subpath": ""}, methods=["GET","POST","PUT","DELETE","PATCH"])
@app.route("/device/<ip>/<int:port>/<path:subpath>", methods=["GET","POST","PUT","DELETE","PATCH"])
def device_proxy(ip, port, subpath=""):
    import requests as _dreq
    from requests.auth import HTTPBasicAuth, HTTPDigestAuth
    scheme = "https" if port in (443, 8443) else "http"
    target = f"{scheme}://{ip}:{port}/{subpath}"
    if request.query_string:
        target += "?" + request.query_string.decode("utf-8", errors="ignore")
    fwd_headers = {k:v for k,v in request.headers
                   if k.lower() not in ("host","content-length","transfer-encoding",
                                        "authorization","referer","origin")}
    # Extract Basic Auth credentials from browser if sent
    auth = None
    auth_header = request.headers.get("Authorization","")
    if auth_header.startswith("Basic "):
        import base64
        try:
            decoded = base64.b64decode(auth_header[6:]).decode()
            user, pwd = decoded.split(":", 1)
            auth = HTTPBasicAuth(user, pwd)
        except Exception:
            pass
    try:
        resp = _dreq.request(
            method=request.method,
            url=target,
            headers=fwd_headers,
            auth=auth,
            data=request.get_data(),
            timeout=15,
            verify=False,
            allow_redirects=False,
        )
        # If 401 with Digest challenge, retry with Digest Auth
        if resp.status_code == 401 and auth and "Digest" in resp.headers.get("WWW-Authenticate",""):
            creds = (auth.username, auth.password)
            resp = _dreq.request(
                method=request.method,
                url=target,
                headers=fwd_headers,
                auth=HTTPDigestAuth(*creds),
                data=request.get_data(),
                timeout=15,
                verify=False,
                allow_redirects=True,
            )
        excluded = ("content-encoding","content-length","transfer-encoding","connection")
        headers = {k:v for k,v in resp.headers.items() if k.lower() not in excluded}
        # Pass auth challenge through
        if "WWW-Authenticate" in resp.headers:
            headers["WWW-Authenticate"] = resp.headers["WWW-Authenticate"]
        # Rewrite Location headers
        if "Location" in resp.headers:
            loc = resp.headers["Location"]
            if loc.startswith(f"{scheme}://{ip}"):
                loc = loc[len(f"{scheme}://{ip}"):]
            if loc.startswith("/"):
                loc = f"/device/{ip}/{port}{loc}"
            headers["Location"] = loc
        # Rewrite HTML asset paths
        ct = resp.headers.get("Content-Type","")
        body = resp.content
        if "text/html" in ct:
            base_path = f"/device/{ip}/{port}".encode()
            body = body.replace(b'href="/', base_path + b'/')
            body = body.replace(b'src="/', base_path + b'/')
            body = body.replace(b'action="/', base_path + b'/')
            body = body.replace(b"href='/", base_path + b'/')
            body = body.replace(b"src='/", base_path + b'/')
        return body, resp.status_code, headers
    except Exception as e:
        return f"Could not reach {ip}:{port} — {e}", 503



@app.route("/api/profiles")
def api_profiles():
    return _json.dumps(load_profiles()), 200, {"Content-Type": "application/json"}


@app.route("/device-login/<ip>/<int:port>", methods=["POST"])
def device_login(ip, port):
    import requests as _lr
    from flask import request as _req, Response as _LResp
    username    = _req.form.get("username", "")
    password    = _req.form.get("password", "")
    vendor_type = _req.form.get("vendor_type", "")
    redirect_to = _req.form.get("redirect_to", "/device/{}/{}/".format(ip, port))
    profile = get_profile(vendor_type)
    if not profile:
        return "No profile for vendor: {}".format(vendor_type), 400
    scheme    = profile.get("protocol", "http")
    login_url = "{}://{}:{}{}".format(scheme, ip, port, profile["login_url"])
    post_data = {}
    if profile.get("username_field") and username:
        post_data[profile["username_field"]] = username
    if profile.get("password_field") and password:
        post_data[profile["password_field"]] = password
    for k, v in profile.get("extra_fields", {}).items():
        post_data[k] = v
    try:
        resp = _lr.post(login_url, data=post_data, timeout=10, verify=False, allow_redirects=False)
        flask_resp = _LResp("", status=302)
        flask_resp.headers["Location"] = redirect_to
        for k, v in resp.raw.headers.items():
            if k.lower() == "set-cookie":
                flask_resp.headers.add("Set-Cookie", v)
        return flask_resp
    except Exception as e:
        return "Login failed: {}".format(e), 503

if __name__=="__main__":
    if is_tunnel_up():
        vpn_ip=get_tunnel_ip(); subnet,local_ip=get_local_info()
        with _lock:
            _state.update(vpn_up=True,vpn_ip=vpn_ip,local_ip=local_ip,
                          subnet=subnet,tunnel_up_at=time.time())
        print(f"[startup] Tunnel already up — VPN:{vpn_ip}  LAN:{local_ip}")
    threading.Thread(target=tunnel_monitor,daemon=True).start()
    port=int(os.environ.get("PORT",8080))
    print(f"Device Browser on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0",port=port,threaded=True)
