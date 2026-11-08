#!/usr/bin/env python3
"""
WILDMC 웹 — Next.js web/src UI 미러 (gold/mint/glass). 단일 파일.
실행: python WILDMC-web.py  →  http://localhost:3000
DB: data/db.json · 세션 쿠키: wildmc_session · Admin: change-me-admin-api-key
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import random
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlencode, urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parent


def load_dotenv_files() -> None:
    # systemd Environment= 에 옛 키가 있어도 .env 의 관리키를 우선 적용
    force_from_file = {"ADMIN_API_KEY", "DESKTOP_API_KEY"}
    candidates = [
        ROOT / ".env",
        ROOT.parent / "web" / ".env.local",
        ROOT.parent / ".env",
    ]
    for path in candidates:
        if not path.is_file():
            continue
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip('"').strip("'")
            if not key:
                continue
            if key in force_from_file or key not in os.environ:
                os.environ[key] = val


load_dotenv_files()

DATA = ROOT / "data"
DB_FILE = DATA / "db.json"
SUPPORT_UPLOADS = DATA / "uploads" / "support"
PRODUCT_UPLOADS = DATA / "uploads" / "products"
ORDER_UPLOADS = DATA / "uploads" / "orders"
COOKIE_NAME = "wildmc_session"
RANK_GROUPS = ["스탠다드", "울트라", "MVP", "오너", "부총괄", "어드민", "가이드", "개발자"]
SITE = os.environ.get("SITE_NAME", "WILDMC")
PORT = int(os.environ.get("SERVER_PORT") or os.environ.get("PORT") or 3000)
HOST = os.environ.get("BIND_HOST", "0.0.0.0")
PLUGIN_KEY = os.environ.get("PLUGIN_API_KEY", "change-me-plugin-api-key")
BOT_KEY = os.environ.get("BOT_API_KEY", "change-me-bot-api-key")
ADMIN_KEY = os.environ.get("ADMIN_API_KEY", "change-me-admin-api-key").strip()
# 데스크탑 전용 키(선택). 있으면 데스크탑은 이 키만으로도 연결 가능. 없으면 ADMIN_API_KEY 사용.
DESKTOP_KEY = (os.environ.get("DESKTOP_API_KEY") or "").strip() or ADMIN_KEY
# 데스크톱 앱에 내장된 평생 고정 키 — 호스트 .env 키가 달라도 이 키로는 반드시 연결됨
BUILTIN_DESKTOP_KEY = "krJGSeHMGFSTzhF3g8JNaOadcOJm0sjb6Ce8HW2ra6EdyBEpFblIfA"
WEAK_ADMIN = ADMIN_KEY in {"", "change-me-admin-api-key", "admin", "password", "1234", "secret"}
DISCORD_CLIENT_ID = (os.environ.get("DISCORD_CLIENT_ID") or "").strip()
DISCORD_CLIENT_SECRET = (os.environ.get("DISCORD_CLIENT_SECRET") or "").strip().strip('"').strip("'")


def normalize_public_url(url: str) -> str:
    """Public sites must use https — Discord OAuth rejects http/https mismatch."""
    raw = (url or "").strip().rstrip("/")
    if not raw:
        return "http://localhost:3000"
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlparse(raw)
        host = (parts.hostname or "").lower()
        local = host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local")
        scheme = parts.scheme or "https"
        if not local and scheme == "http":
            scheme = "https"
        return f"{scheme}://{parts.netloc}".rstrip("/")
    except Exception:
        if raw.startswith("http://") and "localhost" not in raw and "127.0.0.1" not in raw:
            return "https://" + raw[len("http://") :]
        return raw


APP_URL = normalize_public_url(os.environ.get("NEXT_PUBLIC_APP_URL") or os.environ.get("APP_URL") or "http://localhost:3000")


def normalize_discord_redirect(url: str, app_url: str) -> str:
    """Keep configured callback path; upgrade http→https on public hosts."""
    raw = (url or "").strip() or f"{app_url}/api/auth/discord/callback"
    if "://" not in raw:
        raw = f"{app_url.rstrip('/')}/{raw.lstrip('/')}"
    parts = urlparse(raw)
    host = (parts.hostname or "").lower()
    local = host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local")
    scheme = parts.scheme or ("http" if local else "https")
    if not local and scheme == "http":
        scheme = "https"
    path = (parts.path or "").rstrip("/") or "/api/auth/discord/callback"
    # Accept both common forms registered in Discord Developer Portal
    if path in {"/auth/discord/callback", "/api/auth/discord/callback"}:
        pass
    elif path.endswith("/discord/callback"):
        pass
    else:
        path = "/api/auth/discord/callback"
    return f"{scheme}://{parts.netloc}{path}"


_raw_redirect = (os.environ.get("DISCORD_REDIRECT_URI") or f"{APP_URL}/api/auth/discord/callback").strip()
DISCORD_REDIRECT_URI = normalize_discord_redirect(_raw_redirect, APP_URL)
COOKIE_SECURE = APP_URL.startswith("https://")
DISCORD_CALLBACK_PATHS = {
    "/api/auth/discord/callback",
    "/auth/discord/callback",
    urlparse(DISCORD_REDIRECT_URI).path.rstrip("/") or "/api/auth/discord/callback",
}

def cookie_header(token: str, *, clear: bool = False) -> str:
    if clear:
        base = f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    else:
        base = f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000"
    if COOKIE_SECURE:
        base += "; Secure"
    return base

DATA.mkdir(parents=True, exist_ok=True)
SUPPORT_UPLOADS.mkdir(parents=True, exist_ok=True)
PRODUCT_UPLOADS.mkdir(parents=True, exist_ok=True)
ORDER_UPLOADS.mkdir(parents=True, exist_ok=True)

def decode_data_url_image(raw: str, max_bytes: int = 8 * 1024 * 1024) -> tuple[bytes, str]:
    """Return (bytes, ext) from a data URL. Raises ValueError on bad input."""
    raw = str(raw or "")
    if ";base64," not in raw:
        raise ValueError("이미지 파일(JPG/PNG/WEBP)만 올릴 수 있습니다.")
    header, b64data = raw.split(";base64,", 1)
    mime = header.split(":", 1)[-1].lower().strip() if ":" in header else ""
    try:
        buf = base64.b64decode(b64data, validate=False)
    except Exception as e:
        raise ValueError("이미지 데이터를 읽지 못했습니다.") from e
    if len(buf) < 24:
        raise ValueError("이미지 파일이 손상되었습니다.")
    if buf[:8] == b"\x89PNG\r\n\x1a\n":
        ext = "png"
    elif buf[:3] == b"\xff\xd8\xff":
        ext = "jpg"
    elif len(buf) >= 12 and buf[:4] == b"RIFF" and buf[8:12] == b"WEBP":
        ext = "webp"
    elif "png" in mime:
        ext = "png"
    elif "webp" in mime:
        ext = "webp"
    elif "jpeg" in mime or "jpg" in mime:
        ext = "jpg"
    else:
        raise ValueError("이미지 파일(JPG/PNG/WEBP)만 올릴 수 있습니다.")
    if len(buf) > max_bytes:
        raise ValueError(f"이미지는 {max_bytes // (1024 * 1024)}MB 이하만 가능합니다.")
    return buf, ext


def save_support_images(raw_list, prefix: str) -> list[str]:
    SUPPORT_UPLOADS.mkdir(parents=True, exist_ok=True)
    urls: list[str] = []
    for i, raw in enumerate(list(raw_list or [])[:6]):
        if not raw:
            continue
        try:
            buf, ext = decode_data_url_image(str(raw))
        except ValueError:
            continue
        name = f"{prefix}_{i}_{secrets.token_hex(4)}.{ext}"
        (SUPPORT_UPLOADS / name).write_bytes(buf)
        urls.append(f"/uploads/support/{name}")
    return urls


def save_order_images(raw_list, prefix: str) -> list[str]:
    """입금 증빙·구매 첨부 사진 → /uploads/orders/…"""
    ORDER_UPLOADS.mkdir(parents=True, exist_ok=True)
    urls: list[str] = []
    for i, raw in enumerate(list(raw_list or [])[:6]):
        if not raw:
            continue
        try:
            buf, ext = decode_data_url_image(str(raw), max_bytes=10 * 1024 * 1024)
        except ValueError:
            continue
        name = f"{prefix}_{i}_{secrets.token_hex(4)}.{ext}"
        (ORDER_UPLOADS / name).write_bytes(buf)
        urls.append(f"/uploads/orders/{name}")
    return urls


def save_product_image(raw: str, filename: str = "upload.png") -> str:
    """Save product/banner image from data URL → /uploads/products/…"""
    buf, ext = decode_data_url_image(str(raw or ""), max_bytes=8 * 1024 * 1024)
    name = secrets.token_hex(8) + "." + ext
    PRODUCT_UPLOADS.mkdir(parents=True, exist_ok=True)
    (PRODUCT_UPLOADS / name).write_bytes(buf)
    return f"/uploads/products/{name}"


def normalize_product_image_url(raw) -> str | None:
    """상대경로·절대URL 유지. data URL이면 파일로 저장 후 경로 반환."""
    s = str(raw or "").strip()
    if not s:
        return None
    if s.startswith("data:"):
        return save_product_image(s)
    if len(s) > 2000 and ";base64," in s:
        return save_product_image(s if s.startswith("data:") else f"data:image/jpeg;base64,{s}")
    return s


lock = threading.Lock()
live_players: dict[str, dict] = {}
plugin_online = False
server_metrics: dict = {}
console_logs: list[dict] = []
# IP별 관리키 실패 제한 — 사용 안 함(무한 시도)
_admin_fail: dict[str, list[float]] = {}
# ServerBridge WebSocket (/ws/plugin)
_plugin_ws_sockets: set = set()
_plugin_ws_lock = threading.Lock()


def _ws_accept_key(sec_key: str) -> str:
    digest = hashlib.sha1((sec_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


def _ws_recv_frame(sock) -> tuple[int, bytes] | None:
    """Return (opcode, payload) or None on close/error."""
    try:
        hdr = sock.recv(2)
        if len(hdr) < 2:
            return None
        b1, b2 = hdr[0], hdr[1]
        opcode = b1 & 0x0F
        masked = (b2 & 0x80) != 0
        length = b2 & 0x7F
        if length == 126:
            ext = sock.recv(2)
            if len(ext) < 2:
                return None
            length = int.from_bytes(ext, "big")
        elif length == 127:
            ext = sock.recv(8)
            if len(ext) < 8:
                return None
            length = int.from_bytes(ext, "big")
        mask = b""
        if masked:
            mask = sock.recv(4)
            if len(mask) < 4:
                return None
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        if masked:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return opcode, data
    except Exception:
        return None


def _ws_send_frame(sock, payload: bytes, opcode: int = 0x1) -> None:
    header = bytearray()
    header.append(0x80 | (opcode & 0x0F))
    n = len(payload)
    if n < 126:
        header.append(n)
    elif n < 65536:
        header.append(126)
        header.extend(n.to_bytes(2, "big"))
    else:
        header.append(127)
        header.extend(n.to_bytes(8, "big"))
    sock.sendall(header + payload)


def handle_plugin_ws_message(raw: str) -> None:
    """Process ServerBridge WS events (PLAYER_JOIN/QUIT etc.)."""
    global plugin_online
    try:
        msg = json.loads(raw)
    except Exception:
        return
    if not isinstance(msg, dict):
        return
    mtype = str(msg.get("type") or "")
    p = msg.get("payload") if isinstance(msg.get("payload"), dict) else {}
    with lock:
        plugin_online = True
        if mtype in {"PLAYER_JOIN", "PLAYER_QUIT", "PLUGIN_ONLINE"}:
            uid = str(p.get("uuid") or "")
            if uid and mtype != "PLUGIN_ONLINE":
                online = mtype == "PLAYER_JOIN" or p.get("online", True) is not False
                if mtype == "PLAYER_QUIT":
                    online = False
                live_players[uid] = {
                    "uuid": uid,
                    "name": str(p.get("name") or ""),
                    "online": online,
                }
                cache = db.setdefault("player_cache", {}).setdefault(uid, {})
                cache["minecraft_name"] = str(p.get("name") or cache.get("minecraft_name") or "")
                if p.get("group"):
                    cache["luckperms_group"] = p.get("group")
                cache["online"] = 1 if online else 0
                cache["updated_at"] = now_ms()
                if mtype == "PLAYER_JOIN":
                    db.setdefault("joins", []).append(
                        {"uuid": uid, "name": str(p.get("name") or ""), "at": now_ms(), "date": seoul_date()}
                    )
                    if len(db["joins"]) > 5000:
                        db["joins"] = db["joins"][-4000:]
                    save_db(db)


ADMIN_WEB_HTML = r"""<!doctype html>
<html lang="ko"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>WILDMC 관리자 웹</title>
<link rel="stylesheet" href="/fonts/round.css"/>
<link href="https://fonts.googleapis.com/css2?family=Nunito:wght@600;700;800;900&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0f1412;--panel:#171e1a;--line:rgba(212,175,106,.22);--gold:#d4af6a;--gold2:#e8d5a8;--mint:#7dcea0;--text:#f2efe7;--muted:#93a099;--danger:#e07a6a}
*{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:"WM Round",Nunito,"Malgun Gothic",sans-serif;color:var(--text);background:radial-gradient(900px 500px at 0% 0%,rgba(125,206,160,.12),transparent 50%),#0a0e0c;-webkit-font-smoothing:antialiased;word-break:keep-all}
button,input,textarea{font-family:inherit}
.wrap{max-width:720px;margin:0 auto;padding:2rem 1.25rem}
.card{border:1px solid var(--line);background:linear-gradient(160deg,#1d2621f2,#121815e6);border-radius:22px;padding:1.3rem;margin-top:1rem;box-shadow:inset 0 1px 0 rgba(255,255,255,.05),0 20px 50px -34px rgba(0,0,0,.85)}
h1{color:var(--gold2);font-size:1.7rem;margin:0;font-family:Nunito,"WM Round",sans-serif;font-weight:900;letter-spacing:-.02em}p{color:var(--muted);line-height:1.6}
.field{width:100%;margin-top:.5rem;border-radius:14px;border:1px solid rgba(212,175,106,.18);background:rgba(8,12,10,.7);color:var(--text);padding:.8rem .9rem;transition:border-color .2s,box-shadow .2s}
.field:focus{outline:none;border-color:rgba(125,206,160,.55);box-shadow:0 0 0 3px rgba(125,206,160,.12)}
.btn{display:inline-flex;align-items:center;justify-content:center;margin-top:.75rem;margin-right:.5rem;border:none;border-radius:999px;padding:.7rem 1.15rem;font-weight:800;cursor:pointer;text-decoration:none;transition:transform .25s cubic-bezier(.34,1.56,.64,1),filter .2s}
.btn:hover{filter:brightness(1.06)}.btn:active{transform:scale(.95)}
.btn-primary{background:linear-gradient(135deg,#e8d5a8,#c9a24d);color:#1a1408}
.btn-ghost{background:transparent;border:1px solid var(--line);color:var(--gold2)}
.row{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center}
.ok{color:var(--mint)}.err{color:var(--danger)}
label{display:block;margin-top:.75rem;font-size:.8rem;color:var(--muted)}
.site-build-badge{position:fixed;right:.85rem;bottom:.75rem;z-index:9998;pointer-events:none;font-size:.72rem;font-weight:700;letter-spacing:.04em;color:rgba(232,213,168,.9);background:rgba(8,12,10,.75);border:1px solid rgba(232,213,168,.28);border-radius:999px;padding:.35rem .7rem}
</style></head><body>
<div class="wrap">
  <h1>WILDMC 관리자 웹</h1>
  <p>디스코드 로그인 + Team. Wildmc 권한이 있어야 들어올 수 있습니다. 공지 작성 · 사이트 에디터 · 위키 편집 · 작업은 데스크톱 앱 활동 로그에 남습니다.</p>
  <div id="gate" class="card"><p>확인 중…</p></div>
  <div id="app" style="display:none">
    <div class="card">
      <strong style="color:var(--gold2)">빠른 이동</strong>
      <div class="row" style="margin-top:.75rem">
        <a class="btn btn-primary" href="/decorate">사이트 에디터</a>
        <a class="btn btn-ghost" href="/wiki/editor">위키 편집실</a>
        <a class="btn btn-ghost" href="/wiki/" target="_blank">위키 보기</a>
        <a class="btn btn-ghost" href="/">상점 사이트</a>
      </div>
    </div>
    <form id="noticeForm" class="card">
      <strong style="color:var(--gold2)">공지 작성</strong>
      <label>제목</label><input class="field" id="nTitle" required/>
      <label>내용</label><textarea class="field" id="nBody" rows="5" required></textarea>
      <label class="row"><input type="checkbox" id="nPin"/> 상단 고정</label>
      <button class="btn btn-primary" type="submit">공지 등록</button>
      <p id="nMsg"></p>
    </form>
    <div class="card">
      <strong style="color:var(--gold2)">최근 공지</strong>
      <div id="nList"></div>
    </div>
    <div class="card row">
      <button class="btn btn-ghost" type="button" id="logoutBtn">로그아웃</button>
      <span id="who" style="color:var(--muted);font-size:.85rem"></span>
    </div>
  </div>
</div>
<script>
async function me(){const r=await fetch('/api/me'); if(r.status===401) return null; return r.json();}
async function boot(){
  const gate=document.getElementById('gate');
  const m=await me();
  if(!m||!m.authenticated){
    gate.innerHTML=`<p>디스코드로 로그인한 뒤 이용하세요.</p><a class="btn btn-primary" href="/api/auth/discord?next=/admin">디스코드 로그인</a>`;
    return;
  }
  if(!m.canEditSite){
    const myId=m.discord?.id||'';
    gate.innerHTML=`<p class="err">로그인됨 · Team. Wildmc 권한이 없습니다.</p>
      <p>사이트 편집은 <b>Team. Wildmc</b> 권한이 있어야만 할 수 있습니다. 데스크톱 앱에서 아래 ID에 권한을 받으세요.</p>
      <p style="margin:.75rem 0"><code style="font-size:1rem;color:var(--gold2)">${myId}</code></p>
      <p>경로: 데스크톱 앱 <b>유저</b> → 「Team. Wildmc 주기」</p>
      <a class="btn btn-primary" href="/admin">다시 확인</a>
      <a class="btn btn-ghost" href="/api/auth/logout">로그아웃</a>`;
    return;
  }
  gate.style.display='none'; document.getElementById('app').style.display='block';
  document.getElementById('who').textContent=(m.discord?.username||'')+' · '+ (m.discord?.id||'');
  await loadNotices();
}
async function loadNotices(){
  const d=await (await fetch('/api/admin/web/notices')).json().catch(()=>({}));
  const list=d.notices||[];
  document.getElementById('nList').innerHTML=list.slice(0,8).map(n=>`<div style="margin-top:.65rem;padding:.65rem;border:1px solid var(--line);border-radius:12px"><b>${n.title||''}</b><div style="font-size:.85rem;color:var(--muted);white-space:pre-wrap;margin-top:.35rem">${n.body||''}</div></div>`).join('')||'<p style="color:var(--muted)">공지 없음</p>';
}
document.getElementById('noticeForm').onsubmit=async(e)=>{
  e.preventDefault();
  const title=document.getElementById('nTitle').value.trim();
  const body=document.getElementById('nBody').value.trim();
  const pinned=document.getElementById('nPin').checked?1:0;
  const r=await fetch('/api/admin/web/notices',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title,body,pinned,active:1})});
  const j=await r.json().catch(()=>({}));
  const msg=document.getElementById('nMsg');
  if(!r.ok){msg.className='err';msg.textContent=j.error||'실패';return;}
  msg.className='ok';msg.textContent='공지가 등록되었습니다. (데스크톱 로그에도 기록)';
  document.getElementById('nTitle').value='';document.getElementById('nBody').value='';
  loadNotices();
};
document.getElementById('logoutBtn').onclick=async()=>{await fetch('/api/auth/logout',{method:'POST'}); location.href='/admin';};
(function(){const el=document.createElement('div');el.className='site-build-badge';el.textContent='web v__WEB_BUILD__';document.body.appendChild(el);})();
boot();
</script></body></html>
"""


DECORATE_HTML = r"""<!doctype html>
<html lang="ko"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>WILDMC · 사이트 에디터</title>
<meta name="theme-color" content="#0a0f0d"/>
<link rel="stylesheet" href="/fonts/round.css"/>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Dongle:wght@400;700&family=Nunito:wght@600;700;800;900&family=Gowun+Dodum&family=Jua&family=Noto+Sans+KR:wght@500;800&display=swap" rel="stylesheet"/>
<style>
:root{--bg0:#0a0f0d;--line:rgba(232,213,168,.16);--line2:rgba(232,213,168,.3);--gold:#d9b673;--gold2:#f0dfb5;--mint:#86d6aa;--text:#f4f0e6;--muted:#9fb0a6;--danger:#ef8a78;--ok:#7fd8a6;--ease:cubic-bezier(.22,1,.36,1)}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;font-family:"WM Round",Nunito,"Malgun Gothic",sans-serif;color:var(--text);background:radial-gradient(900px 520px at 0% -10%,rgba(134,214,170,.1),transparent 55%),radial-gradient(800px 480px at 100% 0%,rgba(217,182,115,.1),transparent 50%),var(--bg0);-webkit-font-smoothing:antialiased;word-break:keep-all;overflow:hidden}
button,input,textarea,select{font:inherit;color:inherit}
a{color:inherit;text-decoration:none}
.hidden{display:none!important}
.gate{min-height:100vh;display:grid;place-items:center;padding:1.5rem}
.gate-card{width:min(440px,100%);padding:2rem;border-radius:24px;border:1px solid var(--line2);background:linear-gradient(160deg,#1a2520f2,#101714f0);text-align:center;box-shadow:0 30px 80px -40px #000}
.gate-card h1{margin:.2rem 0 .5rem;font:900 1.6rem Nunito,"WM Round",sans-serif;color:var(--gold2)}
.gate-card p{color:var(--muted);line-height:1.6;margin:.4rem 0}
.gate-card code{display:inline-block;margin:.5rem 0;padding:.35rem .7rem;border-radius:10px;background:rgba(0,0,0,.35);color:var(--gold2)}
.ed{display:grid;grid-template-rows:auto 1fr;height:100vh}
.top{display:flex;align-items:center;gap:.7rem;padding:.7rem 1rem;border-bottom:1px solid var(--line);background:rgba(10,15,13,.82);backdrop-filter:blur(14px)}
.logo{font:900 1.15rem Nunito,"WM Round",sans-serif;letter-spacing:-.02em;color:var(--gold2);white-space:nowrap}
.logo span{color:var(--mint)}
.logo small{margin-left:.45rem;font:800 .68rem "WM Round",sans-serif;letter-spacing:.08em;color:var(--muted);vertical-align:middle}
.status{display:inline-flex;align-items:center;gap:.45rem;padding:.35rem .75rem;border-radius:999px;border:1px solid var(--line);font-size:.78rem;font-weight:700;color:var(--muted);white-space:nowrap}
.status i{width:.5rem;height:.5rem;border-radius:999px;background:var(--ok)}
.status.dirty{color:var(--gold2);border-color:var(--line2)}
.status.dirty i{background:var(--gold);box-shadow:0 0 8px var(--gold)}
.grow{flex:1}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:.4rem;border:1px solid var(--line2);background:rgba(255,255,255,.03);border-radius:999px;padding:.55rem 1rem;font-weight:800;font-size:.84rem;cursor:pointer;white-space:nowrap;transition:transform .25s cubic-bezier(.34,1.56,.64,1),background .2s,border-color .2s,filter .2s}
.btn:hover{background:rgba(255,255,255,.07)}
.btn:active{transform:scale(.95)}
.btn:disabled{opacity:.45;cursor:not-allowed;transform:none}
.btn.primary{border:none;background:linear-gradient(135deg,#f0dfb5,#cfa24e 60%,#a88435);color:#1a1408;box-shadow:0 10px 26px -12px rgba(207,162,78,.8)}
.btn.primary:hover{filter:brightness(1.06)}
.btn kbd{font:800 .65rem "WM Round",sans-serif;padding:.1rem .35rem;border-radius:6px;background:rgba(0,0,0,.18)}
.body{display:grid;grid-template-columns:minmax(360px,440px) 1fr;min-height:0}
.panel{display:grid;grid-template-columns:78px 1fr;min-height:0;border-right:1px solid var(--line);background:rgba(12,18,15,.6)}
.tabs{display:flex;flex-direction:column;gap:.3rem;padding:.7rem .45rem;border-right:1px solid var(--line)}
.tab{display:flex;flex-direction:column;align-items:center;gap:.28rem;padding:.6rem .2rem;border:1px solid transparent;border-radius:14px;background:none;cursor:pointer;color:var(--muted);font-size:.7rem;font-weight:800;transition:background .2s,color .2s,border-color .2s}
.tab b{font-size:1.15rem;line-height:1}
.tab:hover{color:var(--text);background:rgba(255,255,255,.04)}
.tab.on{color:var(--gold2);background:rgba(217,182,115,.12);border-color:var(--line2)}
.pane{overflow-y:auto;padding:1.1rem 1.1rem 4rem;min-height:0}
.pane h2{margin:.1rem 0 .25rem;font:900 1.25rem Nunito,"WM Round",sans-serif;color:var(--gold2);letter-spacing:-.01em}
.pane .lead{margin:0 0 .9rem;color:var(--muted);font-size:.82rem;line-height:1.55}
.grp{border:1px solid var(--line);border-radius:16px;padding:.95rem;margin-top:.8rem;background:linear-gradient(160deg,rgba(26,37,32,.7),rgba(14,20,17,.6))}
.grp>h3{margin:0 0 .65rem;font-size:.78rem;font-weight:800;letter-spacing:.06em;color:var(--mint)}
.f{display:block;margin-top:.75rem}
.grp>h3+.f{margin-top:0}
.f-head{display:flex;align-items:center;gap:.4rem;font-size:.78rem;font-weight:700;color:var(--muted);margin-bottom:.35rem}
.f-head .cnt{margin-left:auto;font-size:.7rem;opacity:.7}
.f-head .rst{border:none;background:none;color:var(--muted);cursor:pointer;font-size:.85rem;padding:0 .15rem;opacity:.7}
.f-head .rst:hover{opacity:1;color:var(--gold2)}
.inp{width:100%;border-radius:12px;border:1px solid rgba(232,213,168,.14);background:rgba(6,10,8,.6);padding:.7rem .8rem;outline:none;transition:border-color .2s,box-shadow .2s}
.inp:hover{border-color:var(--line2)}
.inp:focus{border-color:rgba(134,214,170,.55);box-shadow:0 0 0 3px rgba(134,214,170,.12)}
.inp.changed{border-color:rgba(217,182,115,.6)}
textarea.inp{resize:vertical;min-height:4.4rem;line-height:1.55}
.seg{display:flex;padding:.2rem;border-radius:12px;background:rgba(0,0,0,.3);border:1px solid var(--line);gap:.2rem}
.seg button{flex:1;border:none;background:none;border-radius:9px;padding:.5rem .45rem;font-weight:800;font-size:.8rem;color:var(--muted);cursor:pointer;transition:background .2s,color .2s}
.seg button.on{background:rgba(217,182,115,.18);color:var(--gold2)}
.sub-label{margin:.85rem 0 .35rem;font-size:.78rem;font-weight:700;color:var(--muted)}
.grp>h3+.sub-label{margin-top:0}
.drop{position:relative;display:grid;place-items:center;min-height:9.5rem;border-radius:14px;border:1.5px dashed var(--line2);background:#0b100e center/cover no-repeat;overflow:hidden;cursor:pointer;transition:border-color .2s}
.drop:hover,.drop.over{border-color:var(--gold)}
.drop .dz{position:relative;z-index:1;text-align:center;padding:.8rem 1rem;color:var(--muted);font-size:.82rem;font-weight:700;background:rgba(0,0,0,.5);border-radius:12px;line-height:1.5}
.drop.has .dz{opacity:0;transition:opacity .2s}
.drop.has:hover .dz{opacity:1}
.row{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap}
.range{display:flex;align-items:center;gap:.6rem}
.range input{flex:1;accent-color:var(--gold)}
.range output{min-width:2.8rem;text-align:right;font-weight:800;color:var(--gold2);font-size:.82rem}
.themes{display:grid;grid-template-columns:repeat(2,1fr);gap:.5rem;margin-top:.7rem}
.th{display:flex;align-items:center;gap:.6rem;padding:.7rem;border-radius:14px;border:1px solid var(--line);background:rgba(0,0,0,.25);cursor:pointer;text-align:left;transition:border-color .2s,background .2s}
.th:hover{border-color:var(--line2)}
.th.on{border-color:var(--gold);background:rgba(217,182,115,.14)}
.th b{font-size:1.35rem;line-height:1}
.th span{display:block;font-weight:800;font-size:.84rem}
.th small{display:block;color:var(--muted);font-size:.7rem;margin-top:.1rem}
.sw{display:flex;flex-wrap:wrap;gap:.45rem;align-items:center}
.sw button{width:2.1rem;height:2.1rem;border-radius:999px;border:2px solid transparent;cursor:pointer;box-shadow:inset 0 0 0 1px rgba(255,255,255,.18);transition:transform .2s}
.sw button:hover{transform:scale(1.08)}
.sw button.on{border-color:#fff}
.sw .def{width:auto;padding:0 .85rem;border:1px solid var(--line2);background:rgba(255,255,255,.04);font-weight:800;font-size:.76rem;color:var(--muted);box-shadow:none}
.sw .def.on{color:var(--gold2);border-color:var(--gold)}
.sw input[type=color]{width:2.1rem;height:2.1rem;border:none;border-radius:999px;padding:0;background:none;cursor:pointer}
.fonts{display:grid;gap:.5rem}
.fo{display:flex;align-items:center;justify-content:space-between;gap:.8rem;padding:.75rem .9rem;border-radius:14px;border:1px solid var(--line);background:rgba(0,0,0,.25);cursor:pointer;text-align:left;transition:border-color .2s,background .2s}
.fo:hover{border-color:var(--line2)}
.fo.on{border-color:var(--gold);background:rgba(217,182,115,.14)}
.fo .nm{font-size:.76rem;font-weight:800;color:var(--muted)}
.fo .sm{font-size:1.1rem;white-space:nowrap}
.tg{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.75rem 0;border-top:1px solid var(--line)}
.grp>h3+.tg{border-top:none;padding-top:0}
.tg b{display:block;font-size:.86rem}
.tg small{color:var(--muted);font-size:.74rem}
.sw-t{position:relative;width:2.9rem;height:1.6rem;flex-shrink:0}
.sw-t input{position:absolute;inset:0;opacity:0;cursor:pointer;margin:0;z-index:1}
.sw-t i{position:absolute;inset:0;border-radius:999px;background:rgba(255,255,255,.12);transition:background .2s}
.sw-t i::after{content:"";position:absolute;left:.2rem;top:.2rem;width:1.2rem;height:1.2rem;border-radius:999px;background:#fff;transition:transform .25s var(--ease)}
.sw-t input:checked+i{background:linear-gradient(135deg,var(--gold2),var(--gold))}
.sw-t input:checked+i::after{transform:translateX(1.3rem)}
.hist{display:grid;gap:.5rem;grid-template-columns:minmax(0,1fr)}
.hi{display:flex;align-items:center;gap:.7rem;padding:.7rem .8rem;border-radius:14px;border:1px solid var(--line);background:rgba(0,0,0,.22)}
.hi .dot{width:.55rem;height:.55rem;border-radius:999px;background:var(--line2);flex-shrink:0}
.hi.cur{border-color:var(--line2)}
.hi.cur .dot{background:var(--mint);box-shadow:0 0 8px var(--mint)}
.hi .meta{flex:1;min-width:0}
.hi .meta b{display:block;font-size:.84rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.hi .meta small{color:var(--muted);font-size:.72rem}
.hi .btn{padding:.4rem .75rem;font-size:.74rem}
.hi .now{font-size:.72rem;font-weight:800;color:var(--mint)}
.empty{color:var(--muted);font-size:.82rem;line-height:1.6}
.hint{margin:.5rem 0 0;color:var(--muted);font-size:.74rem;line-height:1.55}
.hint b{color:var(--gold2)}
.stage{display:grid;grid-template-rows:auto 1fr;min-height:0;min-width:0}
.pbar{display:flex;align-items:center;gap:.5rem;padding:.6rem .9rem;border-bottom:1px solid var(--line)}
.pbar .seg{flex:0 0 auto}
.pbar .seg button{white-space:nowrap}
.pbar .url{flex:1;min-width:0;padding:.42rem .8rem;border-radius:999px;background:rgba(0,0,0,.3);border:1px solid var(--line);font-size:.76rem;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pbar .url b{color:var(--gold2)}
.frame-wrap{position:relative;min-height:0;display:grid;padding:1rem;overflow:auto;background:repeating-linear-gradient(45deg,rgba(255,255,255,.012) 0 12px,transparent 12px 24px)}
.frame{width:100%;height:100%;min-height:520px;border:1px solid var(--line2);border-radius:18px;background:#0b1210;box-shadow:0 30px 80px -40px #000}
.frame-wrap.mobile{justify-items:center;align-items:start}
.frame-wrap.mobile .frame{width:390px;height:780px;min-height:0;border-radius:34px;border:8px solid #1c2622}
.loading{position:absolute;inset:1rem;display:grid;place-items:center;color:var(--muted);font-size:.85rem;pointer-events:none}
.toast{position:fixed;left:50%;bottom:1.4rem;transform:translate(-50%,20px);opacity:0;z-index:50;padding:.75rem 1.1rem;border-radius:14px;border:1px solid var(--line2);background:rgba(14,21,18,.96);font-weight:700;font-size:.86rem;transition:opacity .3s,transform .3s var(--ease);pointer-events:none;box-shadow:0 20px 50px -24px #000}
.toast.show{opacity:1;transform:translate(-50%,0)}
.toast.ok{border-color:rgba(127,216,166,.5);color:var(--ok)}
.toast.bad{border-color:rgba(239,138,120,.5);color:var(--danger)}
@media (max-width:980px){
  body{overflow:auto}
  .ed{height:auto;min-height:100vh}
  .body{grid-template-columns:1fr}
  .panel{border-right:none;border-bottom:1px solid var(--line);grid-template-columns:1fr}
  .tabs{flex-direction:row;overflow-x:auto;border-right:none;border-bottom:1px solid var(--line)}
  .tab{flex:0 0 auto;padding:.5rem .8rem}
  .pane{padding-bottom:1.5rem}
  .frame-wrap{height:80vh}
  .top{flex-wrap:wrap}
  .hide-sm{display:none!important}
}
</style></head><body>
<div id="gate" class="gate"><div class="gate-card"><h1>사이트 에디터</h1><p>확인 중…</p></div></div>
<div id="app" class="ed hidden">
  <header class="top">
    <a class="logo" href="/">WILDMC<span>.</span>EDITOR<small class="hide-sm">web v__WEB_BUILD__</small></a>
    <span class="status" id="status"><i></i><span id="statusText">모두 저장됨</span></span>
    <span class="grow"></span>
    <a class="btn hide-sm" href="/?edit=1">✏️ 페이지에서 바로 편집</a>
    <button class="btn" type="button" id="revertBtn" disabled>되돌리기</button>
    <button class="btn primary" type="button" id="saveBtn" disabled>저장 <kbd>Ctrl S</kbd></button>
  </header>
  <div class="body">
    <aside class="panel">
      <nav class="tabs" id="tabs" aria-label="편집 메뉴"></nav>
      <div class="pane" id="pane"></div>
    </aside>
    <section class="stage">
      <div class="pbar">
        <div class="seg" id="device"><button type="button" data-d="desktop" class="on">🖥 데스크톱</button><button type="button" data-d="mobile">📱 모바일</button></div>
        <div class="url"><b>미리보기</b> · 저장하기 전 모습이 바로 보여요</div>
        <button class="btn" type="button" id="reloadBtn" title="미리보기 새로고침">↻</button>
        <a class="btn" href="/" target="_blank" rel="noopener">새 탭 ↗</a>
      </div>
      <div class="frame-wrap" id="frameWrap"><div class="loading" id="pvLoading">미리보기 불러오는 중…</div><iframe class="frame" id="pv" title="사이트 미리보기"></iframe></div>
    </section>
  </div>
</div>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<script>
const $=(s,r=document)=>r.querySelector(s);
const $$=(s,r=document)=>[...r.querySelectorAll(s)];
const esc=(s)=>String(s??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
const clone=(o)=>JSON.parse(JSON.stringify(o));
const BANNER_KEYS=["title","subtitle","cta_label","link_url","image_url"];
let BOOT=null, saved=null, draft=null, tab="hero", pvReady=false, busy=false;

const F=(k,label,ph,o={})=>Object.assign({k,label,ph},o);
const TABS=[
  {id:"hero",icon:"✨",label:"히어로",title:"히어로 · 큰 배너",lead:"홈 맨 위 큰 배너의 문구, 버튼, 배경을 바꿉니다.",groups:[
    {title:"문구",fields:[F("b:title","제목","",{max:80,siteNamePh:true}),F("b:subtitle","부제목","디스코드 인증부터 랭크·닉네임 변경까지, 한곳에서 관리하세요.",{max:240,area:true}),F("s:site_tagline","윗줄 뱃지","Minecraft × Discord",{max:60})]},
    {title:"버튼",fields:[F("s:hero_link_cta","버튼 1 · 마인크래프트 계정과 연동하기","마인크래프트 계정과 연동하기",{max:30}),F("b:cta_label","버튼 2 · 문구","시작하기",{max:30}),F("b:link_url","버튼 2 · 이동할 주소","/login",{max:300}),F("s:shop_cta","버튼 3 · 상점","상점",{max:30})]},
    {title:"배경 이미지",custom:"heroImage"},
    {title:"배치",custom:"heroLayout"}
  ]},
  {id:"text",icon:"✍️",label:"문구",title:"문구",lead:"상단 띠, 서버 현황, 상품 섹션 등 홈의 글자를 바꿉니다.",groups:[
    {title:"상단 띠",custom:"announce"},
    {title:"서버 현황",fields:[F("s:stats_kicker","작은 제목","LIVE STATUS",{max:40}),F("s:stats_title","섹션 제목","서버 현황",{max:40}),F("s:stat_online_label","카드 1","실시간 접속",{max:30}),F("s:stat_peak_label","카드 2","오늘 최고 동접",{max:30}),F("s:stat_today_label","카드 3","오늘 누적 접속",{max:30}),F("s:stat_week_label","카드 4","일주일 누적 접속",{max:30}),F("s:live_online","서버 켜짐 표시","Minecraft Online",{max:40}),F("s:live_offline","서버 꺼짐 표시","Minecraft Offline",{max:40})]},
    {title:"상품",fields:[F("s:shop_kicker","작은 제목","SHOP",{max:40}),F("s:shop_title","섹션 제목","상품",{max:40}),F("s:shop_all_label","전체 보기 링크","전체 보기",{max:30}),F("s:shop_page_desc","상점 페이지 설명","디스코드 로그인 + 마인크래프트 연동 후 구매할 수 있습니다.",{max:200,area:true})]},
    {title:"쿠폰 페이지",fields:[F("s:coupon_page_title","제목","쿠폰받기",{max:40}),F("s:coupon_page_desc","설명","해당 쿠폰으로 구매할 시 할인이 적용이 돼요.",{max:200,area:true})]},
    {title:"푸터",fields:[F("s:footer_link_label","오른쪽 강조 링크","도전과제",{max:30})]}
  ]},
  {id:"menu",icon:"🧭",label:"메뉴",title:"로고 · 메뉴",lead:"왼쪽 위 로고와 상단 메뉴 이름입니다.",groups:[
    {title:"로고",fields:[F("s:site_name","이름","WILDMC",{max:30}),F("s:site_suffix","점 뒤 글자 (비우면 숨김)","",{max:20,keepEmpty:true})]},
    {title:"메뉴 이름",fields:[F("s:nav_notice","공지","공지",{max:20}),F("s:shop_nav","상점","상점",{max:20}),F("s:nav_coupon","쿠폰받기","쿠폰받기",{max:20}),F("s:nav_friends","친구","친구",{max:20}),F("s:nav_support","문의","문의",{max:20}),F("s:nav_achievements","도전과제","도전과제",{max:20}),F("s:nav_link","마인크래프트 계정과 연동하기","마인크래프트 계정과 연동하기",{max:20}),F("s:nav_inbox","우편함","우편함",{max:20})]}
  ]},
  {id:"look",icon:"🎨",label:"테마·색",title:"테마 · 색 · 글꼴",lead:"시즌 테마, 포인트 색, 글꼴로 분위기를 바꿉니다.",groups:[
    {title:"시즌 테마",custom:"theme"},
    {title:"포인트 색",custom:"accent"},
    {title:"글꼴",custom:"font"},
    {title:"글자 · 블록 크기",custom:"sizes"},
    {title:"배경음악",custom:"bgm"}
  ]},
  {id:"layout",icon:"🧩",label:"레이아웃",title:"레이아웃",lead:"홈에 보일 섹션과 입장 방식을 고릅니다.",groups:[{title:"입장",custom:"gate"},{title:"홈 섹션",custom:"sections"}]},
  {id:"history",icon:"🕘",label:"기록",title:"저장 기록",lead:"저장할 때마다 버전이 남습니다. 예전 버전으로 언제든 되돌릴 수 있어요.",groups:[{title:"버전",custom:"history"}]}
];
const ACCENTS=["#d4af6a","#7dcea0","#6aa9ff","#b18cff","#ff8fab","#ff9e5e","#ffd166","#4dd4c9","#e8e3d6"];
const FONTS=[
  {id:"cute",name:"동글 · 귀여운 기본",css:'Dongle,Jua,"NanumSquareRound",sans-serif'},
  {id:"round",name:"둥근 고딕",css:'"WM Round",Nunito,sans-serif'},
  {id:"gowun",name:"고운돋움 · 부드러운 본문",css:'"Gowun Dodum",sans-serif'},
  {id:"jua",name:"주아 · 귀여운 제목",css:'Jua,sans-serif'},
  {id:"gothic",name:"노토 산스 · 깔끔한 고딕",css:'"Noto Sans KR",sans-serif'}
];

function srcOf(obj,k){ const [kind,key]=k.split(":"); return [kind==="b"?obj.banner:obj.settings,key]; }
function getV(k,obj=draft){ const [src,key]=srcOf(obj,k); const v=src[key]; return v==null?"":String(v); }
function setV(k,v){ const [src,key]=srcOf(draft,k); src[key]=v; changed(); }
function S(key){ return getV("s:"+key); }
function setS(key,v){ setV("s:"+key,v); }

function diff(){
  const out={settings:{},banner:{}};
  new Set([...Object.keys(draft.settings),...Object.keys(saved.settings)]).forEach(k=>{
    const a=String(draft.settings[k]??""), b=String(saved.settings[k]??"");
    if(a!==b) out.settings[k]=a;
  });
  BANNER_KEYS.forEach(k=>{ const a=String(draft.banner[k]??""), b=String(saved.banner[k]??""); if(a!==b) out.banner[k]=a; });
  return out;
}
const countChanges=(d)=>Object.keys(d.settings).length+Object.keys(d.banner).length;
function refreshStatus(){
  const n=countChanges(diff());
  $("#status").classList.toggle("dirty", n>0);
  $("#statusText").textContent=n?`변경 ${n}개 · 저장 안 됨`:"모두 저장됨";
  $("#saveBtn").disabled=n===0||busy;
  $("#revertBtn").disabled=n===0||busy;
}
function changed(){ refreshStatus(); schedulePreview(); }

let pvTimer=0;
function schedulePreview(){ clearTimeout(pvTimer); pvTimer=setTimeout(sendPreview,120); }
function sendPreview(){
  if(!pvReady) return;
  const w=$("#pv").contentWindow;
  if(w) w.postMessage({type:"wm-draft",settings:draft.settings,banner:draft.banner}, location.origin);
}
function loadPreview(){ pvReady=false; $("#pvLoading").classList.remove("hidden"); $("#pv").src="/?preview=1&t="+Date.now(); }
window.addEventListener("message",(e)=>{
  if(e.origin!==location.origin) return;
  if(e.data&&e.data.type==="wm-preview-ready"){ pvReady=true; $("#pvLoading").classList.add("hidden"); sendPreview(); }
});

let toastT=0;
function toast(msg,kind){ const t=$("#toast"); t.textContent=msg; t.className="toast show"+(kind?" "+kind:""); clearTimeout(toastT); toastT=setTimeout(()=>{ t.className="toast"; },2800); }
function ago(ms){
  const s=Math.max(1,Math.round((Date.now()-Number(ms||0))/1000));
  if(s<60) return "방금";
  if(s<3600) return Math.floor(s/60)+"분 전";
  if(s<86400) return Math.floor(s/3600)+"시간 전";
  return new Date(ms).toLocaleString("ko-KR",{month:"numeric",day:"numeric",hour:"2-digit",minute:"2-digit"});
}

function fieldHtml(f){
  const ph=f.siteNamePh?(S("site_name")||"WILDMC"):f.ph;
  const attrs=`class="inp" data-k="${f.k}" maxlength="${f.max||300}" placeholder="${esc(ph)}"`;
  const input=f.area?`<textarea ${attrs} rows="3"></textarea>`:`<input ${attrs}/>`;
  return `<label class="f"><span class="f-head">${esc(f.label)}<span class="cnt" data-cnt="${f.k}"></span><button type="button" class="rst" data-rst="${f.k}" title="기본값으로 되돌리기">↺</button></span>${input}</label>`;
}
const CUSTOM={
  heroImage:()=>`<div class="drop" id="drop"><div class="dz">🖼 클릭하거나 이미지를 끌어다 놓으세요<br><small>JPG · PNG · WEBP · 자동으로 줄여서 올려요</small></div></div><input type="file" accept="image/*" id="heroFile" hidden>
    <div class="row" style="margin-top:.6rem"><input class="inp" style="flex:1" id="heroUrl" placeholder="또는 이미지 주소 붙여넣기 (https://…)"><button type="button" class="btn" id="heroClear">제거</button></div>
    <div class="sub-label">배경 어둡기 · 글씨가 잘 보이게</div><div class="range"><input type="range" min="0" max="95" step="1" id="heroOv"><output id="heroOvOut"></output></div>`,
  heroLayout:()=>`<div class="sub-label">글자 정렬</div><div class="seg" data-seg="hero_align" data-def="left"><button type="button" data-v="left">왼쪽</button><button type="button" data-v="center">가운데</button></div>
    <div class="sub-label">높이 · 화면 너비에 맞춰 비율 유지</div><div class="seg" data-seg="hero_height" data-def="normal"><button type="button" data-v="compact">낮게 · 3:1</button><button type="button" data-v="normal">보통 · 2:1</button><button type="button" data-v="tall">사진 비율 · 16:9</button></div>`,
  announce:()=>`<div class="sub-label">무엇을 보여줄까요?</div><div class="seg" data-seg="announce_source" data-def="notice"><button type="button" data-v="notice">최신 공지 제목</button><button type="button" data-v="custom">직접 입력</button><button type="button" data-v="off">숨기기</button></div>
    ${fieldHtml(F("s:announcement","띠 문구 (직접 입력 · 공지가 없을 때)","환영합니다!",{max:120}))}<p class="hint" id="annHint"></p>`,
  theme:()=>{
    const all=(BOOT.theme&&BOOT.theme.catalog)||[];
    const auto=all.find(c=>c.id===BOOT.theme.autoId);
    return `<div class="seg" data-seg="theme_mode" data-def="auto"><button type="button" data-v="auto">자동 (날짜)</button><button type="button" data-v="manual">직접 고르기</button><button type="button" data-v="off">끄기</button></div>
      <p class="hint">${auto&&auto.id!=="default"?`오늘 자동 테마: <b>${esc(auto.emoji)} ${esc(auto.label)}</b>`:"오늘은 자동 시즌 테마가 없어요 · 기본 숲 테마"}</p>
      <div class="themes">${all.filter(c=>c.id!=="default").map(c=>`<button type="button" class="th" data-theme="${esc(c.id)}"><b>${esc(c.emoji)}</b><div><span>${esc(c.label)}</span><small>${esc(c.hint)}</small></div></button>`).join("")}</div>`;
  },
  accent:()=>`<div class="sw"><button type="button" class="def" data-acc="">테마 색 그대로</button>${ACCENTS.map(c=>`<button type="button" data-acc="${c}" style="background:${c}" title="${c}"></button>`).join("")}<input type="color" id="accPick" title="직접 고르기"></div><p class="hint">버튼 · 제목 · 테두리 색이 바뀌어요. 시즌 테마 색 위에 덮어씌웁니다.</p>`,
  font:()=>`<div class="fonts">${FONTS.map(f=>`<button type="button" class="fo" data-font="${f.id}"><span class="nm">${f.name}</span><span class="sm" style="font-family:${f.css}">가나다 WILDMC 123</span></button>`).join("")}</div>`,
  sizes:()=>`<div class="sub-label">전체 글자 크기</div><div class="range"><input type="range" min="80" max="140" step="5" id="fontScale"><output id="fontScaleOut"></output></div>
    <div class="sub-label">카드 · 블록 여백</div><div class="range"><input type="range" min="80" max="140" step="5" id="blockScale"><output id="blockScaleOut"></output></div>
    <div class="sub-label">모서리 둥글기</div><div class="range"><input type="range" min="70" max="150" step="5" id="radiusScale"><output id="radiusScaleOut"></output></div>
    <p class="hint">미리보기에서 바로 확인할 수 있어요. 100이 기본값입니다.</p>`,
  bgm:()=>`<div class="tg"><div><b>배경음악 사용</b><small>사이트 오른쪽 🔊 버튼으로 켜고 끌 수 있어요</small></div><label class="sw-t"><input type="checkbox" data-toggle="bgm_enabled" aria-label="배경음악"><i></i></label></div>
    <label class="f"><span class="f-head">음악 주소 (mp3 · mp4 · ogg URL)<span class="cnt" data-cnt="s:bgm_url"></span><button type="button" class="rst" data-rst="s:bgm_url" title="비우기">↺</button></span><input class="inp" data-k="s:bgm_url" maxlength="500" placeholder="https://…/music.mp3"/></label>
    <p class="hint">비우면 기본 잔잔한 톤이 재생됩니다. 직접 올린 파일의 공개 URL을 넣으면 그 노래가 나와요.</p>`,
  gate:()=>`<div class="tg"><div><b>처음 들어올 때 로그인 필수</b><small>로그인하지 않은 방문자에게는 디스코드 로그인 화면만 보여요</small></div><label class="sw-t"><input type="checkbox" data-toggle="require_login" aria-label="로그인 필수"><i></i></label></div>`,
  sections:()=>[["show_stats","서버 현황","실시간 접속 · 최고 동접 카드"],["show_shop","상품 미리보기","홈 아래쪽 상품 6개"]]
    .map(([k,t,d])=>`<div class="tg"><div><b>${t}</b><small>${d}</small></div><label class="sw-t"><input type="checkbox" data-toggle="${k}" aria-label="${t}"><i></i></label></div>`).join("")+`<p class="hint">상단 띠는 「문구」 탭에서 숨길 수 있어요.</p>`,
  history:()=>{
    const items=BOOT.history||[];
    if(!items.length) return `<p class="empty">아직 저장 기록이 없어요. 처음 저장하면 원래 모습도 함께 보관돼요.</p>`;
    return `<div class="hist">${items.map(h=>`<div class="hi${h.current?" cur":""}"><span class="dot"></span><div class="meta"><b>${esc(h.label)}</b><small>${esc(h.byName)} · ${ago(h.at)}${h.title?` · «${esc(h.title)}»`:""}</small></div>${h.current?`<span class="now">현재</span>`:`<button type="button" class="btn" data-restore="${h.id}">복원</button>`}</div>`).join("")}</div>`;
  }
};

function renderTabs(){ $("#tabs").innerHTML=TABS.map(t=>`<button type="button" class="tab${t.id===tab?" on":""}" data-tab="${t.id}"><b>${t.icon}</b>${t.label}</button>`).join(""); }
function renderPane(){
  const t=TABS.find(x=>x.id===tab)||TABS[0];
  $("#pane").innerHTML=`<h2>${t.title}</h2><p class="lead">${t.lead}</p>`+t.groups.map(g=>`<section class="grp"><h3>${g.title}</h3>${g.custom?CUSTOM[g.custom]():g.fields.map(fieldHtml).join("")}</section>`).join("");
  $$("#pane [data-k]").forEach(el=>{ el.value=getV(el.dataset.k); markField(el); });
  bindDrop();
  paintCustom();
}
function markField(el){
  const k=el.dataset.k;
  el.classList.toggle("changed", getV(k)!==getV(k,saved));
  const c=$(`[data-cnt="${k}"]`);
  if(c) c.textContent=`${el.value.length}/${el.maxLength}`;
}
function paintCustom(){
  $$("[data-seg]").forEach(seg=>{ const cur=S(seg.dataset.seg)||seg.dataset.def; seg.querySelectorAll("button").forEach(b=>b.classList.toggle("on", b.dataset.v===cur)); });
  const mode=S("theme_mode")||"auto", tid=S("theme_id")||"default";
  $$("[data-theme]").forEach(b=>b.classList.toggle("on", mode==="manual"&&b.dataset.theme===tid));
  const acc=S("accent_color");
  $$("[data-acc]").forEach(b=>b.classList.toggle("on", (b.dataset.acc||"")===acc));
  const pick=$("#accPick"); if(pick) pick.value=/^#[0-9a-f]{6}$/i.test(acc)?acc:"#d4af6a";
  const font=S("site_font")||"cute";
  $$("[data-font]").forEach(b=>b.classList.toggle("on", b.dataset.font===font));
  $$("[data-toggle]").forEach(i=>{ i.checked=S(i.dataset.toggle)!=="0"; });
  const fs=$("#fontScale"), bs=$("#blockScale"), rs=$("#radiusScale");
  if(fs){ const v=S("ui_font_scale")||"100"; fs.value=v; $("#fontScaleOut").textContent=v+"%"; }
  if(bs){ const v=S("ui_block_scale")||"100"; bs.value=v; $("#blockScaleOut").textContent=v+"%"; }
  if(rs){ const v=S("ui_radius_scale")||"100"; rs.value=v; $("#radiusScaleOut").textContent=v+"%"; }
  const hint=$("#annHint");
  if(hint){ const n=BOOT.latestNotice; hint.innerHTML=n?`최신 공지: <b>${esc(n.title)}</b>`:"등록된 공지가 없어서 띠 문구가 보여요."; }
  paintDrop();
}
function paintDrop(){
  const d=$("#drop"); if(!d) return;
  const u=getV("b:image_url");
  d.classList.toggle("has", !!u);
  d.style.backgroundImage=u?`url("${u.replace(/["\\\n]/g,"")}")`:"none";
  const url=$("#heroUrl"); if(url&&document.activeElement!==url) url.value=u;
  const ov=$("#heroOv"), raw=S("hero_overlay"), val=raw===""?82:Number(raw);
  if(ov){ ov.value=String(val); $("#heroOvOut").textContent=val+"%"; }
}
function bindDrop(){
  const d=$("#drop"); if(!d) return;
  d.addEventListener("click",()=>$("#heroFile").click());
  ["dragenter","dragover"].forEach(ev=>d.addEventListener(ev,(e)=>{ e.preventDefault(); d.classList.add("over"); }));
  ["dragleave","drop"].forEach(ev=>d.addEventListener(ev,(e)=>{ e.preventDefault(); d.classList.remove("over"); }));
  d.addEventListener("drop",(e)=>{ const f=e.dataTransfer&&e.dataTransfer.files&&e.dataTransfer.files[0]; if(f) uploadHero(f); });
}
async function compressImage(file){
  if(!file.type.startsWith("image/")) throw new Error("이미지 파일만 올릴 수 있어요.");
  if(file.size>15*1024*1024) throw new Error("15MB 이하 이미지를 올려 주세요.");
  try{
    const bmp=await createImageBitmap(file);
    const max=2000; let w=bmp.width,h=bmp.height;
    if(w>max||h>max){ const s=Math.min(max/w,max/h); w=Math.round(w*s); h=Math.round(h*s); }
    const c=document.createElement("canvas"); c.width=w; c.height=h; c.getContext("2d").drawImage(bmp,0,0,w,h); bmp.close();
    return c.toDataURL("image/jpeg",0.86);
  }catch(e){
    return await new Promise((res,rej)=>{ const r=new FileReader(); r.onload=()=>res(r.result); r.onerror=rej; r.readAsDataURL(file); });
  }
}
async function uploadHero(file){
  try{
    toast("이미지 올리는 중…");
    const data=await compressImage(file);
    const r=await fetch("/api/site-edit/upload",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({data,filename:file.name})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.error||"업로드 실패");
    setV("b:image_url", j.url); paintDrop(); toast("배경 이미지를 올렸어요 · 저장하면 적용돼요","ok");
  }catch(err){ toast(err.message||"업로드 실패","bad"); }
}

$("#tabs").addEventListener("click",(e)=>{
  const b=e.target.closest("[data-tab]"); if(!b) return;
  tab=b.dataset.tab; renderTabs(); renderPane(); history.replaceState(null,"","#"+tab);
});
$("#pane").addEventListener("input",(e)=>{
  const el=e.target.closest("[data-k]");
  if(el){ setV(el.dataset.k, el.value); markField(el); return; }
  if(e.target.id==="heroOv"){ setS("hero_overlay", e.target.value); $("#heroOvOut").textContent=e.target.value+"%"; return; }
  if(e.target.id==="fontScale"){ setS("ui_font_scale", e.target.value); $("#fontScaleOut").textContent=e.target.value+"%"; return; }
  if(e.target.id==="blockScale"){ setS("ui_block_scale", e.target.value); $("#blockScaleOut").textContent=e.target.value+"%"; return; }
  if(e.target.id==="radiusScale"){ setS("ui_radius_scale", e.target.value); $("#radiusScaleOut").textContent=e.target.value+"%"; return; }
  if(e.target.id==="accPick"){ setS("accent_color", e.target.value); paintCustom(); return; }
  if(e.target.id==="heroUrl"){ setV("b:image_url", e.target.value.trim()); paintDrop(); }
});
$("#pane").addEventListener("change",(e)=>{
  const tg=e.target.closest("[data-toggle]");
  if(tg){ setS(tg.dataset.toggle, tg.checked?"1":"0"); return; }
  if(e.target.id==="heroFile"){ const f=e.target.files&&e.target.files[0]; if(f) uploadHero(f); e.target.value=""; }
});
$("#pane").addEventListener("click",(e)=>{
  const t=e.target;
  const rst=t.closest("[data-rst]");
  if(rst){
    e.preventDefault();
    const k=rst.dataset.rst, v=k==="s:site_suffix"?"MC":"";
    setV(k,v);
    const el=$(`[data-k="${k}"]`); if(el){ el.value=v; markField(el); }
    return;
  }
  const seg=t.closest("[data-seg] button");
  if(seg){ setS(seg.parentElement.dataset.seg, seg.dataset.v); paintCustom(); return; }
  const th=t.closest("[data-theme]");
  if(th){ draft.settings.theme_mode="manual"; setS("theme_id", th.dataset.theme); paintCustom(); return; }
  const acc=t.closest("[data-acc]");
  if(acc){ setS("accent_color", acc.dataset.acc); paintCustom(); return; }
  const fo=t.closest("[data-font]");
  if(fo){ setS("site_font", fo.dataset.font==="round"?"":fo.dataset.font); paintCustom(); return; }
  const rs=t.closest("[data-restore]");
  if(rs){ void restore(Number(rs.dataset.restore)); return; }
  if(t.closest("#heroClear")){ setV("b:image_url",""); paintDrop(); }
});
$("#device").addEventListener("click",(e)=>{
  const b=e.target.closest("[data-d]"); if(!b) return;
  $$("#device button").forEach(x=>x.classList.toggle("on", x===b));
  $("#frameWrap").classList.toggle("mobile", b.dataset.d==="mobile");
});
$("#reloadBtn").addEventListener("click", loadPreview);
$("#saveBtn").addEventListener("click",()=>void save());
$("#revertBtn").addEventListener("click",()=>{
  if(!confirm("저장하지 않은 변경을 모두 되돌릴까요?")) return;
  draft=clone(saved); renderPane(); changed();
});
document.addEventListener("keydown",(e)=>{ if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="s"){ e.preventDefault(); void save(); } });
window.addEventListener("beforeunload",(e)=>{ if(draft&&countChanges(diff())){ e.preventDefault(); e.returnValue=""; } });

function normalize(j){
  const settings=Object.assign({}, j.settings||{});
  if(settings.site_suffix==null) settings.site_suffix="MC";
  const banner={}; BANNER_KEYS.forEach(k=>{ banner[k]=String((j.banner||{})[k]||""); });
  return {settings, banner};
}
function applyServer(j){
  BOOT=Object.assign(BOOT||{}, j);
  saved=normalize(j); draft=clone(saved);
  renderPane(); refreshStatus(); sendPreview();
}
async function save(){
  const d=diff();
  if(!countChanges(d)||busy) return;
  busy=true; refreshStatus(); $("#saveBtn").textContent="저장 중…";
  try{
    const r=await fetch("/api/site-edit/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(d)});
    const j=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.error||"저장 실패");
    applyServer(j);
    toast("저장했어요 · 사이트에 바로 반영됐어요","ok");
  }catch(err){ toast(err.message||"저장 실패","bad"); }
  finally{ busy=false; $("#saveBtn").innerHTML="저장 <kbd>Ctrl S</kbd>"; refreshStatus(); }
}
async function restore(id){
  if(countChanges(diff())&&!confirm("저장하지 않은 변경이 있어요. 버리고 복원할까요?")) return;
  if(!confirm(`#${id} 버전으로 되돌릴까요? 지금 모습도 기록에 남아요.`)) return;
  const r=await fetch("/api/site-edit/restore",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id})});
  const j=await r.json().catch(()=>({}));
  if(!r.ok){ toast(j.error||"복원 실패","bad"); return; }
  applyServer(j); toast("복원했어요 · 사이트에 바로 반영됐어요","ok");
}
async function boot(){
  const card=$("#gate .gate-card");
  let me=null;
  try{ const r=await fetch("/api/me"); if(r.ok) me=await r.json(); }catch(e){}
  if(!me||!me.authenticated){
    card.innerHTML=`<h1>사이트 에디터</h1><p>디스코드로 로그인하면 사이트를 꾸밀 수 있어요.</p><a class="btn primary" style="margin-top:1rem" href="/api/auth/discord?next=/decorate">디스코드 로그인</a>`;
    return;
  }
  const r=await fetch("/api/site-edit/bootstrap");
  const j=await r.json().catch(()=>({}));
  if(!r.ok){
    card.innerHTML=`<h1>Team. Wildmc 권한이 필요해요</h1><p>사이트 편집은 <b>Team. Wildmc</b> 권한이 있어야만 할 수 있습니다.</p><code>${esc((me.discord&&me.discord.id)||"")}</code><p>데스크톱 앱 「유저」에서 이 계정에 「Team. Wildmc 주기」를 눌러 달라고 요청하세요.</p><a class="btn" style="margin-top:.8rem" href="/">사이트로</a>`;
    return;
  }
  BOOT=j; saved=normalize(j); draft=clone(saved);
  const h=location.hash.slice(1); if(TABS.some(t=>t.id===h)) tab=h;
  $("#gate").classList.add("hidden"); $("#app").classList.remove("hidden");
  renderTabs(); renderPane(); refreshStatus(); loadPreview();
}
boot();
</script></body></html>
"""


_ROUND_FONT_BASE = "https://hangeul.pstatic.net/hangeul_static/webfont/NanumSquareRound/NanumSquareRound"
ROUND_FONT_CSS = "".join(
    '@font-face{font-family:"WM Round";font-style:normal;font-weight:%d;font-display:swap;'
    'src:url(%s%s.woff2) format("woff2"),url(%s%s.woff) format("woff")}\n' % (weight, _ROUND_FONT_BASE, cut, _ROUND_FONT_BASE, cut)
    for weight, cut in ((300, "L"), (400, "R"), (700, "B"), (800, "EB"))
)


CSS = r"""
:root {
  --bg0: #0a0f0d; --bg1: #121c18; --bg2: #1a2922;
  --line: rgba(212, 175, 106, 0.24);
  --gold: #d9b673; --gold-soft: #eeddb0; --mint: #82d3a4;
  --text: #f4f0e6; --muted: #9aa89f; --danger: #e07a6a; --ok: #6fcf97;
  --shadow-soft: 0 20px 50px -30px rgba(0,0,0,.85);
  --shadow-lift: 0 26px 60px -24px rgba(0,0,0,.9);
}
* { box-sizing: border-box; }
html, body { min-height: 100%; }
body {
  margin: 0; color: var(--text);
  background:
    radial-gradient(1300px 760px at 8% -12%, rgba(130, 211, 164, 0.16), transparent 55%),
    radial-gradient(1000px 640px at 96% -4%, rgba(217, 182, 115, 0.14), transparent 50%),
    radial-gradient(900px 520px at 50% 115%, rgba(130, 211, 164, 0.08), transparent 60%),
    linear-gradient(165deg, #0a0f0d 0%, #0f1815 45%, #0b110f 100%);
  font-family: Outfit, "Apple SD Gothic Neo", "Malgun Gothic", sans-serif;
  overflow-x: hidden;
}
body::before {
  content: ""; position: fixed; inset: 0; pointer-events: none; z-index: 0;
  background-image:
    linear-gradient(rgba(255,255,255,.016) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.016) 1px, transparent 1px);
  background-size: 48px 48px;
  mask-image: radial-gradient(ellipse at center, black 30%, transparent 75%);
}
a { color: inherit; text-decoration: none; }
button, input, textarea { font: inherit; }
.display { font-family: "Space Grotesk", Outfit, sans-serif; letter-spacing: -0.03em; }
.panel-shell { position: relative; z-index: 1; min-height: 100vh; }
.glass {
  position: relative;
  background: linear-gradient(160deg, rgba(28, 44, 37, 0.88), rgba(13, 20, 17, 0.74));
  border: 1px solid var(--line); backdrop-filter: blur(16px);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.05), var(--shadow-soft);
}
.gold-btn {
  background: linear-gradient(135deg, #f0dfb5, #d9b673 50%, #b48c40);
  color: #1a1408; font-weight: 700; border: none; cursor: pointer;
  box-shadow: 0 14px 32px -8px rgba(201, 162, 77, 0.4);
  transition: transform .25s ease, filter .25s ease, box-shadow .25s ease;
}
.gold-btn:hover { transform: translateY(-2px); filter: brightness(1.06); box-shadow: 0 18px 38px -8px rgba(201, 162, 77, 0.5); }
.ghost-btn {
  background: rgba(255,255,255,.02); border: 1px solid var(--line); color: var(--gold-soft); cursor: pointer;
  transition: background .2s ease, border-color .2s ease, transform .2s ease;
}
.ghost-btn:hover { background: rgba(212,175,106,.1); border-color: rgba(212,175,106,.5); transform: translateY(-1px); }
.nav-active {
  background: rgba(212,175,106,.14) !important;
  border-color: rgba(212,175,106,.55) !important;
  color: var(--gold-soft) !important;
  box-shadow: none !important;
}
.rank-chip {
  display: inline-flex; align-items: center; padding: .35rem .75rem; border-radius: 999px;
  background: rgba(125,206,160,.12); border: 1px solid rgba(125,206,160,.28);
  color: var(--mint); font-size: .85rem; font-weight: 600; flex-shrink: 0;
}
.wrap { max-width: 72rem; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
@media (min-width: 768px) { .wrap { padding-left: 2.5rem; padding-right: 2.5rem; } }
.header { display: flex; align-items: center; justify-content: space-between; gap: .75rem; margin-bottom: 2rem; flex-wrap: wrap; }
.brand { font-size: 1.35rem; font-weight: 600; color: var(--gold-soft); }
@media (min-width: 768px) { .brand { font-size: 1.5rem; } }
.brand .dot { color: var(--mint); }
.nav { display: flex; align-items: center; gap: .5rem; flex-wrap: wrap; }
.pill { border-radius: 999px; padding: .5rem 1rem; font-size: .875rem; display: inline-flex; align-items: center; }
.announce {
  display: block; border-bottom: 1px solid var(--line); background: rgba(212,175,106,.08);
  padding: .65rem 1rem; text-align: center; font-size: .875rem; color: var(--gold-soft);
}
.hero { position: relative; overflow: hidden; border-radius: 28px; min-height: 58vh; }
.hero-bg {
  position: absolute; inset: 0;
  background: linear-gradient(120deg, rgba(18,40,30,.95), rgba(40,28,12,.75)),
    radial-gradient(circle at 80% 20%, rgba(212,175,106,.28), transparent 45%);
}
.hero-bg.has-photo {
  background-image:
    linear-gradient(120deg, rgba(18,40,30,.9), rgba(40,28,12,.72)),
    var(--hero-photo) !important;
  background-size: cover !important;
  background-position: center !important;
  background-repeat: no-repeat !important;
}
.hero-inner { position: relative; display: flex; min-height: 58vh; flex-direction: column; justify-content: flex-end; padding: 2.5rem 1.75rem; }
@media (min-width: 768px) { .hero-inner { padding: 3.5rem 3rem; } }
.kicker { margin: 0 0 .75rem; font-size: .75rem; letter-spacing: .28em; text-transform: uppercase; color: var(--muted); }
.hero h1 { margin: 0; max-width: 36rem; font-size: clamp(2rem, 5vw, 3.75rem); font-weight: 600; line-height: 1.08; }
.hero .sub { margin: 1rem 0 0; max-width: 36rem; color: var(--gold-soft); font-size: 1.05rem; line-height: 1.6; }
.cta { margin-top: 2rem; display: flex; flex-wrap: wrap; gap: .75rem; }
.cta .pill { padding: .85rem 1.75rem; }
.stats-head { margin-top: 2.5rem; display: flex; flex-wrap: wrap; align-items: flex-end; justify-content: space-between; gap: .75rem; margin-bottom: 1.25rem; }
.stats-head h2 { margin: .5rem 0 0; font-size: 1.875rem; color: var(--gold); }
.live { display: flex; align-items: center; gap: .5rem; border: 1px solid var(--line); border-radius: 999px; padding: .35rem .75rem; font-size: .875rem; color: var(--gold-soft); }
.dot { width: .65rem; height: .65rem; border-radius: 999px; display: inline-block; }
.grid-4 { display: grid; gap: 1rem; }
@media (min-width: 640px) { .grid-4 { grid-template-columns: 1fr 1fr; } }
@media (min-width: 1024px) { .grid-4 { grid-template-columns: repeat(4, 1fr); } }
.stat { border-radius: 22px; padding: 1.25rem 1.35rem; transition: transform .3s var(--ease-out, ease), box-shadow .3s ease, border-color .3s ease; }
.stat:hover { transform: translateY(-3px); border-color: color-mix(in srgb, var(--gold) 45%, var(--line)); box-shadow: var(--shadow-lift, 0 22px 44px -28px rgba(0,0,0,.75)); }
.stat .label { margin: 0; font-size: .75rem; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); }
.stat .val { margin-top: .5rem; font-size: 2.25rem; font-weight: 600; }
.stat .hint { margin-top: .5rem; font-size: .75rem; color: var(--muted); }
.shop-head { margin-top: 4rem; margin-bottom: 1.75rem; display: flex; align-items: flex-end; justify-content: space-between; gap: 1rem; }
.shop-head h2 { margin: .5rem 0 0; font-size: 1.875rem; color: var(--gold); }
.mint { color: var(--mint); font-size: .875rem; }
.mint:hover { text-decoration: underline; }
.grid-3 { display: grid; gap: 1.25rem; }
@media (min-width: 640px) { .grid-3 { grid-template-columns: 1fr 1fr; } }
@media (min-width: 1024px) { .grid-3 { grid-template-columns: 1fr 1fr 1fr; } }
.card { overflow: hidden; border-radius: 22px; }
.thumb {
  height: 10rem;
  background: linear-gradient(135deg, #1a2922, #2a2214);
  overflow: hidden;
  position: relative;
}
.thumb:empty::after {
  content: "이미지 없음";
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  color: rgba(154,168,159,.55);
  font-size: .8rem;
}
.thumb img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  display: block;
  border: 0;
}
.card-body { padding: 1.25rem; }
.card h3 { margin: 0; font-size: 1.125rem; color: var(--gold-soft); }
.desc { margin: .5rem 0 0; font-size: .875rem; color: var(--muted); display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
.price { margin-top: 1rem; font-size: 1rem; font-weight: 600; color: var(--mint); }
.buy { margin-top: 1rem; display: inline-flex; border-radius: 999px; padding: .65rem 1.25rem; font-size: .875rem; }
.empty { border-radius: 1rem; border: 1px solid var(--line); padding: 2rem 1.25rem; font-size: .875rem; color: var(--muted); }
.footer { margin-top: 4rem; padding-bottom: 1.5rem; font-size: .75rem; color: var(--muted); }
.site-build-badge {
  position: fixed;
  right: .85rem;
  bottom: .75rem;
  z-index: 9998;
  pointer-events: none;
  font-family: "Space Grotesk", Outfit, sans-serif;
  font-size: .72rem;
  font-weight: 700;
  letter-spacing: .04em;
  color: rgba(232, 213, 168, .88);
  background: rgba(8, 14, 12, .72);
  border: 1px solid rgba(232, 213, 168, .28);
  border-radius: 999px;
  padding: .35rem .7rem;
  backdrop-filter: blur(8px);
  box-shadow: 0 8px 24px rgba(0,0,0,.28);
}
@media (max-width: 640px) {
  .site-build-badge { right: .55rem; bottom: .55rem; font-size: .68rem; padding: .3rem .55rem; }
}
.page-title {
  font-size: 2.25rem; margin: 0;
  background: linear-gradient(120deg, var(--gold-soft), var(--gold) 55%, var(--mint));
  -webkit-background-clip: text; background-clip: text; color: transparent;
}
.login-wrap { display: grid; min-height: 100vh; place-items: center; padding: 1.25rem; }
.login-card { width: 100%; max-width: 28rem; border-radius: 28px; padding: 2rem; }
.field {
  width: 100%; background: rgba(8,14,12,.65); border: 1px solid rgba(212,175,106,.18);
  color: var(--text); border-radius: 14px; padding: .9rem 1rem; outline: none;
}
.field:focus { border-color: rgba(125,206,160,.55); box-shadow: 0 0 0 3px rgba(125,206,160,.12); }
.row { display: flex; align-items: flex-start; justify-content: space-between; gap: .5rem; }
.notice-card { margin-top: 1rem; border-radius: 20px; overflow: hidden; }
.notice-btn { display: flex; width: 100%; align-items: flex-start; justify-content: space-between; gap: .75rem; padding: 1rem 1.25rem; background: none; border: none; color: inherit; cursor: pointer; text-align: left; }
.notice-body { border-top: 1px solid var(--line); padding: 1rem 1.25rem; white-space: pre-wrap; font-size: .875rem; line-height: 1.6; }
.cat { margin: .25rem 0 0; font-size: .75rem; color: var(--muted); }
.badge { display: inline-flex; min-width: 1.15rem; align-items: center; justify-content: center; border-radius: 999px; background: #e23b3b; padding: 0 .4rem; font-size: 11px; font-weight: 700; color: #fff; margin-left: .25rem; box-shadow: 0 0 0 2px #121c18; line-height: 1.35; }
.avatar { width: 2rem; height: 2rem; border-radius: 999px; object-fit: cover; }
.avatar-fallback { display: grid; width: 2rem; height: 2rem; place-items: center; border-radius: 999px; background: rgba(212,175,106,.2); font-size: .75rem; color: var(--gold); }
.profile-link { display: inline-flex; align-items: center; gap: .5rem; padding: .35rem .75rem .35rem .35rem !important; }
.profile-name { max-width: 7.5rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--gold-soft); font-size: .875rem; }
.profile-complete { flex-shrink: 0; font-size: .9rem; line-height: 1; filter: drop-shadow(0 0 5px rgba(212,175,106,.55)); animation: profile-complete-glow 2.8s ease-in-out infinite; }
@keyframes profile-complete-glow {
  0%, 100% { transform: scale(1); opacity: .92; }
  50% { transform: scale(1.08); opacity: 1; }
}
.gold-btn:disabled, .ghost-btn:disabled { opacity: .55; cursor: not-allowed; transform: none; }
.spinner { width: 2.5rem; height: 2.5rem; border: 2px solid var(--line); border-top-color: var(--gold); border-radius: 999px; animation: spin 1s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.grid-2 { display: grid; gap: 1.25rem; }
@media (min-width: 768px) { .grid-2 { grid-template-columns: 1fr 1fr; } }
.info-block { border-radius: 1rem; border: 1px solid var(--line); background: rgba(8,14,12,.45); padding: 1rem; }
.info-block .label { font-size: .75rem; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); margin: 0; }
.info-block .val { margin: .5rem 0 0; font-size: .875rem; word-break: break-all; }
.toast {
  position: fixed; bottom: 1.5rem; left: 50%; transform: translateX(-50%);
  z-index: 50; width: min(92vw, 420px); box-sizing: border-box;
  border-radius: 1rem; border: 1px solid; padding: .75rem 1rem;
  font-size: .875rem; line-height: 1.45; word-break: keep-all; overflow-wrap: anywhere;
  background: rgba(14, 22, 18, 0.96);
}
.toast.is-inline {
  position: static; left: auto; transform: none; width: 100%; max-width: 100%;
  margin-top: .75rem;
}
.stack { display: flex; flex-direction: column; gap: .75rem; }
.narrow { max-width: 42rem; margin: 0 auto; }
.inbox-wrap { max-width: 78rem; }
.inbox-stage {
  display: grid;
  gap: 1.5rem;
  align-items: start;
}
@media (min-width: 1100px) {
  .inbox-stage {
    grid-template-columns: minmax(11rem, 15rem) minmax(0, 1fr) minmax(11rem, 15rem);
    gap: 1.75rem;
  }
}
.inbox-rail {
  display: none;
  border-radius: 24px;
  padding: 1.35rem 1.25rem;
  position: relative;
  overflow: hidden;
  min-height: 18rem;
}
@media (min-width: 1100px) {
  .inbox-rail { display: block; }
}
.inbox-rail::before {
  content: "";
  position: absolute; inset: 0; pointer-events: none;
  background:
    radial-gradient(circle at 20% 10%, rgba(212,175,106,.18), transparent 45%),
    radial-gradient(circle at 80% 90%, rgba(125,206,160,.12), transparent 50%);
}
.inbox-rail > * { position: relative; z-index: 1; }
.inbox-rail .rail-kicker {
  margin: 0;
  font-size: .7rem;
  letter-spacing: .22em;
  text-transform: uppercase;
  color: var(--muted);
}
.inbox-rail .rail-title {
  margin: .55rem 0 0;
  font-size: 1.2rem;
  color: var(--gold-soft);
  line-height: 1.3;
}
.inbox-rail .rail-copy {
  margin: .75rem 0 0;
  font-size: .85rem;
  color: var(--muted);
  line-height: 1.65;
}
.rail-links { margin-top: 1.25rem; display: flex; flex-direction: column; gap: .55rem; }
.rail-links a {
  display: block;
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: .7rem .85rem;
  font-size: .85rem;
  color: var(--gold-soft);
  background: rgba(8,14,12,.35);
  transition: border-color .2s ease, background .2s ease, transform .2s ease;
}
.rail-links a:hover {
  border-color: rgba(212,175,106,.5);
  background: rgba(212,175,106,.08);
  transform: translateX(3px);
}
.rail-stat {
  margin-top: 1.35rem;
  border-top: 1px solid var(--line);
  padding-top: 1rem;
}
.rail-stat .num {
  margin: .35rem 0 0;
  font-size: 2rem;
  color: var(--mint);
  font-weight: 600;
}
.rail-ornament {
  position: absolute;
  width: 7rem; height: 7rem;
  border: 1px solid rgba(212,175,106,.16);
  border-radius: 50%;
  right: -1.5rem; bottom: -1.5rem;
  pointer-events: none;
  animation: railPulse 6s ease-in-out infinite;
}
.rail-ornament::after {
  content: "";
  position: absolute; inset: 1rem;
  border: 1px solid rgba(125,206,160,.14);
  border-radius: 50%;
}
@keyframes railPulse {
  0%, 100% { transform: scale(1); opacity: .7; }
  50% { transform: scale(1.06); opacity: 1; }
}
.inbox-main { min-width: 0; }
.inbox-head { display: flex; justify-content: space-between; align-items: center; gap: 1rem; margin-bottom: 1.75rem; }
.inbox-list { display: flex; flex-direction: column; gap: 1.35rem; }
.mail-card {
  border-radius: 22px;
  padding: 1.5rem 1.6rem 1.45rem;
  display: flex;
  flex-direction: column;
  gap: 0.85rem;
}
.mail-card.is-read { opacity: 0.72; }
.mail-card h2 { margin: 0; font-size: 1.15rem; color: var(--gold-soft); line-height: 1.35; }
.mail-body { margin: 0; white-space: pre-wrap; font-size: .9rem; color: var(--muted); line-height: 1.7; }
.mail-meta { margin: 0; font-size: .75rem; color: var(--muted); opacity: .9; }
.mail-card .gold-btn { align-self: flex-start; margin-top: .25rem; padding: .55rem 1.15rem; }
.page-ambient {
  pointer-events: none;
  position: absolute;
  inset: 0;
  overflow: hidden;
  z-index: 0;
}
.page-ambient span {
  position: absolute;
  border-radius: 50%;
  filter: blur(40px);
  opacity: .35;
}
.page-ambient .a1 {
  width: 18rem; height: 18rem; left: -4rem; top: 18%;
  background: rgba(125, 206, 160, 0.22);
  animation: floaty 10s ease-in-out infinite;
}
.page-ambient .a2 {
  width: 22rem; height: 22rem; right: -6rem; top: 8%;
  background: rgba(212, 175, 106, 0.18);
  animation: floaty 12s ease-in-out infinite reverse;
}
.page-ambient .a3 {
  width: 14rem; height: 14rem; right: 8%; bottom: 10%;
  background: rgba(125, 206, 160, 0.12);
  animation: floaty 14s ease-in-out infinite;
}
@keyframes floaty {
  0%, 100% { transform: translateY(0); }
  50% { transform: translateY(-18px); }
}
.panel-shell.has-ambient { isolation: isolate; }
.panel-shell.has-ambient > .wrap { position: relative; z-index: 1; }
.center-page { display: grid; min-height: 100vh; place-items: center; padding: 1.25rem; }
.ach-grid { display: grid; gap: 1rem; margin-top: 1.5rem; }
@media (min-width: 640px) { .ach-grid { grid-template-columns: 1fr 1fr; } }
.ach-card { border-radius: 20px; padding: 1.15rem 1.25rem; position: relative; overflow: hidden; transition: transform .25s ease, border-color .25s ease; }
.ach-card.locked { opacity: .55; filter: grayscale(.35); }
.ach-card.unlocked { border-color: rgba(125,206,160,.35); }
.ach-card.unlocked:hover { transform: translateY(-2px); }
.ach-card.secret.locked .ach-title { letter-spacing: .08em; }
.ach-icon { font-size: 1.75rem; line-height: 1; margin-bottom: .5rem; }
.ach-title { margin: 0; font-size: 1.05rem; color: var(--gold-soft); }
.ach-desc { margin: .4rem 0 0; font-size: .8rem; color: var(--muted); line-height: 1.45; }
.ach-meta { margin-top: .75rem; display: flex; align-items: center; justify-content: space-between; gap: .5rem; font-size: .7rem; color: var(--muted); }
.ach-progress { margin-top: 1.25rem; border-radius: 16px; padding: 1rem 1.15rem; }
.ach-bar { height: .45rem; border-radius: 999px; background: rgba(255,255,255,.06); overflow: hidden; margin-top: .65rem; }
.ach-bar > span { display: block; height: 100%; border-radius: 999px; background: linear-gradient(90deg, var(--mint), var(--gold)); transition: width .4s ease; }
@font-face {
  font-family: "Galmuri11";
  src: url("https://cdn.jsdelivr.net/npm/galmuri@latest/dist/galmuri11.woff2") format("woff2");
  font-display: swap;
}
.mc-toast {
  position: fixed; top: 1.1rem; right: 1.1rem; z-index: 90;
  width: min(92vw, 360px);
  font-family: Galmuri11, Galmuri14, "Malgun Gothic", sans-serif;
  pointer-events: none;
  animation: mcToastIn .4s cubic-bezier(.2,.8,.2,1);
  filter: drop-shadow(0 8px 18px rgba(0,0,0,.55));
}
.mc-toast-frame {
  border: 3px solid #1b1408;
  background: #1b1408;
  box-shadow: 0 0 0 1px #000;
}
.mc-toast-top {
  display: flex; align-items: center; gap: .75rem;
  background: linear-gradient(180deg, #d4b21a 0%, #b8920e 55%, #9a780c 100%);
  border-bottom: 2px solid #5c4300;
  box-shadow: inset 0 2px 0 rgba(255,236,150,.55), inset 0 -2px 0 rgba(0,0,0,.18);
  padding: .7rem .85rem .7rem .7rem; min-height: 3.4rem;
}
.mc-toast-icon {
  flex-shrink: 0; width: 2.6rem; height: 2.6rem;
  display: grid; place-items: center; font-size: 1.45rem; line-height: 1;
  background: linear-gradient(180deg, #3a3a3a, #222);
  border: 2px solid #0d0d0d;
  box-shadow: inset 1px 1px 0 #666, inset -1px -1px 0 #111, 1px 1px 0 #6b5208;
}
.mc-toast-copy { min-width: 0; flex: 1; }
.mc-toast-label {
  margin: 0 0 .2rem; color: #fff8d6; font-size: .72rem; letter-spacing: .02em;
  text-shadow: 1px 1px 0 #5a4300; opacity: .95;
}
.mc-toast-title {
  margin: 0; color: #fff; font-size: 1.05rem; line-height: 1.3; font-weight: 700;
  text-shadow: 2px 2px 0 #3d2e00; word-break: keep-all;
}
.mc-toast-bottom {
  background: linear-gradient(180deg, #2a2a2a, #1a1a1a);
  padding: .85rem .9rem .95rem;
  color: #ffe08a; font-size: .92rem; line-height: 1.45;
  text-align: center; text-shadow: 1px 1px 0 #000;
  word-break: keep-all;
}
@keyframes mcToastIn {
  0% { opacity: 0; transform: translateX(40px) scale(.96); }
  100% { opacity: 1; transform: none; }
}
.egg-hot { cursor: default; user-select: none; }

/* —— Seasonal themes (refined) —— */
html[data-theme] body { transition: background .55s ease, color .35s ease; }
html[data-theme] {
  --theme-glow: transparent;
}
.theme-banner {
  display: flex; align-items: center; justify-content: center; gap: .65rem; flex-wrap: wrap;
  padding: .7rem 1.1rem; font-size: .86rem; letter-spacing: .04em;
  border-bottom: 1px solid var(--line);
  color: var(--gold-soft);
  background: rgba(0,0,0,.28);
  backdrop-filter: blur(8px);
  position: relative;
  overflow: hidden;
}
.theme-banner::before {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,.06), transparent);
  animation: themeSheen 4.5s ease-in-out infinite;
}
.theme-banner b { color: var(--text); font-weight: 700; position: relative; }
.theme-banner span { position: relative; }
@keyframes themeSheen {
  0%, 100% { transform: translateX(-30%); opacity: .2; }
  50% { transform: translateX(30%); opacity: .55; }
}
#themeFx {
  position: fixed; inset: 0; pointer-events: none; z-index: 2; overflow: hidden;
}
#themeFx::after {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background:
    radial-gradient(ellipse 80% 50% at 50% -10%, var(--theme-glow), transparent 60%),
    radial-gradient(ellipse 70% 40% at 50% 110%, rgba(0,0,0,.35), transparent 55%);
  opacity: .85;
}
.theme-flake, .theme-spark, .theme-petal, .theme-ember {
  position: absolute; top: -10%; border-radius: 50%;
  animation: themeFall linear infinite;
  opacity: .75;
}
.theme-emoji {
  position: absolute;
  font-size: clamp(1.4rem, 2.4vw, 2.4rem);
  line-height: 1;
  opacity: .2;
  filter: saturate(1.1) drop-shadow(0 2px 6px rgba(0,0,0,.35));
  animation: themeDrift ease-in-out infinite;
  user-select: none;
}
.theme-emoji.is-edge {
  opacity: .38;
  font-size: clamp(1.85rem, 3vw, 3.1rem);
}
@media (max-width: 900px) {
  .theme-emoji { opacity: .12; font-size: 1.15rem; }
  .theme-emoji.is-edge { opacity: .2; font-size: 1.4rem; }
}
@keyframes themeFall {
  0% { transform: translate3d(0,-10vh,0) rotate(0deg); opacity: 0; }
  12% { opacity: .85; }
  100% { transform: translate3d(var(--drift, 20px), 110vh, 0) rotate(360deg); opacity: .12; }
}
@keyframes themeDrift {
  0%, 100% { transform: translateY(0) rotate(var(--rot, 0deg)) scale(1); }
  50% { transform: translateY(var(--bob, -14px)) rotate(calc(var(--rot, 0deg) + 8deg)) scale(1.06); }
}

/* Christmas — crimson / pine / frost */
html[data-theme="christmas"] {
  --theme-glow: rgba(220,40,50,.28);
  --bg0: #120606; --bg1: #1a100c; --bg2: #241410;
  --line: rgba(220, 55, 55, 0.36);
  --gold: #f2c85c; --gold-soft: #ffe9b0; --mint: #4aaa6a;
  --text: #fff5ec; --muted: #c4a090;
}
html[data-theme="christmas"] body {
  background:
    radial-gradient(1000px 560px at 6% -5%, rgba(210,28,42,.5), transparent 52%),
    radial-gradient(860px 500px at 96% 8%, rgba(18,110,50,.42), transparent 50%),
    radial-gradient(640px 420px at 50% 100%, rgba(200,150,50,.14), transparent 55%),
    linear-gradient(168deg, #1c0707 0%, #0c1610 48%, #140808 100%);
}
html[data-theme="christmas"] .glass {
  background: linear-gradient(155deg, rgba(70,18,20,.86), rgba(10,32,18,.72));
  border-color: rgba(220,70,70,.38);
  box-shadow: 0 18px 50px rgba(80,0,10,.25), inset 0 1px 0 rgba(255,220,160,.08);
}
html[data-theme="christmas"] .gold-btn {
  background: linear-gradient(135deg, #ffe9b0, #e8483a 48%, #6e1018);
  color: #1a0808;
  box-shadow: 0 10px 28px rgba(180,40,40,.28);
}
html[data-theme="christmas"] .hero-bg {
  background:
    linear-gradient(125deg, rgba(42,8,10,.96), rgba(6,36,18,.9)),
    radial-gradient(circle at 78% 16%, rgba(255,215,100,.42), transparent 42%);
}
html[data-theme="christmas"] .theme-banner {
  background: linear-gradient(90deg, rgba(150,18,28,.58), rgba(14,68,32,.48), rgba(150,18,28,.58));
}
html[data-theme="christmas"] .brand .dot { color: #4aaa6a; }
.theme-flake {
  width: 6px; height: 6px; background: rgba(255,255,255,.92);
  box-shadow: 0 0 10px rgba(255,255,255,.7), 0 0 2px #fff;
}

/* Chuseok — harvest moon */
html[data-theme="chuseok"] {
  --theme-glow: rgba(255,210,120,.32);
  --bg0: #181006; --bg1: #261a0a; --bg2: #3a2810;
  --line: rgba(240, 180, 70, 0.38);
  --gold: #ffc24e; --gold-soft: #ffe6b0; --mint: #e8a838;
  --text: #fff7e8; --muted: #c4a878;
}
html[data-theme="chuseok"] body {
  background:
    radial-gradient(560px 560px at 88% 4%, rgba(255,236,170,.62), transparent 42%),
    radial-gradient(920px 520px at 8% 92%, rgba(160,80,20,.3), transparent 52%),
    radial-gradient(420px 280px at 40% 30%, rgba(255,180,60,.08), transparent 50%),
    linear-gradient(165deg, #1c1206 0%, #2c1e0c 45%, #120c06 100%);
}
html[data-theme="chuseok"] .glass {
  background: linear-gradient(155deg, rgba(78,52,16,.9), rgba(28,18,8,.8));
  border-color: rgba(240,180,70,.42);
  box-shadow: 0 18px 48px rgba(60,30,0,.28), inset 0 1px 0 rgba(255,230,160,.1);
}
html[data-theme="chuseok"] .gold-btn {
  background: linear-gradient(135deg, #ffe6b0, #ffc24e 45%, #a86818);
  color: #2a1808;
}
html[data-theme="chuseok"] .hero-bg {
  background:
    linear-gradient(120deg, rgba(40,24,8,.95), rgba(62,38,12,.88)),
    radial-gradient(circle at 86% 12%, rgba(255,238,170,.6), transparent 38%);
}
html[data-theme="chuseok"] .theme-banner {
  background: linear-gradient(90deg, rgba(140,80,20,.42), rgba(230,170,55,.3));
}
.theme-petal {
  width: 11px; height: 11px;
  background: rgba(255,196,80,.8);
  border-radius: 2px 11px 2px 11px;
  box-shadow: 0 0 8px rgba(255,180,60,.35);
}

/* Halloween — violet night / pumpkin */
html[data-theme="halloween"] {
  --theme-glow: rgba(255,120,30,.26);
  --bg0: #0a0410; --bg1: #160c1c; --bg2: #241028;
  --line: rgba(255, 130, 40, 0.38);
  --gold: #ff9e38; --gold-soft: #ffd4a8; --mint: #c878ff;
  --text: #fff2e8; --muted: #b898b0;
}
html[data-theme="halloween"] body {
  background:
    radial-gradient(860px 500px at 50% -10%, rgba(255,110,20,.4), transparent 48%),
    radial-gradient(720px 520px at 8% 85%, rgba(120,40,190,.4), transparent 52%),
    radial-gradient(500px 360px at 90% 60%, rgba(80,20,120,.2), transparent 50%),
    linear-gradient(165deg, #080310 0%, #180c22 50%, #0e0812 100%);
}
html[data-theme="halloween"] .glass {
  background: linear-gradient(155deg, rgba(52,22,64,.9), rgba(28,12,18,.82));
  border-color: rgba(255,130,40,.42);
  box-shadow: 0 18px 48px rgba(40,0,60,.3), inset 0 1px 0 rgba(255,180,100,.08);
}
html[data-theme="halloween"] .gold-btn {
  background: linear-gradient(135deg, #ffd4a8, #ff9e38 40%, #7a28b8);
  color: #180810;
}
html[data-theme="halloween"] .theme-banner {
  background: linear-gradient(90deg, rgba(255,100,20,.32), rgba(120,40,180,.38));
}
html[data-theme="halloween"] .brand .dot { color: #c878ff; }
.theme-ember {
  width: 5px; height: 5px; background: rgba(255,150,50,.95);
  box-shadow: 0 0 12px rgba(255,120,20,.75);
}

/* New Year — midnight navy / fireworks */
html[data-theme="newyear"] {
  --theme-glow: rgba(255,210,90,.22);
  --bg0: #030712; --bg1: #0a1230; --bg2: #141e48;
  --line: rgba(255, 210, 90, 0.4);
  --gold: #ffd700; --gold-soft: #fff2b8; --mint: #8ad0ff;
  --text: #fff9ec; --muted: #a0aec8;
}
html[data-theme="newyear"] body {
  background:
    radial-gradient(520px 340px at 16% 6%, rgba(255,210,80,.38), transparent 45%),
    radial-gradient(500px 320px at 84% 16%, rgba(90,140,255,.34), transparent 45%),
    radial-gradient(420px 300px at 55% 72%, rgba(255,80,130,.14), transparent 50%),
    linear-gradient(180deg, #040814 0%, #0c1640 55%, #050a16 100%);
}
html[data-theme="newyear"] .glass {
  background: linear-gradient(155deg, rgba(22,34,86,.9), rgba(10,14,40,.82));
  border-color: rgba(255,210,90,.42);
  box-shadow: 0 18px 48px rgba(10,20,60,.35), inset 0 1px 0 rgba(255,230,150,.1);
}
html[data-theme="newyear"] .gold-btn {
  background: linear-gradient(135deg, #fff2b8, #ffd700 45%, #3a70e0);
  color: #0a1230;
}
html[data-theme="newyear"] .theme-banner {
  background: linear-gradient(90deg, rgba(255,200,60,.3), rgba(50,90,200,.38));
}
.theme-spark {
  width: 3px; height: 3px; background: #ffe9a8;
  box-shadow: 0 0 12px #ffd76a, 0 0 2px #fff;
}

/* Valentine — deep rose */
html[data-theme="valentine"] {
  --theme-glow: rgba(255,70,120,.28);
  --bg0: #14050a; --bg1: #280c18; --bg2: #3c1424;
  --line: rgba(255, 90, 130, 0.38);
  --gold: #ff94b4; --gold-soft: #ffd4e0; --mint: #ff5a8a;
  --text: #fff2f6; --muted: #c898a8;
}
html[data-theme="valentine"] body {
  background:
    radial-gradient(820px 500px at 50% -8%, rgba(255,55,110,.44), transparent 50%),
    radial-gradient(640px 420px at 92% 82%, rgba(160,20,70,.32), transparent 52%),
    linear-gradient(165deg, #14050a 0%, #2c0c18 50%, #10060c 100%);
}
html[data-theme="valentine"] .glass {
  background: linear-gradient(155deg, rgba(78,22,44,.9), rgba(30,8,18,.82));
  border-color: rgba(255,100,140,.42);
  box-shadow: 0 18px 48px rgba(80,0,30,.28), inset 0 1px 0 rgba(255,180,200,.1);
}
html[data-theme="valentine"] .gold-btn {
  background: linear-gradient(135deg, #ffd4e0, #ff5a8a 50%, #a01848);
  color: #2a0814;
}
html[data-theme="valentine"] .theme-banner {
  background: linear-gradient(90deg, rgba(200,40,90,.42), rgba(255,100,140,.24));
}
html[data-theme="valentine"] .brand .dot { color: #ff5a8a; }
html[data-theme="valentine"] .theme-petal {
  background: rgba(255,120,160,.85);
  box-shadow: 0 0 8px rgba(255,80,130,.4);
}

/* Children's Day — sky / lemonade */
html[data-theme="childrens"] {
  --theme-glow: rgba(70,210,240,.26);
  --bg0: #051216; --bg1: #0c2428; --bg2: #143840;
  --line: rgba(70, 210, 240, 0.38);
  --gold: #ffe066; --gold-soft: #fff4b8; --mint: #4dd4f0;
  --text: #f4fffc; --muted: #90c0c8;
}
html[data-theme="childrens"] body {
  background:
    radial-gradient(740px 440px at 10% -2%, rgba(70,210,240,.44), transparent 48%),
    radial-gradient(740px 440px at 90% 6%, rgba(255,210,70,.34), transparent 48%),
    radial-gradient(520px 380px at 50% 100%, rgba(120,255,180,.14), transparent 55%),
    linear-gradient(165deg, #061418 0%, #0e2830 50%, #071820 100%);
}
html[data-theme="childrens"] .glass {
  background: linear-gradient(155deg, rgba(22,64,74,.88), rgba(18,42,32,.8));
  border-color: rgba(70,210,240,.4);
  box-shadow: 0 18px 48px rgba(0,40,50,.28), inset 0 1px 0 rgba(180,255,255,.1);
}
html[data-theme="childrens"] .gold-btn {
  background: linear-gradient(135deg, #fff4b8, #4dd4f0 45%, #ffe066);
  color: #0a2028;
}
html[data-theme="childrens"] .theme-banner {
  background: linear-gradient(90deg, rgba(70,210,240,.32), rgba(255,210,70,.26));
}
html[data-theme="childrens"] .brand .dot { color: #4dd4f0; }

/* Click / micro interactions */
.gold-btn, .ghost-btn, .pill, .card, .notice-btn, .buy, a.mint, .stat, .profile-link {
  -webkit-tap-highlight-color: transparent;
  touch-action: manipulation;
}
.gold-btn, .ghost-btn, button.pill {
  transition: transform .28s cubic-bezier(.34,1.56,.64,1), filter .2s ease, box-shadow .25s ease, background .2s ease, border-color .2s ease;
}
.gold-btn:active, .ghost-btn:active, button.pill:active {
  transform: scale(.92);
}
.fx-press {
  animation: fx-press .42s cubic-bezier(.34,1.56,.64,1);
}
@keyframes fx-press {
  0% { transform: scale(1); }
  35% { transform: scale(.9); }
  70% { transform: scale(1.06); }
  100% { transform: scale(1); }
}
.fx-layer {
  position: fixed; inset: 0; pointer-events: none; z-index: 9999; overflow: hidden;
}
.fx-ripple {
  position: absolute; border-radius: 999px;
  border: 2px solid rgba(232,213,168,.85);
  background: radial-gradient(circle, rgba(125,206,160,.35), transparent 70%);
  transform: translate(-50%,-50%) scale(.15);
  animation: fx-ripple .7s ease-out forwards;
}
@keyframes fx-ripple {
  to { transform: translate(-50%,-50%) scale(2.4); opacity: 0; }
}
.fx-spark {
  position: absolute; width: 6px; height: 6px; border-radius: 999px;
  background: var(--gold-soft); box-shadow: 0 0 10px rgba(232,213,168,.9);
  transform: translate(-50%,-50%);
  animation: fx-spark .65s ease-out forwards;
}
@keyframes fx-spark {
  0% { opacity: 1; transform: translate(-50%,-50%) scale(1); }
  100% { opacity: 0; transform: translate(calc(-50% + var(--dx)), calc(-50% + var(--dy))) scale(.2); }
}
.fx-ring {
  position: absolute; border-radius: 999px;
  border: 2px solid rgba(125,206,160,.7);
  transform: translate(-50%,-50%) scale(.2);
  animation: fx-ring .55s cubic-bezier(.2,.8,.2,1) forwards;
}
@keyframes fx-ring {
  to { transform: translate(-50%,-50%) scale(1.8); opacity: 0; }
}
.fx-float {
  position: absolute; font-size: 1.1rem; pointer-events: none;
  transform: translate(-50%,-50%);
  animation: fx-float .9s ease-out forwards;
  filter: drop-shadow(0 4px 10px rgba(0,0,0,.35));
}
@keyframes fx-float {
  0% { opacity: 1; transform: translate(-50%,-50%) scale(.6) rotate(-8deg); }
  40% { opacity: 1; transform: translate(-50%, calc(-50% - 18px)) scale(1.15) rotate(6deg); }
  100% { opacity: 0; transform: translate(-50%, calc(-50% - 54px)) scale(.9) rotate(12deg); }
}
.fx-burst {
  position: absolute; width: 10px; height: 10px; border-radius: 2px;
  background: linear-gradient(135deg, var(--mint), var(--gold));
  transform: translate(-50%,-50%) rotate(var(--rot));
  animation: fx-burst .7s ease-out forwards;
}
@keyframes fx-burst {
  to { opacity: 0; transform: translate(calc(-50% + var(--dx)), calc(-50% + var(--dy))) rotate(calc(var(--rot) + 120deg)) scale(.3); }
}
.link-steps {
  margin-top: 1.25rem; display: grid; gap: .75rem;
}
.link-step {
  display: flex; gap: .9rem; align-items: flex-start;
  border-radius: 18px; padding: 1rem 1.1rem;
  border: 1px solid var(--line);
  background: rgba(8,14,12,.4);
}
.link-step .n {
  flex-shrink: 0; width: 1.75rem; height: 1.75rem; border-radius: 999px;
  display: grid; place-items: center;
  background: rgba(212,175,106,.16); color: var(--gold-soft);
  font-size: .8rem; font-weight: 700;
}
.link-step p { margin: 0; font-size: .9rem; color: var(--muted); line-height: 1.55; }
.link-step b { color: var(--gold-soft); }

/* Plane flight auth — polished */
.flight-auth {
  margin: 1.75rem auto 0;
  width: min(100%, 420px);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 1.15rem;
}
.flight-cells {
  display: flex;
  gap: .55rem;
  justify-content: center;
  align-items: center;
  width: 100%;
}
.flight-cell {
  flex: 0 0 auto;
  width: 3rem; height: 3.55rem;
  border-radius: 14px;
  border: 1px solid rgba(232,213,168,.22);
  background: linear-gradient(180deg, rgba(255,255,255,.07), rgba(255,255,255,.025));
  color: var(--gold-soft);
  font-family: "Space Grotesk", Outfit, sans-serif;
  font-size: 1.4rem;
  font-weight: 700;
  text-align: center;
  outline: none;
  caret-color: transparent;
  box-shadow: inset 0 1px 0 rgba(255,255,255,.06);
  transition: border-color .35s ease, background .35s ease, box-shadow .35s ease, transform .35s cubic-bezier(.22,1,.36,1), opacity .4s ease;
}
.flight-cell:focus {
  border-color: rgba(232,213,168,.7);
  background: linear-gradient(180deg, rgba(232,213,168,.14), rgba(255,255,255,.04));
  box-shadow: 0 0 0 4px rgba(232,213,168,.12), inset 0 1px 0 rgba(255,255,255,.08);
  transform: translateY(-2px);
}
.flight-cell.is-filled {
  border-color: rgba(125,206,160,.4);
  color: #fff;
  background: linear-gradient(180deg, rgba(125,206,160,.14), rgba(255,255,255,.04));
}
.flight-auth.is-busy .flight-cell {
  opacity: .28;
  pointer-events: none;
  transform: scale(.94);
  filter: blur(.3px);
}
.flight-stage {
  position: relative;
  width: 100%;
  min-height: 188px;
  height: 188px;
  overflow: hidden;
  border-radius: 24px;
  border: 1px solid rgba(232,213,168,.16);
  background:
    radial-gradient(ellipse 70% 60% at 50% 40%, rgba(125,206,160,.08), transparent 65%),
    radial-gradient(ellipse 50% 40% at 20% 70%, rgba(232,213,168,.06), transparent 60%),
    linear-gradient(165deg, rgba(16,24,22,.98), rgba(8,12,11,.98));
  box-shadow:
    0 20px 50px rgba(0,0,0,.35),
    inset 0 1px 0 rgba(255,255,255,.06);
  display: grid;
  place-items: center;
  transition: height .35s ease, min-height .35s ease;
}
.flight-auth.is-success .flight-stage {
  height: auto;
  min-height: 300px;
  overflow: visible;
  padding: 1.15rem .75rem 1.35rem;
}
.link-bridge {
  position: relative;
  z-index: 2;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0;
  width: min(92%, 340px);
}
.link-node {
  position: relative;
  z-index: 2;
  width: 64px;
  height: 64px;
  border-radius: 20px;
  display: grid;
  place-items: center;
  border: 1px solid rgba(232,213,168,.28);
  background:
    linear-gradient(160deg, rgba(255,255,255,.08), rgba(255,255,255,.02));
  box-shadow: 0 10px 28px rgba(0,0,0,.35);
  transition: border-color .45s ease, box-shadow .45s ease, transform .5s cubic-bezier(.22,1,.36,1);
}
.link-node span {
  font-family: "Space Grotesk", Outfit, sans-serif;
  font-size: .72rem;
  font-weight: 700;
  letter-spacing: .12em;
  color: rgba(232,213,168,.85);
}
.link-node.site {
  border-color: rgba(232,213,168,.35);
}
.link-node.mc {
  border-color: rgba(125,206,160,.35);
}
.link-node.mc span { color: rgba(125,206,160,.9); }
.flight-auth.is-idle .link-node {
  animation: node-breathe 3.2s ease-in-out infinite;
}
.flight-auth.is-idle .link-node.mc { animation-delay: .4s; }
@keyframes node-breathe {
  0%,100% { transform: translateY(0); }
  50% { transform: translateY(-3px); }
}
.link-beam {
  position: relative;
  flex: 1;
  height: 3px;
  margin: 0 .35rem;
  border-radius: 999px;
  background: rgba(255,255,255,.08);
  overflow: hidden;
}
.link-beam::before {
  content: "";
  position: absolute;
  inset: 0;
  background: linear-gradient(90deg, transparent, rgba(232,213,168,.35), rgba(125,206,160,.45), transparent);
  opacity: .45;
}
.flight-auth.is-idle .link-beam::after {
  content: "";
  position: absolute;
  top: 0; bottom: 0;
  left: -30%;
  width: 30%;
  background: linear-gradient(90deg, transparent, rgba(255,255,255,.55), transparent);
  animation: beam-idle 2.4s ease-in-out infinite;
}
@keyframes beam-idle {
  0% { left: -30%; opacity: 0; }
  20% { opacity: 1; }
  100% { left: 100%; opacity: 0; }
}
.link-beam .link-fill {
  position: absolute;
  left: 0; top: 0; bottom: 0;
  width: 0%;
  border-radius: inherit;
  background: linear-gradient(90deg, #e8d5a8, #7dcea0);
  box-shadow: 0 0 16px rgba(125,206,160,.45);
  transition: width .15s linear;
}
.flight-auth.is-busy .link-fill {
  animation: beam-fill 1.15s cubic-bezier(.4,.05,.2,1) forwards;
}
@keyframes beam-fill {
  0% { width: 0%; }
  100% { width: 100%; }
}
.flight-auth.is-busy .link-node {
  animation: none;
  transform: scale(1.04);
  box-shadow: 0 0 0 4px rgba(232,213,168,.1), 0 12px 32px rgba(0,0,0,.4);
}
.flight-auth.is-busy .link-node.site {
  border-color: rgba(232,213,168,.7);
}
.flight-auth.is-busy .link-node.mc {
  border-color: rgba(125,206,160,.75);
  box-shadow: 0 0 0 4px rgba(125,206,160,.12), 0 12px 32px rgba(0,0,0,.4);
}
.flight-auth.is-busy .link-ring {
  opacity: 1;
  animation: ring-spin 1.1s linear infinite;
}
.link-ring {
  position: absolute;
  width: 118px;
  height: 118px;
  border-radius: 999px;
  border: 1.5px solid transparent;
  border-top-color: rgba(232,213,168,.55);
  border-right-color: rgba(125,206,160,.35);
  opacity: 0;
  pointer-events: none;
  z-index: 1;
}
@keyframes ring-spin {
  to { transform: rotate(360deg); }
}
.flight-auth.is-success .link-bridge {
  opacity: 0;
  transform: scale(.92);
  transition: opacity .35s ease, transform .35s ease;
  pointer-events: none;
}
.flight-auth.is-success .link-ring { opacity: 0; }
.flight-auth.is-fail .link-fill {
  width: 62% !important;
  animation: none;
  background: linear-gradient(90deg, #e8a0a0, #e85a5a);
  box-shadow: 0 0 14px rgba(232,90,90,.35);
}
.flight-auth.is-fail .link-beam {
  animation: beam-snap .55s cubic-bezier(.36,.07,.19,.97);
}
@keyframes beam-snap {
  0%,100% { transform: scaleX(1); opacity: 1; }
  35% { transform: scaleX(.15); opacity: .4; }
  55% { transform: scaleX(1.05); opacity: .85; }
}
.flight-auth.is-fail .link-node {
  animation: none;
  border-color: rgba(232,90,90,.45);
}
.flight-auth.is-fail .link-ring {
  opacity: 0;
}
.flight-verified {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  opacity: 0;
  pointer-events: none;
  z-index: 5;
  padding: .9rem;
  background: rgba(6,12,10,.35);
  backdrop-filter: blur(3px);
}
.flight-auth.is-success .flight-verified {
  position: relative;
  inset: auto;
  opacity: 1;
  pointer-events: auto;
  width: 100%;
  background: transparent;
  backdrop-filter: none;
  padding: 0;
  animation: flight-lock .65s cubic-bezier(.16,1,.3,1) .08s both;
}
.flight-auth.is-success .link-bridge,
.flight-auth.is-success .link-ring {
  display: none;
}
@keyframes flight-lock {
  0% { opacity: 0; transform: translateY(14px) scale(.92); }
  100% { opacity: 1; transform: translateY(0) scale(1); }
}
.flight-tile {
  width: min(100%, 280px);
  border-radius: 20px;
  padding: 1.2rem 1.05rem 1.25rem;
  text-align: center;
  border: 1px solid rgba(111,207,151,.48);
  background:
    radial-gradient(circle at 50% -10%, rgba(111,207,151,.28), transparent 55%),
    linear-gradient(165deg, rgba(18,32,26,.96), rgba(8,14,12,.94));
  box-shadow: 0 18px 40px rgba(0,0,0,.4), 0 0 30px rgba(111,207,151,.1);
}
.flight-tile .gold-btn {
  margin-top: .85rem;
  display: inline-flex;
}
.flight-tile .ok-mark {
  display: inline-grid; place-items: center;
  width: 2.35rem; height: 2.35rem; border-radius: 999px;
  margin-bottom: .55rem;
  background: rgba(111,207,151,.16);
  border: 1px solid rgba(111,207,151,.5);
  color: var(--ok);
  font-size: 1rem;
  box-shadow: 0 0 18px rgba(111,207,151,.2);
}
.flight-tile h3 { margin: 0; font-size: 1.15rem; color: var(--ok); letter-spacing: -.02em; }
.flight-tile .name { margin: .45rem 0 0; color: var(--gold-soft); font-size: .92rem; }
.flight-tile .uuid {
  margin: .3rem 0 0; font-size: .68rem; color: var(--muted);
  font-family: ui-monospace, monospace; word-break: break-all;
}
.flight-hint {
  text-align: center;
  font-size: .82rem;
  color: var(--muted);
  min-height: 1.25em;
  letter-spacing: .02em;
  transition: color .35s ease, opacity .35s ease;
}
.flight-hint.ok { color: var(--ok); }
.flight-hint.bad { color: var(--danger); }
.flight-auth.is-fail-shake .flight-cells {
  animation: flight-shake .48s cubic-bezier(.36,.07,.19,.97);
}
@keyframes flight-shake {
  0%,100% { transform: translateX(0); }
  20% { transform: translateX(-7px); }
  40% { transform: translateX(7px); }
  60% { transform: translateX(-4px); }
  80% { transform: translateX(4px); }
}
#linkErr {
  transition: opacity .3s ease;
}

/* ===================== v2 · 둥근 글꼴 & 전체 폴리시 ===================== */
:root {
  --font-body: "Dongle", "Jua", "NanumSquareRound", "WM Round", "Nunito", "Apple SD Gothic Neo", "Malgun Gothic", system-ui, sans-serif;
  --font-display: "Jua", "Dongle", "NanumSquareRound", "WM Round", "Nunito", "Apple SD Gothic Neo", "Malgun Gothic", system-ui, sans-serif;
  --ease-out: cubic-bezier(.22,1,.36,1);
  --ease-spring: cubic-bezier(.34,1.56,.64,1);
  --r-xl: calc(36px * var(--ui-radius-scale, 1)); --r-lg: calc(26px * var(--ui-radius-scale, 1)); --r-md: calc(18px * var(--ui-radius-scale, 1));
  --wrap-max: clamp(72rem, 78vw, 90rem);
  --wrap-pad: 1.5rem;
  --hero-ratio: 2.1;
  --ui-font-scale: 1;
  --ui-radius-scale: 1;
  --ui-block-scale: 1;
  --bg-glow: radial-gradient(900px 500px at 8% -10%, rgba(125,206,160,.16), transparent 55%), radial-gradient(800px 480px at 100% 0%, rgba(217,182,115,.14), transparent 50%);
}
html { font-size: calc(100% * var(--ui-font-scale, 1)); }
@media (min-width: 768px) { :root { --wrap-pad: 2.5rem; } }
@media (min-width: 1600px) { html { font-size: calc(clamp(17px, calc(.6vw + 7px), 21px) * var(--ui-font-scale, 1)); } }
.wrap:not(.narrow):not(.inbox-wrap) { max-width: var(--wrap-max); }
#plist { grid-template-columns: repeat(auto-fill, minmax(min(100%, 19rem), 1fr)); }
html[data-font="cute"], html:not([data-font]) {
  --font-body: "Dongle", "Jua", "NanumSquareRound", "WM Round", sans-serif;
  --font-display: "Jua", "Dongle", "NanumSquareRound", sans-serif;
}
html[data-font="gowun"] { --font-body: "Gowun Dodum", "WM Round", "Malgun Gothic", sans-serif; }
html[data-font="jua"] { --font-display: "Jua", "WM Round", "Malgun Gothic", sans-serif; }
html[data-font="gothic"] {
  --font-body: "Noto Sans KR", "Malgun Gothic", sans-serif;
  --font-display: "Noto Sans KR", "Malgun Gothic", sans-serif;
}
html[data-font="cute"] body, html:not([data-font]) body { font-size: 1.32rem; letter-spacing: .02em; line-height: 1.65; }
html[data-font="cute"] .display, html[data-font="cute"] .brand, html[data-font="cute"] .page-title,
html:not([data-font]) .display, html:not([data-font]) .brand, html:not([data-font]) .page-title { font-weight: 400; letter-spacing: .01em; font-size: 1.08em; }
html[data-font="cute"] .page-title, html:not([data-font]) .page-title { font-size: clamp(2rem, 4.5vw, 2.75rem); }
html[data-font="cute"] .pill, html:not([data-font]) .pill { font-size: 1.02rem; }
html[data-font="cute"] .price, html:not([data-font]) .price { font-size: 1.35rem; }
html { -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility; scroll-behavior: smooth; }
body { font-family: var(--font-body); line-height: 1.65; letter-spacing: -.003em; word-break: keep-all; overflow-wrap: break-word; background-color: #0a0f0d; color: var(--text); background-image: var(--bg-glow); }
html { background-color: #0a0f0d; }
button, input, textarea, select { font-family: inherit; font-size: 1.05em; }
.display, .brand, .page-title, .stat .val, .price, .flight-cell, .link-node span, .site-build-badge { font-family: var(--font-display); }
.display { font-weight: 800; letter-spacing: -.02em; }
html[data-font="jua"] .display, html[data-font="jua"] .brand, html[data-font="jua"] .page-title { font-weight: 400; letter-spacing: 0; }
[hidden] { display: none !important; }
::selection { background: color-mix(in srgb, var(--gold) 40%, transparent); color: #fff; }
:where(a, button, summary, [tabindex]):focus-visible { outline: 2px solid var(--gold-soft); outline-offset: 3px; border-radius: 10px; }
* { scrollbar-width: thin; scrollbar-color: color-mix(in srgb, var(--gold) 35%, transparent) transparent; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-thumb { background: color-mix(in srgb, var(--gold) 32%, transparent); border-radius: 999px; border: 3px solid transparent; background-clip: padding-box; }
::-webkit-scrollbar-track { background: transparent; }

/* 헤더 · 내비 */
.header { margin-bottom: 2rem; padding: .7rem .75rem .7rem 1.1rem; border-radius: 28px; border: 1px solid var(--line); background: rgba(18, 28, 24, .94); flex-wrap: wrap; align-items: center; overflow: visible; }
.nav { flex: 1 1 16rem; min-width: 0; flex-wrap: wrap; overflow: visible; }
@media (max-width: 860px) {
  .nav { -webkit-mask-image: none; mask-image: none; }
}
@media (min-width: 861px) {
  .header { position: sticky; top: .65rem; z-index: 40; }
  .header.is-stuck {
    background: color-mix(in srgb, var(--bg1) 82%, transparent);
    border-color: var(--line);
    box-shadow: 0 14px 40px -20px rgba(0,0,0,.75);
    backdrop-filter: blur(16px) saturate(1.25);
    -webkit-backdrop-filter: blur(16px) saturate(1.25);
  }
}
.brand { font-weight: 900; letter-spacing: -.025em; }
.nav { gap: .4rem; }
.pill { font-weight: 700; font-size: .85rem; padding: .5rem .95rem; gap: .35rem; line-height: 1.2; }
.pill svg { width: .95rem; height: .95rem; flex-shrink: 0; }
.ghost-btn { background: rgba(255,255,255,.025); }
.edit-pill { box-shadow: 0 8px 22px -10px color-mix(in srgb, var(--gold) 70%, transparent); }
@media (max-width: 860px) {
  .header { border-radius: 22px; flex-direction: column; flex-wrap: nowrap; align-items: stretch; gap: .6rem; padding: .7rem .7rem .6rem; }
  .header > .brand { padding-left: .3rem; }
  .nav {
    flex-wrap: wrap; overflow: visible; padding: .1rem;
    -webkit-mask-image: none;
    mask-image: none;
  }
  .nav::-webkit-scrollbar { display: none; }
  .nav > * { flex: 0 0 auto; }
}

/* 버튼 */
.gold-btn { position: relative; overflow: hidden; font-weight: 800; letter-spacing: -.01em; }
.gold-btn::after {
  content: ""; position: absolute; inset: 0; pointer-events: none;
  background: linear-gradient(110deg, transparent 25%, rgba(255,255,255,.42) 48%, transparent 70%);
  transform: translateX(-130%); transition: transform .9s var(--ease-out);
}
.gold-btn:hover::after { transform: translateX(130%); }
.gold-btn:active, .ghost-btn:active, button.pill:active { transform: scale(.94); }

/* 상단 띠 */
.announce { display: flex; align-items: center; justify-content: center; gap: .5rem; font-weight: 700; letter-spacing: .01em; transition: background .25s ease; }
.announce:hover { background: color-mix(in srgb, var(--gold) 15%, transparent); }
.announce-ico { font-size: .95rem; line-height: 1; }

/* 히어로 */
.hero {
  --hero-w: min(100vw - 2 * var(--wrap-pad), var(--wrap-max) - 2 * var(--wrap-pad));
  --hero-h: clamp(21rem, calc(var(--hero-w) / var(--hero-ratio)), calc(100svh - 14.5rem));
  min-height: var(--hero-h); border-radius: var(--r-xl); isolation: isolate;
  border: 1px solid color-mix(in srgb, var(--gold) 24%, transparent);
  box-shadow: 0 30px 80px -40px rgba(0,0,0,.85), inset 0 1px 0 rgba(255,255,255,.06);
}
.hero.h-compact { --hero-ratio: 3; }
.hero.h-tall { --hero-ratio: 1.78; }
.hero::after {
  content: ""; position: absolute; inset: 0; pointer-events: none; z-index: 0;
  background:
    radial-gradient(120% 90% at 0% 100%, rgba(0,0,0,.42), transparent 58%),
    linear-gradient(180deg, rgba(255,255,255,.05), transparent 26%);
}
.hero-inner { min-height: var(--hero-h); z-index: 1; padding: clamp(2.25rem, 3.4vw, 4.25rem) clamp(1.5rem, 3.8vw, 4.75rem); }
.hero .kicker {
  align-self: flex-start; display: inline-flex; align-items: center; gap: .5rem;
  padding: .42rem .9rem; border-radius: 999px; font-size: .7rem; font-weight: 800; letter-spacing: .2em;
  color: var(--gold-soft); background: rgba(0,0,0,.3);
  border: 1px solid color-mix(in srgb, var(--gold) 32%, transparent);
  backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
}
.hero .kicker::before { content: ""; width: .45rem; height: .45rem; border-radius: 999px; background: var(--mint); box-shadow: 0 0 10px var(--mint); flex-shrink: 0; }
.hero h1 { font-weight: 900; margin-top: .4rem; max-width: 44rem; font-size: clamp(2.1rem, 4.2vw, 4.4rem); text-shadow: 0 8px 40px rgba(0,0,0,.35); }
.hero .sub { max-width: 40rem; font-size: clamp(1rem, 1.2vw, 1.25rem); line-height: 1.7; text-shadow: 0 2px 16px rgba(0,0,0,.35); }
.cta .pill { padding: .9rem 1.6rem; font-size: .92rem; }
.hero.is-center .hero-inner { align-items: center; justify-content: center; text-align: center; }
.hero.is-center .kicker { align-self: center; }
.hero.is-center h1, .hero.is-center .sub { margin-left: auto; margin-right: auto; }
.hero.is-center .cta { justify-content: center; }
.hero-bg.has-photo {
  background-image:
    linear-gradient(120deg, rgba(10,18,15,var(--hero-ov,.82)), rgba(24,17,8,calc(var(--hero-ov,.82) * .85))),
    var(--hero-photo) !important;
}

/* 서버 현황 */
.stats-head h2, .shop-head h2 { font-weight: 900; }
.live { font-weight: 700; background: rgba(0,0,0,.22); }
.stat {
  position: relative; overflow: hidden; border-radius: var(--r-lg); padding: calc(1.3rem * var(--ui-block-scale, 1)) calc(1.4rem * var(--ui-block-scale, 1)) calc(1.2rem * var(--ui-block-scale, 1));
  transition: transform .45s var(--ease-out), border-color .3s ease, box-shadow .45s var(--ease-out);
}
.stat:hover { transform: translateY(-3px); border-color: color-mix(in srgb, var(--gold) 45%, transparent); }
.stat::after {
  content: ""; position: absolute; right: -30%; top: -45%; width: 75%; height: 95%; pointer-events: none;
  background: radial-gradient(circle, color-mix(in srgb, var(--gold) 16%, transparent), transparent 65%);
}
.stat-ico {
  position: absolute; right: 1.1rem; top: 1.05rem; width: 2.2rem; height: 2.2rem; border-radius: 12px;
  display: grid; place-items: center; color: var(--gold-soft);
  background: color-mix(in srgb, var(--gold) 14%, transparent);
  border: 1px solid color-mix(in srgb, var(--gold) 28%, transparent);
}
.stat-ico svg { width: 1.05rem; height: 1.05rem; }
.stat .label { text-transform: none; letter-spacing: .04em; font-weight: 700; font-size: .8rem; padding-right: 2.6rem; }
.stat .val { font-weight: 900; font-size: 2.5rem; line-height: 1.1; letter-spacing: -.02em; font-variant-numeric: tabular-nums; }

/* 상품 카드 */
.card { border-radius: var(--r-lg); display: flex; flex-direction: column; }
.grid-3 > .card { transition: transform .45s var(--ease-out), box-shadow .45s var(--ease-out), border-color .3s ease; }
.grid-3 > .card:hover { transform: translateY(-5px); box-shadow: 0 30px 60px -32px rgba(0,0,0,.85); border-color: color-mix(in srgb, var(--gold) 50%, transparent); }
.thumb { height: auto; aspect-ratio: 16 / 10; }
.thumb img { transition: transform .7s var(--ease-out); }
.card:hover .thumb img { transform: scale(1.06); }
.thumb-ph {
  display: grid; place-items: center;
  background:
    radial-gradient(circle at 28% 22%, color-mix(in srgb, var(--gold) 28%, transparent), transparent 60%),
    radial-gradient(circle at 82% 88%, color-mix(in srgb, var(--mint) 22%, transparent), transparent 55%),
    linear-gradient(135deg, var(--bg1), var(--bg2));
}
.thumb-ph .ph-emoji { font-size: 3.1rem; line-height: 1; filter: drop-shadow(0 10px 18px rgba(0,0,0,.45)); transition: transform .5s var(--ease-spring); }
.card:hover .thumb-ph .ph-emoji { transform: scale(1.12) rotate(-6deg); }
.thumb-ph .ph-label { position: absolute; left: .9rem; bottom: .7rem; font-size: .68rem; font-weight: 800; letter-spacing: .18em; color: var(--gold-soft); opacity: .8; }
.card-body { flex: 1; display: flex; flex-direction: column; padding: calc(1.2rem * var(--ui-block-scale, 1)) calc(1.25rem * var(--ui-block-scale, 1)) calc(1.3rem * var(--ui-block-scale, 1)); }
.card h3 { font-weight: 800; font-size: 1.15rem; }
.grid-3 .price { margin-top: auto; padding-top: 1rem; font-size: 1.35rem; font-weight: 900; }
.buy { width: 100%; justify-content: center; padding: .8rem 1.25rem; font-weight: 800; }
.more-link { display: inline-flex; align-items: center; gap: .3rem; font-weight: 700; white-space: nowrap; flex-shrink: 0; }
.more-link svg { width: 1rem; height: 1rem; }
main section { scroll-margin-top: 5.5rem; }
.chips { display: flex; flex-wrap: wrap; gap: .45rem; margin-top: 1.4rem; }
.chip {
  border: 1px solid var(--line); background: rgba(255,255,255,.03); color: var(--muted);
  border-radius: 999px; padding: .45rem .95rem; font-weight: 700; font-size: .84rem; cursor: pointer;
  transition: color .2s, border-color .2s, background .2s;
}
.chip:hover { color: var(--gold-soft); border-color: color-mix(in srgb, var(--gold) 45%, transparent); }
.chip.on { color: var(--gold-soft); background: color-mix(in srgb, var(--gold) 18%, transparent); border-color: color-mix(in srgb, var(--gold) 60%, transparent); }
.chip .n { margin-left: .35rem; opacity: .6; font-size: .75rem; }

/* 공통 카드 · 폼 · 제목 */
.glass { box-shadow: inset 0 1px 0 rgba(255,255,255,.05), 0 20px 50px -34px rgba(0,0,0,.85); }
.page-title {
  font-weight: 900; font-size: clamp(1.9rem, 4vw, 2.6rem); letter-spacing: -.025em;
  background: linear-gradient(120deg, var(--gold-soft) 10%, var(--gold) 62%, color-mix(in srgb, var(--mint) 60%, var(--gold)));
  -webkit-background-clip: text; background-clip: text; color: transparent;
}
.field { transition: border-color .2s ease, box-shadow .2s ease, background .2s ease; }
.field:hover { border-color: color-mix(in srgb, var(--gold) 38%, transparent); }
.field::placeholder { color: color-mix(in srgb, var(--muted) 72%, transparent); }
textarea.field { resize: vertical; line-height: 1.6; }
.copy-btn {
  margin-left: .5rem; border: 1px solid var(--line); background: rgba(255,255,255,.04); color: var(--gold-soft);
  border-radius: 999px; padding: .2rem .7rem; font-size: .75rem; font-weight: 700; cursor: pointer; vertical-align: middle;
  transition: background .2s;
}
.copy-btn:hover { background: color-mix(in srgb, var(--gold) 16%, transparent); }
.steps { display: flex; gap: .4rem; margin-top: 1rem; }
.steps .st {
  flex: 1; padding: .6rem .4rem .55rem; border-radius: 12px; text-align: center;
  font-size: .78rem; font-weight: 800; color: var(--muted);
  background: rgba(255,255,255,.03); border: 1px solid var(--line);
}
.steps .st.on { color: #14110a; background: linear-gradient(135deg, var(--gold-soft), var(--gold)); border-color: transparent; }
.steps .st.cur { box-shadow: 0 0 0 3px color-mix(in srgb, var(--gold) 30%, transparent); }
.state-chip { display: inline-flex; margin-top: 1rem; padding: .35rem .8rem; border-radius: 999px; font-size: .8rem; font-weight: 800; color: var(--danger); border: 1px solid color-mix(in srgb, var(--danger) 45%, transparent); background: color-mix(in srgb, var(--danger) 10%, transparent); }

/* 푸터 */
.footer {
  margin-top: 4.5rem; padding: 1.6rem 0 1rem; border-top: 1px solid var(--line);
  display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: .9rem 1.5rem; font-size: .82rem;
}
.foot-brand { display: flex; align-items: baseline; gap: .6rem; color: var(--muted); }
.foot-brand b { font-size: 1.05rem; color: var(--gold-soft); }
.foot-links { display: flex; flex-wrap: wrap; gap: .35rem 1.1rem; }
.foot-links a { color: var(--muted); transition: color .2s; }
.foot-links a:hover { color: var(--gold-soft); }

/* 등장 애니메이션 */
@media (prefers-reduced-motion: no-preference) {
  .reveal { opacity: 0; transform: translateY(16px); transition: opacity .75s var(--ease-out), transform .75s var(--ease-out); transition-delay: var(--rd, 0ms); }
  .reveal.in { opacity: 1; transform: none; }
  .hero-bg.has-photo { animation: heroZoom 26s ease-in-out infinite alternate; }
}
@keyframes heroZoom { from { transform: scale(1); } to { transform: scale(1.07); } }

/* 페이지에서 바로 편집 */
html.se-on [data-ek] { outline: 1.5px dashed color-mix(in srgb, var(--gold) 55%, transparent); outline-offset: 4px; border-radius: 6px; cursor: text; transition: outline-color .2s, background .2s; }
html.se-on [data-ek]:hover { outline-color: var(--gold-soft); background: rgba(255,255,255,.05); }
html.se-on [data-ek]:focus { outline: 2px solid var(--gold-soft); background: rgba(0,0,0,.28); }
html.se-on [data-ek].se-changed { outline-color: var(--mint); }
html.se-on body { padding-bottom: 7rem; }
.se-fab {
  position: fixed; left: 1rem; bottom: 1rem; z-index: 60; display: inline-flex; align-items: center; gap: .5rem;
  padding: .75rem 1.15rem; border-radius: 999px; cursor: pointer; font-weight: 800; font-size: .88rem;
  color: var(--gold-soft); background: color-mix(in srgb, var(--bg1) 85%, transparent);
  border: 1px solid color-mix(in srgb, var(--gold) 55%, transparent);
  backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
  box-shadow: 0 16px 40px -18px rgba(0,0,0,.85); transition: transform .3s var(--ease-spring), background .2s;
}
.se-fab:hover { transform: translateY(-2px); background: color-mix(in srgb, var(--gold) 18%, var(--bg1)); }
.se-fab svg, .se-bar svg, .se-chip svg { width: 1rem; height: 1rem; }
.se-bar {
  position: fixed; left: 50%; bottom: 1rem; transform: translateX(-50%); z-index: 70;
  display: flex; align-items: center; flex-wrap: wrap; gap: .5rem .7rem; max-width: calc(100vw - 1.5rem);
  padding: .6rem .7rem .6rem 1rem; border-radius: 22px; font-size: .84rem;
  border: 1px solid color-mix(in srgb, var(--gold) 45%, transparent);
  background: color-mix(in srgb, var(--bg0) 90%, transparent);
  backdrop-filter: blur(18px) saturate(1.3); -webkit-backdrop-filter: blur(18px) saturate(1.3);
  box-shadow: 0 24px 60px -24px rgba(0,0,0,.9); animation: seIn .45s var(--ease-out);
}
@keyframes seIn { from { opacity: 0; transform: translate(-50%, 18px); } to { opacity: 1; transform: translate(-50%, 0); } }
.se-title { display: inline-flex; align-items: center; gap: .4rem; font-weight: 900; color: var(--gold-soft); }
.se-field { display: inline-flex; align-items: center; gap: .4rem; color: var(--muted); font-weight: 700; }
.se-field select { background: rgba(0,0,0,.35); color: var(--text); border: 1px solid var(--line); border-radius: 10px; padding: .35rem .5rem; font: inherit; font-weight: 700; }
.se-field input[type="color"] { width: 2rem; height: 1.7rem; border: 1px solid var(--line); border-radius: 8px; background: none; padding: 0; cursor: pointer; }
.se-mini { border: 1px solid var(--line); background: rgba(255,255,255,.04); color: var(--muted); border-radius: 8px; padding: .25rem .5rem; font: inherit; font-size: .75rem; font-weight: 700; cursor: pointer; }
.se-toggle { display: inline-flex; align-items: center; gap: .35rem; color: var(--muted); font-weight: 700; cursor: pointer; }
.se-toggle input { accent-color: var(--gold); }
.se-status { color: var(--muted); font-size: .78rem; min-width: 8rem; }
.se-status.dirty { color: var(--gold-soft); }
.se-status.ok { color: var(--ok); }
.se-status.bad { color: var(--danger); }
.se-link { color: var(--mint); font-weight: 700; }
.se-hero-tools { position: absolute; top: 1rem; right: 1rem; z-index: 3; display: flex; flex-wrap: wrap; justify-content: flex-end; gap: .4rem; }
.se-chip {
  display: inline-flex; align-items: center; gap: .35rem; padding: .45rem .8rem; border-radius: 999px; cursor: pointer;
  border: 1px solid rgba(255,255,255,.25); background: rgba(0,0,0,.5); color: #fff; font: inherit; font-weight: 700; font-size: .8rem;
  backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
}
.se-chip:hover { background: rgba(0,0,0,.66); }
@media (max-width: 640px) {
  .se-bar { bottom: .5rem; border-radius: 18px; }
  .se-fab { left: .6rem; bottom: .6rem; }
}

/* 버전 뱃지 → 패치노트 링크 */
a.site-build-badge { pointer-events: auto; cursor: pointer; transition: border-color .2s, color .2s, transform .2s; }
a.site-build-badge:hover { color: #fff; border-color: color-mix(in srgb, var(--gold) 70%, transparent); transform: translateY(-1px); }

/* 입장 로그인 화면 */
.gate-shell { position: relative; z-index: 1; min-height: 100vh; display: grid; place-items: center; padding: 1.5rem; overflow: hidden; }
.gate-shell.has-donors { align-content: start; justify-items: center; gap: 1.6rem; padding-top: 2.2rem; padding-bottom: 2.6rem; overflow-x: hidden; overflow-y: auto; }
.gate-shell .donor-board { width: min(100%, 52rem); position: relative; z-index: 1; }
.gate-bg { position: absolute; inset: 0; background-size: cover; background-position: center; transform: scale(1.04); }
.gate-bg::after { content: ""; position: absolute; inset: 0; background: radial-gradient(120% 90% at 50% 10%, rgba(0,0,0,.25), rgba(0,0,0,.8)); }
.gate-card { position: relative; width: min(100%, 26rem); padding: 1.85rem 1.6rem 1.5rem; border-radius: var(--r-xl); text-align: center; animation: gateIn .7s var(--ease-out) both; }
@keyframes gateIn { from { opacity: 0; transform: translateY(18px) scale(.98); } to { opacity: 1; transform: none; } }
.gate-card .kicker { margin: 0; font-size: 1.15rem; letter-spacing: .12em; color: rgba(255,255,255,.82); font-weight: 700; font-family: var(--font-display); }
.gate-brand { display: block; margin-top: .4rem; font-size: clamp(2.2rem, 6.5vw, 2.85rem); line-height: 1.05; }
.gate-title { margin: 1rem 0 0; font-size: clamp(1.75rem, 4.4vw, 2.25rem); color: var(--gold-soft); line-height: 1.2; }
.gate-sub { margin: .7rem auto 0; max-width: 24rem; color: rgba(232,236,230,.95); line-height: 1.5; font-size: 1.15rem; font-weight: 700; font-family: var(--font-display); }
.gate-err { margin: .8rem 0 0; padding: .6rem .85rem; border-radius: 14px; color: var(--danger); background: color-mix(in srgb, var(--danger) 12%, transparent); font-size: 1.05rem; font-weight: 700; font-family: var(--font-display); }
.gate-btn { margin-top: 1.25rem; display: flex; align-items: center; justify-content: center; gap: .5rem; width: 100%; border-radius: 16px; padding: .95rem 1.05rem; font-size: 1.12rem; font-weight: 700; font-family: var(--font-display); }
.gate-btn svg { width: 1.35rem; height: 1.35rem; }
.gate-foot { margin: 1rem 0 0; display: flex; align-items: center; justify-content: center; gap: .45rem; font-size: 1.02rem; color: rgba(232,236,230,.9); font-weight: 700; font-family: var(--font-display); }
.gate-link { display: inline-block; margin-top: .75rem; font-size: 1.02rem; color: var(--mint); font-weight: 700; font-family: var(--font-display); }
html[data-font="cute"] .gate-card .kicker,
html:not([data-font]) .gate-card .kicker { font-size: 1.1rem; }
html[data-font="cute"] .gate-sub,
html:not([data-font]) .gate-sub { font-size: 1.22rem; }
html[data-font="cute"] .gate-foot,
html:not([data-font]) .gate-foot,
html[data-font="cute"] .gate-link,
html:not([data-font]) .gate-link { font-size: 1.08rem; }
html[data-font="cute"] .gate-btn,
html:not([data-font]) .gate-btn { font-size: 1.18rem; }
html[data-font="cute"] .donor-lead,
html:not([data-font]) .donor-lead { font-size: 1.25rem; font-family: var(--font-display); }
html[data-font="cute"] .donor-board .kicker,
html:not([data-font]) .donor-board .kicker { font-size: 1.2rem; font-family: var(--font-display); }

/* 패치노트 */
.pn-h2 { margin: .2rem 0 .9rem; color: var(--gold); font-size: 1.5rem; }
.pn-card { border-radius: var(--r-lg); padding: 1.25rem 1.35rem; }
.pn-card.is-current { border-color: color-mix(in srgb, var(--gold) 55%, transparent); }
.pn-head { display: flex; align-items: center; gap: .55rem; flex-wrap: wrap; }
.pn-ver { font-family: var(--font-display); font-weight: 900; font-size: 1.15rem; color: var(--gold-soft); }
.pn-now { font-size: .7rem; font-weight: 800; padding: .15rem .55rem; border-radius: 999px; color: #14110a; background: linear-gradient(135deg, var(--gold-soft), var(--gold)); }
.pn-date { margin-left: auto; font-size: .78rem; color: var(--muted); }
.pn-title { margin: .45rem 0 0; font-size: 1.05rem; color: var(--text); }
.pn-sec { margin-top: .85rem; }
.pn-label { margin: 0 0 .35rem; font-size: .75rem; font-weight: 800; letter-spacing: .08em; }
.pn-sec ul { margin: 0; padding: 0; list-style: none; display: grid; gap: .3rem; }
.pn-sec li { position: relative; padding-left: 1.35rem; font-size: .9rem; line-height: 1.55; }
.pn-sec li::before { position: absolute; left: 0; top: 0; font-weight: 900; }
.pn-sec.add .pn-label, .pn-sec.add li::before { color: var(--ok); }
.pn-sec.chg .pn-label, .pn-sec.chg li::before { color: var(--gold); }
.pn-sec.del .pn-label, .pn-sec.del li::before { color: var(--danger); }
.pn-sec.add li::before { content: "+"; }
.pn-sec.chg li::before { content: "↻"; }
.pn-sec.del li::before { content: "−"; }
.pn-list { margin: 0; padding: .4rem 1rem; list-style: none; border-radius: var(--r-lg); }
.pn-row { display: flex; align-items: baseline; gap: .6rem; flex-wrap: wrap; padding: .7rem 0; border-bottom: 1px solid var(--line); font-size: .9rem; }
.pn-row:last-child { border-bottom: none; }
.pn-tag { flex-shrink: 0; font-size: .7rem; font-weight: 800; padding: .12rem .5rem; border-radius: 999px; border: 1px solid currentColor; }
.pn-tag.add { color: var(--ok); }
.pn-tag.chg { color: var(--gold); }
.pn-tag.del { color: var(--danger); }
.pn-detail { color: var(--muted); font-size: .82rem; }
.pn-row time { margin-left: auto; color: var(--muted); font-size: .75rem; }
.pn-toast {
  position: fixed; right: 1rem; bottom: 3.4rem; z-index: 80; display: flex; align-items: center; gap: .7rem;
  max-width: min(92vw, 22rem); padding: .8rem .9rem; border-radius: 18px; color: var(--text);
  background: color-mix(in srgb, var(--bg1) 92%, transparent); border: 1px solid color-mix(in srgb, var(--gold) 50%, transparent);
  box-shadow: 0 20px 50px -20px rgba(0,0,0,.85); backdrop-filter: blur(14px); -webkit-backdrop-filter: blur(14px);
  opacity: 0; transform: translateY(12px); transition: opacity .35s ease, transform .45s var(--ease-out);
}
.pn-toast.show { opacity: 1; transform: none; }
.pn-toast-ico { font-size: 1.4rem; }
.pn-toast-txt { display: grid; gap: .1rem; }
.pn-toast-txt b { color: var(--gold-soft); }
.pn-toast-txt small { color: var(--muted); font-size: .76rem; }
.pn-toast button { margin-left: auto; border: none; background: none; color: var(--muted); cursor: pointer; font-size: .9rem; }

/* 닉네임 변경 패널 */
.nick-owned { display:flex; flex-direction:column; gap:.85rem; padding:1rem; border-radius:18px; border:1px solid color-mix(in srgb, var(--mint) 38%, transparent); background:color-mix(in srgb, var(--mint) 9%, transparent); }
.nick-owned-info { display:flex; align-items:center; gap:.75rem; }
.nick-owned-badge { display:grid; place-items:center; width:2.5rem; height:2.5rem; border-radius:12px; background:var(--mint); color:#0c1a13; font-weight:800; font-size:1.05rem; flex-shrink:0; }
.nick-owned-label { margin:0; font-size:.92rem; font-weight:700; color:var(--text); }
.nick-owned-sub { margin:.1rem 0 0; font-size:.76rem; color:var(--muted); }
.nick-hint { margin:0; font-size:.85rem; color:var(--muted); line-height:1.6; padding:.9rem 1rem; border-radius:16px; border:1px dashed var(--line); }
.nick-divider { position:relative; display:flex; align-items:center; justify-content:center; gap:.75rem; margin:.1rem 0; font-size:.72rem; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; }
.nick-divider::before, .nick-divider::after { content:""; flex:1; height:1px; background:var(--line); }
.me-hero { display:flex; gap:1.15rem; align-items:center; flex-wrap:wrap; }
.me-hero img { width:4.8rem; height:4.8rem; border-radius:1.5rem; border:2px solid var(--line); object-fit:cover; box-shadow:0 12px 28px rgba(0,0,0,.25); }
.me-name { margin:0; font-size:clamp(1.85rem, 3.4vw, 2.4rem); display:flex; align-items:center; gap:.5rem; flex-wrap:wrap; }
.dc-rank { display:inline-flex; align-items:center; border-radius:999px; padding:.22rem .85rem; font-size:.95rem; letter-spacing:.02em; border:1px solid var(--line); background:rgba(212,175,106,.14); color:var(--gold-soft); }
.dc-rank[data-rank="Owner"], .dc-rank[data-rank="Co-Owner"] { background:rgba(255,196,92,.18); color:#ffe7a8; }
.dc-rank[data-rank="Admin"], .dc-rank[data-rank="Staff"] { background:rgba(134,214,170,.16); color:var(--mint); }
.dc-rank[data-rank="Ultra"], .dc-rank[data-rank="MVP"] { background:rgba(177,140,255,.16); color:#d7c4ff; }
.dc-rank[data-rank="StanDard"] { background:rgba(106,169,255,.16); color:#b7d4ff; }
.panel-profile { border-radius:32px; padding:1.6rem 1.5rem; margin:1.2rem 0 1.4rem; background:linear-gradient(165deg, rgba(125,206,160,.1), rgba(8,14,12,.42)); border:1px solid color-mix(in srgb, var(--gold) 28%, transparent); }
.rank-now { display:grid; place-items:center; text-align:center; border-radius:24px; padding:1.25rem 1rem; border:1px solid var(--line); background:linear-gradient(180deg, rgba(125,206,160,.12), rgba(8,14,12,.35)); min-height:6.5rem; }
.rank-now .label { margin:0; font-size:.95rem; color:var(--muted); }
.rank-now .val { margin:.4rem 0 0; font-size:clamp(1.9rem, 3vw, 2.4rem); color:var(--gold-soft); }
.wallet-row { display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:.7rem; margin-top:1rem; }
.wallet-row .rank-now { min-height:0; padding:.95rem .55rem; }
.wallet-row .rank-now .val { font-size:clamp(1.15rem, 2.2vw, 1.5rem); }
@media (max-width: 640px) { .wallet-row { grid-template-columns:1fr; } }
.nick-grid { display:grid; gap:1.35rem; align-items:stretch; margin-top:.25rem; }
@media (min-width: 900px) {
  .nick-grid.has-rank { grid-template-columns: 1fr 1fr; }
}
.nick-grid:not(.has-rank) { max-width: 32rem; margin-inline: auto; }
.nick-card {
  --accent: var(--gold);
  position:relative; overflow:hidden;
  border-radius:28px; padding:1.75rem 1.6rem 1.65rem; display:flex; flex-direction:column; gap:1.1rem; min-height:100%;
  border:1px solid var(--line); background:linear-gradient(180deg, rgba(255,255,255,.03), rgba(8,14,12,.5));
  box-shadow: 0 22px 46px -30px rgba(0,0,0,.85);
  transition: transform .3s var(--ease-out, ease), box-shadow .3s ease;
}
.nick-card:hover { transform: translateY(-3px); box-shadow: 0 28px 56px -26px rgba(0,0,0,.9); }
.nick-card::before {
  content:""; position:absolute; inset:0 0 auto 0; height:3px;
  background:linear-gradient(90deg, transparent, var(--accent), transparent);
}
.nick-card.is-rank { --accent: var(--gold); }
.nick-card.is-ticket { --accent: var(--mint); }
.nick-card-top { display:flex; align-items:center; gap:.9rem; }
.nick-card .nick-ico {
  width:3rem; height:3rem; border-radius:1rem; display:grid; place-items:center; font-size:1.4rem; flex-shrink:0;
  background:color-mix(in srgb, var(--accent) 16%, transparent);
  border:1px solid color-mix(in srgb, var(--accent) 42%, transparent);
  box-shadow:0 0 0 5px color-mix(in srgb, var(--accent) 8%, transparent);
}
.nick-card-heading { flex:1; min-width:0; }
.nick-card-heading h2 { margin:0; font-size:clamp(1.3rem, 2.1vw, 1.55rem); color:var(--accent); }
.nick-card-tag { margin:.2rem 0 0; font-size:.78rem; color:var(--muted); letter-spacing:.01em; }
.nick-status {
  flex-shrink:0; padding:.35rem .75rem; border-radius:999px; font-size:.78rem; font-weight:700; color:var(--accent);
  background:color-mix(in srgb, var(--accent) 14%, transparent); border:1px solid color-mix(in srgb, var(--accent) 34%, transparent);
  white-space:nowrap;
}
.nick-card .lead { margin:0; font-size:.98rem; color:var(--muted); line-height:1.6; }
.nick-field { display:flex; flex-direction:column; gap:.4rem; }
.nick-field label { font-size:.72rem; font-weight:700; letter-spacing:.07em; text-transform:uppercase; color:color-mix(in srgb, var(--accent) 75%, var(--muted)); }
.nick-card .field { margin-top:0; border-radius:14px; padding:.85rem .95rem; font-size:1.02rem; }
.nick-submit { width:100%; border-radius:14px; padding:.95rem; font-size:1.04rem; margin-top:.1rem; }
.gift-box, .custom-buy { border:1px solid var(--line); border-radius:20px; padding:1rem; background:rgba(8,14,12,.28); }
.custom-buy { display:grid; gap:.55rem; }
.custom-buy .row { display:flex; gap:.5rem; flex-wrap:wrap; align-items:center; }
.custom-buy input.field { flex:1; min-width:8rem; }

/* 장바구니 · 배경음 · 페이지 전환 */
.page-fx { position: fixed; inset: 0; z-index: 90; pointer-events: none; background: var(--bg0, #0a0e0c); opacity: 0; transition: opacity .38s var(--ease-out); }
.page-fx.on { opacity: 1; }
.bgm-fab, .cart-fab {
  position: fixed; z-index: 55; right: 1.1rem; width: 3.35rem; height: 3.35rem; border-radius: 999px;
  border: 1px solid var(--line); background: color-mix(in srgb, var(--bg1) 88%, transparent); color: var(--gold-soft);
  display: grid; place-items: center; cursor: pointer; box-shadow: 0 14px 32px -16px rgba(0,0,0,.7);
  backdrop-filter: blur(12px); font-size: 1.2rem; transition: transform .2s var(--ease-spring), background .2s;
}
.bgm-fab { bottom: 5.4rem; }
.cart-fab { bottom: 1.35rem; }
.bgm-fab:hover, .cart-fab:hover { transform: scale(1.06); }
.cart-fab .n {
  position: absolute; top: -.2rem; right: -.15rem; min-width: 1.25rem; height: 1.25rem; padding: 0 .3rem;
  border-radius: 999px; background: var(--gold); color: #1a1208; font-size: .78rem; font-weight: 800;
  display: grid; place-items: center;
}
.cart-pay-list { list-style: none; margin: .9rem 0 0; padding: 0; display: grid; gap: .45rem; }
.cart-pay-list li { display: flex; justify-content: space-between; gap: .75rem; padding: .55rem .7rem; border-radius: 12px; border: 1px solid var(--line); background: rgba(255,255,255,.03); font-size: .95rem; }
.cart-drawer-bg { position: fixed; inset: 0; z-index: 70; background: rgba(0,0,0,.45); opacity: 0; pointer-events: none; transition: opacity .28s ease; }
.cart-drawer-bg.open { opacity: 1; pointer-events: auto; }
.cart-drawer {
  position: fixed; z-index: 71; top: 0; right: 0; height: 100%; width: min(100%, 24rem);
  background: linear-gradient(180deg, #121a16, #0b1110); border-left: 1px solid var(--line);
  transform: translateX(105%); transition: transform .38s var(--ease-out); display: flex; flex-direction: column; padding: 1.2rem;
}
.cart-drawer.open { transform: none; }
.cart-drawer h2 { margin: 0; font-size: 1.55rem; color: var(--gold-soft); }
.cart-list { flex: 1; overflow: auto; margin-top: 1rem; display: grid; gap: .7rem; align-content: start; }
.cart-item { display: grid; grid-template-columns: 1fr auto; gap: .35rem .7rem; padding: .85rem; border-radius: 16px; border: 1px solid var(--line); background: rgba(255,255,255,.03); }
.cart-item b { font-size: 1.05rem; }
.cart-item .meta { color: var(--muted); font-size: .92rem; }
.cart-empty { color: var(--muted); text-align: center; padding: 2rem .5rem; }
.cart-foot { display: grid; gap: .55rem; padding-top: .85rem; border-top: 1px solid var(--line); }
.cart-foot .sum { display: flex; justify-content: space-between; font-size: 1.15rem; color: var(--mint); }
.buy-row { display: flex; gap: .45rem; flex-wrap: wrap; margin-top: .35rem; }
.buy-row .gold-btn, .buy-row .ghost-btn { flex: 1; min-width: 6.5rem; justify-content: center; }
.glass.card { border-radius: 26px; overflow: hidden; transition: transform .28s var(--ease-out), box-shadow .28s; }
.glass.card:hover { transform: translateY(-4px); box-shadow: 0 22px 44px -28px rgba(0,0,0,.75); }
.header { backdrop-filter: blur(10px); }
.donor-board { margin-top: 2.4rem; }
.donor-head { text-align: center; margin-bottom: 1.2rem; }
.donor-head h2 { margin: .35rem 0 0; font-size: clamp(1.8rem, 4vw, 2.4rem); color: var(--gold); }
.donor-lead { margin: .4rem 0 0; color: var(--muted); font-size: .95rem; }
.month-gauge { margin-top: .8rem; display: grid; gap: .45rem; }
.month-track { height: 14px; border-radius: 999px; background: rgba(255,255,255,.08); overflow: hidden; border: 1px solid var(--line); }
.month-track > span { display: block; height: 100%; width: 0; border-radius: inherit; background: linear-gradient(90deg, var(--mint), var(--gold)); }
.month-pct { margin: 0; font-size: 1.8rem; color: var(--gold-soft); }
.month-list { display: grid; gap: .4rem; margin-top: .7rem; }
.month-row { display: flex; justify-content: space-between; gap: .6rem; padding: .55rem .75rem; border-radius: 14px; border: 1px solid var(--line); background: rgba(255,255,255,.03); }
.donor-stage { display: flex; align-items: flex-end; justify-content: center; gap: .85rem; flex-wrap: wrap; }
.donor-card { width: min(100%, 13.5rem); text-align: center; border-radius: 26px; padding: 1rem .85rem 1.15rem; border: 1px solid var(--line); background: linear-gradient(180deg, rgba(212,175,106,.1), rgba(8,14,12,.4)); box-shadow: 0 14px 28px rgba(0,0,0,.18); }
.donor-card.is-1 { width: min(100%, 15.2rem); padding-top: 1.2rem; border-color: color-mix(in srgb, var(--gold) 55%, transparent); background: linear-gradient(180deg, rgba(255,214,120,.18), rgba(8,14,12,.42)); transform: translateY(-10px); }
.donor-card.is-2 { order: -1; }
.donor-card.is-empty { opacity: .72; }
.donor-place { margin: 0 0 .45rem; font-size: 1.05rem; color: var(--gold-soft); }
.donor-skin { display: block; height: 168px; width: auto; max-width: 100%; margin: 0 auto .55rem; object-fit: contain; filter: drop-shadow(0 10px 16px rgba(0,0,0,.35)); image-rendering: pixelated; }
.donor-card.is-1 .donor-skin { height: 200px; }
.donor-skin.empty { height: 140px; width: 88px; border-radius: 18px; display: grid; place-items: center; background: rgba(255,255,255,.04); color: var(--muted); font-size: 2rem; margin: 0 auto .55rem; }
.donor-mc { margin: 0; font-size: 1.35rem; color: var(--gold-soft); word-break: break-all; }
.donor-dc { margin: .2rem 0 0; font-size: .92rem; color: var(--muted); word-break: break-all; }
@media (max-width: 720px) {
  .donor-stage { flex-direction: column; align-items: center; }
  .donor-card.is-1, .donor-card.is-2 { order: 0; transform: none; width: min(100%, 16rem); }
  .donor-card.is-1 .donor-skin, .donor-skin { height: 160px; }
}

/* 리뷰 · 커뮤니티 */
.rev-open { margin-top: .55rem; width: 100%; justify-content: center; }
.rev-stars { color: var(--gold); letter-spacing: .08em; font-size: .92rem; }
.rev-modal-bg { position: fixed; inset: 0; z-index: 70; background: rgba(0,0,0,.55); display: grid; place-items: center; padding: 1.2rem; }
.rev-modal { width: min(36rem, 100%); max-height: min(88vh, 48rem); overflow: auto; border-radius: 28px; padding: 1.3rem 1.35rem 1.5rem; }
.rev-list { display: grid; gap: .75rem; margin-top: 1rem; }
.rev-item { padding: .85rem .95rem; border-radius: 18px; border: 1px solid var(--line); background: color-mix(in srgb, var(--bg1) 70%, transparent); }
.rev-item .who { font-size: .82rem; color: var(--muted); }
.rev-form { display: grid; gap: .55rem; margin-top: 1rem; }
.rev-rate { display: flex; gap: .25rem; }
.rev-rate button { border: 0; background: none; font-size: 1.35rem; cursor: pointer; opacity: .35; }
.rev-rate button.on { opacity: 1; }
.com-compose { display: grid; gap: .55rem; margin-top: 1.1rem; }
.com-feed { display: grid; gap: 1rem; margin-top: 1.25rem; }
.com-post { padding: 1.1rem 1.15rem; border-radius: 24px; }
.com-meta { display: flex; justify-content: space-between; gap: .6rem; flex-wrap: wrap; color: var(--muted); font-size: .8rem; }
.com-heart { border: 1px solid var(--line); background: transparent; color: var(--text); border-radius: 999px; padding: .35rem .75rem; cursor: pointer; }
.com-heart.on { border-color: color-mix(in srgb, #ff6b8a 55%, transparent); color: #ff8aa3; background: color-mix(in srgb, #ff6b8a 12%, transparent); }
.com-comments { margin-top: .85rem; display: grid; gap: .55rem; }
.com-cmt { padding: .65rem .75rem; border-radius: 14px; background: color-mix(in srgb, var(--bg0) 55%, transparent); }
.com-cmt .replies { margin: .5rem 0 0 1rem; display: grid; gap: .45rem; padding-left: .7rem; border-left: 2px solid var(--line); }
.com-reply-form { display: flex; gap: .4rem; margin-top: .45rem; }

"""

SHELL = r"""<!DOCTYPE html>
<html lang="ko" data-font="cute">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>WILDMC · 인증 &amp; 상점</title>
  <meta name="theme-color" content="#0b1210" />
  <meta name="description" content="WILDMC 마인크래프트 서버 · 디스코드 인증, 랭크·상점, 공지와 도전과제" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link rel="preconnect" href="https://hangeul.pstatic.net" crossorigin />
  <link rel="preload" as="font" type="font/woff2" crossorigin href="https://hangeul.pstatic.net/hangeul_static/webfont/NanumSquareRound/NanumSquareRoundR.woff2" />
  <link rel="preload" as="font" type="font/woff2" crossorigin href="https://hangeul.pstatic.net/hangeul_static/webfont/NanumSquareRound/NanumSquareRoundEB.woff2" />
  <link href="https://fonts.googleapis.com/css2?family=Dongle:wght@400;700&family=Jua&family=Nunito:wght@500;600;700;800;900&display=swap" rel="stylesheet" />
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/galmuri@latest/dist/galmuri.css" />
  <style>__CSS__</style>
</head>
<body>
<script>
const PRODUCTS = __PRODUCTS__;
const WEB_BUILD = "__WEB_BUILD__";
let STORE = { settings: {}, banners: [], products: PRODUCTS, latestNotice: null, theme: null, donors: [] };
let ME = { loading: true, authenticated: false, inboxUnread: 0, isDiscordLogin: false, minecraftLinked: false };
const PREVIEW = new URLSearchParams(location.search).get("preview")==="1" && window.parent!==window;
const REDUCED_MOTION = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;

function esc(s){ return String(s??"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }
function T(key, def){ return esc(S(key, def)); }
const ICONS={
  pen:'<path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 1 1 3 3L7 19l-4 1 1-4Z"/>',
  image:'<rect x="3" y="3" width="18" height="18" rx="3"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.1-3.1a2 2 0 0 0-2.8 0L6 21"/>',
  users:'<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>',
  peak:'<path d="m22 7-8.5 8.5-5-5L2 17"/><path d="M16 7h6v6"/>',
  cal:'<rect x="3" y="4" width="18" height="18" rx="3"/><path d="M16 2v4M8 2v4M3 10h18"/>',
  chart:'<path d="M3 3v18h18"/><path d="M7 16v-5M12 16V8M17 16v-8"/>',
  arrow:'<path d="M5 12h14"/><path d="m12 5 7 7-7 7"/>',
  link:'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>'
};
function ico(n){ return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n]||""}</svg>`; }
const FONT_LINKS={
  cute:"https://fonts.googleapis.com/css2?family=Dongle:wght@400;700&family=Jua&display=swap",
  gowun:"https://fonts.googleapis.com/css2?family=Gowun+Dodum&display=swap",
  jua:"https://fonts.googleapis.com/css2?family=Jua&display=swap",
  gothic:"https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@400;500;700;800;900&display=swap"
};
function ensureFontLink(id){
  const href=FONT_LINKS[id];
  if(!href||document.querySelector(`link[data-font-link="${id}"]`)) return;
  const l=document.createElement("link"); l.rel="stylesheet"; l.href=href; l.dataset.fontLink=id; document.head.appendChild(l);
}
function hexToRgb(h){ const m=/^#([0-9a-f]{6})$/i.exec(String(h||"").trim()); if(!m) return null; const n=parseInt(m[1],16); return [(n>>16)&255,(n>>8)&255,n&255]; }
function brandHtml(st){
  const name=esc((st&&st.site_name)||"WILDMC");
  const suffix=String((st&&st.site_suffix)??"MC").replace(/^[.]/,"").trim();
  return suffix?`${name}<span class="dot">.</span>${esc(suffix)}`:name;
}
function paintAnnounce(st){
  const bar=document.getElementById("annBar"); if(!bar) return;
  const src=(st&&st.announce_source)||"notice";
  const n=STORE&&STORE.latestNotice;
  bar.hidden=src==="off";
  const span=document.getElementById("annText");
  if(span&&document.activeElement!==span){
    span.textContent=src==="custom"?((st&&st.announcement)||"환영합니다!"):(n?n.title:((st&&st.announcement)||"환영합니다!"));
  }
}
function setHeroPhoto(url){
  const bg=document.querySelector("#heroSec .hero-bg"); if(!bg) return;
  const u=String(url||"").trim();
  bg.classList.toggle("has-photo", !!u);
  if(u) bg.style.setProperty("--hero-photo", `url("${u.replace(/["\\\n]/g,"")}")`);
  else bg.style.removeProperty("--hero-photo");
}
function applySiteLook(st){
  st=st||{};
  const root=document.documentElement;
  const raw=st.site_font||"cute";
  const f=["gowun","jua","gothic"].includes(raw)?raw:"cute";
  root.setAttribute("data-font", f);
  ensureFontLink(f);
  const rgb=hexToRgb(st.accent_color);
  if(rgb){
    const [r,g,b]=rgb; const soft=(c)=>Math.round(c+(255-c)*.55);
    root.style.setProperty("--gold", `rgb(${r},${g},${b})`);
    root.style.setProperty("--gold-soft", `rgb(${soft(r)},${soft(g)},${soft(b)})`);
    root.style.setProperty("--line", `rgba(${r},${g},${b},.34)`);
    root.setAttribute("data-accent", "1");
  } else {
    ["--gold","--gold-soft","--line"].forEach(p=>root.style.removeProperty(p));
    root.removeAttribute("data-accent");
  }
  const hero=document.getElementById("heroSec");
  if(hero){
    hero.classList.toggle("is-center", st.hero_align==="center");
    hero.classList.toggle("h-compact", st.hero_height==="compact");
    hero.classList.toggle("h-tall", st.hero_height==="tall");
    const ov=parseInt(st.hero_overlay,10);
    if(Number.isFinite(ov)) hero.style.setProperty("--hero-ov", String(Math.max(0,Math.min(95,ov))/100));
    else hero.style.removeProperty("--hero-ov");
  }
  const secStats=document.getElementById("secStats"); if(secStats) secStats.hidden=st.show_stats==="0";
  const secShop=document.getElementById("secShop"); if(secShop) secShop.hidden=st.show_shop==="0";
  const fontScale=Math.max(80, Math.min(140, Number(st.ui_font_scale)||100));
  const blockScale=Math.max(80, Math.min(140, Number(st.ui_block_scale)||100));
  const radiusScale=Math.max(70, Math.min(150, Number(st.ui_radius_scale)||100));
  root.style.setProperty("--ui-font-scale", (fontScale/100).toFixed(3));
  root.style.setProperty("--ui-block-scale", (blockScale/100).toFixed(3));
  root.style.setProperty("--ui-radius-scale", (radiusScale/100).toFixed(3));
  paintAnnounce(st);
}
function themeFromChoice(mode, id){
  const base=(STORE&&STORE.theme)||{};
  const catalog=base.catalog||[];
  const pick=mode==="off"?"default":(mode==="manual"?(id||"default"):(base.autoId||"default"));
  const t=catalog.find(c=>c.id===pick)||{id:"default",label:"기본",emoji:"",hint:"",fx:"",icons:[]};
  return Object.assign({}, t, {mode:mode||"auto", catalog, autoId:base.autoId});
}
function repaintThemeBanner(){
  document.querySelectorAll(".theme-banner").forEach(el=>el.remove());
  const tb=themeBannerHtml();
  const main=document.querySelector("main.panel-shell, main.login-wrap");
  if(tb&&main) main.insertAdjacentHTML("afterbegin", tb);
}
function animateNum(el, to){
  if(!el) return;
  to=Number(to)||0;
  const from=Number(el.dataset.v||0);
  el.dataset.v=String(to);
  if(from===to||PREVIEW||REDUCED_MOTION){ el.textContent=to.toLocaleString("ko-KR"); return; }
  const t0=performance.now(), dur=750;
  const step=(t)=>{ const p=Math.min(1,(t-t0)/dur); const e=1-Math.pow(1-p,3); el.textContent=Math.round(from+(to-from)*e).toLocaleString("ko-KR"); if(p<1) requestAnimationFrame(step); };
  requestAnimationFrame(step);
}
function enhanceUI(){
  if(!window.__hdBound){
    window.__hdBound=true;
    const onScroll=()=>{ const h=document.querySelector(".header"); if(h) h.classList.toggle("is-stuck", window.scrollY>12); };
    window.addEventListener("scroll", onScroll, {passive:true});
  }
  const h=document.querySelector(".header"); if(h) h.classList.toggle("is-stuck", window.scrollY>12);
  if(PREVIEW||REDUCED_MOTION||!("IntersectionObserver" in window)) return;
  const targets=[...document.querySelectorAll(".hero, .stats-head, .grid-4 > .stat, .shop-head, #plist > .card, .chips, .page-title, .footer, .login-card, .link-steps, main .grid-2 > section, .donor-board, .donor-card")];
  if(!targets.length) return;
  const done=(el)=>{ el.classList.add("in"); setTimeout(()=>{ el.classList.remove("reveal","in"); el.style.removeProperty("--rd"); }, 1100); };
  const io=new IntersectionObserver((entries)=>{
    entries.forEach(en=>{ if(en.isIntersecting){ io.unobserve(en.target); done(en.target); } });
  }, {rootMargin:"0px 0px -8% 0px", threshold:.06});
  const groups=new Map();
  targets.forEach(el=>{
    const k=el.parentElement; const i=groups.get(k)||0; groups.set(k, i+1);
    el.style.setProperty("--rd", Math.min(i,6)*70+"ms");
    el.classList.add("reveal");
    io.observe(el);
  });
  setTimeout(()=>targets.forEach(el=>{ if(el.classList.contains("reveal")&&!el.classList.contains("in")) done(el); }), 2400);
}

function ensureBuildBadge(){
  let el=document.getElementById("siteBuildBadge");
  if(!el){
    el=document.createElement("a");
    el.id="siteBuildBadge";
    el.className="site-build-badge";
    el.href="/patch-notes";
    el.title="패치노트 보기";
    document.body.appendChild(el);
  }
  el.textContent="web v"+WEB_BUILD+" · 패치노트";
}
function won(n){ return Number(n||0).toLocaleString("ko-KR")+"원"; }
function S(key, def){ const s=(STORE&&STORE.settings)||{}; const v=s[key]; return (v===undefined||v===null||v==='')?def:String(v); }
function playNotifySound(kind){
  try{
    const AC=window.AudioContext||window.webkitAudioContext; if(!AC)return;
    if(!window.__notifyAudioCtx) window.__notifyAudioCtx=new AC();
    const ctx=window.__notifyAudioCtx;
    if(ctx.state==="suspended") ctx.resume().catch(()=>{});
    const now=ctx.currentTime;
    const tones={
      friend:[880,1174],
      chat:[740,988],
      notice:[523,784,1046],
      coupon:[659,880,1174],
      inbox:[987,1318],
      default:[880,1108]
    };
    const seq=tones[kind]||tones.default;
    seq.forEach((hz,i)=>{
      const o=ctx.createOscillator(); const g=ctx.createGain();
      o.type="sine"; o.frequency.setValueAtTime(hz, now+i*0.09);
      g.gain.setValueAtTime(0.0001, now+i*0.09);
      g.gain.exponentialRampToValueAtTime(0.12, now+i*0.09+0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, now+i*0.09+0.28);
      o.connect(g); g.connect(ctx.destination);
      o.start(now+i*0.09); o.stop(now+i*0.09+0.3);
    });
  }catch(e){}
}
function playInboxDing(){ playNotifySound("inbox"); }
let __alertSnap={ inbox:null, friends:null, noticeId:null, coupons:null, chatAt:null };
async function pollAlerts(){
  if(!ME||!ME.authenticated) return;
  try{
    const r=await fetch("/api/alerts");
    if(!r.ok) return;
    const d=await r.json();
    const inbox=Number(d.inboxUnread)||0;
    const friends=Number(d.friendIncoming)||0;
    const noticeId=Number(d.latestNoticeId)||0;
    const coupons=Number(d.claimableCoupons)||0;
    const chatAt=Number(d.latestChatAt)||0;
    const prev=__alertSnap;
    if(prev.inbox!==null){
      if(inbox>prev.inbox){
        const kinds=d.newKinds||[];
        if(kinds.includes("friend")) playNotifySound("friend");
        else if(kinds.includes("chat")) playNotifySound("chat");
        else if(kinds.includes("notice")||kinds.includes("broadcast")) playNotifySound("notice");
        else if(kinds.includes("coupon")||kinds.includes("coupon_gift")) playNotifySound("coupon");
        else playNotifySound("inbox");
      }
      if(friends>prev.friends) playNotifySound("friend");
      if(noticeId>prev.noticeId && prev.noticeId!==null) playNotifySound("notice");
      if(coupons>prev.coupons) playNotifySound("coupon");
      if(chatAt>prev.chatAt && prev.chatAt!==null) playNotifySound("chat");
    }
    __alertSnap={ inbox, friends, noticeId, coupons, chatAt };
    __lastInboxUnread=inbox; ME.inboxUnread=inbox;
    document.querySelectorAll('.nav a[href="/inbox"]').forEach(a=>{
      const label=T("nav_inbox","우편함");
      a.innerHTML=inbox>0?`${label}<span class="badge">${inbox>99?"99+":inbox}</span>`:label;
    });
    document.querySelectorAll('.nav a[href="/friends"]').forEach(a=>{
      const label=T("nav_friends","친구");
      a.innerHTML=friends>0?`${label}<span class="badge">${friends>99?"99+":friends}</span>`:label;
    });
    document.querySelectorAll('.nav a[href="/coupon"]').forEach(a=>{
      const label=T("nav_coupon","쿠폰받기");
      a.innerHTML=coupons>0?`${label}<span class="badge">${coupons>99?"99+":coupons}</span>`:label;
    });
  }catch(e){}
}
async function pollInboxBadge(){ return pollAlerts(); }

function avatarSrc(id, av){
  if(!id||String(id).startsWith("local_")) return null;
  if(!av) return "https://cdn.discordapp.com/embed/avatars/0.png";
  return "https://cdn.discordapp.com/avatars/"+id+"/"+av+".png?size=64";
}
function purchaseBlock(){
  if(ME.loading) return null;
  if(!ME.isDiscordLogin) return "디스코드 로그인 후 구매할 수 있습니다.";
  if(!ME.minecraftLinked) return "마인크래프트 계정 연동 후 구매할 수 있습니다.";
  return null;
}
function applySiteTheme(theme){
  const t = theme || { id: "default", label: "", fx: "", icons: [] };
  const id = t.id && t.id !== "default" ? t.id : "";
  if(!id) document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", id);
  let fx = document.getElementById("themeFx");
  if(!fx){
    fx = document.createElement("div");
    fx.id = "themeFx";
    fx.setAttribute("aria-hidden", "true");
    document.body.prepend(fx);
  }
  fx.innerHTML = "";
  if(!id) return;
  const icons = Array.isArray(t.icons) ? t.icons.filter(Boolean) : [];
  const placeEmoji = (side) => {
    if(!icons.length) return;
    const count = side === "edge" ? 10 : 6;
    for(let i=0;i<count;i++){
      const el=document.createElement("span");
      el.className = "theme-emoji" + (side === "edge" ? " is-edge" : "");
      el.textContent = icons[i % icons.length];
      const leftSide = Math.random() < 0.5;
      if(side === "edge"){
        el.style.left = leftSide ? (1 + Math.random()*10) + "%" : (88 + Math.random()*10) + "%";
      } else {
        el.style.left = leftSide ? (4 + Math.random()*14) + "%" : (78 + Math.random()*16) + "%";
      }
      el.style.top = (6 + Math.random()*86) + "%";
      el.style.setProperty("--bob", ((Math.random()*-22)-6) + "px");
      el.style.setProperty("--rot", ((Math.random()*24)-12) + "deg");
      el.style.animationDuration = (5 + Math.random()*7) + "s";
      el.style.animationDelay = (-Math.random()*8) + "s";
      fx.appendChild(el);
    }
  };
  placeEmoji("edge");
  placeEmoji("soft");
  const kind = t.fx || "";
  if(!kind) return;
  const n = kind === "snow" ? 36 : kind === "spark" ? 30 : 22;
  const cls = kind === "snow" ? "theme-flake" : kind === "spark" ? "theme-spark" : kind === "petal" ? "theme-petal" : kind === "ember" ? "theme-ember" : "";
  if(!cls) return;
  for(let i=0;i<n;i++){
    const el=document.createElement("span");
    el.className=cls;
    el.style.left=(Math.random()*100)+"%";
    el.style.setProperty("--drift", ((Math.random()*80)-40)+"px");
    el.style.animationDuration=(6+Math.random()*10)+"s";
    el.style.animationDelay=(-Math.random()*12)+"s";
    el.style.opacity=String(0.3+Math.random()*0.5);
    if(kind==="snow"){ const s=3+Math.random()*6; el.style.width=s+"px"; el.style.height=s+"px"; }
    fx.appendChild(el);
  }
}
function themeBannerHtml(){
  const t = STORE && STORE.theme;
  if(!t || !t.id || t.id === "default" || !t.label) return "";
  return `<div class="theme-banner"><span>${t.emoji||""}</span><b>${t.label}</b><span style="opacity:.75">${t.hint||""}</span></div>`;
}
function header(mode){
  const settings = (STORE && STORE.settings) || {};
  const brand = brandHtml(settings);
  const pathOf = { home:"/", shop:"/shop", notice:"/notice", link:"/link", inbox:"/inbox", achievements:"/achievements", pay:"/pay", order:"/pay", panel:"/panel", wild:"/wild", login:"/login", coupon:"/coupon", code:"/code", stocks:"/stocks", friends:"/friends", community:"/community", support:"/support", chat:"/friends", patch:"/patch-notes" };
  const current = pathOf[mode] || (mode && mode.startsWith("/") ? mode : "");
  const h = (href, label, extra, inner) => {
    const active = current && (href === current || (href !== "/" && current.startsWith(href)));
    const base = extra || "ghost-btn";
    const cls = active ? `${base} pill nav-active` : `${base} pill`;
    return `<a href="${href}" class="${cls}">${inner||label}</a>`;
  };
  const showShop = mode !== "shop";
  const showHome = ["shop","notice","link","inbox","pay","order","panel","achievements","wild","coupon","code","stocks","friends","community","support","patch"].includes(mode);
  let inboxInner = T("nav_inbox","우편함");
  if(ME.authenticated && ME.inboxUnread>0){
    const n = ME.inboxUnread>99?"99+":ME.inboxUnread;
    inboxInner = `${T("nav_inbox","우편함")}<span class="badge">${n}</span>`;
  }
  let achInner = T("nav_achievements","도전과제");
  if(ME.authenticated && Number(ME.achUnlocked)>0 && ME.achTotal){
    achInner = `${T("nav_achievements","도전과제")}<span class="badge">${ME.achUnlocked}</span>`;
  }
  let auth = h("/login","로그인");
  if(ME.loading) auth = `<span class="ghost-btn pill" style="color:var(--muted)">…</span>`;
  else if(ME.authenticated){
    const av = avatarSrc(ME.discordId, ME.avatar);
    const img = av ? `<img class="avatar" src="${av}" alt="">` : `<span class="avatar-fallback">${esc((ME.username||"?").slice(0,1).toUpperCase())}</span>`;
    const active = mode === "panel" ? " nav-active" : "";
    const complete = ME.achComplete ? `<span class="profile-complete" title="모든 도전과제 수집">🏅</span>` : "";
    auth = `<a href="/panel" class="ghost-btn pill profile-link${active}" title="내 프로필">${img}${complete}<span class="profile-name">${esc(ME.username||"프로필")}</span></a><button type="button" class="ghost-btn pill" id="logoutBtn">로그아웃</button>`;
    if(ME.canEditSite && !PREVIEW){
      auth = `<a href="/decorate" class="gold-btn pill edit-pill" title="본 사이트 편집">${ico("pen")}편집</a>` + auth;
    }
  }
  return `<header class="header"><a href="/" class="display brand egg-hot" id="eggBrand">${brand}</a><nav class="nav">${showHome?h("/","홈"):""}${h("/notice",T("nav_notice","공지"))}${showShop?h("/shop",T("shop_nav","상점")):""}${h("/community",T("nav_community","커뮤니티"))}${h("/coupon",T("nav_coupon","쿠폰받기"))}${h("/code","코드등록")}<a href="/stocks" class="ghost-btn pill">주식</a><a href="/lottery" class="ghost-btn pill">복권</a>${h("/friends",T("nav_friends","친구"))}${h("/support",T("nav_support","문의"))}${h("/achievements",T("nav_achievements","도전과제"),"ghost-btn",achInner)}${h("/link",T("nav_link","마인크래프트 계정 연동"))}${h("/inbox",T("nav_inbox","우편함"),"ghost-btn",inboxInner)}${auth}</nav></header>`;
}
function productEmoji(p){
  const c=String(p.category||"");
  if(Number(p.voucher_count||0)>0) return "🏷️";
  if(p.rank_group||c.includes("랭크")) return "👑";
  if(Number(p.gem_amount||0)>0||c.includes("젬")) return "💎";
  if(Number(p.cash_amount||0)>0||c.includes("캐시")) return "💰";
  return "🎁";
}
function thumbHtml(p, lazy){
  if(p.image_url) return `<div class="thumb"><img src="${esc(p.image_url)}" alt="" ${lazy?'loading="lazy"':""}/></div>`;
  return `<div class="thumb thumb-ph"><span class="ph-emoji" aria-hidden="true">${productEmoji(p)}</span><span class="ph-label">${esc(p.badge||p.category||"")}</span></div>`;
}
function shopPrice(p){
  const base=Number(p&&p.price)||0;
  const rank=String(ME.rankGroup||"");
  const alt=rank && p && p.price_for ? Number(p.price_for[rank])||0 : 0;
  return alt>0?alt:base;
}
function buyBtn(p){
  if(ME.loading) return `<span class="gold-btn buy" style="opacity:.6">확인 중…</span>`;
  if(!ME.isDiscordLogin) return `<a class="gold-btn buy" href="/login">디스코드 로그인 후 구매</a>`;
  if(!ME.minecraftLinked) return `<a class="gold-btn buy" href="/panel">마인크래프트 계정과 연동하여 구매하기</a>`;
  return `<div class="buy-row"><button type="button" class="ghost-btn buy cart-add" data-id="${p.id}" data-name="${esc(p.name||"")}" data-price="${shopPrice(p)}">담기</button><a class="gold-btn buy" href="/pay?product=${p.id}">결제하기</a></div>`;
}
function productCard(p){
  const grants=[];
  const cash=Number(p.cash_amount||0); const gem=Number(p.gem_amount||0);
  if(cash>0) grants.push(`캐시 ${cash.toLocaleString("ko-KR")}`);
  if(gem>0) grants.push(`젬 ${gem.toLocaleString("ko-KR")}`);
  if(p.rank_group) grants.push(`랭크 ${esc(p.rank_group)}`);
  if(Number(p.voucher_count||0)>0) grants.push(`닉네임 변경권 ${Number(p.voucher_count)}장`);
  const grantHtml=grants.length?`<p class="cat" style="color:var(--mint)">${grants.join(" · ")}</p>`:"";
  const rc=Number(p.review_count||0); const ra=Number(p.review_avg||0);
  const revLabel=rc?`★ ${ra.toFixed(1)} · 리뷰 ${rc}`:"리뷰 보기";
  const show=shopPrice(p);
  const base=Number(p.price)||0;
  const priceHtml=show!==base?`<p class="price"><span style="text-decoration:line-through;color:var(--muted);font-size:.9rem;margin-right:.4rem">${won(base)}</span>${won(show)}</p>`:`<p class="price">${won(show)}</p>`;
  const catHtml=`<p class="cat">${p.category?esc(p.category)+" · ":""}구매 시 환불은 불가합니다.</p>`;
  return `<article class="glass card">${thumbHtml(p, true)}<div class="card-body"><div class="row"><h3 class="display">${esc(p.name||"")}</h3>${p.badge?`<span class="rank-chip">${esc(p.badge)}</span>`:""}</div>${catHtml}${grantHtml}${p.description?`<p class="desc">${esc(p.description)}</p>`:""}${priceHtml}${buyBtn(p)}<button type="button" class="ghost-btn pill rev-open" data-pid="${p.id}">${revLabel}</button></div></article>`;
}
function paintStats(s){
  if(!s) return;
  animateNum(document.getElementById("online"), s.online??0);
  animateNum(document.getElementById("peak"), s.peakToday??0);
  animateNum(document.getElementById("today"), s.joinsToday??0);
  animateNum(document.getElementById("week"), s.joinsWeek??0);
  const on=!!s.pluginOnline, d=document.getElementById("livedot"), t=document.getElementById("livetext");
  if(d){d.style.background=on?"var(--ok)":"var(--danger)";d.style.boxShadow=on?"0 0 10px rgba(111,207,151,.7)":"0 0 8px rgba(224,122,106,.5)";}
  if(t)t.textContent=on?(S("live_online","Minecraft Online")):(S("live_offline","Minecraft Offline"));
  const hint=document.getElementById("onlineHint"); if(hint)hint.textContent=on?"온라인":"플러그인 미연결";
}
async function fillStats(){
  try{
    const s = await (await fetch("/api/server/status")).json();
    window.__stats=s;
    paintStats(s);
  }catch(e){}
}
async function loadMe(){
  try{
    const r=await fetch("/api/me");
    if(r.status===401){ME={loading:false,authenticated:false,inboxUnread:0,isDiscordLogin:false,minecraftLinked:false};return;}
    const d=await r.json();
    const id=d.discord?.id;
    ME={loading:false,authenticated:true,discordId:id,username:d.discord?.username,avatar:d.discord?.avatar,discordRank:d.discord?.rank||"",inboxUnread:Number(d.inboxUnread)||0,isDiscordLogin:!!(id&&!String(id).startsWith("local_")),minecraftLinked:!!d.minecraft?.uuid,minecraftName:d.minecraft?.name,canRankNick:!!d.canRankNick,currentRank:d.currentRank||d.minecraft?.rank||"아직 연동되지 않았어요.",rankGroup:d.rankGroup||"",isWebAdmin:!!d.isWebAdmin,isTeamWildmc:!!d.isTeamWildmc,canEditSite:!!d.canEditSite,nickTickets:Number(d.nickTickets)||0,minecraft:d.minecraft,wallet:d.wallet||{},achUnlocked:d.achievements?.unlocked||0,achTotal:d.achievements?.total||0,achComplete:!!d.achievements?.complete};
  }catch(e){ME={loading:false,authenticated:false,inboxUnread:0,isDiscordLogin:false,minecraftLinked:false};}
}
function pagePath(){
  const p=location.pathname.replace(/\/$/,"")||"/";
  const m=p.match(/^\/pay\/order\/([^/]+)$/);
  if(m) return {path:"order", code:m[1]};
  if(p.startsWith("/pay")) return {path:"pay"};
  return {path:p};
}
function homeHtml(){
  const st=(STORE&&STORE.settings)||{};
  const banner=(STORE.banners||[])[0]||{};
  const siteName=st.site_name||"WILDMC";
  const defSub="디스코드 인증부터 랭크·닉네임 변경까지, 한곳에서 관리하세요.";
  const photo=String(banner.image_url||"").replace(/["\\\n]/g,"");
  const heroBg=photo?`<div class="hero-bg has-photo" style="--hero-photo:url(&quot;${esc(photo)}&quot;)"></div>`:`<div class="hero-bg"></div>`;
  const stat=(icon, key, def, id, color, hint, hintId)=>`<div class="glass stat"><span class="stat-ico">${ico(icon)}</span><p class="label" data-ek="s:${key}" data-def="${esc(def)}">${T(key,def)}</p><p class="val display" style="color:${color}" id="${id}">0</p><p class="hint"${hintId?` id="${hintId}"`:""}>${hint}</p></div>`;
  return `<main class="panel-shell"><a class="announce" id="annBar" href="/notice"><span class="announce-ico" aria-hidden="true">📣</span><span id="annText" data-ek="s:announcement" data-def="환영합니다!"></span></a><div class="wrap">${header("home")}`
    +`<section class="hero" id="heroSec">${heroBg}<div class="hero-inner"><p class="kicker" data-ek="s:site_tagline" data-def="Minecraft × Discord">${T("site_tagline","Minecraft × Discord")}</p><h1 class="display" data-ek="b:title" data-def="${esc(siteName)}">${esc(banner.title||siteName)}</h1><p class="sub" data-ek="b:subtitle" data-def="${esc(defSub)}">${esc(banner.subtitle||defSub)}</p><div class="cta"><a class="gold-btn pill" href="/link"><span data-ek="s:hero_link_cta" data-def="마인크래프트 계정과 연동하기">${T("hero_link_cta","마인크래프트 계정과 연동하기")}</span></a><a class="ghost-btn pill" id="heroCta2" href="${esc(banner.link_url||"/login")}"><span data-ek="b:cta_label" data-def="시작하기">${esc(banner.cta_label||"시작하기")}</span></a><a class="ghost-btn pill" href="/shop"><span data-ek="s:shop_cta" data-def="상점">${T("shop_cta","상점")}</span></a></div></div></section>`
    +`<section id="secMonth" class="donor-board month-board"><div class="donor-head"><p class="kicker">THIS MONTH</p><h2 class="display">이달의 후원</h2><p class="donor-lead" id="monthLead">이번 달 후원 게이지</p></div><div class="month-gauge"><div class="month-track"><span id="monthFill"></span></div><p class="month-pct display" id="monthPct">0.00%</p></div><div class="month-list" id="monthList"></div></section>`
    +`<section id="secDonors" class="donor-board"><div class="donor-head"><p class="kicker">HALL OF FAME</p><h2 class="display">후원 랭킹</h2><p class="donor-lead">WILDMC 서버를 빛낸 후원자 3명의 유저.</p></div><div class="donor-stage" id="donorStage"></div></section>`
    +`<section id="secStats"><div class="stats-head"><div><p class="kicker" data-ek="s:stats_kicker" data-def="LIVE STATUS">${T("stats_kicker","LIVE STATUS")}</p><h2 class="display" data-ek="s:stats_title" data-def="서버 현황">${T("stats_title","서버 현황")}</h2></div><div class="live"><span class="dot" id="livedot"></span><span id="livetext" class="egg-hot">${T("live_offline","Minecraft Offline")}</span></div></div><div class="grid-4">`
    +stat("users","stat_online_label","실시간 접속","online","var(--mint)","플러그인 미연결","onlineHint")
    +stat("peak","stat_peak_label","오늘 최고 동접","peak","var(--gold)","Peak Today")
    +stat("cal","stat_today_label","오늘 누적 접속","today","var(--gold-soft)","Joins Today")
    +stat("chart","stat_week_label","일주일 누적 접속","week","#9fd6b8","Joins Week")
    +`</div></section>`
    +`<section id="secShop"><div class="shop-head"><div><p class="kicker" data-ek="s:shop_kicker" data-def="SHOP">${T("shop_kicker","SHOP")}</p><h2 class="display" data-ek="s:shop_title" data-def="상품">${T("shop_title","상품")}</h2></div><a class="mint more-link" href="/shop"><span data-ek="s:shop_all_label" data-def="전체 보기">${T("shop_all_label","전체 보기")}</span>${ico("arrow")}</a></div><div class="grid-3" id="plist"></div></section>`
    +`<footer class="footer"><div class="foot-brand"><b class="display">${esc(siteName)}</b><span>© <span id="eggYear" class="egg-hot">${new Date().getFullYear()}</span></span></div><nav class="foot-links"><a href="/notice">${T("nav_notice","공지")}</a><a href="/shop">${T("shop_nav","상점")}</a><a href="/community">${T("nav_community","커뮤니티")}</a><a href="/support">${T("nav_support","문의")}</a><a href="/patch-notes">패치노트</a><a href="/wiki/">위키</a><a href="/achievements" class="mint" data-ek="s:footer_link_label" data-def="도전과제">${T("footer_link_label","도전과제")}</a></nav></footer></div></main>`;
}
function productCategory(p){
  const c=String(p.category||"").trim();
  if(c) return c;
  if(p.rank_group) return "랭크";
  return "기타";
}
function customShopCards(){
  const minWon=Number((STORE.settings||{}).custom_min_won)||100;
  const cashRate=Number((STORE.settings||{}).cash_per_won)||10;
  const gemEach=Number((STORE.settings||{}).gem_won_each)||2;
  const minCash=Math.max(cashRate, Math.ceil(minWon*cashRate));
  const minGem=Math.max(1, Math.ceil(minWon/gemEach));
  return `<article class="glass card custom-buy"><div class="thumb thumb-ph"><span class="ph-emoji" aria-hidden="true">💰</span><span class="ph-label">CASH</span></div><div class="card-body"><div class="row"><h3 class="display">커스텀 캐시</h3><span class="rank-chip">${cashRate}당 1원</span></div><p class="desc">원하는 만큼 캐시를 구매해요. 최소 ${minWon.toLocaleString("ko-KR")}원 · 캐시 ${minCash.toLocaleString("ko-KR")}부터.</p><div class="row"><input class="field" id="customCashAmt" type="number" min="${minCash}" step="${cashRate}" value="${minCash}" placeholder="캐시 수량"/><button type="button" class="gold-btn buy" id="customCashBtn">주문하기</button></div><p class="cat" id="customCashHint" style="color:var(--mint)">${minCash.toLocaleString("ko-KR")} 캐시 = ${minWon.toLocaleString("ko-KR")}원</p></div></article>
  <article class="glass card custom-buy"><div class="thumb thumb-ph"><span class="ph-emoji" aria-hidden="true">💎</span><span class="ph-label">GEM</span></div><div class="card-body"><div class="row"><h3 class="display">커스텀 후원잼</h3><span class="rank-chip">${gemEach}원당 1개</span></div><p class="desc">원하는 만큼 후원잼을 구매해요. 최소 ${minWon.toLocaleString("ko-KR")}원 · 잼 ${minGem.toLocaleString("ko-KR")}개부터.</p><div class="row"><input class="field" id="customGemAmt" type="number" min="${minGem}" step="1" value="${minGem}" placeholder="잼 개수"/><button type="button" class="gold-btn buy" id="customGemBtn">주문하기</button></div><p class="cat" id="customGemHint" style="color:var(--mint)">${minGem.toLocaleString("ko-KR")}개 = ${(minGem*gemEach).toLocaleString("ko-KR")}원</p></div></article>`;
}
function bindCustomBuy(){
  const cashInp=document.getElementById("customCashAmt");
  const gemInp=document.getElementById("customGemAmt");
  const cashHint=document.getElementById("customCashHint");
  const gemHint=document.getElementById("customGemHint");
  const cashRate=Number((STORE.settings||{}).cash_per_won)||10;
  const gemEach=Number((STORE.settings||{}).gem_won_each)||2;
  const minWon=Number((STORE.settings||{}).custom_min_won)||100;
  const paintCash=()=>{ const n=Math.max(0,Number(cashInp&&cashInp.value)||0); const wonAmt=Math.floor(n/cashRate); if(cashHint) cashHint.textContent=n?`${n.toLocaleString("ko-KR")} 캐시 = ${wonAmt.toLocaleString("ko-KR")}원`:`캐시 ${cashRate} = 1원 · 최소 ${minWon}원`; };
  const paintGem=()=>{ const n=Math.max(0,Number(gemInp&&gemInp.value)||0); const wonAmt=n*gemEach; if(gemHint) gemHint.textContent=n?`${n.toLocaleString("ko-KR")}개 = ${wonAmt.toLocaleString("ko-KR")}원`:`후원잼 1개 = ${gemEach}원 · 최소 ${minWon}원`; };
  if(cashInp){ cashInp.oninput=paintCash; paintCash(); }
  if(gemInp){ gemInp.oninput=paintGem; paintGem(); }
  const go=(kind, inp)=>{ const amount=Number(inp&&inp.value)||0; location.href="/pay?custom="+encodeURIComponent(kind)+"&amount="+encodeURIComponent(String(amount)); };
  const cashBtn=document.getElementById("customCashBtn");
  const gemBtn=document.getElementById("customGemBtn");
  if(cashBtn) cashBtn.onclick=()=>go("cash", cashInp);
  if(gemBtn) gemBtn.onclick=()=>go("gem", gemInp);
}
function paintProducts(list){
  const box=document.getElementById("plist");
  if(!box) return;
  const home=pagePath().path==="/";
  const cards=(list.slice(0,home?6:999)).map(productCard).join("");
  const extra=home?"":customShopCards();
  box.innerHTML=(cards||(!extra?`<p class="empty">등록된 상품이 없습니다.</p>`:""))+extra;
  bindReviewButtons();
  if(!home) bindCustomBuy();
}
function bindShopChips(products){
  const chips=document.getElementById("shopChips");
  if(!chips) return;
  const counts=new Map();
  products.forEach(p=>{ const c=productCategory(p); counts.set(c,(counts.get(c)||0)+1); });
  if(counts.size<2){ chips.remove(); return; }
  const cats=["전체",...counts.keys()];
  const draw=(on)=>{
    chips.innerHTML=cats.map(c=>`<button type="button" class="chip${c===on?" on":""}" data-cat="${esc(c)}">${esc(c)}<span class="n">${c==="전체"?products.length:counts.get(c)}</span></button>`).join("");
  };
  draw("전체");
  chips.addEventListener("click",(e)=>{
    const b=e.target.closest(".chip"); if(!b) return;
    const cat=b.dataset.cat;
    draw(cat);
    paintProducts(cat==="전체"?products:products.filter(p=>productCategory(p)===cat));
  });
}
async function paintMonthGauge(){
  const fill=document.getElementById("monthFill");
  const pct=document.getElementById("monthPct");
  const list=document.getElementById("monthList");
  const lead=document.getElementById("monthLead");
  if(!fill&&!list) return;
  let d={percent:0,total:0,goal:0,month:"",donors:[]};
  try{ d=await (await fetch("/api/donations/month")).json(); }catch(e){}
  const p=Math.max(0, Number(d.percent)||0);
  if(fill) fill.style.width=Math.min(100, p)+"%";
  if(pct) pct.textContent=p.toFixed(2)+"%";
  if(lead) lead.textContent=`${d.month||""} · ${(Number(d.total)||0).toLocaleString("ko-KR")}원 / ${(Number(d.goal)||0).toLocaleString("ko-KR")}원`;
  if(list){
    const rows=d.donors||[];
    list.innerHTML=rows.length?rows.map(x=>`<div class="month-row"><span><b>${esc(x.minecraftName||x.discordName||"후원자")}</b> <span style="color:var(--muted)">${esc(x.discordName||"")}</span></span><b>${won(x.won)}</b></div>`).join(""):`<p class="donor-lead">이번 달 후원 내역이 아직 없어요.</p>`;
  }
}
function paintDonors(){
  const box=document.getElementById("donorStage");
  if(!box) return;
  const list=(STORE&&STORE.donors)||[];
  const medals=["","🥇","🥈","🥉"];
  const titles=["","1위","2위","3위"];
  box.innerHTML=[1,2,3].map(place=>{
    const d=list.find(x=>Number(x.place)===place)||null;
    if(!d){
      return `<article class="donor-card is-${place} is-empty"><p class="donor-place">${medals[place]} ${titles[place]}</p><div class="donor-skin empty">?</div><p class="donor-mc display">빈 자리</p><p class="donor-dc">다음 후원자를 기다려요</p></article>`;
    }
    const skin=d.skinUrl?`<img class="donor-skin" src="${esc(d.skinUrl)}" alt="${esc(d.minecraftName||"")}" loading="lazy" onerror="this.src='https://mc-heads.net/body/MHF_Steve/right'"/>`:`<div class="donor-skin empty">?</div>`;
    return `<article class="donor-card is-${place}"><p class="donor-place">${medals[place]} ${titles[place]}</p>${skin}<p class="donor-mc display">${esc(d.minecraftName||"아직 연동되지 않았어요.")}</p><p class="donor-dc">${esc(d.discordName||"")}</p></article>`;
  }).join("");
}
function paintChrome(products){
  applySiteTheme(STORE.theme);
  if(!PREVIEW) ensureBuildBadge();
  repaintThemeBanner();
  paintProducts(products);
  bindShopChips(products);
  paintDonors();
  void paintMonthGauge();
  if(document.getElementById("livedot")){
    if(window.__stats) paintStats(window.__stats);
    if(!PREVIEW){ fillStats(); if(!window.__statsTimer) window.__statsTimer=setInterval(fillStats,8000); }
  }
  applySiteLook(STORE.settings);
  enhanceUI();
  ensureCartUi();
  bindCartButtons();
  bindPageTransitions();
}
function bindPreviewMode(){
  if(!PREVIEW) return;
  document.documentElement.classList.add("is-preview");
  document.addEventListener("click",(e)=>{ if(e.target.closest("a, button, form")) e.preventDefault(); }, true);
  document.addEventListener("submit",(e)=>e.preventDefault(), true);
  let lastThemeKey="";
  window.addEventListener("message",(e)=>{
    if(e.origin!==location.origin) return;
    const d=e.data||{};
    if(d.type!=="wm-draft") return;
    STORE.settings=Object.assign({}, STORE.settings||{}, d.settings||{});
    const b=Object.assign({}, (STORE.banners||[])[0]||{}, d.banner||{});
    STORE.banners=[b];
    const themeKey=(STORE.settings.theme_mode||"auto")+":"+(STORE.settings.theme_id||"default");
    const themeChanged=themeKey!==lastThemeKey;
    lastThemeKey=themeKey;
    if(themeChanged) STORE.theme=themeFromChoice(STORE.settings.theme_mode||"auto", STORE.settings.theme_id);
    const main=document.querySelector("main.panel-shell");
    if(main) main.outerHTML=homeHtml();
    if(themeChanged) applySiteTheme(STORE.theme);
    repaintThemeBanner();
    paintProducts(STORE.products||PRODUCTS||[]);
    paintDonors();
    if(window.__stats) paintStats(window.__stats);
    applySiteLook(STORE.settings);
  });
  fillStats();
  try{ window.parent.postMessage({type:"wm-preview-ready"}, location.origin); }catch(e){}
}
function bindCopyButtons(){
  if(window.__copyBound) return;
  window.__copyBound=true;
  document.addEventListener("click",(e)=>{
    const b=e.target.closest("[data-copy]"); if(!b) return;
    const text=b.dataset.copy||"";
    const done=()=>{ const prev=b.textContent; b.textContent="복사됨 ✓"; setTimeout(()=>{ b.textContent=prev; },1500); };
    if(navigator.clipboard&&navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done).catch(()=>{});
  });
}
function accountHtml(acc){
  const a=String(acc||"").trim();
  return a?`${esc(a)}<button type="button" class="copy-btn" data-copy="${esc(a)}">복사</button>`:"—";
}
const LOGIN_ERRORS={discord_config:"디스코드 로그인이 아직 설정되지 않았습니다. 웹 운영자에게 문의해 주세요.",oauth:"디스코드 인증이 취소되었거나 실패했습니다.",token:"디스코드 토큰 교환에 실패했습니다. (Redirect URI·Client Secret·네트워크를 확인하세요)",user:"디스코드 사용자 정보를 가져오지 못했습니다."};
const DISCORD_ICON='<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M20.3 4.4A19.8 19.8 0 0 0 15.4 3l-.6 1.3a18.4 18.4 0 0 0-5.6 0L8.6 3a19.7 19.7 0 0 0-4.9 1.5C.6 9.2-.3 13.8.1 18.3a19.9 19.9 0 0 0 6 3.1l1.3-2.1a12.9 12.9 0 0 1-2-1l.5-.4a14.2 14.2 0 0 0 12.2 0l.5.4c-.6.4-1.3.7-2 1l1.3 2.1a19.8 19.8 0 0 0 6-3.1c.5-5.2-.9-9.8-3.6-13.9ZM8.3 15.6c-1.2 0-2.2-1.1-2.2-2.5s1-2.5 2.2-2.5 2.2 1.1 2.2 2.5-1 2.5-2.2 2.5Zm7.4 0c-1.2 0-2.2-1.1-2.2-2.5s1-2.5 2.2-2.5 2.2 1.1 2.2 2.5-1 2.5-2.2 2.5Z"/></svg>';
function showLoginGate(){
  const st=STORE.settings||{};
  const banner=(STORE.banners||[])[0]||{};
  const photo=String(banner.image_url||"").replace(/["\\\n]/g,"");
  const next=encodeURIComponent(location.pathname+location.search);
  const err=new URLSearchParams(location.search).get("error");
  document.body.innerHTML=`<main class="gate-shell has-donors">${photo?`<div class="gate-bg" style="background-image:url(&quot;${esc(photo)}&quot;)"></div>`:""}<section class="glass gate-card"><p class="kicker">${T("site_tagline","Minecraft × Discord")}</p><div class="display brand gate-brand">${brandHtml(st)}</div><h1 class="display gate-title">로그인하고 입장하기</h1><p class="gate-sub">디스코드 계정으로 로그인하면 WILDMC의 서비스를 이용할 수 있어요.</p>${err?`<p class="gate-err">${esc(LOGIN_ERRORS[err]||"로그인에 실패했습니다.")}</p>`:""}<a class="gold-btn gate-btn" href="/api/auth/discord?next=${next}">${DISCORD_ICON}디스코드로 로그인</a><p class="gate-foot"><span class="dot" id="livedot"></span><span id="livetext">서버 상태 확인 중…</span></p><a class="gate-link" href="/wiki/">위키 둘러보기 →</a></section><section id="secDonors" class="donor-board"><div class="donor-head"><p class="kicker">HALL OF FAME</p><h2 class="display">후원 랭킹</h2><p class="donor-lead">WILDMC 서버를 빛낸 후원자 3명의 유저</p></div><div class="donor-stage" id="donorStage"></div></section></main>`;
  applySiteTheme(STORE.theme);
  applySiteLook(st);
  ensureBuildBadge();
  fillStats();
  paintDonors();
}
function nickTicketHtml(){
  const n=Number(ME.nickTickets)||0;
  const linked=!!ME.minecraftLinked;
  if(!n) return `<p class="nick-hint">상점에서 <a href="/shop" class="mint">닉네임 변경권</a>을 사면 여기서 사용을 눌러 코드를 받을 수 있어요.</p>`;
  return `<div class="nick-owned">
    <div class="nick-owned-info"><span class="nick-owned-badge">${n}</span><div><p class="nick-owned-label">보유 변경권 ${n}장</p><p class="nick-owned-sub">사용을 누르면 코드가 나와요</p></div></div>
    <button type="button" id="ticketBtn" class="gold-btn nick-submit" ${linked?"":"disabled"}>사용</button>
    <div id="ticketCodeOut"></div>
  </div>`;
}
function panelHtml(){
  const av=avatarSrc(ME.discordId, ME.avatar);
  const completeMark=ME.achComplete?`<span class="profile-complete" title="모든 도전과제 수집">🏅</span>`:"";
  const dcRank=ME.discordRank||"";
  const rankChip=dcRank?`<span class="dc-rank" data-rank="${esc(dcRank)}">${esc(dcRank)}</span>`:"";
  const currentRank=esc(ME.currentRank||"앗, 연동이 되어 있지 않은 것같아요!");
  const linked=!!ME.minecraftLinked;
  const wallet=ME.wallet||{};
  const walletText=(known,value)=>known?Number(value||0).toLocaleString("ko-KR"):"접속 후 표시";
  const walletHtml=linked?`<div class="wallet-row"><div class="rank-now"><p class="label">캐시</p><p class="val display">${walletText(wallet.cashKnown,wallet.cash)}</p></div><div class="rank-now"><p class="label">후원젬</p><p class="val display">${walletText(wallet.gemKnown,wallet.gem)}</p></div><div class="rank-now"><p class="label">소유금</p><p class="val display">${walletText(wallet.moneyKnown,wallet.money)}</p></div></div>`:"";
  const rankCard=ME.canRankNick?`<section class="glass nick-card is-rank">
    <div class="nick-card-top"><span class="nick-ico" aria-hidden="true">👑</span><div class="nick-card-heading"><h2 class="display">랭크 전용 닉네임 변경</h2><p class="nick-card-tag">랭크 전용</p></div><span class="nick-status">${currentRank}</span></div>
    <p class="lead">
        현재 랭크로 닉네임을 바꿔요.</p>
        (최대 5글자)</a>
        <a href="https://color.wildmc.xyz"
           target="_blank"
           target="_blank"
           rel="noopener noreferrer"
           style="color:#FF4AC7;">
            RGB 닉네임 만들기
        </a>
    </p>
    <div class="nick-field"><label for="rankNick">바꿀 닉네임</label><input class="field" id="rankNick" placeholder="예: Steve" ${linked?"":"disabled"} /></div>
    <button type="button" id="rankBtn" class="gold-btn nick-submit" ${linked?"":"disabled"}>변경하기</button>
  </section>`:"";
  return `<main class="panel-shell"><div class="wrap narrow">${header("panel")}<h1 class="display page-title">내 프로필</h1>
    <section class="glass panel-profile">
      <div class="me-hero">${av?`<img src="${av}" alt="">`:""}<div><p style="color:var(--muted);font-size:1rem;margin:0">Discord</p><h2 class="display me-name">${esc(ME.username||"")}${rankChip}${completeMark}</h2></div></div>
      <div class="rank-now" style="margin-top:1.25rem"><p class="label">현재 랭크</p><p class="val display">${currentRank}</p></div>
      ${walletHtml}
      ${!linked?`<p style="margin:1rem 0 0;padding:.9rem 1.05rem;border-radius:1.2rem;border:1px solid rgba(224,122,106,.35);background:rgba(224,122,106,.08);color:var(--danger);font-size:1.02rem">아직 마인크래프트와 연동되지 않았어요.</p><a class="gold-btn pill" href="/link" style="margin-top:.85rem">마인크래프트 계정과 연동하기</a>`:""}
    </section>
    <div class="nick-grid${ME.canRankNick?" has-rank":""}">${rankCard}
      <section class="glass nick-card is-ticket">
        <div class="nick-card-top"><span class="nick-ico" aria-hidden="true">🏷️</span><div class="nick-card-heading"><h2 class="display">닉네임 변경권</h2><p class="nick-card-tag">상점 구매권 또는 인게임 코드</p></div></div>
        <p class="lead">
            상점에서 산 변경권이나 인게임 코드로 닉네임을 변경해요.</p>
            (최대 5글자)</a>
            <a href="https://color.wildmc.xyz"
	       target="_blank"
	       rel="noopener noreferrer"
	       style="color:#FF4AC7;">
		RGB 닉네임 만들기
            </a>
        </p>
        ${nickTicketHtml()}
        <div class="nick-divider"><span>닉네임 변경권으로 변경하기</span></div>
        <div class="nick-field"><label for="voucherCode">변경권 코드</label><input class="field" id="voucherCode" placeholder="예: ABCD-1234" ${linked?"":"disabled"} /></div>
        <div class="nick-field"><label for="voucherNick">바꿀 닉네임</label><input class="field" id="voucherNick" placeholder="예: Steve" ${linked?"":"disabled"} /></div>
        <button type="button" id="voucherBtn" class="gold-btn nick-submit" ${linked?"":"disabled"}>변경하기</button>
      </section>
    </div>
    <section class="glass" id="supportBox" style="margin-top:1rem;border-radius:24px;padding:1.15rem"><h2 class="display" style="color:var(--gold);font-size:1.2rem;margin:0">내 후원</h2><p id="supportTotal" style="margin:.45rem 0 0;color:var(--mint)">불러오는 중…</p><div id="supportOrders" style="margin-top:.75rem"></div></section>
    <div id="panelToast"></div></div></main>`;
}
async function renderPatchNotes(){
  const root=document.getElementById("patchRoot"); if(!root) return;
  let d={web:[],shop:[]};
  try{ d=await (await fetch("/api/patch-notes")).json(); }catch(e){}
  const sec=(cls,label,items)=>(items&&items.length)?`<div class="pn-sec ${cls}"><p class="pn-label">${label}</p><ul>${items.map(t=>`<li>${esc(t)}</li>`).join("")}</ul></div>`:"";
  const web=(d.web||[]).map(n=>`<article class="glass pn-card${n.version===WEB_BUILD?" is-current":""}"><div class="pn-head"><span class="pn-ver">v${esc(n.version)}</span>${n.version===WEB_BUILD?`<span class="pn-now">현재 버전</span>`:""}<span class="pn-date">${esc(n.date||"")}</span></div>${n.title?`<h2 class="display pn-title">${esc(n.title)}</h2>`:""}${sec("add","추가",n.added)}${sec("chg","변경",n.changed)}${sec("del","삭제",n.removed)}</article>`).join("");
  const kinds={added:["add","추가"],removed:["del","삭제"],updated:["chg","변경"]};
  const shop=(d.shop||[]).map(r=>{ const k=kinds[r.kind]||kinds.updated; return `<li class="pn-row"><span class="pn-tag ${k[0]}">${k[1]}</span><b>${esc(r.name)}</b>${r.detail?`<span class="pn-detail">${esc(r.detail)}</span>`:""}<time>${new Date(r.at).toLocaleDateString("ko-KR",{month:"numeric",day:"numeric"})}</time></li>`; }).join("");
  root.innerHTML=`<section><p class="kicker">WEB UPDATE</p><h2 class="display pn-h2">웹사이트 업데이트</h2><div class="stack">${web||`<p class="empty">아직 패치노트가 없습니다.</p>`}</div></section><section style="margin-top:2.4rem"><p class="kicker">SHOP</p><h2 class="display pn-h2">상점 변경 기록</h2>${shop?`<ul class="glass pn-list">${shop}</ul>`:`<p class="empty">아직 상점 변경 기록이 없습니다.</p>`}</section>`;
}
async function maybeShowPatchToast(){
  return;
  let seen="";
  try{ seen=localStorage.getItem("wm_seen_build")||""; localStorage.setItem("wm_seen_build", WEB_BUILD); }catch(e){ return; }
  if(!seen||seen===WEB_BUILD||pagePath().path==="/patch-notes") return;
  try{
    const d=await (await fetch("/api/patch-notes")).json();
    const n=(d.web||[]).find(x=>x.version===WEB_BUILD); if(!n) return;
    const c=(a)=>(a||[]).length;
    const el=document.createElement("a");
    el.href="/patch-notes"; el.className="pn-toast";
    el.innerHTML=`<span class="pn-toast-ico" aria-hidden="true">🆕</span><span class="pn-toast-txt"><b>v${esc(n.version)} 업데이트</b><small>추가 ${c(n.added)} · 변경 ${c(n.changed)} · 삭제 ${c(n.removed)} — 눌러서 보기</small></span><button type="button" aria-label="닫기">✕</button>`;
    el.querySelector("button").onclick=(e)=>{ e.preventDefault(); e.stopPropagation(); el.remove(); };
    document.body.appendChild(el);
    requestAnimationFrame(()=>el.classList.add("show"));
    setTimeout(()=>el.remove(), 15000);
  }catch(e){}
}
function orderSteps(status){
  if(status==="cancelled") return `<span class="state-chip">취소된 주문</span>`;
  if(status==="refunded") return `<span class="state-chip">환불 완료</span>`;
  const idx={pending:0,paid:1,fulfilled:2}[status]??0;
  return `<div class="steps">${["입금 대기","입금 확인","지급 완료"].map((label,i)=>`<div class="st${i<=idx?" on":""}${i===idx?" cur":""}">${label}</div>`).join("")}</div>`;
}
const CART_KEY="wm_cart_v1";
function cartRead(){ try{ return JSON.parse(localStorage.getItem(CART_KEY)||"[]")||[]; }catch(e){ return []; } }
function cartWrite(items){ try{ localStorage.setItem(CART_KEY, JSON.stringify(items||[])); }catch(e){} paintCartFab(); }
function cartAdd(item){
  const items=cartRead();
  const id=String(item.id||"");
  const found=items.find(x=>String(x.id)===id && !x.customKind);
  if(found && !item.customKind){ found.qty=(Number(found.qty)||1)+1; }
  else items.push({id:item.id, name:item.name, price:Number(item.price)||0, qty:1, customKind:item.customKind||"", customAmount:item.customAmount||0});
  cartWrite(items);
  openCart(true);
}
function cartCount(){ return cartRead().reduce((s,x)=>s+(Number(x.qty)||1),0); }
function cartTotal(){ return cartRead().reduce((s,x)=>s+(Number(x.price)||0)*(Number(x.qty)||1),0); }
function paintCartFab(){
  const fab=document.getElementById("cartFab");
  if(!fab) return;
  const n=cartCount();
  fab.innerHTML=`🛒${n?`<span class="n">${n>99?"99+":n}</span>`:""}`;
  fab.hidden=false;
}
function openCart(force){
  ensureCartUi();
  const bg=document.getElementById("cartBg");
  const dr=document.getElementById("cartDrawer");
  if(!bg||!dr) return;
  paintCartList();
  if(force!==false){ bg.classList.add("open"); dr.classList.add("open"); }
}
function closeCart(){
  document.getElementById("cartBg")?.classList.remove("open");
  document.getElementById("cartDrawer")?.classList.remove("open");
}
function paintCartList(){
  const list=document.getElementById("cartList");
  const sum=document.getElementById("cartSum");
  if(!list) return;
  const items=cartRead();
  if(!items.length){ list.innerHTML=`<p class="cart-empty">장바구니가 비어 있어요</p>`; if(sum) sum.textContent="0원"; return; }
  list.innerHTML=items.map((it,i)=>`<div class="cart-item"><div><b>${esc(it.name)}</b><div class="meta">${won(it.price)} · ${Number(it.qty)||1}개</div></div><button type="button" class="ghost-btn pill cart-rm" data-i="${i}">삭제</button></div>`).join("");
  if(sum) sum.textContent=won(cartTotal());
  list.querySelectorAll(".cart-rm").forEach(b=>b.onclick=()=>{ const next=cartRead(); next.splice(Number(b.dataset.i),1); cartWrite(next); paintCartList(); });
}
function ensureCartUi(){
  if(document.getElementById("cartFab")) return;
  const fab=document.createElement("button"); fab.type="button"; fab.id="cartFab"; fab.className="cart-fab"; fab.title="장바구니"; fab.onclick=()=>openCart(true);
  const bgm=document.createElement("button"); bgm.type="button"; bgm.id="bgmFab"; bgm.className="bgm-fab"; bgm.title="배경음"; bgm.onclick=()=>toggleBgm();
  const bg=document.createElement("div"); bg.id="cartBg"; bg.className="cart-drawer-bg"; bg.onclick=closeCart;
  const dr=document.createElement("aside"); dr.id="cartDrawer"; dr.className="cart-drawer";
  dr.innerHTML=`<div class="row" style="justify-content:space-between;align-items:center"><h2 class="display">장바구니</h2><button type="button" class="ghost-btn pill" id="cartClose">닫기</button></div><div class="cart-list" id="cartList"></div><div class="cart-foot"><div class="sum"><span>합계</span><b id="cartSum">0원</b></div><button type="button" class="gold-btn" id="cartCheckout" style="width:100%;border-radius:1rem;padding:.9rem">결제하기</button><button type="button" class="ghost-btn" id="cartClear" style="width:100%;border-radius:1rem;padding:.75rem">비우기</button></div>`;
  document.body.appendChild(fab); document.body.appendChild(bgm); document.body.appendChild(bg); document.body.appendChild(dr);
  document.getElementById("cartClose").onclick=closeCart;
  document.getElementById("cartClear").onclick=()=>{ cartWrite([]); paintCartList(); };
  document.getElementById("cartCheckout").onclick=()=>{
    const items=cartRead();
    if(!items.length) return;
    closeCart();
    location.href="/pay?cart=1";
  };
  paintCartFab();
  paintBgmFab();
}
function bindCartButtons(){
  document.querySelectorAll(".cart-add").forEach(b=>{
    if(b.dataset.bound) return; b.dataset.bound="1";
    b.onclick=()=>cartAdd({id:b.dataset.id, name:b.dataset.name, price:b.dataset.price});
  });
}
let __bgm=null, __bgmOn=false, __bgmNodes=null, __bgmAudio=null;
function paintBgmFab(){
  const el=document.getElementById("bgmFab"); if(!el) return;
  const enabled=((STORE.settings||{}).bgm_enabled||"1")!=="0";
  el.hidden=!enabled;
  el.textContent=__bgmOn?"🔊":"🔈";
  el.style.opacity=__bgmOn?"1":".72";
}
function startBgm(){
  if(((STORE.settings||{}).bgm_enabled||"1")==="0") return;
  if(__bgmOn && ((__bgmAudio && !__bgmAudio.paused) || __bgmNodes)) { paintBgmFab(); return; }
  const url=String((STORE.settings||{}).bgm_url||"").trim();
  try{
    if(url){
      if(!__bgmAudio){
        __bgmAudio=new Audio(url);
        __bgmAudio.loop=true;
        __bgmAudio.volume=0.45;
      } else if(__bgmAudio.src!==url && !__bgmAudio.src.endsWith(url)){
        __bgmAudio.src=url;
      }
      __bgmAudio.play().then(()=>{ __bgmOn=true; paintBgmFab(); }).catch(()=>{});
      return;
    }
    const AC=window.AudioContext||window.webkitAudioContext; if(!AC) return;
    if(!__bgm) __bgm=new AC();
    __bgm.resume().catch(()=>{});
    if(__bgmNodes) return;
    const master=__bgm.createGain(); master.gain.value=0.045; master.connect(__bgm.destination);
    const make=(freq, type, gain)=>{
      const o=__bgm.createOscillator(); const g=__bgm.createGain();
      o.type=type; o.frequency.value=freq; g.gain.value=gain; o.connect(g); g.connect(master); o.start();
      return {o,g};
    };
    __bgmNodes=[make(196,"sine",.35), make(246.94,"sine",.22), make(293.66,"triangle",.12)];
    const lfo=__bgm.createOscillator(); const lg=__bgm.createGain();
    lfo.frequency.value=.08; lg.gain.value=.018; lfo.connect(lg); lg.connect(master.gain); lfo.start();
    __bgmNodes.push({o:lfo,g:lg});
    __bgmOn=true; paintBgmFab();
  }catch(e){}
}
function stopBgm(){
  try{ (__bgmNodes||[]).forEach(n=>{ try{n.o.stop();}catch(e){} }); }catch(e){}
  __bgmNodes=null;
  try{ if(__bgmAudio){ __bgmAudio.pause(); __bgmAudio.currentTime=0; } }catch(e){}
  __bgmOn=false; paintBgmFab();
}
function toggleBgm(){
  if(__bgmOn){ stopBgm(); try{ localStorage.setItem("wm_bgm","0"); }catch(e){} }
  else { startBgm(); try{ localStorage.setItem("wm_bgm","1"); }catch(e){} }
}
function bindPageTransitions(){
  if(PREVIEW||window.__wmNavBound) return;
  window.__wmNavBound=true;
  let navTimer=0;
  const clearFx=()=>{ const fx=document.getElementById("pageFx"); if(fx) fx.classList.remove("on"); };
  window.addEventListener("pageshow", clearFx);
  document.addEventListener("visibilitychange",()=>{ if(document.visibilityState==="visible") clearFx(); });
  document.addEventListener("click",(e)=>{
    if(typeof SE!=="undefined" && SE) return;
    const a=e.target.closest("a[href]");
    if(!a) return;
    if(a.hasAttribute("download") || a.dataset.noFx!=null) return;
    const raw=a.getAttribute("href")||"";
    if(!raw || raw.startsWith("#") || raw.toLowerCase().startsWith("javascript:")) return;
    if(!raw.startsWith("/")||raw.startsWith("//")||a.target==="_blank"||e.metaKey||e.ctrlKey||e.shiftKey||e.altKey) return;
    if(raw.startsWith("/api/")||raw.startsWith("/wiki")||raw.startsWith("/decorate")||raw.startsWith("/market")||raw.startsWith("/stocks")||raw.startsWith("/lottery")) return;
    let dest;
    try{ dest=new URL(raw, location.href); }catch(err){ return; }
    if(dest.origin!==location.origin) return;
    if(dest.pathname===location.pathname && dest.search===location.search) return;
    e.preventDefault();
    clearTimeout(navTimer);
    let fx=document.getElementById("pageFx");
    if(!fx){ fx=document.createElement("div"); fx.id="pageFx"; fx.className="page-fx"; document.body.appendChild(fx); }
    requestAnimationFrame(()=>fx.classList.add("on"));
    const go=dest.pathname+dest.search+dest.hash;
    navTimer=setTimeout(()=>{
      history.pushState({}, "", go);
      void showCurrentPage();
      const fx=document.getElementById("pageFx");
      if(fx) fx.classList.remove("on");
    }, 160);
  }, true);
}
async function boot(){
  await loadMe();
  __lastInboxUnread=Number(ME.inboxUnread)||0;
  if(!PREVIEW){
    setInterval(()=>void pollAlerts(), 8000);
    // 브라우저 자동재생 정책: 첫 클릭 시 AudioContext 만 잠금 해제
    document.addEventListener("pointerdown",()=>{
      try{
        const AC=window.AudioContext||window.webkitAudioContext;
        if(!AC)return;
        if(!window.__notifyAudioCtx) window.__notifyAudioCtx=new AC();
        window.__notifyAudioCtx.resume().catch(()=>{});
        if(((STORE.settings||{}).bgm_enabled||"1")!=="0" && localStorage.getItem("wm_bgm")!=="0") startBgm();
      }catch(e){}
    }, { once:true });
    void pollAlerts();
  }

  try{STORE=await (await fetch("/api/store")).json();}catch(e){}
  applySiteTheme(STORE.theme);
  await showCurrentPage();
  if(!window.__wmSoftNav){
    window.__wmSoftNav=true;
    window.addEventListener("popstate",()=>{ void showCurrentPage(); });
  }
}
async function showCurrentPage(){
  const products=STORE.products||PRODUCTS||[];
  const pg=pagePath();
  if(!ME.authenticated && !PREVIEW && pg.path!=="/login" && (STORE.settings||{}).require_login!=="0"){
    showLoginGate();
    return;
  }
  let html="";
  if(pg.path==="/"||pg.path===""){
    html=homeHtml();
  } else if(pg.path==="/patch-notes"){
    html=`<main class="panel-shell"><div class="wrap narrow">${header("patch")}<h1 class="display page-title">패치노트</h1><p style="color:var(--muted);margin-top:.5rem">업데이트될 때마다 추가 · 변경 · 삭제된 내용과 상점 변경이 자동으로 기록됩니다.</p><div id="patchRoot" style="margin-top:1.5rem"><div class="center-page" style="min-height:8rem"><div class="spinner"></div></div></div></div></main>`;
  } else if(pg.path==="/shop"){
    html=`<main class="panel-shell"><div class="wrap">${header("shop")}<h1 class="display page-title">${T("shop_nav","상점")}</h1><p style="color:var(--muted);margin-top:.5rem">${T("shop_page_desc","디스코드 계정과 마인크래프트 계정을 연동해야 이용할 수 있어요.")}</p><p style="color:var(--muted);margin-top:.35rem">구매 시 환불은 불가합니다.</p><div class="chips" id="shopChips"></div><div class="grid-3" style="margin-top:1.5rem" id="plist"></div></div></main>`;
  } else if(pg.path==="/notice"){
    let nh=`<p style="color:var(--muted);margin-top:1.5rem">등록된 공지가 없습니다.</p>`;
    try{const nd=await (await fetch("/api/notices")).json(); const list=nd.notices||[];
      if(list.length){window.__notices=list; nh=`<div class="stack" style="margin-top:1.5rem" id="noticeList"></div>`;}
    }catch(e){}
    html=`<main class="panel-shell"><div class="wrap narrow">${header("notice")}<h1 class="display page-title">공지</h1><p style="color:var(--muted);margin-top:.5rem">서버 소식을 확인해요.</p>${nh}</div></main>`;
  } else if(pg.path==="/login"){
    html=`<main class="panel-shell login-wrap"><div class="glass login-card"><a href="/" class="display" style="font-size:.875rem;color:var(--muted)">← 홈으로</a><h1 class="display" style="margin:1rem 0 0;font-size:1.875rem;color:var(--gold-soft)">로그인</h1><p style="margin-top:.5rem;font-size:.875rem;color:var(--muted)">디스코드 계정으로 로그인하세요.</p><div id="loginErr"></div><a href="/api/auth/discord" class="gold-btn" style="margin-top:1.75rem;display:flex;width:100%;justify-content:center;border-radius:1rem;padding:.9rem;font-size:.875rem">디스코드로 로그인</a></div></main>`;
  } else if(pg.path==="/link"){
    const digits=[0,1,2,3,4,5].map(i=>`<input class="flight-cell" data-i="${i}" inputmode="numeric" maxlength="1" autocomplete="one-time-code" aria-label="코드 ${i+1}" />`).join("");
    html=`<main class="panel-shell"><div class="wrap narrow">${header("link")}<h1 class="display page-title">마인크래프트 계정 연동</h1><p style="color:var(--muted);margin-top:.75rem"><b style="color:rgba(255,255,255,.75)">WILDMC서버</b>에서 받은 6자리 코드를 입력해주세요.</p><div class="link-steps"><div class="link-step"><span class="n">1</span><p>서버 접속 후 <b>/NPC를 클릭</b>하기</p></div><div class="link-step"><span class="n">2</span><p>6자리 코드를 입력해주세요.</p></div></div>${!ME.authenticated?`<a class="gold-btn pill" href="/login" style="margin-top:1.5rem">마인크래트 계정 연동하기</a>`:`${ME.minecraftLinked?`<div class="flight-tile" style="margin:1.5rem auto 0"><span class="ok-mark">✓</span><h3>이미 연동되어 있어요.</h3><p class="name">${ME.minecraftName||ME.minecraft?.name||"—"}</p><p class="uuid">${ME.minecraft?.uuid||""}</p></div><p class="flight-hint">이 연동은 계속 유지돼요.</p>`:`<div class="flight-auth is-idle" id="flightAuth"><div class="flight-cells" id="flightCells">${digits}</div><div class="flight-stage" id="flightStage"><div class="link-ring" aria-hidden="true"></div><div class="link-bridge" aria-hidden="true"><div class="link-node site"><span>DISCORD</span></div><div class="link-beam"><span class="link-fill"></span></div><div class="link-node mc"><span>WILDMC</span></div></div><div class="flight-verified" id="flightVerified"><div class="flight-tile"><span class="ok-mark">✓</span><h3>마인크래프트 계정과 디스코드 계정 연동에 성공하였어요!</h3><p class="name" id="flightName"></p><p class="uuid" id="flightUuid"></p><a class="gold-btn pill" href="/panel" style="margin-top:.85rem">프로필 보기</a></div></div></div><p class="flight-hint" id="flightHint">6자리 코드를 입력해주세요!</p></div><p id="linkErr" style="color:var(--danger);margin-top:.5rem;text-align:center"></p>`}`}</div></main>`;
  } else if(pg.path==="/panel"){
    if(!ME.authenticated){
      html=`<main class="panel-shell center-page"><div class="glass login-card" style="text-align:center"><h1 class="display page-title">로그인이 필요합니다</h1><a class="gold-btn pill" href="/login" style="margin-top:1rem">로그인하기</a></div></main>`;
    } else {
      html=panelHtml();
    }
  } else if(pg.path==="/achievements"){
    html=`<main class="panel-shell"><div class="wrap">${header("achievements")}<h1 class="display page-title">도전과제</h1><p style="color:var(--muted);margin-top:.5rem">마크처럼 업적을 모아 보세요. 숨겨진 이스터에그도 있습니다.</p><div id="achRoot"><div class="center-page" style="min-height:12rem"><div class="spinner"></div></div></div></div></main>`;
  } else if(pg.path==="/wild"){
    html=`<main class="panel-shell"><div class="wrap narrow">${header("wild")}<section class="glass" style="border-radius:28px;padding:2rem;text-align:center;margin-top:1rem"><p class="kicker">Secret Path</p><h1 class="display" style="font-size:2.5rem;color:var(--mint);margin:.5rem 0">/wild</h1><p style="color:var(--muted)">숲 한가운데에 도착했습니다.</p><p id="wildMsg" style="margin-top:1rem;color:var(--gold-soft)"></p><a class="gold-btn pill" href="/achievements" style="margin-top:1.5rem">도전과제로</a></section></div></main>`;
  } else if(pg.path==="pay"){
    const qs=new URLSearchParams(location.search);
    const pid=qs.get("product")||qs.get("productId")||"0";
    const custom=qs.get("custom")||"";
    const amount=qs.get("amount")||"";
    const cart=qs.get("cart")==="1"?"1":"";
    html=`<main class="panel-shell"><div class="wrap narrow" id="payRoot" data-product="${esc(pid)}" data-custom="${esc(custom)}" data-amount="${esc(amount)}" data-cart="${cart}"><div class="center-page"><div class="spinner"></div></div></div></main>`;
  } else if(pg.path==="order"){
    html=`<main class="panel-shell"><div class="wrap narrow" id="orderRoot" data-code="${pg.code}"><div class="center-page"><div class="spinner"></div></div></div></main>`;
  } else if(pg.path==="/inbox"){
    html=`<main class="panel-shell has-ambient"><div class="page-ambient" aria-hidden="true"><span class="a1"></span><span class="a2"></span><span class="a3"></span></div><div class="wrap inbox-wrap">${header("inbox")}<div class="inbox-stage"><aside class="glass inbox-rail"><p class="rail-kicker">Mailbox</p><h2 class="display rail-title">숲 속<br>우편함</h2><p class="rail-copy">쿠폰·주문·도전과제 알림이 여기에 모입니다.</p><div class="rail-links"><a href="/coupon">선착순 쿠폰받기</a><a href="/shop">상점 둘러보기</a><a href="/achievements">도전과제</a></div><span class="rail-ornament" aria-hidden="true"></span></aside><div class="inbox-main"><div class="inbox-head"><h1 class="display page-title">우편함</h1><button type="button" id="readAll" class="ghost-btn pill">모두 읽음</button></div><div id="inboxList" class="inbox-list"></div></div><aside class="glass inbox-rail"><p class="rail-kicker">Status</p><h2 class="display rail-title">읽지 않은<br>소식</h2><div class="rail-stat"><p class="rail-copy" style="margin:0">미확인 우편</p><p class="display num" id="inboxUnreadStat">${ME.inboxUnread||0}</p></div><p class="rail-copy">바로가기로 상점·도전과제 페이지로 이동할 수 있어요.</p><span class="rail-ornament" aria-hidden="true"></span></aside></div></div></main>`;
  } else if(pg.path==="/code"){
    html=`<main class="panel-shell"><div class="wrap narrow">${header("code")}<h1 class="display page-title">코드등록</h1><p style="color:var(--muted);margin-top:.5rem">받은 코드를 등록하면 캐시, 잼, 할인 쿠폰, 랭크가 지급돼요.</p><form id="codeForm" class="glass" style="margin-top:1.25rem;border-radius:24px;padding:1.25rem"><input class="field" id="promoCode" placeholder="코드 입력" maxlength="40" style="text-transform:uppercase" /><button class="gold-btn" type="submit" style="margin-top:.85rem;width:100%;border-radius:1rem;padding:.85rem">등록하기</button><p id="codeMsg" style="margin:.7rem 0 0;color:var(--muted)"></p></form></div></main>`;
  } else if(pg.path==="/coupon"){
    html=`<main class="panel-shell"><div class="wrap narrow">${header("coupon")}<h1 class="display page-title">${S("coupon_page_title","쿠폰받기")}</h1><p style="color:var(--muted);margin-top:.5rem">${S("coupon_page_desc","원하는 쿠폰을 다운로드하세요. 결제 시 자동 적용하거나 직접 고를 수 있습니다.")}</p><div id="couponClaimRoot" style="margin-top:1.5rem"><div class="center-page" style="min-height:8rem"><div class="spinner"></div></div></div></div></main>`;
  } else if(pg.path==="/friends"){
    html=`<main class="panel-shell"><div class="wrap">${header("friends")}<h1 class="display page-title">친구</h1><p style="color:var(--muted);margin-top:.5rem">디스코드 닉으로 친구를 추가하고 채팅하세요.</p><div id="friendsRoot" style="margin-top:1.5rem"><div class="center-page" style="min-height:8rem"><div class="spinner"></div></div></div></div></main>`;
  } else if(pg.path==="/community"){
    html=`<main class="panel-shell"><div class="wrap narrow">${header("community")}<h1 class="display page-title">커뮤니티</h1><p style="color:var(--muted);margin-top:.5rem">자유롭게 글을 쓰고, 하트와 댓글 · 대댓글을 남길 수 있어요.</p><div id="communityRoot" style="margin-top:1.5rem"><div class="center-page" style="min-height:8rem"><div class="spinner"></div></div></div></div></main>`;
  } else if(pg.path==="/support"){
    html=`<main class="panel-shell"><div class="wrap narrow">${header("support")}<h1 class="display page-title">문의 채팅</h1><p style="color:var(--muted);margin-top:.5rem">편리하게 문의를 열어봐요.</p><div id="supportRoot" style="margin-top:1.5rem"><div class="center-page" style="min-height:8rem"><div class="spinner"></div></div></div></div></main>`;
  } else {
    html=`<main class="panel-shell"><div class="wrap">${header()}<p style="color:var(--muted)">페이지를 찾을 수 없습니다.</p></div></main>`;
  }
  document.body.innerHTML=html;
  window.scrollTo(0, 0);
  paintChrome(products);
  bindCopyButtons();
  if(PREVIEW){ bindPreviewMode(); return; }
  bindPage(pg);
  initSiteEditor(pg);
  maybeShowPatchToast();
  checkNewAchievements();
  visitThemeAchievement();
  visitCalendarAchievement();
}
/* —— 페이지에서 바로 편집 —— */
let SE=null;
function initSiteEditor(pg){
  if(PREVIEW||!(ME.isDiscordLogin&&ME.canEditSite)) return;
  if(!(pg.path==="/"||pg.path==="")) return;
  const fab=document.createElement("button");
  fab.type="button"; fab.className="se-fab"; fab.id="seFab";
  fab.innerHTML=`${ico("pen")}<span>이 페이지 바로 편집</span>`;
  fab.onclick=()=>startSiteEdit();
  document.body.appendChild(fab);
  if(new URLSearchParams(location.search).get("edit")==="1") startSiteEdit();
}
function seSetStatus(text, cls){
  const el=document.getElementById("seStatus"); if(!el) return;
  el.textContent=text; el.className="se-status"+(cls?" "+cls:"");
}
function seMark(){
  SE.dirty=true;
  seSetStatus("저장 안 됨","dirty");
}
function seCurrent(){ return Object.assign({}, STORE.settings||{}, SE.settings); }
async function seCompressImage(file){
  if(!file.type.startsWith("image/")) throw new Error("이미지 파일만 올릴 수 있습니다.");
  if(file.size>15*1024*1024) throw new Error("15MB 이하 이미지를 올려 주세요.");
  try{
    const bmp=await createImageBitmap(file);
    const max=2000; let w=bmp.width,h=bmp.height;
    if(w>max||h>max){ const s=Math.min(max/w,max/h); w=Math.round(w*s); h=Math.round(h*s); }
    const c=document.createElement("canvas"); c.width=w; c.height=h; c.getContext("2d").drawImage(bmp,0,0,w,h); bmp.close();
    return c.toDataURL("image/jpeg",0.86);
  }catch(e){
    return await new Promise((res,rej)=>{ const r=new FileReader(); r.onload=()=>res(r.result); r.onerror=rej; r.readAsDataURL(file); });
  }
}
function startSiteEdit(){
  if(SE) return;
  SE={settings:{}, banner:{}, dirty:false};
  document.documentElement.classList.add("se-on");
  document.getElementById("seFab")?.remove();
  document.querySelectorAll("main [data-ek]").forEach(el=>{
    el.dataset.orig=el.textContent;
    try{ el.contentEditable="plaintext-only"; }catch(e){ /* 구형 브라우저는 plaintext-only 미지원 */ }
    if(el.contentEditable!=="plaintext-only") el.contentEditable="true";
    el.spellcheck=false;
    el.addEventListener("input",()=>{
      const [kind,key]=el.dataset.ek.split(":");
      const v=el.textContent.replace(/\s+/g," ").trim();
      (kind==="b"?SE.banner:SE.settings)[key]=v;
      if(key==="announcement") SE.settings.announce_source="custom";
      el.classList.toggle("se-changed", v!==(el.dataset.orig||"").trim());
      seMark();
    });
    el.addEventListener("keydown",(e)=>{ if(e.key==="Enter"||e.key==="Escape"){ e.preventDefault(); el.blur(); } });
    el.addEventListener("paste",(e)=>{
      e.preventDefault();
      const text=(e.clipboardData||window.clipboardData).getData("text/plain").replace(/\s+/g," ");
      document.execCommand("insertText", false, text);
    });
  });
  document.addEventListener("click", seBlockNav, true);
  const hero=document.getElementById("heroSec");
  if(hero){
    hero.insertAdjacentHTML("beforeend",`<div class="se-hero-tools"><label class="se-chip">${ico("image")}배경 이미지<input type="file" accept="image/*" id="seHeroFile" hidden></label><button type="button" class="se-chip" id="seHeroClear">배경 제거</button><button type="button" class="se-chip" id="seHeroLink">${ico("link")}버튼 링크</button></div>`);
    document.getElementById("seHeroFile").onchange=async(e)=>{
      const f=e.target.files&&e.target.files[0]; if(!f) return;
      seSetStatus("이미지 올리는 중…");
      try{
        const data=await seCompressImage(f);
        const r=await fetch("/api/site-edit/upload",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({data,filename:f.name})});
        const j=await r.json().catch(()=>({}));
        if(!r.ok) throw new Error(j.error||"업로드 실패");
        SE.banner.image_url=j.url; setHeroPhoto(j.url); seMark();
      }catch(err){ seSetStatus(err.message||"업로드 실패","bad"); }
    };
    document.getElementById("seHeroClear").onclick=()=>{ SE.banner.image_url=""; setHeroPhoto(""); seMark(); };
    document.getElementById("seHeroLink").onclick=()=>{
      const cur=SE.banner.link_url??(((STORE.banners||[])[0]||{}).link_url||"/login");
      const v=prompt("두 번째 버튼을 누르면 이동할 주소 (예: /login, /shop, https://…)", cur);
      if(v===null) return;
      SE.banner.link_url=v.trim(); seMark();
    };
  }
  const st=seCurrent();
  const catalog=(STORE.theme&&STORE.theme.catalog)||[];
  const autoItem=catalog.find(c=>c.id===(STORE.theme&&STORE.theme.autoId));
  const mode=st.theme_mode||"auto";
  const themeVal=mode==="manual"?"manual:"+(st.theme_id||"default"):mode;
  const opts=[`<option value="auto">자동 · 날짜${autoItem&&autoItem.id!=="default"?` (${esc(autoItem.emoji)} ${esc(autoItem.label)})`:""}</option>`,`<option value="off">끄기</option>`]
    .concat(catalog.filter(c=>c.id!=="default").map(c=>`<option value="manual:${esc(c.id)}">${esc(c.emoji)} ${esc(c.label)}</option>`)).join("");
  document.body.insertAdjacentHTML("beforeend",`<div class="se-bar" id="seBar" role="toolbar" aria-label="사이트 편집">
    <span class="se-title">${ico("pen")}편집 모드</span>
    <label class="se-field">테마 <select id="seTheme">${opts}</select></label>
    <label class="se-field">포인트 색 <input type="color" id="seColor" value="${esc(st.accent_color||"#d4af6a")}"><button type="button" class="se-mini" id="seColorReset">기본</button></label>
    <label class="se-toggle"><input type="checkbox" id="seStats" ${st.show_stats==="0"?"":"checked"}>현황</label>
    <label class="se-toggle"><input type="checkbox" id="seShop" ${st.show_shop==="0"?"":"checked"}>상품</label>
    <a class="se-link" href="/decorate">고급 편집 →</a>
    <span class="se-status" id="seStatus">글자를 눌러 바로 고치세요</span>
    <button type="button" class="ghost-btn pill" id="seCancel">취소</button>
    <button type="button" class="gold-btn pill" id="seSave">저장</button>
  </div>`);
  document.getElementById("seTheme").value=themeVal;
  document.getElementById("seTheme").onchange=(e)=>{
    const v=e.target.value;
    const m=v.startsWith("manual:")?"manual":v;
    SE.settings.theme_mode=m;
    if(m==="manual") SE.settings.theme_id=v.slice(7);
    STORE.theme=themeFromChoice(m, SE.settings.theme_id||st.theme_id);
    applySiteTheme(STORE.theme); repaintThemeBanner(); applySiteLook(seCurrent());
    seMark();
  };
  document.getElementById("seColor").oninput=(e)=>{ SE.settings.accent_color=e.target.value; applySiteLook(seCurrent()); seMark(); };
  document.getElementById("seColorReset").onclick=()=>{ SE.settings.accent_color=""; applySiteLook(seCurrent()); seMark(); };
  document.getElementById("seStats").onchange=(e)=>{ SE.settings.show_stats=e.target.checked?"1":"0"; applySiteLook(seCurrent()); seMark(); };
  document.getElementById("seShop").onchange=(e)=>{ SE.settings.show_shop=e.target.checked?"1":"0"; applySiteLook(seCurrent()); seMark(); };
  document.getElementById("seCancel").onclick=()=>{
    if(SE.dirty&&!confirm("저장하지 않은 변경을 버릴까요?")) return;
    SE.dirty=false; location.href="/";
  };
  document.getElementById("seSave").onclick=()=>void saveSiteEdit();
  document.addEventListener("keydown",(e)=>{ if(SE&&(e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==="s"){ e.preventDefault(); void saveSiteEdit(); } });
  window.addEventListener("beforeunload",(e)=>{ if(SE&&SE.dirty){ e.preventDefault(); e.returnValue=""; } });
}
function seBlockNav(e){
  if(!SE) return;
  if(e.target.closest(".se-bar, .se-hero-tools")) return;
  const a=e.target.closest("a");
  if(a) e.preventDefault();
}
async function saveSiteEdit(){
  if(!SE) return;
  if(!SE.dirty){ seSetStatus("바뀐 내용이 없습니다"); return; }
  const btn=document.getElementById("seSave");
  if(btn) btn.disabled=true;
  seSetStatus("저장 중…");
  try{
    const r=await fetch("/api/site-edit/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({settings:SE.settings,banner:SE.banner})});
    const j=await r.json().catch(()=>({}));
    if(!r.ok) throw new Error(j.error||"저장 실패");
    SE.dirty=false;
    seSetStatus("저장됨 ✓ 새로고침 중…","ok");
    setTimeout(()=>{ location.href="/"; }, 650);
  }catch(err){
    seSetStatus(err.message||"저장 실패","bad");
    if(btn) btn.disabled=false;
  }
}
async function visitThemeAchievement(){
  if(!ME.authenticated) return;
  const tid = STORE && STORE.theme && STORE.theme.id;
  if(!tid || tid==="default") return;
  try{
    const r=await fetch("/api/achievements/theme-visit",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({themeId:tid})});
    if(!r.ok) return;
    const d=await r.json();
    const list=d.unlocked||[];
    if(!list.length) return;
    for(const a of list){
      if(a && a.id){
        showAchPopup(a);
        try{
          const prev=JSON.parse(sessionStorage.getItem("achUnlockedIds")||"[]");
          if(!prev.includes(a.id)) sessionStorage.setItem("achUnlockedIds", JSON.stringify([...prev, a.id]));
        }catch(e){}
      }
    }
  }catch(e){}
}
async function visitCalendarAchievement(){
  if(!ME.authenticated) return;
  try{
    const r=await fetch("/api/achievements/calendar-check",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
    if(!r.ok) return;
    const d=await r.json();
    const list=d.unlocked||[];
    for(const a of list){
      if(a && a.id){
        showAchPopup(a);
        try{
          const prev=JSON.parse(sessionStorage.getItem("achUnlockedIds")||"[]");
          if(!prev.includes(a.id)) sessionStorage.setItem("achUnlockedIds", JSON.stringify([...prev, a.id]));
        }catch(e){}
      }
    }
  }catch(e){}
}
function showToast(el, text, ok){
  if(!el)return;
  const safe=String(text||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  el.innerHTML=`<div class="toast is-inline" style="border-color:${ok?"rgba(111,207,151,.4)":"rgba(224,122,106,.45)"};color:${ok?"var(--ok)":"var(--danger)"}">${safe}</div>`;
  setTimeout(()=>{el.innerHTML="";},4200);
}
async function bindPage(pg){
  if(pg.path==="/notice"&&window.__notices){
    let openId=window.__notices[0]?.id;
    const root=document.getElementById("noticeList");
    const render=()=>{root.innerHTML=window.__notices.map(n=>`<article class="glass notice-card"><button type="button" class="notice-btn" data-id="${n.id}"><div>${n.pinned?`<span class="rank-chip" style="font-size:11px;margin-bottom:.35rem">고정</span>`:""}<h2 class="display" style="margin:0;color:var(--gold-soft);font-size:1.125rem">${n.title}</h2><p style="font-size:.75rem;color:var(--muted);margin:.25rem 0 0">${new Date(n.created_at).toLocaleString("ko-KR")}</p></div><span style="color:var(--muted);font-size:.875rem">${openId===n.id?"접기":"보기"}</span></button>${openId===n.id?`<div class="notice-body">${n.body||""}</div>`:""}</article>`).join("");
      root.querySelectorAll(".notice-btn").forEach(b=>b.onclick=()=>{openId=openId===Number(b.dataset.id)?null:Number(b.dataset.id);render();});};
    render();
  }
  const err=new URLSearchParams(location.search).get("error");
  if(err&&document.getElementById("loginErr")){
    document.getElementById("loginErr").innerHTML=`<p style="color:var(--danger);margin-top:1rem">${esc(LOGIN_ERRORS[err]||"로그인 실패")}</p>`;
  }
  const ticketBtn=document.getElementById("ticketBtn");
  if(ticketBtn) ticketBtn.onclick=async()=>{
    ticketBtn.disabled=true;
    const r=await fetch("/api/nick/ticket",{method:"POST",headers:{"Content-Type":"application/json"},body:"{}"});
    const d=await r.json().catch(()=>({}));
    if(!r.ok){
      showToast(document.getElementById("panelToast"),d.error||"발급 실패",false);
      ticketBtn.disabled=false;
      return;
    }
    const out=document.getElementById("ticketCodeOut");
    if(out) out.innerHTML=`<p class="nick-owned-sub" style="margin-top:.8rem">발급된 코드 · 10분 안에 사용</p><p class="display" style="font-size:2rem;letter-spacing:.14em;color:var(--mint);margin:.25rem 0">${esc(d.code||"")}</p>`;
    const codeInput=document.getElementById("voucherCode");
    if(codeInput) codeInput.value=d.code||"";
    const badge=document.querySelector(".nick-owned-badge");
    const label=document.querySelector(".nick-owned-label");
    const left=Number(d.left)||0;
    if(badge) badge.textContent=String(left);
    if(label) label.textContent=`보유 변경권 ${left}장`;
    ticketBtn.disabled=left<=0;
    showToast(document.getElementById("panelToast"),d.message||"코드가 나왔어요.",true);
  };
  if(pg.path==="/patch-notes") await renderPatchNotes();
  if(pg.path==="/panel" && document.getElementById("supportBox")){
    try{
      const d=await (await fetch("/api/me/purchases")).json();
      const total=document.getElementById("supportTotal");
      const box=document.getElementById("supportOrders");
      if(total) total.textContent=`누적 후원 ${(Number(d.totalWon)||0).toLocaleString("ko-KR")}원`;
      const rows=d.orders||[];
      const stKo={pending:"입금 대기",paid:"입금 확인",fulfilled:"지급 완료",cancelled:"취소",refunded:"환불"};
      if(box) box.innerHTML=rows.length?rows.map(o=>`<div class="month-row"><span>${esc(o.name||"상품")} <span style="color:var(--muted)">${esc(stKo[o.status]||o.status||"")}</span>${o.coupon?`<span style="color:var(--gold-soft)"> · 쿠폰 ${esc(o.coupon)}</span>`:""}</span><b>${won(o.price)}</b></div>`).join(""):`<p style="color:var(--muted);margin:0">구매한 상품이 아직 없어요.</p>`;
    }catch(e){}
  }
  const issue=document.getElementById("issueCode");
  if(issue) issue.onclick=async()=>{const r=await fetch("/api/link-code",{method:"POST"}); const d=await r.json(); if(r.status===401){location.href="/login";return;} if(!r.ok){document.getElementById("linkErr").textContent=d.error||"발급 실패";return;} document.getElementById("codeBox").innerHTML=`<div class="glass" style="margin-top:1.5rem;border-radius:24px;padding:1.5rem;text-align:center"><p style="color:var(--muted)">인게임 입력</p><p class="display" style="font-size:2.25rem;letter-spacing:.2em;color:var(--mint);margin:.5rem 0">${d.code}</p><p style="color:var(--gold-soft)">/인증 ${d.code} 또는 /link ${d.code}</p></div>`;};
  if(document.getElementById("flightAuth")) bindFlightAuth();
  const logout=document.getElementById("logoutBtn");
  if(logout) logout.onclick=async()=>{await fetch("/api/auth/logout",{method:"POST"});location.href="/";};
  const rankBtn=document.getElementById("rankBtn");
  if(rankBtn) rankBtn.onclick=async()=>{const r=await fetch("/api/nick/rank",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({nick:document.getElementById("rankNick").value})}); const d=await r.json(); showToast(document.getElementById("panelToast"),d.message||d.error||"완료",r.ok);};
  const voucherBtn=document.getElementById("voucherBtn");
  if(voucherBtn) voucherBtn.onclick=async()=>{const r=await fetch("/api/nick/voucher",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code:document.getElementById("voucherCode").value,nick:document.getElementById("voucherNick").value})}); const d=await r.json(); showToast(document.getElementById("panelToast"),d.message||d.error||"완료",r.ok);};
  if(pg.path==="pay") await renderPay(document.getElementById("payRoot"));
  if(pg.path==="order") await renderOrder(document.getElementById("orderRoot"));
  if(pg.path==="/inbox") await renderInbox();
  if(pg.path==="/code"){
    const form=document.getElementById("codeForm");
    if(form) form.onsubmit=async(e)=>{
      e.preventDefault();
      const msg=document.getElementById("codeMsg");
      const btn=form.querySelector("button");
      if(btn) btn.disabled=true;
      const r=await fetch("/api/codes/redeem",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code:document.getElementById("promoCode").value})});
      const d=await r.json().catch(()=>({}));
      if(msg){ msg.style.color=r.ok?"var(--ok)":"var(--danger)"; msg.textContent=d.message||d.error||(r.ok?"등록됐어요.":"등록 실패"); }
      if(btn) btn.disabled=false;
    };
  }
  if(pg.path==="/coupon") await renderCouponClaim();
  if(pg.path==="/friends") await renderFriends();
  if(pg.path==="/community") await renderCommunity();
  if(pg.path==="/support") await renderSupport();
  try{ await fetch("/api/activity",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({action:"page_view",page:pg.path||"/",detail:location.pathname})}); }catch(e){}
  if(pg.path==="/achievements") await renderAchievements();
  if(pg.path==="/wild") await claimEgg("egg_wild", document.getElementById("wildMsg"));
  bindEggs();
  bindClickFx();
}
function bindFlightAuth(){
  const root=document.getElementById("flightAuth");
  const cells=[...document.querySelectorAll(".flight-cell")];
  const errEl=document.getElementById("linkErr");
  const hint=document.getElementById("flightHint");
  let busy=false;
  if(!root||!cells.length) return;

  const readCode=()=>cells.map(c=>(c.value||"").trim()).join("");
  const paintFilled=()=>cells.forEach(c=>c.classList.toggle("is-filled", !!(c.value||"").trim()));
  const setHint=(text, cls)=>{
    if(!hint) return;
    hint.textContent=text;
    hint.classList.remove("ok","bad");
    if(cls) hint.classList.add(cls);
  };
  const wait=(ms)=>new Promise(r=>setTimeout(r,ms));

  const resetIdle=()=>{
    root.classList.remove("is-busy","is-success","is-fail","is-fail-shake","is-crash","is-flying");
    root.classList.add("is-idle");
  };

  const verify=async()=>{
    const code=readCode();
    if(busy||code.length<cells.length) return;
    busy=true;
    if(errEl){ errEl.textContent=""; errEl.style.opacity="0"; }
    cells.forEach(c=>c.disabled=true);
    root.classList.remove("is-idle","is-success","is-fail","is-fail-shake","is-crash");
    root.classList.add("is-busy");
    setHint("연동 중…");

    const minSpin=900;
    const started=Date.now();
    let apiResult={ ok:false, status:0, data:{} };
    try{
      const r=await fetch("/api/link-verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code})});
      const d=await r.json().catch(()=>({}));
      apiResult={ ok:r.ok, status:r.status, data:d };
    }catch(e){
      apiResult={ ok:false, status:0, data:{ error:"네트워크 오류" } };
    }
    const left=Math.max(0, minSpin-(Date.now()-started));
    await wait(left);

    if(apiResult.status===401){ location.href="/login"; return; }

    if(!apiResult.ok){
      if(errEl){ errEl.style.opacity="1"; errEl.textContent=apiResult.data.error||"인증 실패"; }
      root.classList.remove("is-busy");
      root.classList.add("is-fail","is-fail-shake");
      setHint("연동 실패 · 다시 입력해 주세요", "bad");
      await wait(1100);
      cells.forEach(c=>{c.disabled=false;c.value="";c.classList.remove("is-filled");});
      resetIdle();
      cells[0]?.focus();
      busy=false;
      setHint("코드 입력 · 마지막 숫자에서 인증");
      return;
    }

    root.classList.remove("is-busy");
    root.classList.add("is-success");
    const n=document.getElementById("flightName");
    const u=document.getElementById("flightUuid");
    if(n) n.textContent=apiResult.data.minecraftName||"";
    if(u) u.textContent=apiResult.data.minecraftUuid||"";
    setHint("마인크래프트 계정과 디스코드 계정 연동에 성공하였어요!", "ok");
    spawnClickBurst(window.innerWidth/2, window.innerHeight*0.4, "success");
    await loadMe();
  };

  cells.forEach((cell,i)=>{
    cell.addEventListener("input",()=>{
      if(busy) return;
      const v=(cell.value||"").replace(/\D/g,"").slice(-1);
      cell.value=v;
      paintFilled();
      if(v && i<cells.length-1) cells[i+1].focus();
      if(readCode().length===cells.length) void verify();
    });
    cell.addEventListener("keydown",e=>{
      if(busy) return;
      if(e.key==="Backspace" && !cell.value && i>0){
        cells[i-1].focus();
        cells[i-1].value="";
        paintFilled();
      }
      if(e.key==="ArrowLeft" && i>0) cells[i-1].focus();
      if(e.key==="ArrowRight" && i<cells.length-1) cells[i+1].focus();
    });
    cell.addEventListener("paste",e=>{
      e.preventDefault();
      if(busy) return;
      const text=(e.clipboardData||window.clipboardData).getData("text").replace(/\D/g,"").slice(0,cells.length);
      text.split("").forEach((ch,idx)=>{ if(cells[idx]) cells[idx].value=ch; });
      paintFilled();
      if(text.length===cells.length) void verify();
      else cells[Math.min(text.length, cells.length-1)]?.focus();
    });
    cell.addEventListener("focus",()=>root.classList.remove("is-fail-shake","is-fail"));
  });
  cells[0]?.focus();
}
function ensureFxLayer(){
  let layer=document.getElementById("fxLayer");
  if(!layer){
    layer=document.createElement("div");
    layer.id="fxLayer";
    layer.className="fx-layer";
    document.body.appendChild(layer);
  }
  return layer;
}
function spawnClickBurst(x,y,kind){
  const layer=ensureFxLayer();
  const modes=["ripple","sparks","ring","burst","float"];
  const pick=kind==="success"?["ripple","sparks","burst","float"]:modes;
  const mode=pick[Math.floor(Math.random()*pick.length)];
  if(mode==="ripple"||kind==="success"){
    const r=document.createElement("span");
    r.className="fx-ripple";
    r.style.left=x+"px"; r.style.top=y+"px";
    r.style.width="28px"; r.style.height="28px";
    layer.appendChild(r); setTimeout(()=>r.remove(),750);
  }
  if(mode==="ring"||kind==="success"){
    const ring=document.createElement("span");
    ring.className="fx-ring";
    ring.style.left=x+"px"; ring.style.top=y+"px";
    ring.style.width="40px"; ring.style.height="40px";
    layer.appendChild(ring); setTimeout(()=>ring.remove(),600);
  }
  if(mode==="sparks"||mode==="burst"||kind==="success"){
    const n=kind==="success"?16:10;
    for(let i=0;i<n;i++){
      const ang=(Math.PI*2*i)/n + Math.random()*0.4;
      const dist=28+Math.random()*48;
      const el=document.createElement("span");
      el.className=mode==="burst"?"fx-burst":"fx-spark";
      el.style.left=x+"px"; el.style.top=y+"px";
      el.style.setProperty("--dx", Math.cos(ang)*dist+"px");
      el.style.setProperty("--dy", Math.sin(ang)*dist+"px");
      el.style.setProperty("--rot", Math.floor(Math.random()*180)+"deg");
      if(i%3===0) el.style.background=i%2?"var(--mint)":"var(--gold)";
      layer.appendChild(el); setTimeout(()=>el.remove(),750);
    }
  }
  if(mode==="float"||kind==="success"){
    const icons=kind==="success"?["✦","★","✔","✨"]:["✦","✧","◆","●","♡","☆"];
    const f=document.createElement("span");
    f.className="fx-float";
    f.textContent=icons[Math.floor(Math.random()*icons.length)];
    f.style.left=x+"px"; f.style.top=y+"px";
    f.style.color=kind==="success"?"var(--ok)":"var(--gold-soft)";
    layer.appendChild(f); setTimeout(()=>f.remove(),950);
  }
}
function bindClickFx(){
  if(window.__clickFxBound) return;
  window.__clickFxBound=true;
  document.addEventListener("pointerdown",ev=>{
    if(ev.button!==0) return;
    const t=ev.target.closest("a,button,.gold-btn,.ghost-btn,.pill,.card,.stat,.notice-btn,.buy,.profile-link,.egg-hot,.claim-btn");
    if(!t) return;
    if(t.closest(".fx-layer")) return;
    spawnClickBurst(ev.clientX, ev.clientY);
    t.classList.remove("fx-press");
    void t.offsetWidth;
    t.classList.add("fx-press");
    setTimeout(()=>t.classList.remove("fx-press"),450);
  }, {passive:true});
}
async function claimEgg(id, msgEl){
  if(!ME.authenticated){
    if(msgEl) msgEl.textContent="로그인하면 이스터에그가 해금됩니다.";
    return null;
  }
  try{
    const r=await fetch("/api/achievements/claim",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id})});
    const d=await r.json();
    if(r.status===401){if(msgEl)msgEl.textContent="로그인이 필요합니다.";return null;}
    if(d.unlocked){
      showAchPopup(d.unlocked);
      try{
        const prev=JSON.parse(sessionStorage.getItem("achUnlockedIds")||"[]");
        if(!prev.includes(id)) sessionStorage.setItem("achUnlockedIds", JSON.stringify([...prev, id]));
      }catch(e){}
      if(msgEl) msgEl.textContent=`해금: ${d.unlocked.icon||""} ${d.unlocked.title}`;
      return d.unlocked;
    }
    if(msgEl && d.already) msgEl.textContent="이미 해금한 이스터에그입니다.";
    return null;
  }catch(e){return null;}
}
function playAchSound(){
  try{
    const AC=window.AudioContext||window.webkitAudioContext;
    if(!AC) return;
    if(!window.__achAudio) window.__achAudio=new AC();
    const ctx=window.__achAudio;
    if(ctx.state==="suspended") ctx.resume();
    const now=ctx.currentTime;
    const notes=[523.25,659.25,783.99,1046.5];
    notes.forEach((freq,i)=>{
      const o=ctx.createOscillator();
      const g=ctx.createGain();
      o.type=i%2===0?"triangle":"square";
      o.frequency.value=freq;
      const t0=now+i*0.09;
      g.gain.setValueAtTime(0.0001,t0);
      g.gain.exponentialRampToValueAtTime(0.12,t0+0.02);
      g.gain.exponentialRampToValueAtTime(0.0001,t0+0.28);
      o.connect(g); g.connect(ctx.destination);
      o.start(t0); o.stop(t0+0.3);
    });
    const o2=ctx.createOscillator();
    const g2=ctx.createGain();
    o2.type="sine"; o2.frequency.value=1318.5;
    g2.gain.setValueAtTime(0.0001,now+0.32);
    g2.gain.exponentialRampToValueAtTime(0.08,now+0.36);
    g2.gain.exponentialRampToValueAtTime(0.0001,now+0.7);
    o2.connect(g2); g2.connect(ctx.destination);
    o2.start(now+0.32); o2.stop(now+0.72);
  }catch(e){}
}
function showAchPopup(ach){
  if(!ach) return;
  const old=document.getElementById("achPopup");
  if(old) old.remove();
  const el=document.createElement("div");
  el.id="achPopup";
  el.className="mc-toast";
  el.setAttribute("role","status");
  el.innerHTML=`<div class="mc-toast-frame"><div class="mc-toast-top"><div class="mc-toast-icon">${ach.icon||"🏆"}</div><div class="mc-toast-copy"><p class="mc-toast-label">도전과제 달성!</p><p class="mc-toast-title">${ach.title||"도전과제"}</p></div></div><div class="mc-toast-bottom">${ach.desc||"도전과제를 달성했습니다"}</div></div>`;
  document.body.appendChild(el);
  playAchSound();
  setTimeout(()=>el.remove(),5600);
}
async function checkNewAchievements(){
  if(!ME.authenticated) return;
  try{
    const r=await fetch("/api/achievements");
    if(!r.ok) return;
    const d=await r.json();
    const items=d.items||[];
    const now=items.filter(a=>a.unlocked).map(a=>a.id);
    const key="achUnlockedIds";
    const prev=JSON.parse(sessionStorage.getItem(key)||"[]");
    const neu=now.filter(id=>!prev.includes(id));
    sessionStorage.setItem(key, JSON.stringify(now));
    if(prev.length===0 && neu.length>1) return;
    for(const id of neu){
      const a=items.find(x=>x.id===id);
      if(a) showAchPopup(a);
    }
  }catch(e){}
}
function bindEggs(){
  const brand=document.getElementById("eggBrand");
  if(brand && !brand._eggBound){
    brand._eggBound=true;
    brand.addEventListener("click",(e)=>{
      let n=Number(sessionStorage.getItem("eggBrand")||0)+1;
      sessionStorage.setItem("eggBrand",String(n));
      if(n>=7){
        e.preventDefault();
        sessionStorage.setItem("eggBrand","0");
        claimEgg("egg_brand");
      }
    });
  }
  const year=document.getElementById("eggYear");
  if(year && !year._eggBound){
    year._eggBound=true;
    year.addEventListener("click",()=>claimEgg("egg_footer"));
  }
  const live=document.getElementById("livetext");
  if(live && !live._eggBound){
    live._eggBound=true;
    let taps=0;
    live.addEventListener("click",()=>{
      if(!String(live.textContent||"").includes("Offline")){taps=0;return;}
      taps+=1;
      if(taps>=5){taps=0;claimEgg("egg_offline");}
    });
  }
  if(!window.__konamiBound){
    window.__konamiBound=true;
    const seq=["ArrowUp","ArrowUp","ArrowDown","ArrowDown","ArrowLeft","ArrowRight","ArrowLeft","ArrowRight","b","a"];
    let i=0;
    window.addEventListener("keydown",(e)=>{
      const key=e.key.length===1?e.key.toLowerCase():e.key;
      if(key===seq[i] || (seq[i].length===1 && key===seq[i])){
        i+=1;
        if(i>=seq.length){i=0;claimEgg("egg_konami");}
      } else {
        i = (key===seq[0]) ? 1 : 0;
      }
    });
  }
}
async function renderAchievements(){
  const root=document.getElementById("achRoot");
  if(!root) return;
  if(!ME.authenticated){
    root.innerHTML=`<div class="glass" style="margin-top:1.5rem;border-radius:24px;padding:1.5rem;text-align:center"><p style="color:var(--muted)">로그인 후 도전과제를 확인할 수 있습니다.</p><a class="gold-btn pill" href="/login" style="margin-top:1rem">로그인</a></div>`;
    return;
  }
  const r=await fetch("/api/achievements");
  if(r.status===401){location.href="/login";return;}
  const d=await r.json();
  const cats=["기본","상점","프로필","시즌","이스터에그"];
  const byCat={};
  (d.items||[]).forEach(a=>{(byCat[a.category]=byCat[a.category]||[]).push(a);});
  let html=`<section class="glass ach-progress"><div style="display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap"><div><p class="kicker" style="margin:0">Progress</p><p class="display" style="margin:.25rem 0 0;font-size:1.5rem;color:var(--gold-soft)">${d.unlocked||0} / ${d.total||0}</p></div><p style="color:var(--mint);font-weight:600;align-self:flex-end">${d.percent||0}%</p></div><div class="ach-bar"><span style="width:${d.percent||0}%"></span></div></section>`;
  cats.forEach(cat=>{
    const list=byCat[cat]||[];
    if(!list.length) return;
    html+=`<section style="margin-top:2rem"><p class="kicker">${cat}</p><div class="ach-grid">`+list.map(a=>{
      const cls=`glass ach-card ${a.unlocked?"unlocked":"locked"}${a.secret?" secret":""}`;
      const when=a.unlockedAt?new Date(a.unlockedAt).toLocaleString("ko-KR"): (a.unlocked?"해금됨":"미해금");
      return `<article class="${cls}"><div class="ach-icon">${a.icon||"❔"}</div><h2 class="display ach-title">${a.title||""}</h2><p class="ach-desc">${a.desc||""}</p><div class="ach-meta"><span>${a.secret?"SECRET":cat}</span><span>${when}</span></div></article>`;
    }).join("")+`</div></section>`;
  });
  root.innerHTML=html;
}
async function renderPay(root){
  if(!root) return;
  const pid=Number(root.dataset.product||0);
  const customKind=String(root.dataset.custom||"").trim();
  const customAmt=Number(root.dataset.amount||0);
  const isCart=root.dataset.cart==="1";
  const cartItems=isCart?cartRead():[];
  if(isCart && !cartItems.length){root.innerHTML=`<div class="center-page"><div class="glass login-card" style="text-align:center"><h1 class="display page-title">장바구니가 비어 있어요</h1><a class="gold-btn pill" href="/shop">상점으로</a></div></div>`;return;}
  if(!isCart && !pid && !customKind){root.innerHTML=`<div class="center-page"><div class="glass login-card" style="text-align:center"><h1 class="display page-title">상품을 선택해주세요</h1><a class="gold-btn pill" href="/shop">상점으로</a></div></div>`;return;}
  const gate=purchaseBlock();
  if(gate){root.innerHTML=`<div class="center-page"><div class="glass login-card" style="text-align:center"><h1 class="display page-title">구매 조건 미충족</h1><p style="color:var(--muted);margin-top:.5rem">${gate}</p><a class="gold-btn pill" href="${ME.isDiscordLogin?"/panel":"/login"}" style="margin-top:1rem">${ME.isDiscordLogin?"마크 연동":"로그인"}</a></div></div>`;return;}
  let data, p;
  if(isCart){
    const cartTotalWon=cartItems.reduce((s,it)=>s+(Number(it.price)||0)*(Number(it.qty)||1),0);
    const payBase=await (await fetch("/api/pay")).json();
    p={name:`장바구니 ${cartItems.length}건`, price:cartTotalWon, description:cartItems.map(it=>`${it.name} ×${Number(it.qty)||1}`).join(" · ")};
    data={payment:payBase.payment||{}, product:p, cart:true};
  } else {
    const payUrl=customKind?`/api/pay?custom=${encodeURIComponent(customKind)}&amount=${encodeURIComponent(String(customAmt))}`:"/api/pay?productId="+pid;
    data=await (await fetch(payUrl)).json();
    if(!data.product){root.innerHTML=`<p style="color:var(--danger)">${data.error||"상품 없음"}</p>`;return;}
    p=data.product;
  }
  let applied=null;
  const cartListHtml=isCart?`<ul class="cart-pay-list">${cartItems.map(it=>`<li><span>${esc(it.name)} · ${Number(it.qty)||1}개</span><b>${won((Number(it.price)||0)*(Number(it.qty)||1))}</b></li>`).join("")}</ul>`:"";
  const productCard=isCart
    ?`<section class="glass" style="border-radius:24px;padding:1.25rem"><h2 class="display" style="color:var(--gold-soft);margin:0">한 번에 결제</h2><p style="color:var(--muted);margin:.45rem 0 0;font-size:.9rem">장바구니 상품을 한 주문으로 결제합니다.</p>${cartListHtml}<p class="price" id="payPrice" style="font-size:1.5rem;margin-top:1rem">${won(p.price)}</p><p id="payDiscount" style="font-size:.875rem;color:var(--gold-soft);margin-top:.35rem"></p></section>`
    :`<section class="glass card">${thumbHtml(p)}<div class="card-body"><h2 class="display">${esc(p.name)}</h2><p class="price" id="payPrice" style="font-size:1.5rem">${won(p.price)}</p><p id="payDiscount" style="font-size:.875rem;color:var(--gold-soft);margin-top:.35rem"></p></div></section>`;
  root.innerHTML=`${header("pay")}<h1 class="display page-title">${isCart?"장바구니 결제":"결제"}</h1><div class="grid-2" style="margin-top:1.5rem">${productCard}<section class="glass" style="border-radius:24px;padding:1.25rem"><h3 class="display" style="color:var(--gold)">입금 안내</h3><p style="font-size:.875rem;margin-top:.75rem;color:var(--muted)">은행 ${esc(data.payment.bankName||"—")}</p><p style="font-family:monospace;color:var(--mint)">${accountHtml(data.payment.bankAccount)}</p><p style="font-size:.875rem;color:var(--gold-soft)">예금주 ${esc(data.payment.bankHolder||"—")}</p></section></div><form id="payForm" class="glass" style="margin-top:1rem;border-radius:24px;padding:1.25rem"><p style="font-size:.875rem;color:var(--muted)">디스코드: ${esc(ME.username||"")} · 마크: ${esc(ME.minecraftName||"연동됨")}</p><input class="field" id="buyerName" required placeholder="입금자명 *" value="${esc(ME.username||"")}" style="margin-top:.75rem" /><div class="gift-box" style="margin-top:.75rem"><label style="display:flex;align-items:center;gap:.5rem;cursor:pointer"><input type="checkbox" id="giftOn"/><span>다른 유저에게 선물하기</span></label><div id="giftPanel" style="display:none;margin-top:.55rem"><p style="margin:0;font-size:.8rem;color:var(--muted)">친구가 먼저 보여요. 눌러 고르거나, 아래에 닉네임을 직접 적어도 돼요.</p><div id="giftFriends" style="display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.5rem"></div><input class="field" id="giftNick" placeholder="받을 사람 마인크래프트 닉네임" style="margin-top:.55rem" /></div></div><div id="couponWalletBox" style="margin-top:.75rem;border:1px solid var(--line);border-radius:16px;padding:.85rem"><div style="display:flex;justify-content:space-between;gap:.5rem;flex-wrap:wrap;align-items:center"><strong style="color:var(--gold-soft);font-size:.9rem">내 쿠폰</strong><button type="button" id="couponAutoBtn" class="ghost-btn pill" style="padding:.35rem .8rem;font-size:.8rem">최대 할인 자동적용</button></div><div id="couponWalletList" style="margin-top:.55rem"></div><p id="couponMsg" style="margin-top:.4rem;font-size:.8rem;color:var(--muted)"></p><details style="margin-top:.55rem"><summary style="cursor:pointer;color:var(--muted);font-size:.8rem">코드 직접 입력</summary><div style="margin-top:.5rem;display:flex;gap:.5rem;flex-wrap:wrap"><input class="field" id="couponCode" placeholder="쿠폰 코드" style="flex:1;min-width:10rem;text-transform:uppercase" /><button type="button" id="couponBtn" class="ghost-btn pill">적용</button></div></details></div><textarea class="field" id="memo" placeholder="요청사항 (선택)" style="margin-top:.75rem;min-height:5rem"></textarea><div style="margin-top:.85rem;border:1px solid var(--line);border-radius:16px;padding:.85rem"><strong style="color:var(--gold-soft);font-size:.9rem">입금 증빙 사진</strong><p style="margin:.35rem 0 0;font-size:.8rem;color:var(--muted)">이체 내역·영수증 사진을 첨부할 수 있습니다. (최대 6장)</p><div class="row" style="gap:.5rem;flex-wrap:wrap;align-items:center;margin-top:.55rem"><label class="ghost-btn pill" style="cursor:pointer;margin:0">사진 첨부<input type="file" id="payFiles" accept="image/*" multiple hidden/></label><span id="payPrev" style="font-size:.8rem;color:var(--muted)"></span></div><div id="payThumb" class="row" style="gap:.45rem;flex-wrap:wrap;margin-top:.55rem"></div></div><p id="payErr" style="color:var(--danger);font-size:.875rem"></p><button type="submit" class="gold-btn" style="margin-top:.75rem;width:100%;border-radius:1rem;padding:.85rem">${isCart?"장바구니 전부 주문하기":"주문하고 입금 안내 받기"}</button></form>`;
  const giftOn=document.getElementById("giftOn");
  const giftNick=document.getElementById("giftNick");
  const giftPanel=document.getElementById("giftPanel");
  const giftFriends=document.getElementById("giftFriends");
  if(giftOn&&giftNick&&giftPanel) giftOn.onchange=async()=>{
    giftPanel.style.display=giftOn.checked?"block":"none";
    if(!giftOn.checked){ giftNick.value=""; if(giftFriends) giftFriends.innerHTML=""; return; }
    let friends=[];
    try{ friends=(await (await fetch("/api/friends")).json()).friends||[]; }catch(err){}
    friends.sort((a,b)=>Number(!a.minecraft_name)-Number(!b.minecraft_name));
    if(!giftFriends) return;
    giftFriends.innerHTML=friends.length?friends.map(f=>{
      const nick=String(f.minecraft_name||"").trim();
      return `<button type="button" class="ghost-btn pill gift-friend" data-nick="${esc(nick)}" style="font-size:.85rem">${esc(f.username||"친구")}${nick?` · ${esc(nick)}`:" · 닉 직접 입력"}</button>`;
    }).join(""):`<p style="margin:0;font-size:.8rem;color:var(--muted)">등록된 친구가 없어요. 닉네임을 직접 입력하세요.</p>`;
    giftFriends.querySelectorAll(".gift-friend").forEach(btn=>{
      btn.onclick=()=>{
        const nick=btn.dataset.nick||"";
        if(nick) giftNick.value=nick;
        else giftNick.focus();
        giftFriends.querySelectorAll(".gift-friend").forEach(b=>b.style.outline="");
        btn.style.outline="2px solid var(--gold-soft)";
      };
    });
  };
  let pendingPayImgs=[];
  const readPayFiles=async(files)=>{
    const out=[];
    for(const file of [...files].slice(0,6)){
      if(!file.type.startsWith("image/")) continue;
      if(file.size>10*1024*1024){alert("사진은 10MB 이하로 올려 주세요.");continue;}
      try{
        const bmp=await createImageBitmap(file);
        const max=1600; let w=bmp.width,h=bmp.height;
        if(w>max||h>max){const s=Math.min(max/w,max/h);w=Math.round(w*s);h=Math.round(h*s);}
        const c=document.createElement("canvas"); c.width=w;c.height=h; c.getContext("2d").drawImage(bmp,0,0,w,h); bmp.close();
        out.push(c.toDataURL("image/jpeg",0.84));
      }catch(err){
        out.push(await new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result);r.onerror=rej;r.readAsDataURL(file);}));
      }
    }
    return out;
  };
  const paintPayThumbs=()=>{
    const box=document.getElementById("payThumb");
    const prev=document.getElementById("payPrev");
    if(prev) prev.textContent=pendingPayImgs.length?`사진 ${pendingPayImgs.length}장 선택됨`:"";
    if(box) box.innerHTML=pendingPayImgs.map((u,i)=>`<img src="${u}" alt="" style="width:4.5rem;height:4.5rem;object-fit:cover;border-radius:10px;border:1px solid var(--line)" title="${i+1}"/>`).join("");
  };
  document.getElementById("payFiles").onchange=async(e)=>{
    pendingPayImgs=await readPayFiles(e.target.files||[]);
    paintPayThumbs();
  };
  const priceEl=document.getElementById("payPrice");
  const discEl=document.getElementById("payDiscount");
  const couponMsg=document.getElementById("couponMsg");
  const setPriceView=()=>{
    if(applied){
      priceEl.innerHTML=`<span style="text-decoration:line-through;color:var(--muted);font-size:1rem;margin-right:.5rem">${won(applied.original)}</span>${won(applied.final)}`;
      discEl.textContent=`쿠폰 ${applied.code} · -${won(applied.discount)} 할인`;
      couponMsg.style.color="var(--ok)";
      couponMsg.textContent=`적용됨: ${applied.name||applied.code}`;
    } else {
      priceEl.textContent=won(p.price);
      discEl.textContent="";
    }
  };
  const walletList=document.getElementById("couponWalletList");
  let wallet=[];
  const applyPricing=(pricing)=>{
    applied=pricing; setPriceView();
    if(pricing&&pricing.code){
      const codeEl=document.getElementById("couponCode");
      if(codeEl) codeEl.value=pricing.code;
    }
  };
  const validateCode=async(code)=>{
    const r=await fetch("/api/coupons/validate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code,productId:isCart?0:(pid||0),customKind:isCart?"":customKind,customAmount:isCart?0:customAmt,cartTotal:isCart?p.price:0})});
    const d=await r.json();
    if(!r.ok){applyPricing(null); couponMsg.style.color="var(--danger)"; couponMsg.textContent=d.error||"쿠폰 적용 실패"; return null;}
    applyPricing(d.pricing); return d.pricing;
  };
  const paintWallet=()=>{
    if(!walletList) return;
    if(!wallet.length){walletList.innerHTML=`<p style="margin:0;font-size:.8rem;color:var(--muted)">다운로드한 쿠폰이 없습니다. <a href="/coupon" class="mint">쿠폰받기</a></p>`;return;}
    walletList.innerHTML=wallet.map(c=>{
      const label=c.type==="percent"?`${c.value}%`:`${Number(c.value).toLocaleString("ko-KR")}원`;
      const on=applied&&applied.code===c.code;
      return `<label style="display:flex;align-items:center;gap:.55rem;padding:.45rem .35rem;border-radius:10px;cursor:pointer;${on?"background:rgba(125,206,160,.1)":""}"><input type="radio" name="walletCoupon" value="${c.code}" ${on?"checked":""}/><span style="flex:1"><b style="color:var(--gold-soft)">${c.name||c.code}</b> · <span style="color:var(--mint)">${label}</span></span></label>`;
    }).join("")+`<label style="display:flex;align-items:center;gap:.55rem;padding:.45rem .35rem;cursor:pointer"><input type="radio" name="walletCoupon" value="" ${!applied?"checked":""}/><span style="color:var(--muted);font-size:.85rem">쿠폰 사용 안 함</span></label>`;
    walletList.querySelectorAll('input[name="walletCoupon"]').forEach(inp=>{
      inp.onchange=async()=>{
        const code=inp.value;
        if(!code){applyPricing(null); couponMsg.textContent=""; return;}
        await validateCode(code);
      };
    });
  };
  const autoApplyBest=async()=>{
    if(!wallet.length){couponMsg.textContent="적용 가능한 쿠폰이 없습니다.";return;}
    let best=null;
    for(const c of wallet){
      const r=await fetch("/api/coupons/validate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code:c.code,productId:isCart?0:(pid||0),customKind:isCart?"":customKind,customAmount:isCart?0:customAmt,cartTotal:isCart?p.price:0})});
      const d=await r.json().catch(()=>({}));
      if(!r.ok||!d.pricing) continue;
      if(!best||Number(d.pricing.discount||0)>Number(best.discount||0)) best=d.pricing;
    }
    if(!best){couponMsg.style.color="var(--danger)";couponMsg.textContent="적용 가능한 쿠폰이 없습니다.";return;}
    applyPricing(best); paintWallet();
  };
  document.getElementById("couponBtn").onclick=async()=>{
    const code=(document.getElementById("couponCode").value||"").trim();
    if(!code){applyPricing(null);couponMsg.textContent="";paintWallet();return;}
    await validateCode(code); paintWallet();
  };
  document.getElementById("couponAutoBtn")?.addEventListener("click",()=>void autoApplyBest());
  (async()=>{
    try{
      const walletUrl=isCart?"/api/coupons/wallet":"/api/coupons/wallet?productId="+(pid||0);
      const d=await (await fetch(walletUrl)).json();
      wallet=d.coupons||[];
      paintWallet();
      if(wallet.length) await autoApplyBest();
    }catch(e){ paintWallet(); }
  })();
  document.getElementById("payForm").onsubmit=async(e)=>{
    e.preventDefault();
    const errEl=document.getElementById("payErr");
    const btn=e.target.querySelector('button[type="submit"]');
    if(btn){btn.disabled=true;btn.textContent="주문 접수 중…";}
    const code=((document.getElementById("couponCode").value||"").trim()||(applied&&applied.code)||"");
    const retryLabel=isCart?"장바구니 전부 주문하기":"주문하고 입금 안내 받기";
    try{
      const giftName=(document.getElementById("giftOn")&&document.getElementById("giftOn").checked)?(document.getElementById("giftNick").value||"").trim():"";
      if(document.getElementById("giftOn")&&document.getElementById("giftOn").checked && !giftName){ if(errEl) errEl.textContent="선물할 마인크래프트 닉네임을 입력하세요."; if(btn){btn.disabled=false;btn.textContent=retryLabel;} return; }
      const payload={giftMinecraftName:giftName,buyerName:document.getElementById("buyerName").value,minecraftName:ME.minecraftName||"",discordUsername:ME.username||"",memo:document.getElementById("memo").value,couponCode:code,images:pendingPayImgs};
      if(isCart){
        payload.cartItems=cartItems.map(it=>({productId:it.id, qty:Number(it.qty)||1, customKind:it.customKind||"", customAmount:it.customAmount||0, name:it.name, price:Number(it.price)||0}));
      } else {
        payload.productId=pid||0;
        payload.customKind=customKind;
        payload.customAmount=customAmt;
      }
      const r=await fetch("/api/pay",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
      const d=await r.json();
      if(r.ok){
        try{
          if(isCart) cartWrite([]);
          else {
            const items=cartRead();
            if(items.length){
              if(customKind) cartWrite(items.slice(1));
              else cartWrite(items.filter(x=>String(x.id)!==String(pid)));
            }
          }
        }catch(e){}
        location.href=d.redirect||("/pay/order/"+d.orderCode);
      }
      else { if(errEl) errEl.textContent=d.error||"주문 실패"; if(btn){btn.disabled=false;btn.textContent=retryLabel;} }
    }catch(err){
      if(errEl) errEl.textContent="네트워크 오류";
      if(btn){btn.disabled=false;btn.textContent=retryLabel;}
    }
  };
}
async function renderOrder(root){
  if(!root) return;
  const code=root.dataset.code;
  const data=await (await fetch("/api/pay/order/"+code)).json();
  if(!data.order){root.innerHTML=`<p style="color:var(--danger)">${data.error||"조회 실패"}</p>`;return;}
  const o=data.order, st={pending:"입금 대기",paid:"입금 확인됨",fulfilled:"지급 완료",cancelled:"취소됨",refunded:"환불 완료"};
  const disc=Number(o.discount_amount||0);
  const priceHtml=disc?`<p style="font-size:.875rem;color:var(--muted);text-decoration:line-through">${won(o.original_price||o.price)}</p><p style="font-size:1.5rem;color:var(--mint);font-weight:600">${won(o.price)}</p><p style="font-size:.8rem;color:var(--gold-soft)">쿠폰 ${o.coupon_code||""} · -${won(disc)}</p>`:`<p style="font-size:1.5rem;color:var(--mint);font-weight:600">${won(o.price)}</p>`;
  const imgs=Array.isArray(o.images)?o.images:[];
  const imgBlock=imgs.length
    ? `<div class="row" style="gap:.5rem;flex-wrap:wrap;margin-top:.75rem">${imgs.map(u=>`<a href="${u}" target="_blank" rel="noopener"><img src="${u}" alt="" style="width:6rem;height:6rem;object-fit:cover;border-radius:12px;border:1px solid var(--line)"/></a>`).join("")}</div>`
    : `<p style="margin:.5rem 0 0;font-size:.85rem;color:var(--muted)">아직 첨부된 사진이 없습니다.</p>`;
  const canUpload=!!(ME.authenticated && String(ME.discordId||"")===String(o.discord_id||"") && o.status!=="cancelled" && o.status!=="refunded");
  const giftLine=o.gift||o.gift_minecraft_name?`<p style="margin-top:.55rem;font-size:.88rem;color:var(--mint)">선물 · ${esc(o.gift_minecraft_name||o.minecraft_name||"")}</p>`:"";
  const refundedNote=o.status==="refunded"?`<p style="margin-top:.55rem;font-size:.85rem;color:var(--gold-soft)">환불이 완료되었어요.</p>`:"";
  root.innerHTML=`${header("order")}<h1 class="display page-title">주문 완료</h1><section class="glass" style="margin-top:1.5rem;border-radius:24px;padding:1.25rem"><p style="font-size:.75rem;color:var(--muted)">주문번호</p><p style="font-family:monospace;color:var(--mint);font-size:1.125rem">${o.order_code}</p><p style="margin-top:.75rem;font-size:.875rem;color:var(--muted)">상태: ${st[o.status]||esc(o.status)}</p>${orderSteps(o.status)}<p class="display" style="margin-top:1rem;color:var(--gold-soft)">${esc(o.product_name)}</p>${giftLine}${priceHtml}${refundedNote}</section><section class="glass" style="margin-top:1rem;border-radius:24px;padding:1.25rem"><h2 class="display" style="color:var(--gold);font-size:1.125rem">입금 계좌</h2><p style="font-family:monospace;color:var(--mint);margin-top:.5rem">${accountHtml(data.payment.bankAccount)}</p><p style="font-size:.875rem;color:var(--gold-soft)">예금주 ${esc(data.payment.bankHolder||"—")}</p></section><section class="glass" style="margin-top:1rem;border-radius:24px;padding:1.25rem"><h2 class="display" style="color:var(--gold);font-size:1.125rem">입금 증빙 사진</h2>${imgBlock}${canUpload?`<div class="row" style="gap:.5rem;flex-wrap:wrap;align-items:center;margin-top:.85rem"><label class="ghost-btn pill" style="cursor:pointer;margin:0">사진 추가<input type="file" id="ordFiles" accept="image/*" multiple hidden/></label><span id="ordPrev" style="font-size:.8rem;color:var(--muted)"></span><button type="button" id="ordUploadBtn" class="gold-btn pill" style="display:none">업로드</button></div><p id="ordMsg" style="font-size:.85rem;color:var(--muted);margin:.5rem 0 0"></p>`:""}</section>`;
  if(canUpload){
    let pending=[];
    const readFiles=async(files)=>{
      const out=[];
      for(const file of [...files].slice(0,6)){
        if(!file.type.startsWith("image/")) continue;
        if(file.size>10*1024*1024){alert("사진은 10MB 이하로 올려 주세요.");continue;}
        try{
          const bmp=await createImageBitmap(file);
          const max=1600; let w=bmp.width,h=bmp.height;
          if(w>max||h>max){const s=Math.min(max/w,max/h);w=Math.round(w*s);h=Math.round(h*s);}
          const c=document.createElement("canvas"); c.width=w;c.height=h; c.getContext("2d").drawImage(bmp,0,0,w,h); bmp.close();
          out.push(c.toDataURL("image/jpeg",0.84));
        }catch(err){
          out.push(await new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result);r.onerror=rej;r.readAsDataURL(file);}));
        }
      }
      return out;
    };
    document.getElementById("ordFiles").onchange=async(e)=>{
      pending=await readFiles(e.target.files||[]);
      document.getElementById("ordPrev").textContent=pending.length?`사진 ${pending.length}장`:"";
      document.getElementById("ordUploadBtn").style.display=pending.length?"inline-flex":"none";
    };
    document.getElementById("ordUploadBtn").onclick=async()=>{
      const msg=document.getElementById("ordMsg");
      msg.textContent="업로드 중…";
      const r=await fetch("/api/pay/order/"+encodeURIComponent(code)+"/proof",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({images:pending})});
      const j=await r.json().catch(()=>({}));
      if(!r.ok){msg.style.color="var(--danger)";msg.textContent=j.error||"실패";return;}
      location.reload();
    };
  }
}
async function renderInbox(){
  const r=await fetch("/api/inbox");
  if(r.status===401){location.href="/login";return;}
  const d=await r.json();
  const list=document.getElementById("inboxList");
  if(!list)return;
  const unread=Number(d.unread||0);
  const stat=document.getElementById("inboxUnreadStat");
  if(stat) stat.textContent=String(unread);
  if(!(d.items||[]).length){list.innerHTML=`<p style="color:var(--muted)">알림이 없습니다.</p>`;return;}
  list.innerHTML=d.items.map(m=>`<article class="glass mail-card${m.read?" is-read":""}"><h2 class="display">${m.title||""}</h2><p class="mail-body">${m.body||""}</p><p class="mail-meta">${new Date(m.created_at).toLocaleString("ko-KR")}</p>${m.link_url?`<a class="gold-btn pill" href="${m.link_url}">바로가기</a>`:""}</article>`).join("");
  document.getElementById("readAll")?.addEventListener("click",async()=>{await fetch("/api/inbox",{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({all:true})}); renderInbox();});
}
async function renderCouponClaim(){
  const root=document.getElementById("couponClaimRoot");
  if(!root)return;
  const disc=(c)=>c.type==="percent"?`${c.value}% 할인`:`${Number(c.value||0).toLocaleString("ko-KR")}원 할인`;
  try{
    const d=await (await fetch("/api/coupons/claimable")).json();
    let mine=[];
    if(ME.authenticated){
      try{ mine=(await (await fetch("/api/coupons/wallet")).json()).coupons||[]; }catch(err){}
    }
    const list=d.coupons||[];
    if(!list.length && !mine.length){root.innerHTML=`<p class="empty">이런. 현재 등록된 쿠폰이 없어요..</p>`;return;}
    const mineHtml=mine.length?`<section style="margin-bottom:1.2rem"><p class="kicker">내 쿠폰</p>${mine.map(c=>`<article class="glass" style="border-radius:22px;padding:1.25rem;margin-top:.7rem"><h2 class="display" style="margin:0;font-size:1.25rem;color:var(--gold-soft)">${esc(c.name||"쿠폰")}</h2><p style="margin:.4rem 0 0;color:var(--mint)">${disc(c)}</p><p class="display" style="margin:.55rem 0 0;letter-spacing:.08em;font-size:1.35rem">${esc(c.code||"")}</p><p style="margin:.35rem 0 0;font-size:.85rem;color:var(--muted)">장바구니와 결제에서 적용할 수 있어요.</p></article>`).join("")}</section>`:"";
    const claimHtml=list.map(c=>{
      const left=Number(c.remaining||0);
      const soldOut=left<=0;
      let btn="";
      if(!ME.authenticated) btn=`<a class="gold-btn pill" href="/login" style="margin-top:1rem;display:inline-flex">로그인 후 다운로드</a>`;
      else if(c.claimed||c.downloaded) btn=`<span class="ghost-btn pill" style="margin-top:1rem;opacity:.7">다운로드 완료</span>`;
      else if(soldOut) btn=`<span class="ghost-btn pill" style="margin-top:1rem;opacity:.55">마감</span>`;
      else btn=`<button type="button" class="gold-btn pill claim-btn" data-id="${c.id}" style="margin-top:1rem">쿠폰 다운로드</button>`;
      return `<article class="glass" style="border-radius:22px;padding:1.25rem;margin-bottom:.85rem"><div style="display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;align-items:flex-start"><div><p class="kicker" style="margin:0">쿠폰</p><h2 class="display" style="margin:.35rem 0 0;font-size:1.25rem;color:var(--gold-soft)">${esc(c.name||"쿠폰")}</h2><p style="margin:.45rem 0 0;color:var(--mint)">${disc(c)}</p><p style="margin:.35rem 0 0;font-size:.85rem;color:var(--muted)">남은 수량 <b style="color:var(--gold-soft)">${left}</b> / ${c.max||0}</p></div>${btn}</div><p class="claim-msg" data-id="${c.id}" style="margin:.65rem 0 0;font-size:.85rem;min-height:1.2em"></p></article>`;
    }).join("");
    root.innerHTML=mineHtml+(claimHtml?`<section><p class="kicker">받을 수 있는 쿠폰</p>${claimHtml}</section>`:"");
    root.querySelectorAll(".claim-btn").forEach(b=>b.onclick=async()=>{
      const id=Number(b.dataset.id);
      const msg=root.querySelector(`.claim-msg[data-id="${id}"]`);
      b.disabled=true; b.textContent="받는 중…";
      const r=await fetch("/api/coupons/claim",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id})});
      const dd=await r.json().catch(()=>({}));
      if(r.status===401){location.href="/login";return;}
      if(!r.ok){if(msg){msg.style.color="var(--danger)";msg.textContent=dd.error||"다운로드 실패";} b.disabled=false;b.textContent="쿠폰 다운로드";return;}
      if(msg){msg.style.color="var(--ok)";msg.textContent=`다운로드 완료${dd.code?` · 코드 ${dd.code}`:""}`;}
      setTimeout(()=>void renderCouponClaim(), 700);
    });
  }catch(e){
    root.innerHTML=`<p style="color:var(--danger)">목록을 불러오지 못했습니다.</p>`;
  }
}


function starText(n){ return "★★★★★".slice(0,n)+"☆☆☆☆☆".slice(n); }
function bindReviewButtons(){
  document.querySelectorAll(".rev-open").forEach(btn=>{
    btn.onclick=()=>openReviewModal(Number(btn.dataset.pid));
  });
}
async function openReviewModal(pid){
  const products=(STORE&&STORE.products)||PRODUCTS||[];
  const p=products.find(x=>Number(x.id)===Number(pid));
  if(!p) return;
  const old=document.getElementById("revModalBg"); if(old) old.remove();
  const bg=document.createElement("div");
  bg.id="revModalBg"; bg.className="rev-modal-bg";
  bg.innerHTML=`<section class="glass rev-modal"><div class="row" style="justify-content:space-between;align-items:center"><div><p class="kicker">REVIEW</p><h2 class="display" style="margin:.2rem 0 0;font-size:1.35rem">${esc(p.name||"상품")}</h2></div><button type="button" class="ghost-btn pill" id="revClose">닫기</button></div><div id="revBody"><div class="center-page" style="min-height:6rem"><div class="spinner"></div></div></div></section>`;
  bg.onclick=(e)=>{ if(e.target===bg) bg.remove(); };
  document.body.appendChild(bg);
  document.getElementById("revClose").onclick=()=>bg.remove();
  const paint=async()=>{
    const d=await (await fetch("/api/reviews?product_id="+pid)).json();
    const list=d.reviews||[];
    const mine=d.myReview;
    const can=!!d.canWrite;
    const stats=d.stats||{};
    const body=document.getElementById("revBody"); if(!body) return;
    const items=list.map(r=>`<article class="rev-item"><div class="row" style="justify-content:space-between"><strong>${esc(r.username||"유저")}</strong><span class="rev-stars">${starText(Number(r.rating)||5)}</span></div><p style="margin:.4rem 0 0;white-space:pre-wrap">${esc(r.body||"")}</p><p class="who">${r.created_at?new Date(r.created_at).toLocaleString("ko-KR"):""}</p></article>`).join("")||`<p class="empty">아직 리뷰가 없습니다. 구매한 분이 첫 리뷰를 남겨 주세요.</p>`;
    let form="";
    if(!ME.authenticated) form=`<p style="color:var(--muted);margin-top:1rem">로그인하면 구매한 상품에 리뷰를 쓸 수 있어요. <a class="mint" href="/login">로그인</a></p>`;
    else if(!can) form=`<p style="color:var(--muted);margin-top:1rem">이 상품을 구매하고 입금이 확인된 분만 리뷰를 쓸 수 있어요.</p>`;
    else form=`<form class="rev-form" id="revForm"><p style="margin:0;color:var(--muted);font-size:.85rem">${mine?"내 리뷰를 수정합니다.":"구매자 리뷰"}</p><div class="rev-rate" id="revRate">${[1,2,3,4,5].map(n=>`<button type="button" data-n="${n}" class="${n<=(mine&&mine.rating||5)?"on":""}">★</button>`).join("")}</div><textarea class="field" id="revText" rows="3" maxlength="800" placeholder="상품은 어땠나요?" required>${mine?esc(mine.body||""):""}</textarea><button class="gold-btn pill" type="submit">리뷰 ${mine?"수정":"남기기"}</button><p id="revMsg" style="margin:0;font-size:.82rem;color:var(--muted)"></p></form>`;
    body.innerHTML=`<p style="color:var(--muted);margin:.8rem 0 0">${stats.count?`평균 ★ ${(stats.avg||0).toFixed(1)} · ${stats.count}개`:""}</p><div class="rev-list">${items}</div>${form}`;
    let rate=Number(mine&&mine.rating)||5;
    const rateBox=document.getElementById("revRate");
    if(rateBox){
      const paintStars=()=>rateBox.querySelectorAll("button").forEach(b=>b.classList.toggle("on", Number(b.dataset.n)<=rate));
      rateBox.querySelectorAll("button").forEach(b=>b.onclick=()=>{rate=Number(b.dataset.n);paintStars();});
    }
    const formEl=document.getElementById("revForm");
    if(formEl) formEl.onsubmit=async(e)=>{
      e.preventDefault();
      const r=await fetch("/api/reviews",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({product_id:pid,rating:rate,body:document.getElementById("revText").value})});
      const j=await r.json().catch(()=>({}));
      const msg=document.getElementById("revMsg");
      if(!r.ok){ if(msg){msg.style.color="var(--danger)";msg.textContent=j.error||"실패";} return; }
      await paint();
    };
  };
  await paint();
}
async function renderCommunity(){
  const root=document.getElementById("communityRoot");
  if(!root) return;
  const who=(x)=>`<strong>${esc(x.username||"유저")}</strong>`;
  const paint=async()=>{
    const d=await (await fetch("/api/community")).json();
    const posts=d.posts||[];
    const compose=ME.authenticated
      ? `<form class="glass com-compose" id="comForm" style="padding:1.1rem;border-radius:22px"><input class="field" id="comTitle" maxlength="80" placeholder="제목" required /><textarea class="field" id="comBody" rows="4" maxlength="2000" placeholder="무슨 이야기를 할까요?" required></textarea><button class="gold-btn pill" type="submit">글 올리기</button><p id="comMsg" style="margin:0;font-size:.82rem;color:var(--muted)"></p></form>`
      : `<p style="color:var(--muted)">로그인하면 글을 쓸 수 있어요. <a class="mint" href="/login">로그인</a></p>`;
    const cmtHtml=(c, depth)=>`<div class="com-cmt"><div class="com-meta">${who(c)}<span>${c.created_at?new Date(c.created_at).toLocaleString("ko-KR"):""}</span></div><p style="margin:.35rem 0 0;white-space:pre-wrap">${esc(c.body||"")}</p>${ME.authenticated&&depth<1?`<button type="button" class="ghost-btn pill com-reply-btn" data-id="${c.id}" style="margin-top:.4rem;font-size:.78rem">답글</button><form class="com-reply-form" data-parent="${c.id}" hidden><input class="field" placeholder="대댓글" required style="flex:1"/><button class="gold-btn pill" type="submit">달기</button></form>`:""}${(c.replies||[]).length?`<div class="replies">${c.replies.map(r=>cmtHtml(r, depth+1)).join("")}</div>`:""}</div>`;
    root.innerHTML=`${compose}<div class="com-feed">${posts.length?posts.map(p=>`<article class="glass com-post"><div class="com-meta">${who(p)}<span>${p.created_at?new Date(p.created_at).toLocaleString("ko-KR"):""}</span></div><h2 class="display" style="margin:.45rem 0 .35rem;font-size:1.2rem">${esc(p.title||"")}</h2><p style="white-space:pre-wrap;margin:0">${esc(p.body||"")}</p><div class="row" style="margin-top:.75rem"><button type="button" class="com-heart${p.liked?" on":""}" data-id="${p.id}">♥ ${p.likes||0}</button><span style="color:var(--muted);font-size:.8rem">댓글 ${p.comment_count||0}</span></div><div class="com-comments">${(p.comments||[]).map(c=>cmtHtml(c,0)).join("")||`<p class="empty" style="margin:0">첫 댓글을 남겨 보세요.</p>`}</div>${ME.authenticated?`<form class="com-reply-form" data-post="${p.id}" style="margin-top:.55rem"><input class="field" placeholder="댓글 쓰기" required style="flex:1"/><button class="gold-btn pill" type="submit">댓글</button></form>`:""}</article>`).join(""):`<p class="empty">아직 글이 없습니다.</p>`}</div>`;
    const form=document.getElementById("comForm");
    if(form) form.onsubmit=async(e)=>{
      e.preventDefault();
      const r=await fetch("/api/community",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({title:document.getElementById("comTitle").value,body:document.getElementById("comBody").value})});
      const j=await r.json().catch(()=>({}));
      const msg=document.getElementById("comMsg");
      if(!r.ok){ if(msg){msg.style.color="var(--danger)";msg.textContent=j.error||"실패";} return; }
      await paint();
    };
    root.querySelectorAll(".com-heart").forEach(b=>b.onclick=async()=>{
      if(!ME.authenticated){ location.href="/login"; return; }
      await fetch("/api/community/like",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({post_id:Number(b.dataset.id)})});
      await paint();
    });
    root.querySelectorAll(".com-reply-btn").forEach(b=>b.onclick=()=>{
      const form=root.querySelector(`form.com-reply-form[data-parent="${b.dataset.id}"]`);
      if(form) form.hidden=!form.hidden;
    });
    root.querySelectorAll("form.com-reply-form").forEach(f=>f.onsubmit=async(e)=>{
      e.preventDefault();
      const input=f.querySelector("input");
      const postId=Number(f.dataset.post||f.closest(".com-post")?.querySelector(".com-heart")?.dataset.id);
      await fetch("/api/community/comment",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({post_id:postId,parent_id:Number(f.dataset.parent||0)||null,body:input.value})});
      await paint();
    });
  };
  await paint();
}
async function renderFriends(){
  const root=document.getElementById("friendsRoot");
  if(!root) return;
  if(!ME.authenticated){root.innerHTML=`<p style="color:var(--muted)">로그인 후 이용할 수 있습니다.</p><a class="gold-btn pill" href="/login">로그인</a>`;return;}
  const paint=async()=>{
    const d=await (await fetch("/api/friends")).json();
    const friends=d.friends||[], pendingIn=d.incoming||[], pendingOut=d.outgoing||[];
    const chatWith=new URLSearchParams(location.search).get("with")||"";
    let chatHtml="";
    if(chatWith){
      const msgs=(await (await fetch("/api/chat?with="+encodeURIComponent(chatWith))).json()).messages||[];
      const peer=friends.find(f=>f.discord_id===chatWith)||{username:chatWith};
      chatHtml=`<section class="glass" style="border-radius:22px;padding:1rem;margin-top:1rem;display:flex;flex-direction:column;min-height:22rem"><div style="display:flex;justify-content:space-between;align-items:center"><strong style="color:var(--gold-soft)">${peer.username||chatWith}</strong><a class="ghost-btn pill" href="/friends" style="font-size:.8rem">목록</a></div><div id="chatMsgs" style="flex:1;overflow:auto;margin:.75rem 0;display:flex;flex-direction:column;gap:.45rem">${msgs.map(m=>{const mine=m.from_id===ME.discordId;return `<div style="align-self:${mine?"flex-end":"flex-start"};max-width:80%;padding:.55rem .75rem;border-radius:14px;background:${mine?"rgba(212,175,106,.2)":"rgba(255,255,255,.06)"};font-size:.9rem">${m.body}<div style="font-size:.7rem;color:var(--muted);margin-top:.2rem">${new Date(m.created_at).toLocaleString("ko-KR")}</div></div>`;}).join("")||`<p style="color:var(--muted);font-size:.85rem">대화를 시작해 보세요.</p>`}</div><form id="chatForm" style="display:flex;gap:.5rem"><input class="field" id="chatBody" placeholder="메시지 입력" required style="flex:1"/><button class="gold-btn pill" type="submit">전송</button></form></section>`;
    }
    root.innerHTML=`
      <div class="glass" style="border-radius:22px;padding:1.1rem">
        <form id="friendAdd" style="display:flex;gap:.5rem;flex-wrap:wrap">
          <input class="field" id="friendName" placeholder="디스코드 닉네임" required style="flex:1;min-width:12rem"/>
          <button class="gold-btn pill" type="submit">친구 추가</button>
        </form>
        <p id="friendMsg" style="margin:.5rem 0 0;font-size:.85rem;color:var(--muted)"></p>
      </div>
      ${pendingIn.length?`<section style="margin-top:1.25rem"><p class="kicker">받은 요청</p>${pendingIn.map(f=>`<div class="glass" style="border-radius:16px;padding:.85rem;margin-top:.5rem;display:flex;justify-content:space-between;gap:.5rem;flex-wrap:wrap;align-items:center"><span>${f.username||f.from_id}</span><span><button type="button" class="gold-btn pill fr-accept" data-id="${f.id}">수락</button> <button type="button" class="ghost-btn pill fr-reject" data-id="${f.id}">거절</button></span></div>`).join("")}</section>`:""}
      ${pendingOut.length?`<section style="margin-top:1.25rem"><p class="kicker">보낸 요청</p>${pendingOut.map(f=>`<div class="glass" style="border-radius:16px;padding:.85rem;margin-top:.5rem;color:var(--muted)">${f.username||f.to_id} · 대기중</div>`).join("")}</section>`:""}
      <section style="margin-top:1.25rem"><p class="kicker">친구 목록</p>
        ${friends.length?friends.map(f=>`<div class="glass" style="border-radius:16px;padding:.85rem;margin-top:.5rem;display:flex;justify-content:space-between;gap:.5rem;flex-wrap:wrap;align-items:center"><div><strong>${f.username||f.discord_id}</strong>${f.minecraft_name?`<div style="font-size:.8rem;color:var(--mint)">${f.minecraft_name}</div>`:""}</div><a class="ghost-btn pill" href="/friends?with=${encodeURIComponent(f.discord_id)}">채팅</a></div>`).join(""):`<p style="color:var(--muted)">아직 친구가 없습니다.</p>`}
      </section>${chatHtml}`;
    document.getElementById("friendAdd").onsubmit=async(e)=>{
      e.preventDefault();
      const name=document.getElementById("friendName").value.trim();
      const r=await fetch("/api/friends/request",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({username:name})});
      const j=await r.json().catch(()=>({}));
      const msg=document.getElementById("friendMsg");
      if(!r.ok){msg.style.color="var(--danger)";msg.textContent=j.error||"실패";return;}
      msg.style.color="var(--ok)";msg.textContent="친구 요청을 보냈습니다.";
      paint();
    };
    root.querySelectorAll(".fr-accept").forEach(b=>b.onclick=async()=>{await fetch("/api/friends/respond",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:Number(b.dataset.id),accept:true})});paint();});
    root.querySelectorAll(".fr-reject").forEach(b=>b.onclick=async()=>{await fetch("/api/friends/respond",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:Number(b.dataset.id),accept:false})});paint();});
    const form=document.getElementById("chatForm");
    if(form){
      form.onsubmit=async(e)=>{
        e.preventDefault();
        const body=document.getElementById("chatBody").value.trim();
        if(!body)return;
        const r=await fetch("/api/chat",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({to:chatWith,body})});
        const j=await r.json().catch(()=>({}));
        if(!r.ok){alert(j.error||"전송 실패");return;}
        document.getElementById("chatBody").value="";
        paint();
      };
      const box=document.getElementById("chatMsgs");
      if(box) box.scrollTop=box.scrollHeight;
    }
  };
  await paint();
  if(new URLSearchParams(location.search).get("with")) setInterval(()=>void paint(), 8000);
}
async function renderSupport(){
  const root=document.getElementById("supportRoot");
  if(!root) return;
  if(!ME.authenticated){root.innerHTML=`<p style="color:var(--muted)">로그인 후 문의할 수 있습니다.</p><a class="gold-btn pill" href="/login">로그인</a>`;return;}
  let pendingImgs=[];
  const imgHtml=(arr)=>((arr||[]).map(u=>`<a href="${u}" target="_blank" rel="noopener"><img src="${u}" alt="" style="max-width:12rem;max-height:10rem;border-radius:12px;border:1px solid var(--line);margin-top:.35rem;display:block;object-fit:cover"></a>`).join(""));
  const bubble=(who,body,imgs,at)=>{
    const mine=who==="user"||who==="me";
    return `<div style="align-self:${mine?"flex-end":"flex-start"};max-width:88%;padding:.65rem .8rem;border-radius:16px;background:${mine?"rgba(212,175,106,.18)":"rgba(125,206,160,.1)"};font-size:.9rem"><div style="font-size:.72rem;color:var(--muted);margin-bottom:.2rem">${mine?"나":"관리자"}</div><div style="white-space:pre-wrap">${body||""}</div>${imgHtml(imgs)}<div style="font-size:.68rem;color:var(--muted);margin-top:.25rem">${at?new Date(at).toLocaleString("ko-KR"):""}</div></div>`;
  };
  const readFiles=async(files)=>{
    const out=[];
    for(const file of [...files].slice(0,4)){
      if(!file.type.startsWith("image/")) continue;
      if(file.size>10*1024*1024){alert("사진은 10MB 이하로 올려 주세요.");continue;}
      try{
        const bmp=await createImageBitmap(file);
        const max=1400; let w=bmp.width,h=bmp.height;
        if(w>max||h>max){const s=Math.min(max/w,max/h);w=Math.round(w*s);h=Math.round(h*s);}
        const c=document.createElement("canvas"); c.width=w;c.height=h; c.getContext("2d").drawImage(bmp,0,0,w,h); bmp.close();
        out.push(c.toDataURL("image/jpeg",0.82));
      }catch(e){
        out.push(await new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(r.result);r.onerror=rej;r.readAsDataURL(file);}));
      }
    }
    return out;
  };
  const paint=async()=>{
    const d=await (await fetch("/api/support")).json();
    const items=d.items||[];
    const openId=Number(new URLSearchParams(location.search).get("id")||0);
    const active=items.find(it=>Number(it.id)===openId)||items[0]||null;
    if(!active){
      root.innerHTML=`
        <form id="supportForm" class="glass" style="border-radius:22px;padding:1.1rem;display:flex;flex-direction:column;gap:.55rem">
          <input class="field" id="supSubject" placeholder="제목 (선택)" />
          <textarea class="field" id="supBody" placeholder="문의 내용 · 사진도 첨부 가능" style="min-height:6rem"></textarea>
          <div class="row" style="gap:.5rem;flex-wrap:wrap;align-items:center">
            <label class="ghost-btn pill" style="cursor:pointer">사진 첨부<input type="file" id="supFiles" accept="image/*" multiple hidden/></label>
            <span id="supPrev" style="font-size:.8rem;color:var(--muted)"></span>
          </div>
          <button class="gold-btn" type="submit" style="border-radius:1rem;padding:.85rem">문의 시작</button>
          <p id="supMsg" style="font-size:.85rem;color:var(--muted);margin:0"></p>
        </form>`;
      pendingImgs=[];
      document.getElementById("supFiles").onchange=async(e)=>{pendingImgs=await readFiles(e.target.files||[]);document.getElementById("supPrev").textContent=pendingImgs.length?`사진 ${pendingImgs.length}장 선택됨`:"";};
      document.getElementById("supportForm").onsubmit=async(e)=>{
        e.preventDefault();
        const subject=document.getElementById("supSubject").value.trim()||"문의";
        const body=document.getElementById("supBody").value.trim();
        const r=await fetch("/api/support",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({subject,body,images:pendingImgs})});
        const j=await r.json().catch(()=>({}));
        const msg=document.getElementById("supMsg");
        if(!r.ok){msg.style.color="var(--danger)";msg.textContent=j.error||"실패";return;}
        location.href="/support?id="+(j.item&&j.item.id||"");
      };
      return;
    }
    const opener=active.started_by==="admin"?[]:[bubble("user",active.body,active.images,active.created_at)];
    const thread=[...opener,...(active.replies||[]).map(r=>bubble(r.from==="admin"?"admin":"user",r.body,r.images,r.at))].join("");
    root.innerHTML=`
      <div style="display:flex;justify-content:space-between;align-items:center;gap:.5rem;flex-wrap:wrap;margin-bottom:.75rem">
        <div><strong style="color:var(--gold-soft)">${active.subject||"문의"}</strong><div style="font-size:.75rem;color:var(--muted)">${active.status||""}</div></div>
        <a class="ghost-btn pill" href="/support" style="font-size:.8rem">새 문의</a>
      </div>
      <section class="glass" style="border-radius:22px;padding:1rem;display:flex;flex-direction:column;min-height:24rem">
        <div id="supThread" style="flex:1;overflow:auto;display:flex;flex-direction:column;gap:.55rem">${thread}</div>
        <form id="supReply" style="display:flex;flex-direction:column;gap:.45rem;margin-top:.75rem;border-top:1px solid var(--line);padding-top:.75rem">
          <textarea class="field" id="supBody" placeholder="메시지 입력" style="min-height:3.2rem"></textarea>
          <div class="row" style="gap:.5rem;flex-wrap:wrap;align-items:center">
            <label class="ghost-btn pill" style="cursor:pointer">사진<input type="file" id="supFiles" accept="image/*" multiple hidden/></label>
            <span id="supPrev" style="font-size:.8rem;color:var(--muted);flex:1"></span>
            <button class="gold-btn pill" type="submit">전송</button>
          </div>
          <p id="supMsg" style="font-size:.85rem;color:var(--muted);margin:0"></p>
        </form>
      </section>
      ${items.length>1?`<section style="margin-top:1rem"><p class="kicker">다른 문의</p>${items.filter(it=>it.id!==active.id).map(it=>`<a href="/support?id=${it.id}" class="glass" style="display:block;border-radius:14px;padding:.75rem;margin-top:.45rem;text-decoration:none;color:inherit"><strong>${it.subject||"문의"}</strong><span style="float:right;font-size:.75rem;color:var(--muted)">${it.status||""}</span></a>`).join("")}</section>`:""}`;
    pendingImgs=[];
    const box=document.getElementById("supThread"); if(box) box.scrollTop=box.scrollHeight;
    document.getElementById("supFiles").onchange=async(e)=>{pendingImgs=await readFiles(e.target.files||[]);document.getElementById("supPrev").textContent=pendingImgs.length?`사진 ${pendingImgs.length}장`:"";};
    document.getElementById("supReply").onsubmit=async(e)=>{
      e.preventDefault();
      const body=document.getElementById("supBody").value.trim();
      const r=await fetch("/api/support/reply",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:active.id,body,images:pendingImgs})});
      const j=await r.json().catch(()=>({}));
      const msg=document.getElementById("supMsg");
      if(!r.ok){msg.style.color="var(--danger)";msg.textContent=j.error||"실패";return;}
      pendingImgs=[]; paint();
    };
  };
  await paint();
  setInterval(()=>{ if(document.getElementById("supThread")) void paint(); }, 12000);
}


boot();

</script>
</body>
</html>
"""

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

# 도전과제 카탈로그 (id 고정 — 프론트/해금 트리거와 공유)
ACHIEVEMENTS: list[dict] = [
    {"id": "welcome", "title": "첫 발걸음", "desc": "디스코드로 로그인하기", "icon": "🚪", "category": "기본", "secret": False},
    {"id": "link_mc", "title": "연결 완료", "desc": "마인크래프트 계정 연동하기", "icon": "🔗", "category": "기본", "secret": False},
    {"id": "code_issue", "title": "초대 준비", "desc": "마크 연동 코드를 사이트에 입력하기", "icon": "🎫", "category": "기본", "secret": False},
    {"id": "first_order", "title": "첫 주문", "desc": "상점에서 첫 결제 주문 만들기", "icon": "🛒", "category": "상점", "secret": False},
    {"id": "first_payment", "title": "첫 결제", "desc": "첫 주문이 입금 확인 또는 지급 완료되기", "icon": "💎", "category": "상점", "secret": False},
    {"id": "nick_change", "title": "새로운 이름", "desc": "닉네임 변경 요청하기", "icon": "✏️", "category": "프로필", "secret": False},
    {"id": "ultra_buyer", "title": "울트라 팬", "desc": "울트라 랭크 상품 지급 완료", "icon": "⭐", "category": "상점", "secret": False},
    {"id": "theme_first", "title": "계절의 첫걸음", "desc": "시즌 테마가 켜진 사이트를 처음 방문하기", "icon": "🌤", "category": "시즌", "secret": False},
    {"id": "theme_christmas", "title": "성탄의 숲", "desc": "크리스마스 테마를 경험하기", "icon": "🎄", "category": "시즌", "secret": False},
    {"id": "theme_newyear", "title": "새해의 불꽃", "desc": "새해 테마를 경험하기", "icon": "✨", "category": "시즌", "secret": False},
    {"id": "theme_valentine", "title": "달콤한 하루", "desc": "발렌타인 테마를 경험하기", "icon": "♡", "category": "시즌", "secret": False},
    {"id": "theme_childrens", "title": "동심의 하늘", "desc": "어린이날 테마를 경험하기", "icon": "🎈", "category": "시즌", "secret": False},
    {"id": "theme_chuseok", "title": "보름달 아래", "desc": "추석 테마를 경험하기", "icon": "🌕", "category": "시즌", "secret": False},
    {"id": "theme_halloween", "title": "호박 밤", "desc": "할로윈 테마를 경험하기", "icon": "🎃", "category": "시즌", "secret": False},
    {"id": "theme_collector", "title": "사계절 수집가", "desc": "모든 시즌 테마 도전과제를 모으기", "icon": "🏆", "category": "시즌", "secret": True},
    {"id": "dev_birthday", "title": "개발자 생일날 접속", "desc": "8월 28일, 개발자 생일날 사이트에 접속하기", "icon": "🎂", "category": "시즌", "secret": False},
    {"id": "egg_brand", "title": "로고 수집가", "desc": "브랜드 로고를 여러 번 두드렸다", "icon": "🥚", "category": "이스터에그", "secret": True},
    {"id": "egg_konami", "title": "고전 게이머", "desc": "숨겨진 키 시퀀스를 입력했다", "icon": "🎮", "category": "이스터에그", "secret": True},
    {"id": "egg_wild", "title": "야생의 발견", "desc": "비밀 경로 /wild 에 도착했다", "icon": "🌿", "category": "이스터에그", "secret": True},
    {"id": "egg_offline", "title": "오프라인 탐험가", "desc": "Offline 상태 표시를 오래 지켜봤다", "icon": "🌑", "category": "이스터에그", "secret": True},
    {"id": "egg_footer", "title": "연도 고고학자", "desc": "푸터의 연도를 발견했다", "icon": "📜", "category": "이스터에그", "secret": True},
    {"id": "all_collector", "title": "모든 도전과제 수집", "desc": "사이트에 있는 모든 도전과제를 해금하기", "icon": "🏅", "category": "기본", "secret": True},
]
EGG_IDS = {a["id"] for a in ACHIEVEMENTS if a.get("secret") and str(a["id"]).startswith("egg_")}
ACH_BY_ID = {a["id"]: a for a in ACHIEVEMENTS}
ALL_COLLECTOR_ID = "all_collector"
ALL_COLLECTOR_REQUIRED = tuple(a["id"] for a in ACHIEVEMENTS if a["id"] != ALL_COLLECTOR_ID)
THEME_ACH_BY_THEME = {
    "christmas": "theme_christmas",
    "newyear": "theme_newyear",
    "valentine": "theme_valentine",
    "childrens": "theme_childrens",
    "chuseok": "theme_chuseok",
    "halloween": "theme_halloween",
}
THEME_SEASON_ACH_IDS = tuple(THEME_ACH_BY_THEME.values())


def try_unlock_theme_visit(discord_id: str, theme_id: str) -> list[dict]:
    """시즌 테마 방문 시 관련 도전과제 해금. lock 안에서 호출."""
    out: list[dict] = []
    ach_id = THEME_ACH_BY_THEME.get(str(theme_id or "").strip())
    if not discord_id or not ach_id:
        return out
    for aid in (ach_id, "theme_first"):
        unlocked = unlock_achievement(discord_id, aid)
        if unlocked:
            out.append(unlocked)
    bag = db.get("user_achievements", {}).get(discord_id) or {}
    if all(x in bag for x in THEME_SEASON_ACH_IDS):
        unlocked = unlock_achievement(discord_id, "theme_collector")
        if unlocked:
            out.append(unlocked)
    return out


def seoul_date() -> str:
    return datetime.now(timezone(timedelta(hours=9))).strftime("%Y-%m-%d")


def default_db() -> dict:
    now = int(datetime.now(timezone.utc).timestamp() * 1000)
    return {
        "sessions": {},
        "auth_codes": [],
        "verificationCodes": [],
        "nick_vouchers": [],
        "command_queue": [],
        "player_cache": {},
        "inbox": [],
        "products": [
            {"id": 1, "name": "스탠다드", "price": 3000, "description": "기본 랭크", "badge": "RANK", "currency": "KRW", "image_url": None, "category": "랭크", "rank_group": "스탠다드", "cash_amount": 0, "gem_amount": 0, "active": 1, "featured": 1, "sort_order": 0},
            {"id": 2, "name": "울트라", "price": 8000, "description": "고급 랭크", "badge": "HOT", "currency": "KRW", "image_url": None, "category": "랭크", "rank_group": "울트라", "cash_amount": 0, "gem_amount": 0, "active": 1, "featured": 0, "sort_order": 1},
            {"id": 3, "name": "캐시 100,000", "price": 10000, "description": "접속 시 캐시 10만 지급", "badge": "CASH", "currency": "KRW", "image_url": None, "category": "캐시", "rank_group": None, "cash_amount": 100000, "gem_amount": 0, "active": 1, "featured": 1, "sort_order": 10},
            {"id": 4, "name": "젬 1,000", "price": 5000, "description": "접속 시 젬 1천 지급", "badge": "GEM", "currency": "KRW", "image_url": None, "category": "젬", "rank_group": None, "cash_amount": 0, "gem_amount": 1000, "voucher_count": 0, "active": 1, "featured": 0, "sort_order": 11},
            {"id": 5, "name": "MVP", "price": 15000, "description": "MVP 랭크 · 닉네임 변경 가능", "badge": "MVP", "currency": "KRW", "image_url": None, "category": "랭크", "rank_group": "MVP", "cash_amount": 0, "gem_amount": 0, "voucher_count": 0, "active": 1, "featured": 1, "sort_order": 2},
            {"id": 6, "name": "닉네임 변경권", "price": 3000, "description": "구매 후 패널에서 코드 없이 바로 사용합니다. 인게임 nick 명령으로 변경됩니다.", "badge": "NICK", "currency": "KRW", "image_url": None, "category": "아이템", "rank_group": None, "cash_amount": 0, "gem_amount": 0, "voucher_count": 1, "active": 1, "featured": 1, "sort_order": 12},
        ],
        "banners": [
            {"id": 1, "title": "시즌 오픈", "subtitle": "디스코드 인증부터 랭크·닉네임 변경까지, 한곳에서 관리하세요.", "image_url": "", "link_url": "/login", "cta_label": "시작하기", "active": 1, "sort_order": 0},
        ],
        "notices": [
            {"id": 1, "title": "환영합니다", "body": "디스코드 인증 후 서버를 이용하세요.", "pinned": 1, "active": 1, "created_at": now},
        ],
        "orders": [],
        "users": [],
        "settings": {
            "site_name": "WILDMC",
            "site_suffix": "MC",
            "site_tagline": "MINECRAFT × DISCORD",
            "announcement": "환영합니다! 디스코드 인증 후 서버를 이용하세요.",
            "discord_invite": "",
            "theme_mode": "auto",
            "theme_id": "default",
            "stats_kicker": "LIVE STATUS",
            "stats_title": "서버 현황",
            "shop_kicker": "SHOP",
            "shop_title": "상품",
            "shop_nav": "상점",
            "shop_cta": "상점",
            "hero_link_cta": "마인크래프트 계정 연동",
            "footer_link_label": "도전과제",
            "nav_notice": "공지",
            "nav_coupon": "쿠폰받기",
            "nav_achievements": "도전과제",
            "nav_link": "마인크래프트 계정 연동",
            "nav_inbox": "우편함",
            "live_offline": "Minecraft Offline",
            "live_online": "Minecraft Online",
            "coupon_page_title": "쿠폰받기",
            "coupon_page_desc": "원하는 쿠폰을 다운로드하세요. 결제 시 자동 적용하거나 직접 고를 수 있습니다.",
            "site_font": "cute",
            "custom_min_won": "100",
            "cash_per_won": "10",
            "gem_won_each": "2",
            "bgm_enabled": "1",
            "bgm_url": "",
            "site_logo_url": "",
            "ui_font_scale": "100",
            "ui_block_scale": "100",
            "ui_radius_scale": "100",
            "discord_guild_id": "",
            "discord_role_owner": "",
            "discord_role_co_owner": "",
            "discord_role_admin": "",
            "discord_role_staff": "",
            "discord_role_ultra": "",
            "discord_role_mvp": "",
            "discord_role_standard": "",
        },
        "payment": {
            "enabled": "1",
            "bank_name": "국민은행",
            "bank_account": "000000-00-000000",
            "bank_holder": "예금주명",
            "toss_link": "",
            "payment_notice": "입금자명을 주문 시 입력한 이름과 동일하게 맞춰주세요. 입금 확인 후 상품이 지급됩니다.",
            "agencies": "[]",
        },
        "joins": [],
        "peakToday": {"date": "", "count": 0},
        "user_achievements": {},
        "coupons": [],
        "coupon_redemptions": [],
        "coupon_claims": [],
        "coupon_wallet": [],
        "friendships": [],
        "chat_messages": [],
        "inquiries": [],
        "activity_logs": [],
        "reviews": [],
        "community_posts": [],
        "community_comments": [],
    }


def safe_int(value, default: int = 0) -> int:
    try:
        if value is None or value is False or value == "":
            return default
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        s = str(value).strip()
        if not s:
            return default
        return int(float(s)) if any(ch in s for ch in ".eE") else int(s)
    except (TypeError, ValueError):
        return default


def _next_free_id(used: set[int]) -> int:
    n = 1
    while n in used:
        n += 1
    return n


def sanitize_db(data: dict) -> tuple[dict, bool]:
    """Fix non-numeric ids (e.g. product id 'standard') that crash public_products()."""
    changed = False
    for key in ("products", "banners", "notices", "orders", "coupons"):
        items = data.get(key)
        if not isinstance(items, list):
            continue
        used: set[int] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            raw = item.get("id")
            pid = None
            if isinstance(raw, bool) or raw is None or raw == "":
                pid = None
            else:
                try:
                    pid = int(raw)
                except (TypeError, ValueError):
                    pid = None
            if pid is None or pid <= 0 or pid in used:
                pid = _next_free_id(used)
                item["id"] = pid
                changed = True
            elif item.get("id") != pid:
                item["id"] = pid
                changed = True
            used.add(pid)
            if key == "products":
                for field, default in (("featured", 0), ("sort_order", 0), ("active", 1), ("price", 0)):
                    if field not in item:
                        continue
                    fixed = safe_int(item.get(field), default)
                    if item.get(field) != fixed:
                        item[field] = fixed
                        changed = True
            if key == "orders" and "product_id" in item:
                fixed = safe_int(item.get("product_id"), 0)
                if item.get("product_id") != fixed:
                    item["product_id"] = fixed
                    changed = True
    return data, changed


def load_db() -> dict:
    base = default_db()
    if not DB_FILE.exists():
        save_db(base)
        return base
    data = json.loads(DB_FILE.read_text(encoding="utf-8"))
    for k, v in base.items():
        data.setdefault(k, v)
    data, changed = sanitize_db(data)
    if changed:
        save_db(data)
    return data


def save_db(db: dict) -> None:
    DB_FILE.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")


db = load_db()


def now_ms() -> int:
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def parse_cookies(header: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if not header:
        return out
    for part in header.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k] = unquote(v)
    return out


def find_user(discord_id: str) -> dict | None:
    for u in db.get("users", []):
        if u.get("discord_id") == discord_id:
            return u
    return None


def upsert_user(discord_id: str, **fields) -> dict:
    user = find_user(discord_id)
    if not user:
        user = {"discord_id": discord_id}
        db.setdefault("users", []).append(user)
    existing_uuid = str(user.get("minecraft_uuid") or "").strip()
    incoming_uuid = str(fields.get("minecraft_uuid") or "").strip() if "minecraft_uuid" in fields else ""
    if existing_uuid and incoming_uuid and incoming_uuid != existing_uuid:
        fields.pop("minecraft_uuid", None)
        fields.pop("minecraft_name", None)
        fields.pop("linked_at", None)
    if existing_uuid:
        if "minecraft_uuid" in fields and not str(fields.get("minecraft_uuid") or "").strip():
            fields.pop("minecraft_uuid", None)
        if "minecraft_name" in fields and not str(fields.get("minecraft_name") or "").strip():
            fields.pop("minecraft_name", None)
        if "linked_at" in fields and not fields.get("linked_at"):
            fields.pop("linked_at", None)
    user.update(fields)
    return user


def clear_user_sessions(discord_id: str) -> int:
    """Remove web session cookies for this Discord account."""
    sessions = db.get("sessions") or {}
    drop = [tok for tok, s in sessions.items() if str((s or {}).get("discordId") or "") == str(discord_id)]
    for tok in drop:
        sessions.pop(tok, None)
    return len(drop)


def unlink_minecraft(discord_id: str) -> dict | None:
    user = find_user(discord_id)
    if not user:
        return None
    uuid = str(user.get("minecraft_uuid") or "").strip()
    user["minecraft_uuid"] = None
    user["minecraft_name"] = None
    user["luckperms_group"] = None
    user["linked_at"] = None
    if uuid:
        cache = db.get("player_cache") or {}
        if uuid in cache:
            cache[uuid]["online"] = 0
    return user


def delete_user_account(discord_id: str) -> dict:
    """Full membership removal used by admin desktop."""
    did = str(discord_id or "").strip()
    user = find_user(did)
    uuid = str((user or {}).get("minecraft_uuid") or "").strip()
    cleared_sessions = clear_user_sessions(did)
    before = len(db.get("users") or [])
    db["users"] = [u for u in db.get("users", []) if str(u.get("discord_id") or "") != did]
    removed_user = before - len(db.get("users") or [])
    bags = db.get("user_achievements") or {}
    bags.pop(did, None)
    db["inbox"] = [m for m in db.get("inbox", []) if str(m.get("discord_id") or "") != did]
    db["coupon_claims"] = [c for c in db.get("coupon_claims", []) if str(c.get("discord_id") or "") != did]
    # Keep orders for payment history, but detach identity
    for o in db.get("orders", []):
        if str(o.get("discord_id") or "") == did:
            o["discord_id"] = None
            note = str(o.get("admin_note") or "")
            tag = f"[탈퇴:{did}]"
            if tag not in note:
                o["admin_note"] = f"{note} {tag}".strip()
    if uuid:
        live_players.pop(uuid, None)
    return {
        "removedUser": removed_user > 0,
        "clearedSessions": cleared_sessions,
        "hadMinecraft": bool(uuid),
    }


def get_session_token(handler: BaseHTTPRequestHandler) -> str | None:
    return parse_cookies(handler.headers.get("Cookie")).get(COOKIE_NAME)


def get_session(handler: BaseHTTPRequestHandler) -> dict | None:
    token = get_session_token(handler)
    if not token:
        return None
    with lock:
        return db.get("sessions", {}).get(token)


def create_session(handler: BaseHTTPRequestHandler, discord_id: str, username: str, avatar: str | None = None) -> str:
    token = secrets.token_urlsafe(32)
    with lock:
        db.setdefault("sessions", {})[token] = {
            "discordId": discord_id,
            "username": username,
            "avatar": avatar,
            "createdAt": now_ms(),
        }
        save_db(db)
    handler._set_cookie(token)
    return token


def destroy_session(handler: BaseHTTPRequestHandler) -> None:
    token = get_session_token(handler)
    if token:
        with lock:
            db.get("sessions", {}).pop(token, None)
            save_db(db)
    handler._clear_cookie()


def discord_configured() -> bool:
    return bool(DISCORD_CLIENT_ID and DISCORD_CLIENT_SECRET)


def discord_http_json(url: str, method: str = "GET", data: dict | None = None, headers: dict | None = None):
    hdrs = dict(headers or {})
    # Discord/Cloudflare는 User-Agent 없는 urllib 요청을 403(1010)으로 막는 경우가 많음
    hdrs.setdefault(
        "User-Agent",
        f"WILDMC-Web/1.0 (+{APP_URL}; DiscordOAuth)",
    )
    hdrs.setdefault("Accept", "application/json")
    body = None
    if data is not None:
        body = urlencode(data).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = Request(url, data=body, headers=hdrs, method=method)
    try:
        with urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except HTTPError as e:
        detail = e.read().decode("utf-8", errors="ignore")
        print(f"[discord oauth] {method} {url} -> {e.code} {detail}", flush=True)
        return None, f"{e.code}:{detail[:200]}"
    except URLError as e:
        print(f"[discord oauth] {method} {url} -> {e}", flush=True)
        return None, str(e)




WIKI_ROOT = ROOT / "wiki"
WIKI_DATA = WIKI_ROOT / "data" / "site.json"
WIKI_UPLOADS = WIKI_ROOT / "uploads"
WIKI_STATIC = WIKI_ROOT / "static"
WIKI_TEMPLATE = WIKI_ROOT / "templates" / "index.html"
WIKI_DEFAULT = {
    "site": {
        "name": "wildmc",
        "title": "WILDMC",
        "sub": "서버에 오신 걸 환영해요!",
        "cta": "둘러보기",
        "ctaUrl": "#content",
        "img": "",
        "imgNight": "",
        "footer": "© 2026 wildmc.xyz",
    },
    "pages": [{"id": "guide", "title": "가이드", "icon": "🌿", "sub": "", "blocks": []}],
    "blocks": [
        {"type": "heading", "text": "최고의 힐링 서버, WILDMC"},
        {"type": "text", "text": "약탈 및 테러가 없는 반야생 힐링 서버, WILDMC서버에요. :3"},
    ],
}


def load_wiki() -> dict:
    WIKI_UPLOADS.mkdir(parents=True, exist_ok=True)
    (WIKI_ROOT / "data").mkdir(parents=True, exist_ok=True)
    try:
        if WIKI_DATA.is_file():
            return json.loads(WIKI_DATA.read_text(encoding="utf-8"))
    except Exception:
        pass
    return json.loads(json.dumps(WIKI_DEFAULT))


def save_wiki(data: dict) -> None:
    WIKI_DATA.parent.mkdir(parents=True, exist_ok=True)
    tmp = WIKI_DATA.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(WIKI_DATA)


def admin_discord_ids() -> set[str]:
    """Team. Wildmc 권한(사이트 편집)을 받은 Discord ID — .env 와 데스크톱 부여분을 합친다."""
    raw = ",".join(
        str(x) for x in (os.environ.get("ADMIN_DISCORD_IDS"), (db.get("settings") or {}).get("admin_discord_ids")) if x
    )
    return {x.strip() for x in raw.replace(";", ",").split(",") if x.strip()}


def is_web_admin(session: dict | None) -> bool:
    if not session or not session.get("discordId"):
        return False
    ids = admin_discord_ids()
    if not ids:
        return False
    return str(session["discordId"]) in ids


TEAM_WILDMC_GROUP = "Team. Wildmc"


def is_discord_authenticated(session: dict | None) -> bool:
    """진짜 디스코드 OAuth 로그인만 (로컬 계정 제외)."""
    if not session:
        return False
    did = str(session.get("discordId") or "").strip()
    return bool(did) and not did.startswith("local_")


def user_luckperms_group(discord_id: str | None) -> str | None:
    if not discord_id:
        return None
    user = find_user(str(discord_id))
    group = (user or {}).get("luckperms_group")
    mc_uuid = (user or {}).get("minecraft_uuid")
    if mc_uuid:
        cache = db.get("player_cache", {}).get(mc_uuid) or {}
        if cache.get("luckperms_group"):
            group = cache["luckperms_group"]
    g = str(group or "").strip()
    return g or None


def is_team_wildmc(session: dict | None) -> bool:
    """Discord 인증 + LuckPerms 그룹 Team. Wildmc."""
    if not is_discord_authenticated(session):
        return False
    group = user_luckperms_group(session.get("discordId"))
    if not group:
        return False
    return group.casefold() == TEAM_WILDMC_GROUP.casefold()


def site_edit_via(session: dict | None) -> str | None:
    """사이트 편집 권한 출처: 데스크톱에서 준 Team. Wildmc 권한("grant") 또는 게임 역할("team_role")."""
    if not is_discord_authenticated(session):
        return None
    if is_web_admin(session):
        return "grant"
    if is_team_wildmc(session):
        return "team_role"
    return None


def can_edit_site(session: dict | None) -> bool:
    """사이트 편집·위키·관리자 웹: 디스코드 로그인 + Team. Wildmc 권한 필수 (다른 랭크는 해당 없음)."""
    return site_edit_via(session) is not None


SITE_EDIT_SETTING_KEYS = frozenset(
    {
        "site_name",
        "site_suffix",
        "announcement",
        "site_tagline",
        "theme_mode",
        "theme_id",
        "stats_kicker",
        "stats_title",
        "live_offline",
        "live_online",
        "shop_kicker",
        "shop_title",
        "shop_nav",
        "shop_cta",
        "hero_link_cta",
        "footer_link_label",
        "nav_notice",
        "nav_coupon",
        "nav_achievements",
        "nav_link",
        "nav_inbox",
        "nav_friends",
        "nav_support",
        "coupon_page_title",
        "coupon_page_desc",
        "announce_source",
        "accent_color",
        "site_font",
        "hero_align",
        "hero_height",
        "hero_overlay",
        "show_stats",
        "show_shop",
        "stat_online_label",
        "stat_peak_label",
        "stat_today_label",
        "stat_week_label",
        "shop_all_label",
        "shop_page_desc",
        "require_login",
        "bgm_enabled",
        "bgm_url",
        "ui_font_scale",
        "ui_block_scale",
        "ui_radius_scale",
        "site_logo_url",
    }
)
SITE_EDIT_CHOICES = {
    "require_login": ("1", "0"),
    "bgm_enabled": ("1", "0"),
    "announce_source": ("notice", "custom", "off"),
    "site_font": ("cute", "round", "gowun", "jua", "gothic"),
    "hero_align": ("left", "center"),
    "hero_height": ("compact", "normal", "tall"),
    "show_stats": ("1", "0"),
    "show_shop": ("1", "0"),
    "theme_mode": ("auto", "manual", "off"),
}
SITE_BANNER_FIELDS = ("title", "subtitle", "cta_label", "link_url", "image_url")
SITE_BANNER_LIMITS = {"title": 80, "subtitle": 240, "cta_label": 30, "link_url": 300}
SITE_EDIT_HISTORY_MAX = 30
SITE_EDIT_LABELS = {
    "banner.title": "히어로 제목",
    "banner.subtitle": "히어로 부제",
    "banner.image_url": "히어로 이미지",
    "banner.cta_label": "버튼 문구",
    "banner.link_url": "버튼 링크",
    "theme_mode": "시즌 테마",
    "theme_id": "시즌 테마",
    "accent_color": "포인트 색",
    "site_font": "글꼴",
    "hero_align": "히어로 배치",
    "hero_height": "히어로 높이",
    "hero_overlay": "배경 어둡기",
    "show_stats": "현황 섹션",
    "show_shop": "상품 섹션",
    "announce_source": "상단 띠",
    "announcement": "상단 띠",
    "site_name": "로고",
    "site_suffix": "로고",
    "site_logo_url": "서버 로고 이미지",
    "require_login": "입장 로그인",
    "bgm_enabled": "배경음악",
    "bgm_url": "배경음악 주소",
    "ui_font_scale": "글자 크기",
    "ui_block_scale": "블록 여백",
    "ui_radius_scale": "모서리 둥글기",
}
PRIVATE_SETTING_KEYS = frozenset(
    {
        "admin_discord_ids",
        "site_edit_groups",
        "discord_guild_id",
        "discord_role_owner",
        "discord_role_co_owner",
        "discord_role_admin",
        "discord_role_staff",
        "discord_role_ultra",
        "discord_role_mvp",
        "discord_role_standard",
    }
)

DISCORD_RANK_ORDER = (
    ("Owner", "discord_role_owner"),
    ("Co-Owner", "discord_role_co_owner"),
    ("Admin", "discord_role_admin"),
    ("Staff", "discord_role_staff"),
    ("Ultra", "discord_role_ultra"),
    ("MVP", "discord_role_mvp"),
    ("StanDard", "discord_role_standard"),
)
CASH_PER_WON = 10  # 캐시 10 = 1원
GEM_WON_EACH = 2  # 후원잼 1개 = 2원
CUSTOM_MIN_WON_DEFAULT = 100


def custom_min_won() -> int:
    settings = db.get("settings") or {}
    n = safe_int(settings.get("custom_min_won"), CUSTOM_MIN_WON_DEFAULT)
    return max(100, n) if n else CUSTOM_MIN_WON_DEFAULT


def cash_per_won() -> int:
    settings = db.get("settings") or {}
    n = safe_int(settings.get("cash_per_won"), CASH_PER_WON)
    return n if n > 0 else CASH_PER_WON


def gem_won_each() -> int:
    settings = db.get("settings") or {}
    n = safe_int(settings.get("gem_won_each"), GEM_WON_EACH)
    return n if n > 0 else GEM_WON_EACH


def clean_site_setting(key: str, value) -> str | None:
    """꾸미기 값 검증. None 이면 키를 지워 기본값으로 되돌린다."""
    s = str(value if value is not None else "").strip()
    if key in SITE_EDIT_CHOICES:
        return s if s in SITE_EDIT_CHOICES[key] else None
    if key == "theme_id":
        s = s.lower()
        return s if s in THEME_CATALOG else "default"
    if key == "accent_color":
        return s.lower() if re.fullmatch(r"#[0-9a-fA-F]{6}", s) else None
    if key == "hero_overlay":
        try:
            return str(max(0, min(95, int(float(s)))))
        except ValueError:
            return None
    if key in ("ui_font_scale", "ui_block_scale"):
        try:
            return str(max(80, min(140, int(float(s)))))
        except ValueError:
            return "100"
    if key == "ui_radius_scale":
        try:
            return str(max(70, min(150, int(float(s)))))
        except ValueError:
            return "100"
    if key in ("bgm_url", "site_logo_url"):
        if not s:
            return None
        if not (s.startswith("http://") or s.startswith("https://") or s.startswith("/")):
            return None
        return s[:500]
    if key == "site_suffix":
        return s[:20]
    return s[:300] or None


def primary_banner() -> dict:
    for b in db.get("banners") or []:
        if isinstance(b, dict) and b.get("active", 1) != 0:
            return b
    return {}


def ensure_primary_banner() -> dict:
    target = primary_banner()
    if target:
        return target
    banners = db.setdefault("banners", [])
    target = {
        "id": next_id(banners),
        "title": "시즌 오픈",
        "subtitle": "",
        "image_url": "",
        "link_url": "/login",
        "cta_label": "시작하기",
        "active": 1,
        "sort_order": 0,
    }
    banners.append(target)
    return target


def site_edit_state() -> dict:
    settings = db.get("settings") or {}
    banner = primary_banner()
    return {
        "settings": {k: settings[k] for k in sorted(SITE_EDIT_SETTING_KEYS) if k in settings},
        "banner": {k: banner.get(k) or "" for k in SITE_BANNER_FIELDS},
    }


def record_site_edit(session: dict | None, label: str) -> None:
    hist = db.setdefault("site_edit_history", [])
    did = str((session or {}).get("discordId") or "")
    user = find_user(did) if did else None
    hist.append(
        {
            "id": next_id(hist),
            "at": now_ms(),
            "by": did,
            "by_name": str((user or {}).get("discord_username") or (session or {}).get("username") or did or "시스템"),
            "label": label[:160],
            **site_edit_state(),
        }
    )
    if len(hist) > SITE_EDIT_HISTORY_MAX:
        del hist[: len(hist) - SITE_EDIT_HISTORY_MAX]


def site_edit_history_public() -> list[dict]:
    items = []
    for i, h in enumerate(reversed(db.get("site_edit_history") or [])):
        snap = h.get("settings") or {}
        items.append(
            {
                "id": h.get("id"),
                "at": h.get("at"),
                "byName": h.get("by_name") or "",
                "label": h.get("label") or "",
                "title": (h.get("banner") or {}).get("title") or "",
                "themeMode": snap.get("theme_mode") or "auto",
                "themeId": snap.get("theme_id") or "default",
                "accent": snap.get("accent_color") or "",
                "current": i == 0,
            }
        )
    return items


def apply_site_edit(settings_in: dict, banner_in: dict) -> list[str]:
    """검증 후 적용하고 바뀐 키 목록을 돌려준다. 잘못된 이미지는 ValueError."""
    settings = db.setdefault("settings", {})
    changed: list[str] = []
    for k, v in (settings_in or {}).items():
        if k not in SITE_EDIT_SETTING_KEYS:
            continue
        cleaned = clean_site_setting(k, v)
        if cleaned is None:
            if k in settings:
                settings.pop(k, None)
                changed.append(k)
        elif k not in settings or str(settings.get(k)) != cleaned:
            settings[k] = cleaned
            changed.append(k)
    if banner_in:
        target = ensure_primary_banner()
        for k in SITE_BANNER_FIELDS:
            if k not in banner_in and not (k == "image_url" and "image_data" in banner_in):
                continue
            if k == "image_url":
                val = normalize_product_image_url(banner_in.get("image_data") or banner_in.get("image_url")) or ""
            else:
                val = str(banner_in.get(k) or "").strip()[: SITE_BANNER_LIMITS[k]]
                if k == "link_url" and val and not val.startswith(("/", "http://", "https://")):
                    val = "/" + val.lstrip("/")
            if str(target.get(k) or "") != val:
                target[k] = val
                changed.append("banner." + k)
        target["active"] = 1
    return changed


def describe_site_changes(changed: list[str]) -> str:
    if not changed:
        return "변경 없음"
    names: list[str] = []
    for k in changed:
        name = SITE_EDIT_LABELS.get(k) or ("메뉴 이름" if k.startswith("nav_") or k == "shop_nav" else "문구")
        if name not in names:
            names.append(name)
    extra = f" 외 {len(names) - 4}" if len(names) > 4 else ""
    return " · ".join(names[:4]) + extra


def site_edit_payload() -> dict:
    settings = db.get("settings") or {}
    return {
        "ok": True,
        "banner": {k: primary_banner().get(k) or "" for k in SITE_BANNER_FIELDS},
        "settings": {k: settings[k] for k in SITE_EDIT_SETTING_KEYS if k in settings},
        "theme": resolve_theme(settings),
        "history": site_edit_history_public(),
    }


# 웹 버전 — (대규모).(추가).(버그수정). 맨 위 항목이 현재 버전(WEB_VERSION)이 된다.
PATCH_NOTES: list[dict] = [
    {
        "version": "1.23.2",
        "date": "2026-10-19",
        "title": "주식 안정형 밸런스 패치 · 여유롭게",
        "added": [],
        "changed": [
            "주식 화면: 확대·축소 어떤 배율에서도 모든 기능이 숨김 없이 보이게 개선 (작은 화면에서는 한 화면 고정 대신 스크롤, 시장지수·랭킹·체결도 아래에 표시)",
            "수익 구조 강화: 위로 오르는 흐름을 키우고 기본 수수료를 0.5% → 0.2%로 낮춰 돈이 더 잘 오르게 조정",
            "주식 색상 변경: 상승은 파란색, 하락은 빨간색 (매수 파랑·매도 빨강)",
            "주식 화면 디자인 다듬기 (배경 그라데이션, 카드 그림자, 버튼 입체감)",
            "기본 변동폭 ±2.2% → ±0.9%, 한 틱 최대 등락 ±5% → ±1.5%",
            "하루 상·하한 추가: 전일 종가 대비 최대 +30% (+30만원)·-8% (-30만원)까지만 움직여요",
            "살짝 위로 기우는 흐름을 넣어서 너무 떨어지지 않고 소액은 벌기 쉽게 조정 (관리자가 직접 바꾼 가격은 예외)",
            "데스크탑 앱에서 가격을 올리거나 내리면 그 가격이 새 기준가가 되어 원래대로 복귀하지 않아요",
            "급등락(스파이크) 확률과 크기를 크게 줄임",
            "기준가로 되돌아오는 힘을 약하게 해서 한 방향으로 쭉 움직일 수 있게 조정",
            "가격 변동 범위를 기준가의 35%~320% → 50%~200%로 축소",
            "기준가가 자주 조금씩 움직이고 추세가 이어져서 한곳에 머물지 않고 계속 오르내려요 (과거 차트 생성도 안정형으로 맞춤)",
            "관리자 변동폭 설정 범위 0.3~4%로 조정 (기본 1.2%)",
        ],
        "removed": [],
    },
    {
        "version": "1.23.1",
        "date": "2026-10-18",
        "title": "주식 둥글고 심플하게 · 균형 패치",
        "added": [],
        "changed": [
            "주식 화면 전체를 둥글게 (카드·버튼·탭·입력칸·차트 라벨)",
            "크기와 간격을 알맞게 맞춰 더 심플하게",
            "차트 높이를 줄여 한 화면에 다 보이게 조정",
        ],
        "removed": [],
    },
    {
        "version": "1.23.0",
        "date": "2026-10-18",
        "title": "주식 밸런스 · 새 디자인",
        "added": ["주식 사이트 전면 개편 (낮/밤 전환, 종목 스트립, 큰 차트)", "양옆 시장 현황 · 랭킹 · 실시간 체결 패널", "로그아웃 버튼, 디스코드 프로필 사진·닉네임 표시", "디스코드 로그인 전용 화면"],
        "changed": [
            "시세 변동폭 완화 (한 틱 최대 ±5%, 기본 ±2.2%)",
            "기준가 평균회귀 강화, 가격 상·하한 적용",
            "기본 수수료 0.5%",
            "최대 버튼: 보유 돈에 맞춰 전부 매수, 보유 수량 전부 매도",
        ],
        "removed": [],
    },
    {
        "version": "1.22.0",
        "date": "2026-10-09",
        "title": "캐시·젬 회수",
        "added": ["데스크톱에서 캐시 빼기, 후원젬 빼기"],
        "changed": [],
        "removed": [],
    },
    {
        "version": "1.21.0",
        "date": "2026-10-09",
        "title": "주간 복권",
        "added": ["캐시로 사는 주간 복권", "토요일 20시 추첨", "1~3등만 당첨금"],
        "changed": [],
        "removed": [],
    },
    {
        "version": "1.20.0",
        "date": "2026-10-09",
        "title": "프로필 보유 재화",
        "added": ["프로필에 캐시, 후원젬, 소유금"],
        "changed": [],
        "removed": [],
    },
    {
        "version": "1.19.2",
        "date": "2026-10-03",
        "title": "주식 그래프",
        "added": [],
        "changed": ["주식 캔들을 더 굵고 가격 숫자가 잘 보이게"],
        "removed": [],
    },
    {
        "version": "1.19.1",
        "date": "2026-10-03",
        "title": "주식 한 페이지",
        "added": [],
        "changed": ["주식 메뉴를 없애고 메인 사이트처럼 한 화면에 모음"],
        "removed": [],
    },
    {
        "version": "1.19.0",
        "date": "2026-10-03",
        "title": "주식 사이트",
        "added": [
            "메인·주식·내 자산·거래 내역·뉴스·랭킹·마이페이지",
            "전일 대비, 거래량, 수수료, 평균 매수가, 수익률",
            "관리자 종목·가격·수수료·거래 중지·뉴스",
        ],
        "changed": ["매수·매도 캐시는 마크 서버에서 처리"],
        "removed": [],
    },
    {
        "version": "1.18.0",
        "date": "2026-10-03",
        "title": "주식 캔들 차트",
        "added": ["주식 그래프를 시가·고가·저가·종가 캔들과 추세선으로 표시"],
        "changed": [],
        "removed": [],
    },
    {
        "version": "1.17.1",
        "date": "2026-10-01",
        "title": "강제 연동 해제",
        "added": [],
        "changed": ["데스크톱 유저 탭에서 마크 연동을 강제로 끊을 수 있음"],
        "removed": [],
    },
    {
        "version": "1.17.0",
        "date": "2026-10-01",
        "title": "주식 사이트 분리",
        "added": ["상점과 다른 주식 사이트 /market"],
        "changed": ["주식 매매는 그 사이트에서만, 마크 캐시와 데스크톱 시세는 그대로 연결"],
        "removed": [],
    },
    {
        "version": "1.16.0",
        "date": "2026-10-01",
        "title": "주식 그래프 · 메뉴",
        "added": ["종목을 누르면 가격 그래프"],
        "changed": ["상단 메뉴가 둥근 끝에 가려지지 않음"],
        "removed": [],
    },
    {
        "version": "1.15.0",
        "date": "2026-09-28",
        "title": "웹에서 주식 거래",
        "added": ["웹에서만 주식 매수 · 매도", "거래하면 마크 캐시가 빠지거나 들어옴"],
        "changed": ["인게임 /주식 은 시세만 보여 줌"],
        "removed": [],
    },
    {
        "version": "1.14.0",
        "date": "2026-09-28",
        "title": "가짜 주식",
        "added": ["영재소프트 · 단비테크 · 긍조컴퍼니 · 네오월드 · 규원상점", "5초마다 가격이 자동으로 바뀜", "인게임 /주식 매수 · 매도"],
        "changed": [],
        "removed": [],
    },
    {
        "version": "1.13.0",
        "date": "2026-09-28",
        "title": "배경 · 헤더 · 코드등록",
        "added": ["코드등록 페이지", "알림 배지를 더 잘 보이게"],
        "changed": ["하얗게 비치던 배경을 어두운 색으로", "헤더 글자가 밖으로 나가지 않게 한 줄로"],
        "removed": [],
    },
    {
        "version": "1.12.0",
        "date": "2026-09-27",
        "title": "주문 화면 · 인증 채팅",
        "added": [
            "인증되지 않은 상태에서 /인증 하면 코드 발급",
            "웹에서 연동하면 마크 채팅에 연동 성공 안내",
            "이미 연동된 상태에서 /인증 하면 연동된 계정 안내",
        ],
        "changed": ["주문 완료 화면이 멈추던 문제"],
        "removed": [],
    },
    {
        "version": "1.11.0",
        "date": "2026-09-26",
        "title": "후원 · 패치노트 · 화면",
        "added": [
            "이달의 후원 게이지와 후원자 목록",
            "프로필에 구매 목록과 누적 후원액",
            "계정 연동 시 40% 할인 쿠폰",
            "헤더 로그아웃",
        ],
        "changed": [
            "패치노트 자동 팝업을 끄고 데스크톱에서 직접 작성",
            "페이지를 바꿔도 배경음이 이어짐",
            "상단 메뉴가 틀 밖으로 나가지 않게 정리",
        ],
        "removed": [],
    },
    {
        "version": "1.10.0",
        "date": "2026-09-26",
        "title": "장바구니 일괄결제 · 편집 크기 · 네비 수정",
        "added": [
            "장바구니 상품을 한 번에 결제",
            "사이트 에디터에서 글자 크기 · 블록 여백 · 모서리 둥글기 조절",
            "사이트 에디터에서 배경음악 URL 넣기",
        ],
        "changed": [
            "홈·공지 등 메뉴 클릭 시 검게 멈추던 페이지 전환 버그 수정",
            "입장 로그인 안내 글씨를 크게",
        ],
        "removed": [],
    },
    {
        "version": "1.9.0",
        "date": "2026-09-26",
        "title": "장바구니 · 배경음 · 패널 개편",
        "added": [
            "장바구니에 담고 한곳에서 결제",
            "페이지 이동 부드러운 페이드 · 배경음(토글)",
            "커스텀 캐시/잼 최소금액 · 단가 관리자 설정",
        ],
        "changed": [
            "닉네임 변경 패널 완전 재디자인",
            "전체 사이트 둥글고 큰 글씨 · 디자인 개편",
            "ServerBridge 콘솔 로그 quiet-console 기본 켜짐",
        ],
        "removed": [],
    },
    {
        "version": "1.8.0",
        "date": "2026-09-26",
        "title": "후원 랭킹 박제",
        "added": [
            "메인에 후원 랭킹 3위 박제 · 마크 닉 · 마크 스킨 · 디스코드 닉",
        ],
        "changed": [],
        "removed": [],
    },
    {
        "version": "1.7.0",
        "date": "2026-09-26",
        "title": "패널 · 선물 · 커스텀 캐시/잼 · 환불",
        "added": [
            "랭크가 있으면 랭크 닉네임 변경 + 변경권 패널, 없으면 변경권만",
            "디스코드 닉 옆에 서버 역할(MVP·StanDard·Ultra·Staff·Co-Owner·Admin·Owner)",
            "다른 유저 마크 닉으로 선물 주문",
            "커스텀 캐시(10당 1원) · 후원잼(2원당 1개) · 최소 100원",
            "주문 환불 요청 · 관리자 환불 승인",
        ],
        "changed": [
            "프로필은 현재 랭크만 보여 주고 패널 디자인을 귀엽게 정리",
            "전체 사이트 글꼴을 둥글고 귀여운 글씨로 통일",
        ],
        "removed": ["프로필의 UUID · 마크 닉 · LuckPerms 그룹 칸"],
    },
    {
        "version": "1.6.0",
        "date": "2026-09-26",
        "title": "리뷰 · 커뮤니티 · 데이터 삭제",
        "added": [
            "상품을 산 사람만 쓰는 리뷰 · 누구나 읽기 · 데스크톱에서 삭제",
            "커뮤니티방 · 하트 · 대댓글",
            "데스크톱에서 로그 · 주문내역 등 데이터 삭제",
            "캐시 · 젬 · MVP · 닉네임 변경권 상품을 ServerBridge 명령과 맞춰 지급",
        ],
        "changed": [
            "지급완료 시 캐시관리/젬관리 · lp user … parent set MVP · nick 새닉 플레이어 명령을 플러그인이 그대로 실행",
        ],
        "removed": [],
    },
    {
        "version": "1.5.0",
        "date": "2026-09-26",
        "title": "입장 로그인 · 관리자 채팅 · 판매 상품 확장",
        "added": [
            "처음 들어올 때 디스코드 로그인 화면 (사이트 에디터에서 끌 수 있어요)",
            "패치노트 페이지 · 새 버전이 나오면 자동 알림",
            "상점 변경 기록 자동 표시 (상품 추가 · 삭제 · 가격 변경)",
            "닉네임 변경권 판매 · 구매하면 패널에서 코드 없이 바로 사용",
            "MVP 랭크 판매 · MVP도 랭크 닉네임 변경 가능",
            "관리자와 1:1 채팅 (문의 채팅에서 확인)",
        ],
        "changed": [
            "주문이 취소되면 사용한 쿠폰이 자동으로 복구돼요",
        ],
        "removed": [],
    },
    {
        "version": "1.4.2",
        "date": "2026-09-26",
        "title": "사이트 편집 권한 정리",
        "added": [],
        "changed": ["사이트 · 위키 편집은 Team. Wildmc 권한이 있어야만 가능"],
        "removed": ["오너 · 부총괄 · 어드민 랭크만으로 사이트를 편집하던 방식"],
    },
    {
        "version": "1.4.1",
        "date": "2026-09-26",
        "title": "화면 비율 개선",
        "added": ["상품 칸 수 자동 조절 (넓은 화면 최대 4칸)"],
        "changed": [
            "넓은 화면에서 콘텐츠 폭이 화면에 맞게 넓어짐",
            "홈 큰 배너 높이가 화면 너비 비율(3:1 · 2:1 · 16:9)로 유지",
            "큰 모니터에서 글자 · 버튼 크기 자동 조절",
        ],
        "removed": [],
    },
    {
        "version": "1.4.0",
        "date": "2026-09-26",
        "title": "사이트 에디터 · 전체 디자인 개선",
        "added": [
            "사이트 에디터 (실시간 미리보기 · 테마 · 색 · 글꼴 · 레이아웃 · 저장 기록 복원)",
            "홈에서 바로 편집하는 모드",
            "상점 카테고리 필터",
            "결제 계좌 복사 버튼 · 주문 진행 단계 표시",
        ],
        "changed": ["전체 글꼴을 둥근 글꼴로 변경", "헤더 · 카드 · 버튼 · 애니메이션 디자인 개선"],
        "removed": [],
    },
    {
        "version": "1.3.1",
        "date": "2026-09-26",
        "title": "입금 증빙 사진",
        "added": ["결제할 때 입금 증빙 사진 첨부", "주문 완료 화면에서 사진 추가 첨부"],
        "changed": [],
        "removed": [],
    },
    {
        "version": "1.3.0",
        "date": "2026-09-25",
        "title": "본 사이트 꾸미기",
        "added": ["본 사이트 꾸미기 페이지", "홈 큰 배너 배경 이미지"],
        "changed": [],
        "removed": [],
    },
]
WEB_VERSION = PATCH_NOTES[0]["version"]
SHOP_CHANGES_MAX = 300


def record_shop_change(kind: str, name: str, detail: str = "") -> None:
    """상점 변경을 패치노트에 자동으로 남긴다. kind: added / removed / updated."""
    rows = db.setdefault("shop_changes", [])
    rows.append(
        {"id": next_id(rows), "at": now_ms(), "kind": kind, "name": str(name or "")[:80], "detail": str(detail or "")[:200]}
    )
    if len(rows) > SHOP_CHANGES_MAX:
        del rows[: len(rows) - SHOP_CHANGES_MAX]


PRODUCT_GRANT_LABELS = (("cash_amount", "캐시"), ("gem_amount", "젬"), ("voucher_count", "닉네임 변경권"))


def product_summary(p: dict) -> str:
    parts = [f"{safe_int(p.get('price')):,}원"]
    if p.get("rank_group"):
        parts.append(f"랭크 {p.get('rank_group')}")
    for key, label in PRODUCT_GRANT_LABELS:
        if safe_int(p.get(key)) > 0:
            parts.append(f"{label} {safe_int(p.get(key)):,}")
    return " · ".join(parts)


def product_change(before: dict, after: dict) -> tuple[str, str] | None:
    """공개적으로 의미 있는 상품 변경만 (kind, detail)로 요약한다."""
    was_on = before.get("active", 1) != 0
    now_on = after.get("active", 1) != 0
    if was_on and not now_on:
        return "removed", "판매 중지"
    if not was_on and now_on:
        return "added", "판매 시작 · " + product_summary(after)
    if not now_on:
        return None
    parts: list[str] = []
    if (before.get("name") or "") != (after.get("name") or ""):
        parts.append(f"이름 «{before.get('name')}» → «{after.get('name')}»")
    if safe_int(before.get("price")) != safe_int(after.get("price")):
        parts.append(f"가격 {safe_int(before.get('price')):,}원 → {safe_int(after.get('price')):,}원")
    if (before.get("rank_group") or "") != (after.get("rank_group") or ""):
        parts.append(f"지급 랭크 {after.get('rank_group') or '없음'}")
    for key, label in PRODUCT_GRANT_LABELS:
        if safe_int(before.get(key)) != safe_int(after.get(key)):
            parts.append(f"{label} {safe_int(after.get(key)):,}")
    if (before.get("image_url") or "") != (after.get("image_url") or ""):
        parts.append("이미지 변경")
    if (before.get("description") or "") != (after.get("description") or ""):
        parts.append("설명 변경")
    return ("updated", " · ".join(parts)) if parts else None


def nick_ticket_units(product: dict | None, order: dict | None = None) -> int:
    """상품에 장수가 없어도 이름이 닉네임 변경권이면 1장으로 본다."""
    product = product or {}
    n = safe_int(product.get("voucher_count"))
    if n > 0:
        return n
    name = f"{product.get('name') or ''} {(order or {}).get('product_name') or ''}"
    if "변경권" in name or "닉네임 변경" in name:
        return 1
    return 0


def ensure_nick_tickets_from_orders() -> bool:
    """지급완료된 변경권 주문인데 패널 보유권이 없으면 한 번 채워 준다."""
    changed = False
    for order in db.get("orders") or []:
        if str(order.get("status") or "") != "fulfilled" or order.get("tickets_granted"):
            continue
        products = order_line_products(order)
        tickets = sum(nick_ticket_units(prod, order) for prod in products)
        if tickets <= 0 and nick_ticket_units(None, order):
            tickets = 1
        if tickets <= 0:
            continue
        did = str(order.get("discord_id") or "")
        target_mc = str(order.get("gift_minecraft_name") or order.get("minecraft_name") or "")
        ticket_user = did
        if order.get("gift") and target_mc:
            gifted = find_user_by_minecraft_name(target_mc)
            if gifted:
                ticket_user = str(gifted.get("discord_id") or did)
        if not ticket_user:
            continue
        grant_nick_tickets(ticket_user, tickets, str(order.get("order_code") or ""))
        order["tickets_granted"] = tickets
        changed = True
    return changed


def nick_ticket_count(discord_id: str) -> int:
    return sum(
        1 for t in db.get("nick_tickets", []) if str(t.get("discord_id") or "") == discord_id and not t.get("used_at")
    )


def grant_nick_tickets(discord_id: str, count: int, order_code: str) -> None:
    rows = db.setdefault("nick_tickets", [])
    for _ in range(max(0, count)):
        rows.append({"id": next_id(rows), "discord_id": discord_id, "order_code": order_code, "created_at": now_ms(), "used_at": None})


def revoke_order_tickets(order: dict) -> int:
    code = str(order.get("order_code") or "")
    if not code:
        return 0
    removed = 0
    codes = []
    for t in db.get("nick_tickets", []):
        if str(t.get("order_code") or "") == code and not t.get("used_at"):
            t["used_at"] = now_ms()
            t["revoked"] = 1
            removed += 1
        issued = str(t.get("issued_code") or "")
        if str(t.get("order_code") or "") == code and issued:
            codes.append(issued.upper())
    if codes:
        for voucher in db.get("nick_vouchers", []):
            if str(voucher.get("code") or "").upper() in codes and not voucher.get("used"):
                voucher["used"] = 1
                voucher["revoked"] = 1
    return removed


def clean_user_text(raw, max_len: int = 2000) -> str:
    text = str(raw or "").replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"<[^>]+>", "", text)
    return text.strip()[:max_len]


def session_author(session: dict | None) -> dict:
    did = str((session or {}).get("discordId") or "")
    user = find_user(did) if did else None
    pub = user_public(user) or {}
    return {
        "discord_id": did,
        "username": pub.get("username") or (session or {}).get("username") or did,
        "avatar": pub.get("avatar") or (session or {}).get("avatar"),
        "minecraft_name": pub.get("minecraft_name"),
    }


def user_purchased_product(discord_id: str, product_id: int) -> bool:
    did = str(discord_id or "")
    pid = safe_int(product_id)
    if not did or pid <= 0:
        return False
    for order in db.get("orders", []):
        if str(order.get("discord_id") or "") != did:
            continue
        if safe_int(order.get("product_id")) != pid:
            continue
        if str(order.get("status") or "") in ("paid", "fulfilled"):
            return True
    return False


def review_stats_map() -> dict[int, dict]:
    out: dict[int, dict] = {}
    for row in db.get("reviews", []):
        if row.get("hidden"):
            continue
        pid = safe_int(row.get("product_id"))
        if pid <= 0:
            continue
        bucket = out.setdefault(pid, {"count": 0, "sum": 0})
        bucket["count"] += 1
        bucket["sum"] += max(1, min(5, safe_int(row.get("rating"), 5)))
    for bucket in out.values():
        n = bucket["count"]
        bucket["avg"] = round(bucket["sum"] / n, 1) if n else 0
    return out


def public_review(row: dict, *, admin: bool = False) -> dict:
    item = {
        "id": safe_int(row.get("id")),
        "product_id": safe_int(row.get("product_id")),
        "product_name": row.get("product_name") or "",
        "discord_id": str(row.get("discord_id") or ""),
        "username": row.get("username") or "",
        "avatar": row.get("avatar"),
        "minecraft_name": row.get("minecraft_name"),
        "rating": max(1, min(5, safe_int(row.get("rating"), 5))),
        "body": row.get("body") or "",
        "created_at": safe_int(row.get("created_at")),
        "updated_at": safe_int(row.get("updated_at")),
    }
    if admin:
        item["hidden"] = 1 if row.get("hidden") else 0
    return item


def public_comment(row: dict, *, admin: bool = False) -> dict:
    item = {
        "id": safe_int(row.get("id")),
        "post_id": safe_int(row.get("post_id")),
        "parent_id": safe_int(row.get("parent_id")) or None,
        "discord_id": str(row.get("discord_id") or ""),
        "username": row.get("username") or "",
        "avatar": row.get("avatar"),
        "body": row.get("body") or "",
        "created_at": safe_int(row.get("created_at")),
    }
    if admin:
        item["hidden"] = 1 if row.get("hidden") else 0
    return item


def public_community_post(row: dict, viewer_id: str = "", *, admin: bool = False) -> dict:
    likes = [str(x) for x in (row.get("likes") or []) if str(x)]
    pid = safe_int(row.get("id"))
    comments = [
        public_comment(c, admin=admin)
        for c in db.get("community_comments", [])
        if safe_int(c.get("post_id")) == pid and (admin or not c.get("hidden"))
    ]
    comments.sort(key=lambda c: safe_int(c.get("created_at")))
    item = {
        "id": pid,
        "discord_id": str(row.get("discord_id") or ""),
        "username": row.get("username") or "",
        "avatar": row.get("avatar"),
        "title": row.get("title") or "",
        "body": row.get("body") or "",
        "likes": len(likes),
        "liked": viewer_id in likes,
        "comments": comments,
        "comment_count": len(comments),
        "created_at": safe_int(row.get("created_at")),
    }
    if admin:
        item["hidden"] = 1 if row.get("hidden") else 0
        item["like_ids"] = likes
    return item


def nest_comments(comments: list[dict]) -> list[dict]:
    by_id = {safe_int(c.get("id")): {**c, "replies": []} for c in comments}
    roots: list[dict] = []
    for c in comments:
        node = by_id[safe_int(c.get("id"))]
        parent = safe_int(c.get("parent_id"))
        if parent and parent in by_id:
            by_id[parent]["replies"].append(node)
        else:
            roots.append(node)
    return roots


PURGE_TARGETS = ("orders", "activity_logs", "reviews", "community", "command_queue")


def purge_data(target: str, ids: list[int] | None = None, all_rows: bool = False) -> dict:
    """Desktop admin: delete logs / orders / reviews / community / processed commands."""
    kind = str(target or "").strip()
    if kind not in PURGE_TARGETS:
        raise ValueError("삭제할 수 없는 대상입니다.")
    wanted = {safe_int(x) for x in (ids or []) if safe_int(x) > 0}
    if not all_rows and not wanted:
        raise ValueError("삭제할 항목을 선택하세요.")

    def drop(key: str) -> int:
        rows = list(db.get(key) or [])
        if all_rows:
            db[key] = []
            return len(rows)
        keep = [r for r in rows if safe_int(r.get("id")) not in wanted]
        db[key] = keep
        return len(rows) - len(keep)

    removed = 0
    if kind == "orders":
        removed = drop("orders")
    elif kind == "activity_logs":
        removed = drop("activity_logs")
    elif kind == "reviews":
        removed = drop("reviews")
    elif kind == "community":
        if all_rows:
            removed = len(db.get("community_posts") or []) + len(db.get("community_comments") or [])
            db["community_posts"] = []
            db["community_comments"] = []
        else:
            posts = list(db.get("community_posts") or [])
            comments = list(db.get("community_comments") or [])
            post_ids = {safe_int(p.get("id")) for p in posts if safe_int(p.get("id")) in wanted}
            removed += len(post_ids)
            db["community_posts"] = [p for p in posts if safe_int(p.get("id")) not in post_ids]
            before = len(comments)
            db["community_comments"] = [
                c
                for c in comments
                if safe_int(c.get("id")) not in wanted and safe_int(c.get("post_id")) not in post_ids
            ]
            removed += before - len(db["community_comments"])
    elif kind == "command_queue":
        rows = list(db.get("command_queue") or [])
        if all_rows:
            db["command_queue"] = []
            removed = len(rows)
        else:
            keep = [r for r in rows if safe_int(r.get("id")) not in wanted]
            db["command_queue"] = keep
            removed = len(rows) - len(keep)
    else:
        raise ValueError("삭제할 수 없는 대상입니다.")
    return {"target": kind, "removed": removed}


def restore_order_coupon(order: dict) -> str | None:
    """취소된 주문에서 쓴 쿠폰을 다시 쓸 수 있게 되돌리고 코드를 돌려준다 (한 번만)."""
    code = normalize_coupon_code(order.get("coupon_code") or "")
    if not code or order.get("coupon_restored_at"):
        return None
    cid = safe_int(order.get("coupon_id"))
    did = str(order.get("discord_id") or "")
    coupon = next((c for c in db.get("coupons", []) if cid and safe_int(c.get("id")) == cid), None) or find_coupon(code)
    if coupon:
        coupon["used_count"] = max(0, safe_int(coupon.get("used_count")) - 1)
        cid = safe_int(coupon.get("id"))
    reds = db.get("coupon_redemptions", [])
    match = next((i for i in range(len(reds) - 1, -1, -1) if reds[i].get("order_code") == order.get("order_code")), None)
    if match is None:
        match = next(
            (
                i
                for i in range(len(reds) - 1, -1, -1)
                if safe_int(reds[i].get("coupon_id")) == cid and str(reds[i].get("discord_id") or "") == did
            ),
            None,
        )
    if match is not None:
        reds.pop(match)
    for w in reversed(db.get("coupon_wallet", [])):
        if str(w.get("discord_id") or "") != did or not w.get("used_at"):
            continue
        if safe_int(w.get("coupon_id")) == cid or normalize_coupon_code(w.get("code") or "") == code:
            w["used_at"] = None
            break
    order["coupon_restored_at"] = now_ms()
    return code


def admin_chat_thread(discord_id: str, create: bool = False) -> dict | None:
    """관리자↔유저 대화: 열린 문의 스레드를 쓰고, 없으면 새로 만든다."""
    rows = sorted(
        (i for i in db.get("inquiries", []) if str(i.get("user_id") or "") == discord_id),
        key=lambda x: -safe_int(x.get("id")),
    )
    row = next((r for r in rows if r.get("status") != "closed"), None)
    if row or not create:
        return row or (rows[0] if rows else None)
    user = find_user(discord_id) or {}
    row = {
        "id": next_id(db.get("inquiries", [])),
        "user_id": discord_id,
        "username": user.get("discord_username") or discord_id,
        "subject": "관리자 메시지",
        "body": "",
        "images": [],
        "status": "replied",
        "started_by": "admin",
        "created_at": now_ms(),
        "replies": [],
    }
    db.setdefault("inquiries", []).append(row)
    return row


def render_wiki_html(edit: int) -> bytes:
    if not WIKI_TEMPLATE.is_file():
        return b"<h1>wiki missing</h1>"
    html = WIKI_TEMPLATE.read_text(encoding="utf-8")
    html = html.replace("{{ edit }}", "1" if edit else "0")
    return html.encode("utf-8")


def ensure_runtime_defaults() -> None:
    db.setdefault("coupon_wallet", [])
    db.setdefault("friendships", [])
    db.setdefault("chat_messages", [])
    db.setdefault("inquiries", [])
    db.setdefault("activity_logs", [])
    db.setdefault("promo_codes", [])
    ensure_stocks()
    s = db.setdefault("settings", {})
    defaults = {
        "stats_kicker": "LIVE STATUS",
        "stats_title": "서버 현황",
        "shop_kicker": "SHOP",
        "shop_title": "상품",
        "shop_nav": "상점",
        "shop_cta": "상점",
        "hero_link_cta": "마인크래프트 계정 연동",
        "footer_link_label": "도전과제",
        "nav_notice": "공지",
        "nav_coupon": "쿠폰받기",
        "nav_achievements": "도전과제",
        "nav_link": "마인크래프트 계정과 연동하기",
        "nav_inbox": "우편함",
        "live_offline": "Minecraft Offline",
        "live_online": "Minecraft Online",
        "coupon_page_title": "쿠폰받기",
        "coupon_page_desc": "원하는 쿠폰을 다운로드하세요. 결제 시 자동 적용하거나 직접 고를 수 있습니다.",
        "site_tagline": "MINECRAFT × DISCORD",
        "admin_discord_ids": "",
    }
    for k, v in defaults.items():
        if k not in s or s.get(k) in (None, ""):
            s[k] = v


STOCK_DEFS = (
    ("yeongjae", "영재소프트"),
    ("danbi", "단비테크"),
    ("geungjo", "긍조컴퍼니"),
    ("neoworld", "네오월드"),
    ("gyuwon", "규원상점"),
)


def site_logo_url() -> str:
    v = str((db.get("settings") or {}).get("site_logo_url") or "").strip()
    return v if v.startswith(("http://", "https://", "/")) else ""


STOCK_DEFAULT_FEE_PCT = 0.2   # 기본 수수료 (%) - 단타·도배 방지
STOCK_DEFAULT_VOL = 0.009     # 5초당 기본 변동폭 (±0.9%) - 안정형
STOCK_DAY_LIMIT = 0.30        # 하루 상·하한 (전일 종가 대비 ±30%)
STOCK_DAY_LIMIT_ABS = 300_000  # 하루 최대 등락 금액 (±30만원)
STOCK_DAY_LIMIT_DOWN = 0.08   # 하루 최대 하락 (전일 종가 대비 -8%) — 너무 안 떨어지게
STOCK_DRIFT = 0.000008        # 틱마다 살짝 위로 기우는 힘 — 소액 벌기 쉽게
STOCK_TICK_CAP = 0.015        # 한 틱 최대 등락 (±1.5%) - 안정형
STOCK_MIN_PRICE = 100
STOCK_MAX_PRICE = 3_000_000
STOCK_MAX_QTY = 10_000_000    # 1회 주문 최대 수량 (돈/보유량이 사실상 한도)


def stock_fee_config() -> dict:
    s = db.setdefault("settings", {})
    raw_fee = s.get("stock_fee_pct")
    try:
        fee = STOCK_DEFAULT_FEE_PCT if raw_fee in (None, "") else float(raw_fee)
    except (TypeError, ValueError):
        fee = STOCK_DEFAULT_FEE_PCT
    raw_vol = s.get("stock_volatility")
    try:
        vol = STOCK_DEFAULT_VOL if raw_vol in (None, "", 0) else float(raw_vol)
    except (TypeError, ValueError):
        vol = STOCK_DEFAULT_VOL
    return {
        "feePct": round(max(0.0, min(10.0, fee)), 2),
        "volatility": max(0.003, min(0.04, vol)),
        "trading": str(s.get("stock_trading", "1")) != "0",
    }


def roll_stock_day(row: dict, today: str) -> None:
    price = max(50, safe_int(row.get("price"), 1000))
    row["price"] = price
    row["prev"] = max(50, safe_int(row.get("prev"), price))
    row["anchor"] = max(200, safe_int(row.get("anchor"), price))
    row["halted"] = 1 if safe_int(row.get("halted")) else 0
    row["volume"] = max(0, safe_int(row.get("volume")))
    hist = row.get("history") if isinstance(row.get("history"), list) else []
    if len(hist) < 24:
        row["history"] = seed_stock_path(price)
    if str(row.get("day") or "") == today:
        row["day_high"] = max(price, safe_int(row.get("day_high"), price))
        low = safe_int(row.get("day_low"), price)
        row["day_low"] = min(price, low) if low > 0 else price
        if not safe_int(row.get("prev_close")):
            row["prev_close"] = price
        return
    row["prev_close"] = price
    row["day"] = today
    row["volume"] = 0
    row["day_high"] = price
    row["day_low"] = price
    row["alerted"] = 0


def ensure_stocks() -> None:
    retired = {str(x) for x in (db.get("stock_retired") or [])}
    rows: dict[str, dict] = {}
    order: list[str] = []
    for item in db.get("stocks") or []:
        if not isinstance(item, dict):
            continue
        sid = str(item.get("id") or "")
        if not sid or sid in retired:
            continue
        rows[sid] = item
        order.append(sid)
    for sid, name in STOCK_DEFS:
        if sid in retired:
            continue
        row = rows.get(sid)
        if not row:
            price = random.randint(2000, 60000)
            row = {
                "id": sid,
                "name": name,
                "price": price,
                "prev": price,
                "anchor": price,
                "history": [price],
                "updated_at": now_ms(),
                "builtin": 1,
            }
            rows[sid] = row
            order.append(sid)
        row["name"] = name
        row["builtin"] = 1
    today = seoul_date()
    for sid in order:
        roll_stock_day(rows[sid], today)
    db["stocks"] = [rows[sid] for sid in order]


def find_stock(stock_id: str) -> dict | None:
    key = str(stock_id or "").strip()
    if not key:
        return None
    for row in db.get("stocks") or []:
        if str(row.get("id") or "") == key or str(row.get("name") or "") == key:
            return row
    return None


def seed_stock_path(price: int, n: int = 120) -> list[int]:
    """짧은 시세만 있을 때, 현재 가격에서 끝나도록 과거 흐름을 채운다."""
    cursor = max(50, price)
    past = [cursor]
    for _ in range(max(2, n) - 1):
        step = random.uniform(-0.025, 0.025)
        if random.random() < 0.04:
            step += random.choice((-1, 1)) * random.uniform(0.015, 0.04)
        denom = 1 + step
        if denom < 0.2:
            denom = 0.2
        cursor = max(50, int(round(cursor / denom)))
        past.append(cursor)
    past.reverse()
    past[-1] = max(50, price)
    return past


def stock_public(row: dict) -> dict:
    price = max(50, safe_int(row.get("price")))
    prev = max(50, safe_int(row.get("prev"), price))
    close = max(50, safe_int(row.get("prev_close"), price))
    tick = round((price - prev) / prev * 100, 2) if prev else 0.0
    day = round((price - close) / close * 100, 2) if close else 0.0
    high = max(price, safe_int(row.get("day_high"), price))
    low = safe_int(row.get("day_low"), price) or price
    move = "up" if day >= 5 else "down" if day <= -5 else ""
    return {
        "id": row.get("id") or "",
        "name": row.get("name") or "",
        "price": price,
        "prev": prev,
        "prevClose": close,
        "change": price - close,
        "changePct": day,
        "tickPct": tick,
        "dayHigh": high,
        "dayLow": low,
        "volume": max(0, safe_int(row.get("volume"))),
        "halted": 1 if safe_int(row.get("halted")) else 0,
        "move": move,
        "history": [safe_int(x) for x in (row.get("history") or [])][-240:],
        "updatedAt": safe_int(row.get("updated_at")),
    }


def push_stock_news(title: str, body: str, kind: str, stock_id: str = "") -> dict:
    item = {
        "id": next_id(db.get("stock_news") or []),
        "title": title[:80],
        "body": body[:800],
        "kind": kind if kind in ("market", "stock", "price", "notice", "event") else "market",
        "stock_id": stock_id,
        "at": now_ms(),
    }
    rows = db.setdefault("stock_news", [])
    rows.append(item)
    if len(rows) > 200:
        del rows[:-200]
    return item


def news_public(item: dict) -> dict:
    sid = str(item.get("stock_id") or "")
    stock = find_stock(sid) if sid else None
    return {
        "id": item.get("id"),
        "title": item.get("title") or "",
        "body": item.get("body") or "",
        "kind": item.get("kind") or "market",
        "stockId": sid,
        "stockName": (stock or {}).get("name") or "",
        "at": safe_int(item.get("at")),
    }


def tick_stocks() -> None:
    with lock:
        ensure_stocks()
        today = seoul_date()
        if db.get("stock_snap_day") != today:
            values: dict[str, int] = {}
            for hold in db.get("stock_holdings") or []:
                qty = safe_int(hold.get("qty"))
                if qty <= 0:
                    continue
                stock = find_stock(str(hold.get("stock_id") or ""))
                if not stock:
                    continue
                did = str(hold.get("discord_id") or "")
                values[did] = values.get(did, 0) + safe_int(stock.get("price")) * qty
            snaps = db.setdefault("stock_day_equity", {})
            for did, val in values.items():
                snaps[did] = {"day": today, "start": val, "cash_flow": 0}
            db["stock_snap_day"] = today
        cfg = stock_fee_config()
        vol = cfg["volatility"]
        now = now_ms()
        for row in db.get("stocks") or []:
            if safe_int(row.get("halted")):
                continue
            price = max(50, safe_int(row.get("price"), 1000))
            anchor = max(200, safe_int(row.get("anchor"), price))
            base = max(STOCK_MIN_PRICE, safe_int(row.get("base"), anchor))
            row["base"] = base
            # 평균회귀: 기준가에서 멀어질수록 되돌아오는 힘이 커진다
            pull = (anchor - price) / anchor * random.uniform(0.04, 0.12)
            shock = random.gauss(0, vol * 0.55) + STOCK_DRIFT
            if random.random() < 0.015:
                shock += random.choice((-1, 1)) * random.uniform(vol * 0.5, vol * 1.0)
            # 추세(모멘텀): 한 방향으로 한동안 이어지다가 천천히 바뀌어서 한곳에 머물지 않고 계속 움직인다
            trend = float(row.get("trend") or 0.0)
            trend = trend * 0.985 + random.gauss(0, vol * 0.09)
            trend = max(-vol * 0.8, min(vol * 0.8, trend))
            row["trend"] = trend
            move = max(-STOCK_TICK_CAP, min(STOCK_TICK_CAP, pull + shock + trend))
            nxt = int(round(price * (1 + move)))
            if nxt == price:
                nxt = price + random.choice((-1, 1)) * max(1, int(price * 0.0008))
            lo_band, hi_band = int(base * 0.5), int(base * 2.0)
            nxt = max(STOCK_MIN_PRICE, lo_band, min(STOCK_MAX_PRICE, hi_band, nxt))
            # 하루 상·하한: 전일 종가 대비 ±30% 또는 ±30만원 중 작은 쪽을 넘지 않게
            _pc = max(50, safe_int(row.get("prev_close"), price))
            # 관리자가 직접 올리거나 내린 가격은 상·하한 밖이어도 유지 (복귀 금지)
            _up = min(_pc * STOCK_DAY_LIMIT, STOCK_DAY_LIMIT_ABS)
            _dn = min(_pc * STOCK_DAY_LIMIT_DOWN, STOCK_DAY_LIMIT_ABS)
            nxt = max(min(int(_pc - _dn), price), min(max(int(_pc + _up), price), nxt))
            nxt = max(STOCK_MIN_PRICE, nxt)
            row["prev"] = price
            row["price"] = nxt
            row["updated_at"] = now
            row["day_high"] = max(nxt, safe_int(row.get("day_high"), nxt))
            low = safe_int(row.get("day_low"), nxt)
            row["day_low"] = min(nxt, low) if low > 0 else nxt
            hist = row.get("history") if isinstance(row.get("history"), list) else []
            hist.append(nxt)
            row["history"] = hist[-720:]
            if random.random() < 0.05:
                # 기준가가 전일 종가 주변을 천천히 떠돌아서 가격이 계속 오르내린다 (한곳에 고정 X)
                _ref = max(50, safe_int(row.get("prev_close"), nxt))
                _a = anchor * random.uniform(0.992, 1.014)
                _a += (_ref - _a) * 0.02
                row["anchor"] = max(STOCK_MIN_PRICE * 2, int(max(_ref * 0.92, min(_ref * 1.30, _a))))
            close = max(50, safe_int(row.get("prev_close"), nxt))
            day = (nxt - close) / close * 100 if close else 0
            if abs(day) >= 5 and not safe_int(row.get("alerted")):
                row["alerted"] = 1
                word = "급등" if day > 0 else "급락"
                push_stock_news(
                    f"{row.get('name')} {word}",
                    f"{row.get('name')} 종목이 전일 대비 {day:.2f}% {word}했습니다.",
                    "price",
                    str(row.get("id") or ""),
                )
        save_db(db)


def nudge_stock(stock_id: str, direction: str) -> dict | None:
    ensure_stocks()
    factor = 1.1 if direction == "up" else 0.9
    for row in db.get("stocks") or []:
        if str(row.get("id") or "") != stock_id and str(row.get("name") or "") != stock_id:
            continue
        price = max(50, safe_int(row.get("price"), 1000))
        row["prev"] = price
        nxt = max(50, int(round(price * factor)))
        row["price"] = nxt
        row["anchor"] = nxt  # 관리자가 바꾼 가격이 새 기준가 — 원래 가격으로 복귀하지 않음
        row["base"] = nxt
        row["updated_at"] = now_ms()
        row["day_high"] = max(nxt, safe_int(row.get("day_high"), nxt))
        low = safe_int(row.get("day_low"), nxt)
        row["day_low"] = min(nxt, low) if low > 0 else nxt
        hist = row.get("history") if isinstance(row.get("history"), list) else []
        hist.append(nxt)
        row["history"] = hist[-720:]
        save_db(db)
        return stock_public(row)
    return None


def stock_holding_row(discord_id: str, stock_id: str, create: bool = False) -> dict | None:
    rows = db.setdefault("stock_holdings", [])
    for row in rows:
        if str(row.get("discord_id") or "") == discord_id and str(row.get("stock_id") or "") == stock_id:
            return row
    if not create:
        return None
    row = {"discord_id": discord_id, "stock_id": stock_id, "qty": 0, "avg_price": 0, "realized": 0}
    rows.append(row)
    return row


def stock_holding_qty(discord_id: str, stock_id: str) -> int:
    row = stock_holding_row(discord_id, stock_id)
    return max(0, safe_int((row or {}).get("qty")))


def add_stock_holding(discord_id: str, stock_id: str, delta: int) -> int:
    row = stock_holding_row(discord_id, stock_id, create=True)
    assert row is not None
    row["qty"] = max(0, safe_int(row.get("qty")) + delta)
    row.setdefault("avg_price", 0)
    row.setdefault("realized", 0)
    return row["qty"]


def apply_buy_fill(discord_id: str, stock_id: str, qty: int, price: int) -> None:
    row = stock_holding_row(discord_id, stock_id, create=True)
    assert row is not None
    old_qty = max(0, safe_int(row.get("qty")))
    old_avg = float(row.get("avg_price") or 0)
    new_qty = old_qty + qty
    row["qty"] = new_qty
    row["avg_price"] = round((old_avg * old_qty + price * qty) / new_qty, 4) if new_qty else 0
    row.setdefault("realized", 0)


def apply_sell_fill(discord_id: str, stock_id: str, qty: int, price: int, fee: int) -> None:
    row = stock_holding_row(discord_id, stock_id)
    if not row:
        return
    if "avg_price" not in row:
        row["avg_price"] = price
    avg = float(row.get("avg_price") or 0)
    row["realized"] = safe_int(row.get("realized")) + int(round((price - avg) * qty - fee))
    if safe_int(row.get("qty")) <= 0:
        row["avg_price"] = 0


def remember_minecraft_money(name: str, amount: int) -> None:
    key = str(name or "").strip().lower()
    if not key:
        return
    for user in db.get("users") or []:
        if str(user.get("minecraft_name") or "").strip().lower() == key:
            user["minecraft_money"] = max(0, safe_int(amount))
            user["minecraft_money_at"] = now_ms()
            return


def remember_minecraft_cash(name: str, amount: int) -> None:
    key = str(name or "").strip().lower()
    if not key:
        return
    for user in db.get("users") or []:
        if str(user.get("minecraft_name") or "").strip().lower() == key:
            user["minecraft_cash"] = max(0, safe_int(amount))
            user["minecraft_cash_at"] = now_ms()
            return


def apply_economy_balances(rows) -> int:
    """플러그인이 보낸 인게임 돈(money)을 연동 유저에 반영"""
    if not isinstance(rows, list):
        return 0
    by_name: dict[str, dict] = {}
    for item in rows:
        if isinstance(item, dict):
            key = str(item.get("name") or "").strip().lower()
            if key and item.get("money") is not None:
                by_name[key] = item
    ts = now_ms()
    hit = 0
    for user in db.get("users") or []:
        key = str(user.get("minecraft_name") or "").strip().lower()
        item = by_name.get(key) if key else None
        if not item:
            continue
        user["minecraft_money"] = max(0, safe_int(item.get("money")))
        user["minecraft_money_at"] = ts
        hit += 1
    return hit


def expire_stock_trades() -> None:
    now = now_ms()
    for trade in db.get("stock_trades") or []:
        if str(trade.get("status") or "") not in ("pending", "processing"):
            continue
        limit = 25000 if str(trade.get("status") or "") == "pending" else 120000
        if now - safe_int(trade.get("created_at")) < limit:
            continue
        trade["status"] = "failed"
        trade["error"] = "마크 서버가 응답하지 않았어요. 서버가 켜져 있는지 확인해 주세요."
        if trade.get("side") == "sell":
            add_stock_holding(str(trade.get("discord_id") or ""), str(trade.get("stock_id") or ""), safe_int(trade.get("qty")))


def portfolio_for(discord_id: str) -> list[dict]:
    ensure_stocks()
    out = []
    for stock in db.get("stocks") or []:
        sid = str(stock.get("id") or "")
        row = stock_holding_row(discord_id, sid)
        qty = max(0, safe_int((row or {}).get("qty")))
        if row is None or qty <= 0:
            continue
        price = safe_int(stock.get("price"))
        if "avg_price" not in row:
            row["avg_price"] = price
        avg = float(row.get("avg_price") or 0)
        pnl = int(round((price - avg) * qty))
        rate = round((price - avg) / avg * 100, 2) if avg else 0.0
        out.append({
            "id": sid,
            "name": stock.get("name") or sid,
            "qty": qty,
            "price": price,
            "avg": round(avg, 2),
            "value": price * qty,
            "pnl": pnl,
            "pnlPct": rate,
        })
    return out


def discord_avatar_url(discord_id: str, avatar: str | None) -> str:
    did = str(discord_id or "")
    if not did or did.startswith("local_"):
        return ""
    if not avatar:
        return "https://cdn.discordapp.com/embed/avatars/0.png"
    return f"https://cdn.discordapp.com/avatars/{did}/{avatar}.png?size=64"


def stock_user_card(discord_id: str) -> dict:
    u = find_user(str(discord_id or "")) or {}
    return {
        "discordName": u.get("discord_username") or u.get("username") or "",
        "avatar": discord_avatar_url(str(discord_id or ""), u.get("discord_avatar") or u.get("avatar")),
    }


def trade_public(trade: dict) -> dict:
    card = stock_user_card(str(trade.get("discord_id") or ""))
    return {
        "id": trade.get("id"),
        "discordName": card["discordName"] or str(trade.get("minecraft_name") or "익명"),
        "avatar": card["avatar"],
        "discordId": trade.get("discord_id") or "",
        "name": trade.get("name") or "",
        "stockId": trade.get("stock_id") or "",
        "minecraftName": trade.get("minecraft_name") or "",
        "side": trade.get("side") or "",
        "qty": safe_int(trade.get("qty")),
        "price": safe_int(trade.get("price")),
        "gross": safe_int(trade.get("gross"), safe_int(trade.get("price")) * safe_int(trade.get("qty"))),
        "fee": safe_int(trade.get("fee")),
        "cost": safe_int(trade.get("cost")),
        "status": trade.get("status") or "",
        "error": trade.get("error") or "",
        "flag": trade.get("flag") or "",
        "at": safe_int(trade.get("created_at")),
    }


def user_trade_volume(discord_id: str) -> int:
    total = 0
    for trade in db.get("stock_trades") or []:
        if str(trade.get("discord_id") or "") == discord_id and str(trade.get("status") or "") == "done":
            total += safe_int(trade.get("qty"))
    return total


def stock_account(discord_id: str) -> dict:
    user = find_user(discord_id) or {}
    holdings = portfolio_for(discord_id)
    stock_value = sum(safe_int(h.get("value")) for h in holdings)
    realized = 0
    for row in db.get("stock_holdings") or []:
        if str(row.get("discord_id") or "") == discord_id:
            realized += safe_int(row.get("realized"))
    unreal = sum(safe_int(h.get("pnl")) for h in holdings)
    basis = sum(int(round(float(h.get("avg") or 0) * safe_int(h.get("qty")))) for h in holdings)
    profit = unreal + realized
    rate = round(profit / basis * 100, 2) if basis else 0.0
    today = seoul_date()
    snaps = db.setdefault("stock_day_equity", {})
    snap = snaps.get(discord_id)
    if not isinstance(snap, dict) or snap.get("day") != today:
        snap = {"day": today, "start": stock_value, "cash_flow": 0}
        snaps[discord_id] = snap
    today_pnl = stock_value - safe_int(snap.get("start")) + safe_int(snap.get("cash_flow"))
    cash_known = user.get("minecraft_money_at") is not None
    cash = max(0, safe_int(user.get("minecraft_money"))) if cash_known else None
    assets = (cash or 0) + stock_value
    return {
        "discordId": discord_id,
        "discordName": user.get("discord_username") or discord_id,
        "avatar": discord_avatar_url(discord_id, user.get("discord_avatar") or user.get("avatar")),
        "minecraftName": user.get("minecraft_name") or "",
        "linked": bool(user.get("minecraft_uuid")),
        "money": cash,
        "moneyKnown": cash_known,
        "moneyAt": safe_int(user.get("minecraft_money_at")) if cash_known else 0,
        "stockValue": stock_value,
        "assets": assets,
        "todayPnl": today_pnl,
        "unrealized": unreal,
        "realized": realized,
        "profit": profit,
        "rate": rate,
        "basis": basis,
        "volume": user_trade_volume(discord_id),
        "holdings": holdings,
    }


def stock_rankings() -> dict:
    ensure_stocks()
    ids: set[str] = set()
    for row in db.get("stock_holdings") or []:
        if safe_int(row.get("qty")) > 0 or safe_int(row.get("realized")):
            ids.add(str(row.get("discord_id") or ""))
    for trade in db.get("stock_trades") or []:
        if str(trade.get("status") or "") == "done":
            ids.add(str(trade.get("discord_id") or ""))
    ids.discard("")
    rows = []
    for did in ids:
        acc = stock_account(did)
        if acc["stockValue"] <= 0 and acc["volume"] <= 0 and acc["realized"] == 0 and not acc["moneyKnown"]:
            continue
        rows.append({
            "discordName": acc["discordName"],
            "avatar": acc["avatar"],
            "minecraftName": acc["minecraftName"],
            "assets": acc["assets"],
            "rate": acc["rate"],
            "profit": acc["profit"],
            "volume": acc["volume"],
            "moneyKnown": acc["moneyKnown"],
        })
    ordered = {
        "assets": sorted(rows, key=lambda r: -int(r["assets"]))[:20],
        "rate": sorted(rows, key=lambda r: -float(r["rate"]))[:20],
        "profit": sorted(rows, key=lambda r: -int(r["profit"]))[:20],
        "volume": sorted(rows, key=lambda r: -int(r["volume"]))[:20],
    }
    return ordered


def note_cash_flow(discord_id: str, side: str, cost: int) -> None:
    today = seoul_date()
    snaps = db.setdefault("stock_day_equity", {})
    snap = snaps.get(discord_id)
    if not isinstance(snap, dict) or snap.get("day") != today:
        snap = {"day": today, "start": 0, "cash_flow": 0}
    flow = safe_int(snap.get("cash_flow"))
    snap["cash_flow"] = flow - cost if side == "buy" else flow + cost
    snaps[discord_id] = snap


def create_stock_trade(discord_id: str, minecraft_name: str, stock_id: str, side: str, qty: int) -> tuple[dict | None, str | None]:
    expire_stock_trades()
    if side not in ("buy", "sell"):
        return None, "매수 또는 매도만 할 수 있어요."
    if qty < 1:
        return None, "수량은 1 이상이어야 해요."
    if qty > STOCK_MAX_QTY:
        return None, f"한 번에 최대 {STOCK_MAX_QTY:,}주까지 주문할 수 있어요."
    if not stock_fee_config()["trading"]:
        return None, "지금은 주식 거래가 중지되어 있어요."
    for trade in db.get("stock_trades") or []:
        if str(trade.get("discord_id") or "") == discord_id and str(trade.get("status") or "") in ("pending", "processing"):
            return None, "처리 중인 거래가 있어요. 끝난 뒤에 다시 주문해 주세요."
    ensure_stocks()
    stock = find_stock(stock_id)
    if not stock:
        return None, "없는 종목이에요."
    if safe_int(stock.get("halted")):
        return None, "이 종목은 거래가 중지되어 있어요."
    price = max(50, safe_int(stock.get("price")))
    gross = price * qty
    fee = int(round(gross * stock_fee_config()["feePct"] / 100))
    cost = gross + fee if side == "buy" else max(0, gross - fee)
    if side == "sell" and cost < 1:
        return None, "수수료를 빼면 받을 돈이 없어요."
    sid = str(stock.get("id") or "")
    if side == "sell" and stock_holding_qty(discord_id, sid) < qty:
        return None, "가진 주식이 부족해요."
    if side == "sell":
        add_stock_holding(discord_id, sid, -qty)
    recent = 0
    now = now_ms()
    for trade in db.get("stock_trades") or []:
        if str(trade.get("discord_id") or "") == discord_id and now - safe_int(trade.get("created_at")) < 600000:
            recent += 1
    flag = ""
    if gross >= 20000000 or qty >= 5000:
        flag = "large"
    elif recent >= 15:
        flag = "burst"
    trade = {
        "id": next_id(db.get("stock_trades") or []),
        "discord_id": discord_id,
        "minecraft_name": minecraft_name,
        "stock_id": sid,
        "name": stock.get("name") or sid,
        "side": side,
        "qty": qty,
        "price": price,
        "gross": gross,
        "fee": fee,
        "cost": cost,
        "status": "pending",
        "error": "",
        "flag": flag,
        "created_at": now,
    }
    db.setdefault("stock_trades", []).append(trade)
    return trade, None


def finish_stock_trade(trade_id: int, ok: bool, error: str = "", cash: int | None = None) -> dict | None:
    trade = next((t for t in db.get("stock_trades") or [] if safe_int(t.get("id")) == trade_id), None)
    if not trade or str(trade.get("status") or "") not in ("pending", "processing"):
        return trade
    did = str(trade.get("discord_id") or "")
    sid = str(trade.get("stock_id") or "")
    qty = safe_int(trade.get("qty"))
    price = safe_int(trade.get("price"))
    fee = safe_int(trade.get("fee"))
    if ok:
        trade["status"] = "done"
        trade["error"] = ""
        if trade.get("side") == "buy":
            apply_buy_fill(did, sid, qty, price)
        else:
            apply_sell_fill(did, sid, qty, price, fee)
        stock = find_stock(sid)
        if stock:
            stock["volume"] = max(0, safe_int(stock.get("volume"))) + qty
        note_cash_flow(did, str(trade.get("side") or ""), safe_int(trade.get("cost")))
    else:
        trade["status"] = "failed"
        trade["error"] = error or "마크에서 돈 처리에 실패했어요."
        if trade.get("side") == "sell":
            add_stock_holding(did, sid, qty)
    if cash is not None:
        remember_minecraft_money(str(trade.get("minecraft_name") or ""), cash)
    return trade


def stock_admin_apply(body: dict) -> tuple[dict | None, str | None]:
    ensure_stocks()
    op = str(body.get("op") or "").strip()
    if op == "settings":
        s = db.setdefault("settings", {})
        if "feePct" in body:
            try:
                fee = float(body.get("feePct") or 0)
            except (TypeError, ValueError):
                return None, "수수료는 숫자여야 해요."
            s["stock_fee_pct"] = round(max(0.0, min(10.0, fee)), 2)
        if "volatilityPct" in body:
            try:
                vol = float(body.get("volatilityPct") or 0.9)
            except (TypeError, ValueError):
                return None, "변동폭은 숫자여야 해요."
            s["stock_volatility"] = max(0.003, min(0.04, vol / 100))
        if "trading" in body:
            s["stock_trading"] = "1" if body.get("trading") else "0"
        return {"ok": True, "config": stock_fee_config()}, None
    if op == "create":
        name = str(body.get("name") or "").strip()
        if not name or len(name) > 24:
            return None, "종목 이름을 1~24자로 입력해 주세요."
        if find_stock(name):
            return None, "이미 있는 종목이에요."
        price = max(50, safe_int(body.get("price"), random.randint(1200, 86000)))
        sid = "st" + str(next_id(db.get("stocks") or []))
        row = {
            "id": sid,
            "name": name,
            "price": price,
            "prev": price,
            "prev_close": price,
            "anchor": price,
            "history": seed_stock_path(price),
            "volume": 0,
            "halted": 0,
            "day": seoul_date(),
            "day_high": price,
            "day_low": price,
            "builtin": 0,
            "updated_at": now_ms(),
        }
        db.setdefault("stocks", []).append(row)
        return {"ok": True, "stock": stock_public(row)}, None
    if op == "delete":
        stock = find_stock(str(body.get("id") or ""))
        if not stock:
            return None, "없는 종목이에요."
        sid = str(stock.get("id") or "")
        retired = {str(x) for x in (db.get("stock_retired") or [])}
        retired.add(sid)
        db["stock_retired"] = sorted(retired)
        db["stocks"] = [s for s in db.get("stocks") or [] if str(s.get("id") or "") != sid]
        return {"ok": True}, None
    if op == "price":
        stock = find_stock(str(body.get("id") or ""))
        if not stock:
            return None, "없는 종목이에요."
        nxt = safe_int(body.get("price"))
        if nxt < 50 or nxt > 100000000:
            return None, "가격은 50 이상이어야 해요."
        stock["prev"] = stock.get("price")
        stock["price"] = nxt
        stock["anchor"] = nxt  # 관리자가 정한 가격이 새 기준가 — 복귀하지 않음
        stock["base"] = nxt
        stock["updated_at"] = now_ms()
        stock["day_high"] = max(nxt, safe_int(stock.get("day_high"), nxt))
        low = safe_int(stock.get("day_low"), nxt)
        stock["day_low"] = min(nxt, low) if low > 0 else nxt
        hist = stock.get("history") if isinstance(stock.get("history"), list) else []
        hist.append(nxt)
        stock["history"] = hist[-720:]
        return {"ok": True, "stock": stock_public(stock)}, None
    if op == "halt":
        stock = find_stock(str(body.get("id") or ""))
        if not stock:
            return None, "없는 종목이에요."
        stock["halted"] = 1 if body.get("halted") else 0
        return {"ok": True, "stock": stock_public(stock)}, None
    if op == "news":
        title = str(body.get("title") or "").strip()
        text = str(body.get("body") or "").strip()
        if not title or not text:
            return None, "제목과 내용을 입력해 주세요."
        kind = str(body.get("kind") or "notice")
        sid = str(body.get("stockId") or "").strip()
        if sid and not find_stock(sid):
            return None, "없는 종목이에요."
        item = push_stock_news(title, text, kind, sid)
        return {"ok": True, "news": news_public(item)}, None
    return None, "알 수 없는 작업이에요."


def stock_ticker() -> None:
    while True:
        time.sleep(5)
        try:
            tick_stocks()
        except Exception:
            continue


def find_user_by_name(name: str) -> dict | None:
    n = (name or "").strip().lower()
    if not n:
        return None
    for u in db.get("users", []):
        if not isinstance(u, dict):
            continue
        un = str(u.get("discord_username") or u.get("username") or "").strip().lower()
        if un == n or str(u.get("discord_id") or "") == name.strip():
            return u
    return None


def user_public(u: dict | None) -> dict | None:
    if not u:
        return None
    return {
        "discord_id": str(u.get("discord_id") or ""),
        "username": u.get("discord_username") or u.get("username") or "",
        "minecraft_name": u.get("minecraft_name"),
        "avatar": u.get("discord_avatar") or u.get("avatar"),
    }


def are_friends(a: str, b: str) -> bool:
    a, b = str(a), str(b)
    for f in db.get("friendships", []):
        if f.get("status") != "accepted":
            continue
        x, y = str(f.get("from_id") or ""), str(f.get("to_id") or "")
        if {x, y} == {a, b}:
            return True
    return False


ACTION_LABELS_KO = {
    "page_view": "페이지 방문",
    "wiki_save": "위키 저장",
    "wiki_upload": "위키 이미지 업로드",
    "product_create": "상품 등록",
    "product_update": "상품 수정",
    "product_delete": "상품 삭제",
    "product_image_upload": "상품 이미지 업로드",
    "order_status": "주문 상태 변경",
    "settings_save": "사이트 설정 저장",
    "site_decorate": "본 사이트 꾸미기",
    "order_proof": "입금 증빙 사진",
    "payment_save": "결제 설정 저장",
    "grant_group": "LuckPerms 역할 부여",
    "site_edit_grant": "Team. Wildmc 권한 부여",
    "site_edit_revoke": "Team. Wildmc 권한 회수",
    "admin_web_notice": "관리자 웹 공지",
    "inquiry_create": "문의 작성",
    "inquiry_reply": "문의 답변",
    "admin_chat": "관리자 채팅",
    "nick_ticket_use": "닉네임 변경권 사용",
    "friend_request": "친구 요청",
    "friend_accept": "친구 수락",
    "friend_reject": "친구 거절",
    "chat_send": "채팅 전송",
    "broadcast": "전체 공지 발송",
    "coupon_create": "쿠폰 생성",
    "coupon_issue": "쿠폰 지급",
    "achievement_grant": "도전과제 지급",
    "achievement_reset": "도전과제 초기화",
    "user_unlink": "마크 연동 해제",
    "user_logout": "로그인 강제 해제",
    "user_delete": "회원 탈퇴 처리",
    "link_verify": "마인크래프트 계정 연동 성공했어요.",
    "login_discord": "디스코드 로그인",
    "desktop_connect": "데스크톱 연결",
    "review_write": "상품 리뷰 작성",
    "review_delete": "상품 리뷰 삭제",
    "community_post": "커뮤니티 글 작성",
    "community_comment": "커뮤니티 댓글",
    "community_like": "커뮤니티 하트",
    "community_delete": "커뮤니티 삭제",
    "data_purge": "데이터 삭제",
    "order_refund": "주문 환불",
    "order_refund_request": "환불 요청",
}


def log_activity(
    discord_id: str | None,
    action: str,
    *,
    page: str | None = None,
    detail: str | None = None,
    target_id: str | None = None,
    target_name: str | None = None,
    result: str | None = None,
    ip: str | None = None,
    meta: dict | None = None,
) -> None:
    did = str(discord_id or "").strip() or "anonymous"
    username = ""
    mc_name = ""
    group = ""
    if did and did != "anonymous":
        u = find_user(did)
        if u:
            username = str(u.get("discord_username") or u.get("username") or "")
            mc_name = str(u.get("minecraft_name") or "")
        group = user_luckperms_group(did) or ""
        if not mc_name and group:
            pass
        if u and not mc_name:
            mc_name = str(u.get("minecraft_name") or "")
    label = ACTION_LABELS_KO.get(action, action)
    bits = [label]
    if username:
        bits.append(f"· {username}")
    if mc_name:
        bits.append(f"({mc_name})")
    if group:
        bits.append(f"[{group}]")
    if target_name or target_id:
        bits.append(f"→ {target_name or target_id}")
    if detail:
        bits.append(f"· {detail}")
    if result and result not in ("ok", "success", ""):
        bits.append(f"· {result}")
    item = {
        "id": next_id(db.get("activity_logs", [])),
        "discord_id": did,
        "username": username,
        "minecraft_name": mc_name,
        "group": group,
        "action": action,
        "action_label": label,
        "page": page or "",
        "detail": (detail or "")[:800],
        "target_id": target_id or "",
        "target_name": target_name or "",
        "result": result or "ok",
        "ip": (ip or "")[:64],
        "meta": meta if isinstance(meta, dict) else {},
        "summary": " ".join(bits)[:500],
        "created_at": now_ms(),
    }
    logs = db.setdefault("activity_logs", [])
    logs.append(item)
    if len(logs) > 8000:
        del logs[:-6000]


def send_mail(discord_id: str, title: str, body: str, kind: str = "info", link_url: str | None = None) -> None:
    if not discord_id:
        return
    item = {
        "id": next_id(db.get("inbox", [])),
        "discord_id": discord_id,
        "title": title,
        "body": body,
        "kind": kind,
        "read": 0,
        "created_at": now_ms(),
        "link_url": link_url,
    }
    db.setdefault("inbox", []).append(item)


def try_unlock_all_collector(discord_id: str, *, notify: bool = True) -> dict | None:
    """나머지 도전과제를 모두 모으면 all_collector 해금. lock 안에서 호출."""
    if not discord_id:
        return None
    bag = db.get("user_achievements", {}).get(discord_id) or {}
    if ALL_COLLECTOR_ID in bag:
        return None
    if not all(x in bag for x in ALL_COLLECTOR_REQUIRED):
        return None
    return unlock_achievement(discord_id, ALL_COLLECTOR_ID, notify=notify)


def unlock_achievement(discord_id: str, ach_id: str, *, notify: bool = True) -> dict | None:
    """새로 해금되면 도전과제 dict 반환, 이미 있으면 None. lock 안에서 호출 권장."""
    if not discord_id or ach_id not in ACH_BY_ID:
        return None
    bag = db.setdefault("user_achievements", {}).setdefault(discord_id, {})
    if ach_id in bag:
        return None
    ts = now_ms()
    bag[ach_id] = {"unlocked_at": ts}
    ach = ACH_BY_ID[ach_id]
    if notify:
        send_mail(
            discord_id,
            f"도전과제 해금 · {ach['title']}",
            f"{ach.get('icon', '🏆')} {ach['desc']}\n도전과제 페이지에서 확인해 보세요.",
            "achievement",
            "/achievements",
        )
    if ach_id != ALL_COLLECTOR_ID:
        try_unlock_all_collector(discord_id, notify=notify)
    return dict(ach)


def achievements_payload(discord_id: str | None) -> dict:
    unlocked = {}
    if discord_id:
        unlocked = dict(db.get("user_achievements", {}).get(discord_id) or {})
    items = []
    for a in ACHIEVEMENTS:
        u = unlocked.get(a["id"])
        secret = bool(a.get("secret"))
        done = bool(u)
        items.append(
            {
                "id": a["id"],
                "title": a["title"] if (done or not secret) else "???",
                "desc": a["desc"] if (done or not secret) else "숨겨진 이스터에그",
                "icon": a["icon"] if (done or not secret) else "❔",
                "category": a["category"],
                "secret": secret,
                "unlocked": done,
                "unlockedAt": (u or {}).get("unlocked_at") if done else None,
            }
        )
    total = len(ACHIEVEMENTS)
    done_n = sum(1 for i in items if i["unlocked"])
    complete = ALL_COLLECTOR_ID in unlocked
    return {
        "items": items,
        "unlocked": done_n,
        "total": total,
        "percent": int(round(100 * done_n / total)) if total else 0,
        "complete": complete,
    }


def strip_color_codes(text: str) -> str:
    text = re.sub(r"&#([0-9A-Fa-f]{6})", "", text)
    text = re.sub(r"&x(?:&[0-9A-Fa-f]){6}", "", text, flags=re.I)
    text = re.sub(r"&[0-9A-Fa-fk-or]", "", text, flags=re.I)
    text = re.sub(r"<#([0-9A-Fa-f]{6})>", "", text)
    text = re.sub(r"</?[^>]+>", "", text)
    text = re.sub(r"\u00A7[0-9A-Fa-fk-or]", "", text, flags=re.I)
    return text


def validate_nick(raw: str) -> tuple[bool, str, str]:
    nick = raw.strip()
    if not nick:
        return False, "닉네임을 입력해주세요.", ""
    plain = strip_color_codes(nick)
    if not plain:
        return False, "색코드만으로는 닉네임을 설정할 수 없습니다.", ""
    if len(plain) > 5:
        return False, "RGB 색코드를 제외하고 최대 5글자까지 가능합니다.", ""
    return True, "", nick


def can_change_nick_by_rank(group: str | None) -> bool:
    shown = display_current_rank(group)
    return shown in RANK_GROUPS or str(group or "") in RANK_GROUPS


def shop_viewer_rank(group: str | None) -> str:
    shown = display_current_rank(group)
    if shown.casefold() in ("", "없음", "default", "기본", "member"):
        return ""
    return shown


def clean_price_for(raw) -> dict:
    if not isinstance(raw, dict):
        return {}
    out = {}
    for key in ("MVP", "스탠다드", "울트라"):
        n = safe_int(raw.get(key))
        if n > 0:
            out[key] = n
    return out


def apply_rank_price(product: dict | None, viewer_rank: str) -> dict | None:
    """기본 랭크는 정상가. 가진 랭크에 맞는 price_for 가 있으면 그 가격."""
    if not product:
        return product
    viewer = str(viewer_rank or "").strip()
    table = clean_price_for(product.get("price_for"))
    alt = safe_int(table.get(viewer)) if viewer else 0
    if alt <= 0:
        return product
    out = dict(product)
    out["list_price"] = safe_int(product.get("price"))
    out["price"] = alt
    return out


def buyer_shop_rank(discord_id: str) -> str:
    user = find_user(discord_id)
    group = (user or {}).get("luckperms_group")
    uuid = str((user or {}).get("minecraft_uuid") or "")
    if uuid:
        cache = (db.get("player_cache") or {}).get(uuid) or {}
        if cache.get("luckperms_group"):
            group = cache.get("luckperms_group")
    return shop_viewer_rank(group)


def display_current_rank(group: str | None) -> str:
    raw = str(group or "").strip()
    if not raw:
        return "없음"
    aliases = {
        "standard": "스탠다드",
        "ultra": "울트라",
        "mvp": "MVP",
        "owner": "오너",
        "vice_admin": "부총괄",
        "vice": "부총괄",
        "admin": "어드민",
        "guide": "가이드",
        "developer": "개발자",
        "dev": "개발자",
    }
    return aliases.get(raw.casefold(), raw)


def discord_rank_from_roles(role_ids: list[str] | None) -> str:
    have = {str(x).strip() for x in (role_ids or []) if str(x).strip()}
    if not have:
        return ""
    settings = db.get("settings") or {}
    for label, key in DISCORD_RANK_ORDER:
        rid = str(settings.get(key) or "").strip()
        if rid and rid in have:
            return label
    return ""


def fetch_discord_member_roles(discord_id: str, access_token: str | None = None) -> list[str]:
    settings = db.get("settings") or {}
    guild = str(settings.get("discord_guild_id") or os.environ.get("DISCORD_GUILD_ID") or "").strip()
    if not guild or not discord_id:
        return []
    bot = str(os.environ.get("DISCORD_BOT_TOKEN") or "").strip()
    data = None
    if bot:
        data, _ = discord_http_json(
            f"https://discord.com/api/guilds/{guild}/members/{discord_id}",
            headers={"Authorization": f"Bot {bot}"},
        )
    if (not data or not data.get("roles")) and access_token:
        data, _ = discord_http_json(
            f"https://discord.com/api/users/@me/guilds/{guild}/member",
            headers={"Authorization": f"Bearer {access_token}"},
        )
    if not data:
        return []
    return [str(x) for x in (data.get("roles") or []) if str(x).strip()]


def find_user_by_minecraft_name(name: str) -> dict | None:
    want = str(name or "").strip().casefold()
    if not want:
        return None
    for u in db.get("users", []):
        if str(u.get("minecraft_name") or "").strip().casefold() == want:
            return u
    for cache in (db.get("player_cache") or {}).values():
        if not isinstance(cache, dict):
            continue
        if str(cache.get("minecraft_name") or "").strip().casefold() == want:
            did = str(cache.get("discord_id") or "")
            if did:
                found = find_user(did)
                if found:
                    return found
    return None


def custom_cash_price(amount: int) -> int:
    rate = cash_per_won()
    return safe_int(amount) // rate


def quote_custom_product(kind: str, amount: int) -> dict | None:
    kind = str(kind or "").strip().lower()
    qty = max(0, safe_int(amount))
    min_won = custom_min_won()
    if kind in ("cash", "캐시"):
        if qty <= 0:
            return None
        rate = cash_per_won()
        price = qty // rate
        if price < min_won:
            return None
        return {
            "id": 0,
            "name": f"커스텀 캐시 {qty:,}",
            "description": f"캐시 {qty:,} · {rate}당 1원",
            "price": price,
            "currency": "KRW",
            "category": "캐시",
            "badge": "CASH",
            "cash_amount": qty,
            "gem_amount": 0,
            "voucher_count": 0,
            "rank_group": None,
            "custom_kind": "cash",
            "active": 1,
        }
    if kind in ("gem", "잼", "후원잼"):
        if qty <= 0:
            return None
        each = gem_won_each()
        price = qty * each
        if price < min_won:
            return None
        return {
            "id": 0,
            "name": f"커스텀 후원잼 {qty:,}",
            "description": f"후원잼 {qty:,} · {each}원당 1개",
            "price": price,
            "currency": "KRW",
            "category": "잼",
            "badge": "GEM",
            "cash_amount": 0,
            "gem_amount": qty,
            "voucher_count": 0,
            "rank_group": None,
            "custom_kind": "gem",
            "active": 1,
        }
    return None


def order_product(order: dict) -> dict | None:
    if order.get("custom_kind"):
        built = quote_custom_product(str(order.get("custom_kind")), safe_int(order.get("custom_amount") or order.get("cash_amount") or order.get("gem_amount")))
        if built:
            return built
        return {
            "name": order.get("product_name"),
            "cash_amount": safe_int(order.get("cash_amount")),
            "gem_amount": safe_int(order.get("gem_amount")),
            "voucher_count": safe_int(order.get("voucher_count")),
            "rank_group": order.get("rank_group"),
        }
    return next((p for p in db.get("products", []) if safe_int(p.get("id")) == safe_int(order.get("product_id"))), None)


def order_line_products(order: dict) -> list[dict]:
    """장바구니 일괄 주문이면 줄마다 지급할 상품 스냅샷을, 아니면 단일 상품을 돌려준다."""
    lines = order.get("cart_lines")
    if isinstance(lines, list) and lines:
        out: list[dict] = []
        for line in lines:
            if not isinstance(line, dict):
                continue
            qty = max(1, safe_int(line.get("qty"), 1))
            product = None
            custom_kind = str(line.get("custom_kind") or "").strip()
            if custom_kind:
                product = quote_custom_product(custom_kind, safe_int(line.get("custom_amount")))
            else:
                pid = safe_int(line.get("product_id") or line.get("id"))
                product = next((p for p in db.get("products", []) if safe_int(p.get("id")) == pid), None)
            if not product:
                product = {
                    "name": line.get("name") or "상품",
                    "cash_amount": safe_int(line.get("cash_amount")),
                    "gem_amount": safe_int(line.get("gem_amount")),
                    "voucher_count": safe_int(line.get("voucher_count")),
                    "rank_group": line.get("rank_group"),
                }
            snap = dict(product)
            snap["cash_amount"] = safe_int(product.get("cash_amount")) * qty
            snap["gem_amount"] = safe_int(product.get("gem_amount")) * qty
            snap["voucher_count"] = safe_int(product.get("voucher_count")) * qty
            out.append(snap)
        return out
    product = order_product(order)
    return [product] if product else []


def resolve_cart_items(raw_items, viewer_rank: str = "") -> tuple[list[dict], int, str] | tuple[None, None, str]:
    """장바구니 줄 → (cart_lines, total_price, title) 또는 오류."""
    if not isinstance(raw_items, list) or not raw_items:
        return None, None, "장바구니가 비어 있습니다."
    if len(raw_items) > 30:
        return None, None, "장바구니는 한 번에 최대 30개까지 결제할 수 있습니다."
    lines: list[dict] = []
    total = 0
    names: list[str] = []
    for raw in raw_items:
        if not isinstance(raw, dict):
            continue
        qty = max(1, min(99, safe_int(raw.get("qty"), 1)))
        custom_kind = str(raw.get("customKind") or raw.get("custom_kind") or "").strip()
        custom_amount = safe_int(raw.get("customAmount") or raw.get("custom_amount"))
        product = None
        if custom_kind:
            product = quote_custom_product(custom_kind, custom_amount)
            if not product:
                return None, None, f"커스텀 구매는 최소 {custom_min_won()}원입니다."
        else:
            pid = safe_int(raw.get("productId") or raw.get("id") or raw.get("product_id"))
            product = next((p for p in public_products() if safe_int(p.get("id")) == pid), None)
            if not product:
                return None, None, "장바구니에 없는 상품이 포함되어 있습니다."
            product = apply_rank_price(product, viewer_rank) or product
        unit = safe_int(product.get("price"))
        total += unit * qty
        names.append(str(product.get("name") or "상품"))
        lines.append(
            {
                "product_id": safe_int(product.get("id")),
                "name": product.get("name"),
                "price": unit,
                "qty": qty,
                "custom_kind": product.get("custom_kind"),
                "custom_amount": custom_amount if custom_kind else 0,
                "cash_amount": safe_int(product.get("cash_amount")),
                "gem_amount": safe_int(product.get("gem_amount")),
                "voucher_count": safe_int(product.get("voucher_count")),
                "rank_group": product.get("rank_group"),
            }
        )
    if not lines:
        return None, None, "장바구니가 비어 있습니다."
    title = f"장바구니 {len(lines)}건"
    if len(names) == 1:
        title = f"{names[0]}" + (f" ×{lines[0]['qty']}" if lines[0]["qty"] > 1 else "")
    elif len(names) <= 3:
        title = " + ".join(names)
    return lines, total, title


def queue_product_refund(product: dict | None, minecraft_name: str, order_code: str, restore_rank: str = "default") -> list[str]:
    name = str(minecraft_name or "").strip()
    if not product or not name:
        return []
    queued: list[str] = []
    rank = luckperms_group_id(str(product.get("rank_group") or ""))
    if rank:
        restore = str(restore_rank or "default").strip() or "default"
        if restore.casefold() == rank.casefold():
            restore = "default"
        cmd = f"lp user {name} parent set {restore}"
        queue_command(cmd, f"refund-rank:{rank}:order:{order_code}", "admin-refund")
        queued.append(cmd)
    cash = safe_int(product.get("cash_amount"))
    if cash > 0:
        cmd = f"캐시관리 뺏기 {name} {cash}"
        queue_command(cmd, f"refund-cash:{cash}:order:{order_code}", "admin-refund")
        queued.append(cmd)
    gem = safe_int(product.get("gem_amount"))
    if gem > 0:
        cmd = f"젬관리 뺏기 {name} {gem}"
        queue_command(cmd, f"refund-gem:{gem}:order:{order_code}", "admin-refund")
        queued.append(cmd)
    return queued


def reverse_grant_command(command: str, restore_rank: str = "default") -> str | None:
    parts = str(command or "").split()
    if len(parts) >= 6 and parts[0] == "lp" and parts[1] == "user" and parts[3] == "parent" and parts[4] == "set":
        restore = str(restore_rank or "default").strip() or "default"
        if restore.casefold() == parts[5].casefold():
            restore = "default"
        return f"lp user {parts[2]} parent set {restore}"
    if len(parts) >= 4 and parts[0] == "캐시관리" and parts[1] == "주기":
        return f"캐시관리 뺏기 {parts[2]} {parts[3]}"
    if len(parts) >= 4 and parts[0] == "젬관리" and parts[1] == "주기":
        return f"젬관리 뺏기 {parts[2]} {parts[3]}"
    return None


def apply_minecraft_rank(minecraft_name: str, group: str) -> None:
    user = find_user_by_minecraft_name(minecraft_name)
    if not user:
        return
    did = str(user.get("discord_id") or "")
    if did:
        upsert_user(did, luckperms_group=group)
    uuid = str(user.get("minecraft_uuid") or "")
    if uuid:
        cache = db.setdefault("player_cache", {}).setdefault(uuid, {})
        cache["luckperms_group"] = group
        cache["minecraft_name"] = user.get("minecraft_name") or minecraft_name
        cache["updated_at"] = now_ms()


def queue_player_chat(minecraft_name: str, text: str) -> None:
    name = str(minecraft_name or "").strip()
    if not name or any(ch.isspace() for ch in name):
        return
    safe = str(text or "").replace("\\", "\\\\").replace('"', '\\"')
    queue_command(f'tellraw {name} {{"text":"{safe}","color":"green"}}', "link-chat", "web")


def parse_when_ms(raw) -> int:
    if raw in (None, "", 0, "0"):
        return 0
    if isinstance(raw, (int, float)) or str(raw).strip().isdigit():
        n = int(float(raw))
        return n if n > 10_000_000_000 else n * 1000
    text = str(raw).strip()
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone(timedelta(hours=9)))
    return int(dt.timestamp() * 1000)


def promo_public(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "code": row.get("code") or "",
        "expires_at": row.get("expires_at") or 0,
        "register_until": row.get("register_until") or 0,
        "one_time": 1 if row.get("one_time") else 0,
        "cash": safe_int(row.get("cash")),
        "gem": safe_int(row.get("gem")),
        "coupon_percent": safe_int(row.get("coupon_percent")),
        "rank_group": row.get("rank_group") or "",
        "used_count": safe_int(row.get("used_count")),
        "active": 0 if row.get("active") == 0 else 1,
        "created_at": row.get("created_at") or 0,
    }


def linked_account_label(user: dict | None) -> str:
    did = str((user or {}).get("discord_id") or "").strip()
    nick = str((user or {}).get("discord_username") or (user or {}).get("username") or "").strip()
    who = " ".join(x for x in (did, nick) if x) or "계정"
    return f"({who})"


def build_promo(body: dict, existing: dict | None = None) -> dict:
    code = normalize_coupon_code((body or {}).get("code") or (existing or {}).get("code") or "") or generate_code()
    rank = str((body or {}).get("rank_group") or (body or {}).get("rank") or "").strip()
    if rank not in ("", "스탠다드", "울트라", "MVP"):
        rank = ""
    item = dict(existing or {})
    item.update(
        {
            "code": code,
            "expires_at": parse_when_ms((body or {}).get("expires_at") if "expires_at" in (body or {}) or "expiresAt" in (body or {}) else item.get("expires_at")),
            "register_until": parse_when_ms((body or {}).get("register_until") if "register_until" in (body or {}) or "registerUntil" in (body or {}) else item.get("register_until")),
            "one_time": 1 if (body or {}).get("one_time") or (body or {}).get("oneTime") else 0,
            "cash": max(0, safe_int((body or {}).get("cash"))),
            "gem": max(0, safe_int((body or {}).get("gem"))),
            "coupon_percent": max(0, min(100, safe_int((body or {}).get("coupon_percent") if (body or {}).get("coupon_percent") is not None else (body or {}).get("couponPercent")))),
            "rank_group": rank,
            "active": 0 if (body or {}).get("active") == 0 else 1,
        }
    )
    item.setdefault("used_by", [])
    item.setdefault("used_count", 0)
    item.setdefault("created_at", now_ms())
    return item
    did = str((user or {}).get("discord_id") or "").strip()
    nick = str((user or {}).get("discord_username") or (user or {}).get("username") or "").strip()
    who = " ".join(x for x in (did, nick) if x) or "계정"
    return f"({who})"


def redeem_promo_code(discord_id: str, raw_code: str) -> tuple[str | None, str | None]:
    code = normalize_coupon_code(raw_code)
    if not code:
        return None, "코드를 입력해 주세요."
    row = next((c for c in db.get("promo_codes", []) if normalize_coupon_code(c.get("code") or "") == code), None)
    if not row or int(row.get("active", 1) or 0) == 0:
        return None, "없는 코드예요."
    now = now_ms()
    exp = safe_int(row.get("expires_at"))
    if exp and exp < now:
        return None, "만료된 코드예요."
    reg = safe_int(row.get("register_until"))
    if reg and reg < now:
        return None, "코드 등록 기간이 끝났어요."
    used_by = [str(x) for x in (row.get("used_by") or [])]
    if discord_id in used_by:
        return None, "이미 등록한 코드예요."
    if row.get("one_time") and safe_int(row.get("used_count")) > 0:
        return None, "이미 사용된 일회용 코드예요."
    user = find_user(discord_id)
    mc = str((user or {}).get("minecraft_name") or "").strip()
    cash = safe_int(row.get("cash"))
    gem = safe_int(row.get("gem"))
    rank = str(row.get("rank_group") or "").strip()
    pct = safe_int(row.get("coupon_percent"))
    if (cash or gem or rank) and not mc:
        return None, "마인크래프트 계정을 연동한 뒤 등록해 주세요."
    grants: list[str] = []
    if cash and mc:
        queue_command(f"캐시관리 주기 {mc} {cash}", f"promo-cash:{code}", discord_id)
        grants.append(f"캐시 {cash:,}")
    if gem and mc:
        queue_command(f"젬관리 주기 {mc} {gem}", f"promo-gem:{code}", discord_id)
        grants.append(f"잼 {gem:,}")
    if pct:
        issued = grant_personal_coupon(discord_id, f"코드 할인 {pct}%", pct, f"promo{code}")
        if issued:
            grants.append(f"{pct}% 할인 쿠폰 {issued}")
    if rank and mc:
        queue_command(f"lp user {mc} parent set {rank}", f"promo-rank:{rank}:{code}", discord_id)
        apply_minecraft_rank(mc, rank)
        grants.append(f"랭크 {rank}")
    if not grants:
        return None, "이 코드에 지급 내용이 없어요."
    row.setdefault("used_by", []).append(discord_id)
    row["used_count"] = safe_int(row.get("used_count")) + 1
    send_mail(discord_id, "코드 등록", " · ".join(grants), "coupon", "/code")
    return "등록됐어요. " + " · ".join(grants), None


def queue_command(command: str, reason: str, requested_by: str) -> None:
    db.setdefault("command_queue", []).append(
        {
            "id": next_id(db.get("command_queue", [])),
            "command": command,
            "reason": reason,
            "requested_by": requested_by,
            "created_at": now_ms(),
            "processed": 0,
            "processed_at": None,
        }
    )


def grant_luckperms_group(discord_id: str, group: str, requested_by: str = "desktop-admin") -> dict:
    """Queue LP parent set and mirror group on user + player_cache."""
    user = find_user(discord_id)
    if not user:
        raise ValueError("해당 유저를 찾을 수 없습니다.")
    mc_name = str(user.get("minecraft_name") or "").strip()
    mc_uuid = str(user.get("minecraft_uuid") or "").strip()
    if not mc_name or not mc_uuid:
        raise ValueError("마크 연동이 된 유저만 역할을 부여할 수 있습니다.")
    group = str(group or "").strip()
    if not group:
        raise ValueError("그룹 이름이 필요합니다.")
    cmd = f"lp user {mc_name} parent set {group}"
    queue_command(cmd, f"group:{group}", requested_by)
    upsert_user(discord_id, luckperms_group=group)
    cache = db.setdefault("player_cache", {}).setdefault(mc_uuid, {})
    cache["luckperms_group"] = group
    cache["minecraft_name"] = mc_name
    cache["updated_at"] = now_ms()
    log_activity(
        requested_by,
        "grant_group",
        page="/admin/users",
        target_id=discord_id,
        target_name=str(user.get("discord_username") or mc_name),
        detail=f"{group} → {mc_name}",
    )
    return {"command": cmd, "group": group, "minecraft_name": mc_name, "discord_id": discord_id}


def luckperms_group_id(rank: str) -> str:
    """Shop rank_group → LuckPerms parent set 이름. MVP는 플러그인/서버 그룹 id 그대로."""
    return str(rank or "").strip()


def queue_product_fulfillment(product: dict | None, minecraft_name: str, order_code: str, requested_by: str = "admin-fulfill") -> list[str]:
    """ServerBridge CommandPoller가 콘솔로 실행할 지급 명령을 큐에 넣는다.

    플러그인 계약:
    - 랭크: lp user <player> parent set <group>  (MVP는 parent set MVP)
    - 캐시: 캐시관리 주기 <player> <amount>
    - 젬: 젬관리 주기 <player> <amount>
    닉네임 변경권은 웹 티켓으로 지급하고, 사용 시 NicknameService가 `nick <새닉> <player>` 를 실행한다.
    """
    name = str(minecraft_name or "").strip()
    if not product or not name:
        return []
    queued: list[str] = []
    rank = luckperms_group_id(str(product.get("rank_group") or ""))
    if rank:
        cmd = f"lp user {name} parent set {rank}"
        queue_command(cmd, f"rank:{rank}:order:{order_code}", requested_by)
        queued.append(cmd)
    cash = safe_int(product.get("cash_amount"))
    if cash > 0:
        cmd = f"캐시관리 주기 {name} {cash}"
        queue_command(cmd, f"cash:{cash}:order:{order_code}", requested_by)
        queued.append(cmd)
    gem = safe_int(product.get("gem_amount"))
    if gem > 0:
        cmd = f"젬관리 주기 {name} {gem}"
        queue_command(cmd, f"gem:{gem}:order:{order_code}", requested_by)
        queued.append(cmd)
    return queued


THEME_CATALOG: dict[str, dict] = {
    "default": {"id": "default", "label": "기본", "emoji": "", "hint": "", "fx": "", "icons": []},
    "christmas": {
        "id": "christmas", "label": "크리스마스", "emoji": "🎄", "hint": "눈 내리는 숲의 연말", "fx": "snow",
        "icons": ["🎄", "❄", "⭐", "🎁", "🔔", "☃", "✨"],
    },
    "newyear": {
        "id": "newyear", "label": "새해", "emoji": "✨", "hint": "자정이 여는 새해", "fx": "spark",
        "icons": ["✨", "🎉", "🎊", "⭐", "💫", "🎆", "🥂"],
    },
    "valentine": {
        "id": "valentine", "label": "발렌타인", "emoji": "♡", "hint": "달콤한 분홍빛 하루", "fx": "petal",
        "icons": ["♡", "♥", "💌", "🌹", "🍫", "🎀", "✨"],
    },
    "childrens": {
        "id": "childrens", "label": "어린이날", "emoji": "🎈", "hint": "하늘빛 놀이 하루", "fx": "spark",
        "icons": ["🎈", "🎠", "🪁", "🧸", "🌈", "🍭", "⭐"],
    },
    "chuseok": {
        "id": "chuseok", "label": "추석", "emoji": "🌕", "hint": "보름달 아래 한가위", "fx": "petal",
        "icons": ["🌕", "🌾", "🍂", "🐰", "⭐", "🏮", "🍡"],
    },
    "halloween": {
        "id": "halloween", "label": "할로윈", "emoji": "🎃", "hint": "보랏빛 호박의 밤", "fx": "ember",
        "icons": ["🎃", "🦇", "👻", "🕸", "🌕", "🍬", "✨"],
    },
}

CHUSEOK_WINDOWS = {
    2025: (10, 5, 10, 8),
    2026: (9, 24, 9, 27),
    2027: (9, 14, 9, 17),
    2028: (10, 2, 10, 5),
    2029: (9, 21, 9, 24),
    2030: (9, 11, 9, 14),
}


def _md_in_range(month: int, day: int, start: tuple[int, int], end: tuple[int, int]) -> bool:
    cur = month * 100 + day
    a = start[0] * 100 + start[1]
    b = end[0] * 100 + end[1]
    if a <= b:
        return a <= cur <= b
    return cur >= a or cur <= b


def auto_theme_id_for_date(year: int, month: int, day: int) -> str:
    windows = [
        ("christmas", (12, 1), (12, 26)),
        ("newyear", (12, 31), (12, 31)),
        ("newyear", (1, 1), (1, 3)),
        ("valentine", (2, 10), (2, 15)),
        ("childrens", (5, 3), (5, 7)),
        ("halloween", (10, 25), (10, 31)),
    ]
    for tid, start, end in windows:
        if _md_in_range(month, day, start, end):
            return tid
    ch = CHUSEOK_WINDOWS.get(year)
    if ch:
        sm, sd, em, ed = ch
        if _md_in_range(month, day, (sm, sd), (em, ed)):
            return "chuseok"
    return "default"


def resolve_theme(settings: dict | None = None) -> dict:
    s = settings if isinstance(settings, dict) else (db.get("settings") or {})
    mode = str(s.get("theme_mode") or "auto").strip().lower()
    manual = str(s.get("theme_id") or "default").strip().lower()
    now = datetime.now(timezone(timedelta(hours=9)))
    auto_id = auto_theme_id_for_date(now.year, now.month, now.day)
    if mode == "off":
        tid = "default"
    elif mode == "manual" and manual in THEME_CATALOG:
        tid = manual
    else:
        tid = auto_id
    meta = dict(THEME_CATALOG.get(tid) or THEME_CATALOG["default"])
    meta["mode"] = mode if mode in ("auto", "manual", "off") else "auto"
    meta["autoId"] = auto_id
    meta["catalog"] = [
        {
            "id": k,
            "label": v["label"],
            "emoji": v.get("emoji") or "",
            "hint": v.get("hint") or "",
            "fx": v.get("fx") or "",
            "icons": list(v.get("icons") or []),
        }
        for k, v in THEME_CATALOG.items()
    ]
    return meta


def payment_settings() -> dict:
    return dict(db.get("payment") or {})


def payment_payload() -> dict:
    s = payment_settings()
    return {
        "bankName": s.get("bank_name") or "",
        "bankAccount": s.get("bank_account") or "",
        "bankHolder": s.get("bank_holder") or "",
        "tossLink": s.get("toss_link") or "",
        "notice": s.get("payment_notice") or "",
    }


def payment_agencies() -> list:
    try:
        raw = json.loads(payment_settings().get("agencies") or "[]")
        if isinstance(raw, list):
            return [a for a in raw if a and a.get("enabled", True) is not False and a.get("link") and a.get("name")]
    except Exception:
        pass
    return []


def make_order_code() -> str:
    s = "".join(secrets.choice(ALPHABET) for _ in range(8))
    return f"ORD-{s[:4]}-{s[4:]}"


def normalize_coupon_code(raw: str) -> str:
    return re.sub(r"[^A-Za-z0-9\-]", "", str(raw or "").strip().upper())


def parse_optional_ts(raw) -> int | None:
    if raw in (None, "", 0, "0"):
        return None
    try:
        return int(raw)
    except Exception:
        return None


def coupon_value_from_body(ctype: str, raw) -> int:
    value = float(raw or 0)
    return int(round(value))


def find_coupon(code: str) -> dict | None:
    c = normalize_coupon_code(code)
    if not c:
        return None
    for row in db.get("coupons", []):
        if normalize_coupon_code(row.get("code") or "") == c:
            return row
    return None


def apply_coupon_discount(price: int, coupon: dict) -> tuple[int, int]:
    """returns (final_price, discount_amount)"""
    price = max(0, int(price or 0))
    ctype = str(coupon.get("type") or "percent")
    value = float(coupon.get("value") or 0)
    if ctype == "fixed":
        discount = min(price, max(0, int(round(value))))
    else:
        pct = max(0.0, min(100.0, value))
        discount = min(price, int(round(price * pct / 100.0)))
    return max(0, price - discount), discount


def claim_slots_remaining(coupon: dict) -> int:
    limit = int(coupon.get("max_uses") or 0)
    claimed = int(coupon.get("claimed_count") or 0)
    if limit <= 0:
        return 0
    return max(0, limit - claimed)


def user_already_claimed(discord_id: str, parent_id: int) -> bool:
    for row in db.get("coupon_claims", []):
        if int(row.get("parent_id") or 0) == parent_id and str(row.get("discord_id") or "") == discord_id:
            return True
    return False


def public_claimable_coupons(discord_id: str | None = None) -> list[dict]:
    now = now_ms()
    out: list[dict] = []
    for c in db.get("coupons", []):
        if int(c.get("claimable") or 0) != 1:
            continue
        if int(c.get("active", 1) or 0) == 0:
            continue
        reg = int(c.get("register_until") or 0)
        if reg and reg < now:
            continue
        exp = int(c.get("expires_at") or 0)
        if exp and exp < now:
            continue
        remaining = claim_slots_remaining(c)
        cid = int(c.get("id") or 0)
        claimed = bool(discord_id and user_already_claimed(discord_id, cid))
        out.append(
            {
                "id": cid,
                "name": c.get("name") or "",
                "type": c.get("type") or "percent",
                "value": c.get("value"),
                "remaining": remaining,
                "max": int(c.get("max_uses") or 0),
                "claimed": claimed,
                "downloaded": bool(discord_id and (claimed or wallet_has(discord_id, cid))),
                "min_price": int(c.get("min_price") or 0),
                "expires_at": c.get("expires_at"),
                "register_until": c.get("register_until"),
            }
        )
    out.sort(key=lambda x: -int(x.get("id") or 0))
    return out



def wallet_has(discord_id: str, coupon_id: int) -> bool:
    for row in db.get("coupon_wallet", []):
        if str(row.get("discord_id") or "") == discord_id and int(row.get("coupon_id") or 0) == coupon_id:
            return True
    return False


def add_to_wallet(discord_id: str, coupon: dict, code: str | None = None) -> dict:
    item = {
        "id": next_id(db.get("coupon_wallet", [])),
        "discord_id": discord_id,
        "coupon_id": int(coupon.get("id") or 0),
        "code": normalize_coupon_code(code or coupon.get("code") or ""),
        "name": coupon.get("name") or "",
        "type": coupon.get("type") or "percent",
        "value": coupon.get("value"),
        "downloaded_at": now_ms(),
        "used_at": None,
    }
    db.setdefault("coupon_wallet", []).append(item)
    return item


def wallet_coupons_for(discord_id: str, product_id: int | None = None, price: int | None = None) -> list[dict]:
    now = now_ms()
    out: list[dict] = []
    for w in db.get("coupon_wallet", []):
        if str(w.get("discord_id") or "") != discord_id:
            continue
        if w.get("used_at"):
            continue
        coupon = next((c for c in db.get("coupons", []) if int(c.get("id") or 0) == int(w.get("coupon_id") or 0)), None)
        if not coupon and w.get("code"):
            coupon = find_coupon(str(w.get("code")))
        if not coupon:
            continue
        if int(coupon.get("active", 1) or 0) == 0:
            continue
        exp = int(coupon.get("expires_at") or 0)
        if exp and exp < now:
            continue
        if product_id is not None:
            pids = coupon.get("product_ids") or []
            if pids and product_id not in [safe_int(x) for x in pids]:
                continue
        if price is not None:
            min_price = int(coupon.get("min_price") or 0)
            if min_price and price < min_price:
                continue
        out.append(
            {
                "walletId": w.get("id"),
                "id": coupon.get("id"),
                "code": normalize_coupon_code(w.get("code") or coupon.get("code") or ""),
                "name": coupon.get("name") or w.get("name") or "",
                "type": coupon.get("type") or "percent",
                "value": coupon.get("value"),
                "min_price": int(coupon.get("min_price") or 0),
            }
        )
    out.sort(key=lambda x: -float(x.get("value") or 0))
    return out


def validate_coupon_for_order(

    code: str,
    *,
    product: dict,
    discord_id: str | None = None,
    consume: bool = False,
    order_code: str | None = None,
) -> tuple[dict | None, dict | None, str | None]:
    """
    Returns (coupon, pricing, error).
    pricing = {original, discount, final, code, name, type, value}
    """
    coupon = find_coupon(code)
    if not coupon:
        return None, None, "유효하지 않은 쿠폰 코드입니다."
    if int(coupon.get("claimable") or 0) == 1:
        return None, None, "선착순 쿠폰은 '쿠폰받기'에서 받은 개인 코드로 사용하세요."
    if int(coupon.get("active", 1) or 0) == 0:
        return None, None, "비활성화된 쿠폰입니다."
    reg = int(coupon.get("register_until") or 0)
    if reg and reg < now_ms():
        return None, None, "쿠폰 등록 기간이 마감되었습니다."
    exp = int(coupon.get("expires_at") or 0)
    if exp and exp < now_ms():
        return None, None, "쿠폰 사용 기간이 만료되었습니다."
    max_uses = int(coupon.get("max_uses") or 0)
    used = int(coupon.get("used_count") or 0)
    if max_uses > 0 and used >= max_uses:
        return None, None, "사용 횟수가 소진된 쿠폰입니다."
    price = int(product.get("price") or 0)
    min_price = int(coupon.get("min_price") or 0)
    if min_price and price < min_price:
        return None, None, f"이 쿠폰은 {min_price:,}원 이상 상품에만 사용할 수 있습니다."
    pids = coupon.get("product_ids") or []
    if isinstance(pids, list) and pids:
        try:
            allowed = {int(x) for x in pids}
        except Exception:
            allowed = set()
        if int(product.get("id") or 0) not in allowed:
            return None, None, "이 상품에는 사용할 수 없는 쿠폰입니다."
    if discord_id:
        assigned = str(coupon.get("assigned_discord_id") or "").strip()
        if assigned and assigned != discord_id:
            return None, None, "이 쿠폰은 지정된 유저만 사용할 수 있습니다."
        per_user = int(coupon.get("per_user") or 1)
        if per_user > 0:
            mine = sum(
                1
                for r in db.get("coupon_redemptions", [])
                if r.get("coupon_id") == coupon.get("id") and r.get("discord_id") == discord_id
            )
            if mine >= per_user:
                return None, None, "이미 이 쿠폰을 사용하셨습니다."
    elif str(coupon.get("assigned_discord_id") or "").strip():
        return None, None, "로그인한 유저만 이 쿠폰을 사용할 수 있습니다."
    final, discount = apply_coupon_discount(price, coupon)
    if discount <= 0:
        return None, None, "할인 금액이 없습니다."
    pricing = {
        "original": price,
        "discount": discount,
        "final": final,
        "code": normalize_coupon_code(coupon.get("code") or ""),
        "name": coupon.get("name") or "",
        "type": coupon.get("type") or "percent",
        "value": coupon.get("value"),
        "couponId": coupon.get("id"),
    }
    if consume:
        coupon["used_count"] = used + 1
        db.setdefault("coupon_redemptions", []).append(
            {
                "id": next_id(db.get("coupon_redemptions", [])),
                "coupon_id": coupon.get("id"),
                "code": pricing["code"],
                "discord_id": discord_id,
                "product_id": product.get("id"),
                "order_code": order_code,
                "discount": discount,
                "created_at": now_ms(),
            }
        )
        if discord_id:
            code_n = pricing["code"]
            cid = int(coupon.get("id") or 0)
            for w in db.get("coupon_wallet", []):
                if str(w.get("discord_id") or "") != discord_id:
                    continue
                if w.get("used_at"):
                    continue
                if int(w.get("coupon_id") or 0) == cid or normalize_coupon_code(w.get("code") or "") == code_n:
                    w["used_at"] = now_ms()
                    break
    return coupon, pricing, None


def six_digit_code() -> str:
    return str(secrets.randbelow(900000) + 100000)


def find_order_by_code(code: str) -> dict | None:
    c = code.strip().upper()
    for o in db.get("orders", []):
        if str(o.get("order_code") or "").upper() == c:
            return o
    return None


def seoul_month(ms: int | None = None) -> str:
    if ms:
        dt = datetime.fromtimestamp(max(0, int(ms)) / 1000, timezone(timedelta(hours=9)))
    else:
        dt = datetime.now(timezone(timedelta(hours=9)))
    return dt.strftime("%Y-%m")


def order_support_ms(order: dict) -> int:
    return safe_int(order.get("paid_at") or order.get("fulfilled_at") or order.get("created_at"))


def donation_months_for(discord_id: str) -> set[str]:
    months: set[str] = set()
    for order in db.get("orders") or []:
        if str(order.get("discord_id") or "") != discord_id:
            continue
        if str(order.get("status") or "") not in ("paid", "fulfilled"):
            continue
        months.add(seoul_month(order_support_ms(order)))
    return months


def donation_streak(discord_id: str) -> int:
    months = donation_months_for(discord_id)
    now = datetime.now(timezone(timedelta(hours=9)))
    year, month = now.year, now.month
    key = f"{year:04d}-{month:02d}"
    if key not in months:
        month -= 1
        if month == 0:
            month, year = 12, year - 1
    streak = 0
    while streak < 48:
        key = f"{year:04d}-{month:02d}"
        if key not in months:
            break
        streak += 1
        month -= 1
        if month == 0:
            month, year = 12, year - 1
    return streak


def month_donation_report(month: str | None = None) -> dict:
    month = month or seoul_month()
    goal = max(1, safe_int((db.get("settings") or {}).get("month_goal_won"), 1_000_000))
    buckets: dict[str, dict] = {}
    for order in db.get("orders") or []:
        if str(order.get("status") or "") not in ("paid", "fulfilled"):
            continue
        if seoul_month(order_support_ms(order)) != month:
            continue
        did = str(order.get("discord_id") or "").strip()
        if not did:
            continue
        row = buckets.setdefault(did, {"won": 0, "count": 0, "dc": "", "mc": ""})
        row["won"] += max(0, safe_int(order.get("price")))
        row["count"] += 1
        if order.get("discord_username"):
            row["dc"] = str(order.get("discord_username") or "")
        if not order.get("gift") and order.get("minecraft_name"):
            row["mc"] = str(order.get("minecraft_name") or "")
    donors = []
    total = 0
    for did, info in sorted(buckets.items(), key=lambda kv: -kv[1]["won"]):
        total += info["won"]
        user = find_user(did)
        donors.append(
            {
                "discordId": did,
                "discordName": str((user or {}).get("discord_username") or info["dc"] or did),
                "minecraftName": str((user or {}).get("minecraft_name") or info["mc"] or ""),
                "won": info["won"],
                "count": info["count"],
                "streak": donation_streak(did),
            }
        )
    percent = round((total / goal) * 100, 2) if goal else 0.0
    return {"month": month, "goal": goal, "total": total, "percent": percent, "donors": donors}


def user_purchase_summary(discord_id: str) -> dict:
    rows = []
    total = 0
    for order in reversed(db.get("orders") or []):
        if str(order.get("discord_id") or "") != discord_id:
            continue
        price = max(0, safe_int(order.get("price")))
        status = str(order.get("status") or "")
        if status in ("paid", "fulfilled"):
            total += price
        rows.append(
            {
                "code": order.get("order_code") or "",
                "name": order.get("product_name") or "",
                "price": price,
                "status": status,
                "coupon": order.get("coupon_code") or "",
                "discount": safe_int(order.get("discount_amount")),
                "at": order.get("created_at"),
            }
        )
    return {"totalWon": total, "orders": rows[:40]}


def grant_personal_coupon(discord_id: str, name: str, percent: int, source: str) -> str | None:
    if any(str(w.get("discord_id") or "") == discord_id and str(w.get("source") or "") == source for w in db.get("coupon_wallet") or []):
        return None
    code = f"{source[:4].upper()}{str(discord_id)[-4:]}{safe_int(now_ms()) % 10000:04d}"
    coupon = {
        "id": next_id(db.get("coupons", [])),
        "name": name,
        "code": code,
        "type": "percent",
        "value": max(1, min(100, int(percent))),
        "active": 1,
        "claimable": 0,
        "max_uses": 1,
        "used_count": 0,
        "min_price": 0,
        "created_at": now_ms(),
    }
    db.setdefault("coupons", []).append(coupon)
    item = add_to_wallet(discord_id, coupon, code)
    item["source"] = source
    return code


def grant_support_bonus(discord_ids: list[str], kind: str, amount: int, direction: str = "give") -> list[str]:
    done: list[str] = []
    kind = str(kind or "").strip()
    amount = max(0, int(amount or 0))
    take = str(direction or "give") == "take"
    verb = "뺏기" if take else "주기"
    for did in discord_ids:
        did = str(did or "").strip()
        if not did:
            continue
        user = find_user(did)
        mc = str((user or {}).get("minecraft_name") or "").strip()
        if kind == "coupon" and not take:
            code = grant_personal_coupon(did, f"후원 보너스 {amount}%", amount or 10, f"bonus{seoul_month()}")
            if code:
                send_mail(did, "후원 보너스 쿠폰", f"{amount}% 할인 쿠폰 {code} 이 지급되었습니다.", "coupon", "/coupon")
                done.append(did)
        elif kind in ("cash", "gem") and mc and amount > 0:
            cmd = f"{'캐시관리' if kind == 'cash' else '젬관리'} {verb} {mc} {amount}"
            queue_command(cmd, f"support-bonus:{kind}:{verb}:{amount}", "desktop-admin")
            label = "캐시" if kind == "cash" else "후원젬"
            action = "회수" if take else "지급"
            send_mail(did, f"{label} {action}", f"{mc} 님에게 {label} {amount:,} {action}가 마크 서버 대기열에 들어갔습니다.", "order_done", "/panel")
            done.append(did)
    return done


def donation_ranking(limit: int = 3) -> list[dict]:
    totals: dict[str, dict] = {}
    for o in db.get("orders") or []:
        if str(o.get("status") or "") not in ("paid", "fulfilled"):
            continue
        did = str(o.get("discord_id") or "").strip()
        if not did:
            continue
        row = totals.setdefault(did, {"won": 0, "last": 0, "mc": "", "dc": ""})
        row["won"] += max(0, safe_int(o.get("price")))
        row["last"] = max(
            row["last"],
            safe_int(o.get("fulfilled_at") or o.get("paid_at") or o.get("updated_at") or o.get("created_at")),
        )
        if not row["dc"] and o.get("discord_username"):
            row["dc"] = str(o.get("discord_username") or "")
        own_mc = "" if o.get("gift") else str(o.get("minecraft_name") or "")
        if own_mc and not row["mc"]:
            row["mc"] = own_mc
    ranked = sorted(totals.items(), key=lambda kv: (-kv[1]["won"], -kv[1]["last"]))[: max(0, limit)]
    out: list[dict] = []
    for i, (did, info) in enumerate(ranked, 1):
        user = find_user(did)
        mc_name = str((user or {}).get("minecraft_name") or info["mc"] or "").strip() or "아직 연동되지 않았어요."
        mc_uuid = str((user or {}).get("minecraft_uuid") or "").strip()
        dc_name = str((user or {}).get("discord_username") or info["dc"] or "").strip() or "—"
        key = mc_uuid or (mc_name if mc_name != "아직 연동되지 않았어요." else "")
        out.append(
            {
                "place": i,
                "discordId": did,
                "discordName": dc_name,
                "minecraftName": mc_name,
                "minecraftUuid": mc_uuid or None,
                "skinUrl": f"https://mc-heads.net/body/{key}/right" if key else "",
                "totalWon": info["won"],
            }
        )
    return out


def user_wallet(user: dict | None, cache: dict | None) -> dict:
    user = user or {}
    cache = cache or {}

    def one(user_key: str, at_key: str, cache_key: str) -> tuple[int | None, bool]:
        if user.get(at_key) is not None:
            return max(0, safe_int(user.get(user_key))), True
        if cache.get(cache_key) is not None:
            return max(0, safe_int(cache.get(cache_key))), True
        return None, False

    cash, cash_known = one("minecraft_cash", "minecraft_cash_at", "cash")
    gem, gem_known = one("minecraft_gem", "minecraft_gem_at", "gem")
    money, money_known = one("minecraft_money", "minecraft_money_at", "money")
    return {
        "cash": cash,
        "cashKnown": cash_known,
        "gem": gem,
        "gemKnown": gem_known,
        "money": money,
        "moneyKnown": money_known,
    }


def me_payload(session: dict | None) -> tuple[int, dict]:
    if not session or not session.get("discordId"):
        return 401, {"authenticated": False}
    discord_id = session["discordId"]
    user = find_user(discord_id)
    group = (user or {}).get("luckperms_group")
    mc_uuid = (user or {}).get("minecraft_uuid")
    mc_name = (user or {}).get("minecraft_name")
    if mc_uuid:
        cache = db.get("player_cache", {}).get(mc_uuid) or {}
        if cache.get("luckperms_group"):
            group = cache["luckperms_group"]
        if cache.get("minecraft_name"):
            mc_name = cache["minecraft_name"]
    unread = sum(1 for m in db.get("inbox", []) if m.get("discord_id") == discord_id and not m.get("read"))
    # 이미 전부 모은 유저에게 all_collector 소급 해금
    with lock:
        if try_unlock_all_collector(discord_id):
            save_db(db)
        if ensure_nick_tickets_from_orders():
            save_db(db)
        ach = achievements_payload(discord_id)
    return 200, {
        "authenticated": True,
        "discord": {
            "id": discord_id,
            "username": session.get("username"),
            "avatar": session.get("avatar"),
            "rank": discord_rank_from_roles((user or {}).get("discord_roles") or session.get("discordRoles")),
        },
        "minecraft": (
            {
                "uuid": mc_uuid,
                "name": mc_name,
                "group": group,
                "rank": display_current_rank(group),
                "linkedAt": (user or {}).get("linked_at"),
            }
            if mc_uuid
            else None
        ),
        "currentRank": display_current_rank(group) if mc_uuid else "아직 연동되지 않았어요.",
        "rankGroup": shop_viewer_rank(group) if mc_uuid else "",
        "canRankNick": can_change_nick_by_rank(group),
        "isWebAdmin": is_web_admin(session),
        "isTeamWildmc": is_team_wildmc(session),
        "canEditSite": can_edit_site(session),
        "siteEditVia": site_edit_via(session),
        "nickTickets": nick_ticket_count(discord_id),
        "inboxUnread": unread,
        "achievements": {
            "unlocked": ach["unlocked"],
            "total": ach["total"],
            "complete": ach["complete"],
        },
        "wallet": user_wallet(user, db.get("player_cache", {}).get(mc_uuid) if mc_uuid else None),
    }


def next_id(items: list) -> int:
    return max((safe_int(x.get("id")) for x in items), default=0) + 1


def public_products() -> list:
    stats = review_stats_map()
    items = []
    for p in db.get("products", []):
        if safe_int(p.get("active"), 1) == 0:
            continue
        row = dict(p)
        info = stats.get(safe_int(p.get("id"))) or {"count": 0, "avg": 0}
        row["review_count"] = info["count"]
        row["review_avg"] = info["avg"]
        items.append(row)
    items.sort(
        key=lambda p: (
            -safe_int(p.get("featured")),
            safe_int(p.get("sort_order")),
            -safe_int(p.get("id")),
        )
    )
    return items


def public_notices() -> list:
    items = [n for n in db.get("notices", []) if safe_int(n.get("active"), 1) != 0]
    items.sort(key=lambda n: (-safe_int(n.get("pinned")), -safe_int(n.get("id"))))
    return items


def public_banner():
    banners = [b for b in db.get("banners", []) if safe_int(b.get("active"), 1) != 0]
    banners.sort(key=lambda b: (safe_int(b.get("sort_order")), -safe_int(b.get("id"))))
    return banners[0] if banners else None


def admin_stats() -> dict:
    users = db.get("users", [])
    linked = [u for u in users if u.get("minecraft_uuid")]
    unlinked = [u for u in users if not u.get("minecraft_uuid")]
    products = db.get("products", [])
    banners = db.get("banners", [])
    orders = db.get("orders", [])
    return {
        "linkedUsers": len(linked),
        "loggedIn": len(users),
        "unlinked": len(unlinked),
        "products": len(products),
        "activeProducts": len([p for p in products if p.get("active", 1) != 0]),
        "activeBanners": len([b for b in banners if b.get("active", 1) != 0]),
        "pendingOrders": len([o for o in orders if o.get("status") == "pending"]),
    }


def order_counts() -> dict:
    orders = db.get("orders", [])
    out = {"pending": 0, "paid": 0, "fulfilled": 0, "cancelled": 0, "refunded": 0}
    for o in orders:
        st = o.get("status") or "pending"
        if st in out:
            out[st] += 1
    return out


def cors(handler: BaseHTTPRequestHandler) -> None:
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type, x-admin-key, x-api-key, Authorization")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
    handler.send_header("Access-Control-Max-Age", "86400")
    # 프록시/CDN rate-limit 오인 완화용 힌트 (앱 자체는 429를 내지 않음)
    handler.send_header("X-RateLimit-Limit", "unlimited")
    handler.send_header("X-WILDMC-No-RateLimit", "1")


def generate_code(groups: int = 2, group_len: int = 4) -> str:
    return "-".join("".join(secrets.choice(ALPHABET) for _ in range(group_len)) for _ in range(groups))


def hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()


def get_stats() -> dict:
    today = seoul_date()
    with lock:
        if db["peakToday"].get("date") != today:
            db["peakToday"] = {"date": today, "count": 0}
        online = sum(1 for p in live_players.values() if p.get("online"))
        if online > db["peakToday"]["count"]:
            db["peakToday"]["count"] = online
            save_db(db)
        week_ago = datetime.now(timezone.utc).timestamp() * 1000 - 7 * 24 * 60 * 60 * 1000
        today_joins = sum(1 for j in db["joins"] if j.get("date") == today)
        week_joins = sum(1 for j in db["joins"] if j.get("at", 0) >= week_ago)
        return {
            "pluginOnline": plugin_online,
            "online": online,
            "peakToday": db["peakToday"]["count"],
            "joinsToday": today_joins,
            "joinsWeek": week_joins,
            "siteName": SITE,
            "serverMetrics": dict(server_metrics),
        }


MARKET_HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>WILDMC 주식</title>
<link href="https://fonts.googleapis.com/css2?family=Dongle:wght@400;700&family=Jua&display=swap" rel="stylesheet"/>
<style>
:root { color-scheme: dark; --bg:#0a0f0d; --gold:#d9b673; --gold2:#f0dfb5; --mint:#86d6aa; --text:#f4f0e6; --muted:#9fb0a6; --line:rgba(232,213,168,.16); --up:#e23b3b; --down:#3b78e7; }
* { box-sizing: border-box; }
html, body { margin:0; background:#0a0f0d; color:var(--text); }
body { min-height:100vh; font-family:"Dongle","Jua","Malgun Gothic",sans-serif; font-size:1.28rem; line-height:1.45; background-image:radial-gradient(900px 500px at 8% -10%, rgba(125,206,160,.16), transparent 55%), radial-gradient(800px 480px at 100% 0%, rgba(217,182,115,.14), transparent 50%); }
a { color:inherit; }
button, input, select, textarea { font:inherit; color:inherit; }
.wrap { max-width:72rem; margin:0 auto; padding:1.4rem 1.2rem 3rem; }
.header { display:flex; align-items:center; justify-content:space-between; gap:.75rem; flex-wrap:wrap; margin-bottom:1.2rem; padding:.7rem .8rem .7rem 1.1rem; border-radius:28px; border:1px solid var(--line); background:rgba(18,28,24,.94); }
.brand { font-family:"Jua","Dongle",sans-serif; font-size:1.7rem; color:var(--gold2); text-decoration:none; }
.brand .dot { color:var(--mint); }
.nav { display:flex; gap:.45rem; align-items:center; flex-wrap:wrap; }
.pill { border-radius:999px; border:1px solid var(--line); background:rgba(255,255,255,.03); padding:.15rem .9rem; text-decoration:none; cursor:pointer; }
.pill.gold { background:var(--gold); color:#1a1408; border-color:transparent; }
h2 { font-family:"Jua","Dongle",sans-serif; font-size:1.7rem; margin:1.3rem 0 .45rem; color:var(--gold2); }
.grid { display:grid; grid-template-columns:repeat(4, minmax(0,1fr)); gap:.7rem; }
.card, .table-wrap { background:rgba(18,28,24,.72); border:1px solid var(--line); border-radius:22px; padding:.8rem 1rem; }
.card b { display:block; font-size:1.55rem; }
.muted { color:var(--muted); }
.up { color:var(--up); } .down { color:var(--down); }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:.35rem .35rem; border-bottom:1px solid var(--line); white-space:nowrap; }
tr[data-open] { cursor:pointer; }
tr.on { background:rgba(217,182,115,.08); }
.table-wrap { overflow:auto; }
.row { display:flex; gap:.5rem; flex-wrap:wrap; align-items:center; }
input, select, textarea { background:#0d120c; border:1px solid var(--line); border-radius:14px; padding:.35rem .7rem; }
textarea { width:100%; min-height:4.5rem; }
.tag { border:1px solid var(--line); border-radius:999px; padding:0 .55rem; }
.split { display:grid; grid-template-columns:1fr 1fr 1.4fr; gap:.7rem; }
@media (max-width: 900px) { .grid, .split { grid-template-columns:1fr 1fr; } .split { grid-template-columns:1fr; } }
</style>
</head>
<body>
<div class="wrap">
<header class="header">
  <a class="brand" href="/">WILDMC <span class="dot">·</span> 주식</a>
  <div class="nav">
    <a class="pill" href="/">상점</a>
    <span id="who">확인 중</span>
  </div>
</header>
<main id="page"></main>
</div>
<script>
const $=id=>document.getElementById(id);
const KIND={market:"시장",stock:"종목",price:"가격",notice:"공지",event:"이벤트"};
let market={stocks:[],leaders:{up:[],down:[]},news:[],feePct:0,trading:true,volatilityPct:0.9};
let me=null, account=null, trades=[], news=[], rank=null, admin=null;
let pick="", q="";
function won(n){ return Number(n||0).toLocaleString("ko-KR"); }
function pct(n){ const v=Number(n)||0; return (v>=0?"+":"")+v.toFixed(2)+"%"; }
function tone(n){ return (Number(n)||0)>=0?"up":"down"; }
function when(ms){ if(!ms) return ""; const d=new Date(Number(ms)); const p=n=>String(n).padStart(2,"0"); return (d.getMonth()+1)+"/"+d.getDate()+" "+p(d.getHours())+":"+p(d.getMinutes()); }
function esc(s){ return String(s==null?"":s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;"); }
function stockBy(id){ return (market.stocks||[]).find(s=>s.id===id); }
function sideName(side){ return side==="buy"?"매수":side==="sell"?"매도":side; }
function candle(prices){
  const pts=(prices||[]).map(Number).filter(n=>n>0);
  if(pts.length<2) return `<p class="muted">캔들이 그려지려면 가격이 조금 더 움직여야 합니다.</p>`;
  const group=pts.length>=96?4:pts.length>=36?3:pts.length>=12?2:1;
  const candles=[];
  for(let i=0;i<pts.length;i+=group){
    const sl=pts.slice(i,i+group);
    candles.push({o:sl[0], h:Math.max.apply(null,sl), l:Math.min.apply(null,sl), c:sl[sl.length-1]});
  }
  const viewC=candles.slice(-20);
  const w=860,h=360,padL=108,padR=18,padT=22,padB=20;
  const lows=viewC.map(c=>c.l), highs=viewC.map(c=>c.h);
  let min=Math.min.apply(null,lows), max=Math.max.apply(null,highs);
  const span=Math.max(1,max-min);
  min-=span*0.12; max+=span*0.12;
  const range=Math.max(1,max-min);
  const yOf=p=>padT+(1-(p-min)/range)*(h-padT-padB);
  const innerW=w-padL-padR, slot=innerW/viewC.length, bodyW=Math.max(14, Math.min(32, slot*0.62));
  let grid="";
  for(let i=0;i<=4;i++){
    const price=min+(range*i)/4, y=yOf(price);
    grid+=`<line x1="${padL}" y1="${y.toFixed(1)}" x2="${w-padR}" y2="${y.toFixed(1)}" stroke="rgba(244,240,230,.22)" stroke-width="1"/>`;
    grid+=`<text x="${padL-10}" y="${(y+5).toFixed(1)}" text-anchor="end" fill="#f4f0e6" font-size="18" font-family="Malgun Gothic,sans-serif">${won(Math.round(price))}</text>`;
  }
  let marks="", trend=[];
  viewC.forEach((c,i)=>{
    const x=padL+slot*i+slot/2, rising=c.c>=c.o, color=rising?"#ff5a5a":"#5b92ff";
    const top=Math.min(yOf(c.o), yOf(c.c)), bh=Math.max(6, Math.abs(yOf(c.c)-yOf(c.o)));
    marks+=`<line x1="${x.toFixed(1)}" y1="${yOf(c.h).toFixed(1)}" x2="${x.toFixed(1)}" y2="${yOf(c.l).toFixed(1)}" stroke="${color}" stroke-width="2.4"/>`;
    marks+=`<rect x="${(x-bodyW/2).toFixed(1)}" y="${top.toFixed(1)}" width="${bodyW.toFixed(1)}" height="${bh.toFixed(1)}" rx="2" fill="${color}"><title>시가 ${won(c.o)} 고가 ${won(c.h)} 저가 ${won(c.l)} 종가 ${won(c.c)}</title></rect>`;
    const from=Math.max(0,i-4); let sum=0;
    for(let k=from;k<=i;k++) sum+=viewC[k].c;
    trend.push(x.toFixed(1)+","+yOf(sum/(i-from+1)).toFixed(1));
  });
  const last=viewC[viewC.length-1];
  const yLast=yOf(last.c).toFixed(1);
  const nowLine=`<line x1="${padL}" y1="${yLast}" x2="${w-padR}" y2="${yLast}" stroke="#f0dfb5" stroke-width="1.4" stroke-dasharray="5 4"/>`;
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" height="340" role="img" aria-label="캔들 차트">${grid}<polyline fill="none" stroke="rgba(255,90,90,.85)" stroke-width="2.2" points="${trend.join(" ")}"/>${marks}${nowLine}</svg><p class="muted">시가 ${won(last.o)} · 고가 ${won(last.h)} · 저가 ${won(last.l)} · 종가 ${won(last.c)} · 노란 점선이 현재가</p>`;
}
function stats(){
  if(!account) return `<p class="muted">디스코드로 로그인하면 내 자산이 보여요. <a href="/api/auth/discord?next=/market">로그인</a></p>`;
  const cash=account.cashKnown? won(account.cash)+" 캐시" : "마크 접속 후 표시";
  const cells=[["내 총 자산", won(account.assets)+" 캐시"],["보유 현금", cash],["오늘 수익/손실", `<span class="${tone(account.todayPnl)}">${account.todayPnl>=0?"+":""}${won(account.todayPnl)}</span>`],["전체 수익률", `<span class="${tone(account.rate)}">${pct(account.rate)}</span>`]];
  return `<div class="grid">${cells.map(([k,v])=>`<section class="card"><span class="muted">${k}</span><b>${v}</b></section>`).join("")}</div>
    <div class="grid" style="margin-top:.7rem">
      <section class="card"><span class="muted">평가손익</span><b class="${tone(account.unrealized)}">${won(account.unrealized)}</b></section>
      <section class="card"><span class="muted">실현손익</span><b class="${tone(account.realized)}">${won(account.realized)}</b></section>
      <section class="card"><span class="muted">보유 주식</span><b>${won(account.stockValue)}</b></section>
      <section class="card"><span class="muted">전체 수익</span><b class="${tone(account.profit)}">${won(account.profit)}</b></section>
    </div>`;
}
function stockTable(){
  const list=(market.stocks||[]).filter(s=>!q || String(s.name).includes(q));
  return `<div class="table-wrap"><table><thead><tr><th>종목</th><th>현재 주가</th><th>등락률</th><th>전일 대비</th><th>거래량</th><th></th></tr></thead><tbody>${
    list.map(s=>{
      const diff=(Number(s.price)||0)-(Number(s.prevClose)||0);
      const badge=s.halted?`<span class="tag">중지</span>`:s.move==="up"?`<span class="tag up">급등</span>`:s.move==="down"?`<span class="tag down">급락</span>`:"";
      return `<tr data-open="${esc(s.id)}" class="${s.id===pick?"on":""}"><td>${esc(s.name)}</td><td>${won(s.price)}</td><td class="${tone(s.changePct)}">${pct(s.changePct)}</td><td class="${tone(diff)}">${diff>=0?"+":""}${won(diff)}</td><td>${won(s.volume)}</td><td>${badge}</td></tr>`;
    }).join("") || `<tr><td colspan="6" class="muted">종목이 없어요.</td></tr>`
  }</tbody></table></div>`;
}
function detail(){
  const s=stockBy(pick) || (market.stocks||[])[0];
  if(!s) return "";
  pick=s.id;
  const hold=(account&&account.holdings||[]).find(h=>h.id===s.id);
  const holdText=hold?`보유 ${won(hold.qty)}주 · 평균 매수가 ${won(hold.avg)} · 수익률 <span class="${tone(hold.pnlPct)}">${pct(hold.pnlPct)}</span>`:"보유 수량 없음";
  const blocked=!market.trading || s.halted;
  return `<section class="card">
    <h2 style="margin-top:0">${esc(s.name)} ${s.halted?`<span class="tag">거래 중지</span>`:""}</h2>
    <p style="font-size:2rem;margin:.1rem 0">${won(s.price)} 캐시 <span class="${tone(s.changePct)}">${pct(s.changePct)}</span></p>
    <p class="muted">전일 종가 ${won(s.prevClose)} · 오늘 최고 ${won(s.dayHigh)} · 오늘 최저 ${won(s.dayLow)} · 거래량 ${won(s.volume)}</p>
    ${candle(s.history)}
    <p>${holdText}</p>
    <div class="row">
      <input id="qty" type="number" min="1" value="1" ${blocked?"disabled":""}/>
      <button class="pill gold" id="buy" type="button" ${blocked?"disabled":""}>매수</button>
      <button class="pill" id="sell" type="button" ${blocked?"disabled":""}>매도</button>
      <span class="muted">수수료 ${market.feePct||0}% · 캐시는 마크에서 처리됩니다.</span>
    </div>
    <p id="msg" class="muted"></p>
  </section>`;
}
function holdings(){
  if(!account) return "";
  const rows=(account.holdings||[]).map(h=>`<tr data-open="${esc(h.id)}"><td>${esc(h.name)}</td><td>${won(h.qty)}</td><td>${won(h.avg)}</td><td>${won(h.price)}</td><td>${won(h.value)}</td><td class="${tone(h.pnl)}">${h.pnl>=0?"+":""}${won(h.pnl)} (${pct(h.pnlPct)})</td></tr>`).join("");
  return `<div class="table-wrap"><table><thead><tr><th>종목</th><th>수량</th><th>평균 매수가</th><th>현재가</th><th>평가액</th><th>수익률</th></tr></thead><tbody>${rows||`<tr><td colspan="6" class="muted">보유 주식이 없어요.</td></tr>`}</tbody></table></div>`;
}
function history(){
  if(!me||!me.authenticated) return `<p class="muted">로그인하면 거래 내역이 보여요.</p>`;
  const rows=(trades||[]).map(t=>`<tr><td>${when(t.at)}</td><td>${sideName(t.side)}</td><td>${esc(t.name)}</td><td>${won(t.price)}</td><td>${won(t.qty)}</td><td>${won(t.gross)}</td><td>${won(t.fee)}</td><td>${esc(t.status)}</td></tr>`).join("");
  return `<div class="table-wrap"><table><thead><tr><th>시간</th><th>구분</th><th>종목</th><th>가격</th><th>수량</th><th>금액</th><th>수수료</th><th>상태</th></tr></thead><tbody>${rows||`<tr><td colspan="8" class="muted">거래가 없어요.</td></tr>`}</tbody></table></div>`;
}
function newsBlock(){
  const rows=(news.length?news:market.news)||[];
  const up=(market.leaders&&market.leaders.up)||[], down=(market.leaders&&market.leaders.down)||[];
  return `<div class="split">
    <section class="card"><span class="muted">급등</span>${up.map(s=>`<p class="up" data-open="${esc(s.id)}" style="cursor:pointer">${esc(s.name)} ${pct(s.changePct)}</p>`).join("")||`<p class="muted">없음</p>`}</section>
    <section class="card"><span class="muted">급락</span>${down.map(s=>`<p class="down" data-open="${esc(s.id)}" style="cursor:pointer">${esc(s.name)} ${pct(s.changePct)}</p>`).join("")||`<p class="muted">없음</p>`}</section>
    <section class="card"><span class="muted">최근 뉴스</span>${rows.slice(0,5).map(n=>`<p><b>${esc(n.title)}</b> <span class="muted">${KIND[n.kind]||""} · ${when(n.at)}</span><br>${esc(n.body)}</p>`).join("")||`<p class="muted">소식이 없어요.</p>`}</section>
  </div>`;
}
function rankList(title, rows, field){
  const body=(rows||[]).map((r,i)=>`<p>${i+1}. ${esc(r.discordName)} <b>${field==="rate"?pct(r.rate):won(r[field])}</b></p>`).join("");
  return `<section class="card"><span class="muted">${title}</span>${body||`<p class="muted">아직 없어요.</p>`}</section>`;
}
function ranks(){
  const b=rank||{assets:[],rate:[],profit:[],volume:[]};
  return `<div class="grid">${rankList("총 자산", b.assets, "assets")}${rankList("수익률", b.rate, "rate")}${rankList("총 수익", b.profit, "profit")}${rankList("거래량", b.volume, "volume")}</div>`;
}
function meBlock(){
  if(!me||!me.authenticated) return "";
  const mc=me.minecraft;
  return `<section class="card"><p>디스코드 <b>${esc((me.discord&&me.discord.username)||"")}</b> · 마인크래프트 <b>${mc?esc(mc.name):"연동 안 됨"}</b> · ${mc?"연동됨":`<a href="/link">연동하기</a>`}</p></section>`;
}
function adminBlock(){
  if(!me||!me.admin) return "";
  const a=admin||{config:{},stocks:[],trades:[],flagged:[],accounts:[]};
  const cfg=a.config||{};
  const stockOpts=(a.stocks||[]).map(s=>`<option value="${esc(s.id)}">${esc(s.name)}</option>`).join("");
  const lines=(a.stocks||[]).map(s=>`<div class="row" data-id="${esc(s.id)}"><b>${esc(s.name)}</b><input data-price value="${s.price}"/><button type="button" class="pill" data-act="price">가격 저장</button><button type="button" class="pill" data-act="halt">${s.halted?"재개":"중지"}</button><button type="button" class="pill" data-act="delete">삭제</button></div>`).join("");
  const flags=(a.flagged||[]).slice(0,12).map(t=>`<p>${when(t.at)} ${esc(t.minecraftName||t.discordId)} ${sideName(t.side)} ${esc(t.name)} ${won(t.qty)} ${esc(t.flag||t.status)} ${esc(t.error||"")}</p>`).join("");
  const people=(a.accounts||[]).slice(0,20).map(p=>`<p>${esc(p.discordName)} · ${esc(p.minecraftName||"—")} · 현금 ${p.cashKnown?won(p.cash):"—"} · 총자산 ${won(p.assets)}</p>`).join("");
  return `<form id="setForm" class="card row">
      <label>수수료 % <input id="fee" type="number" min="0" max="10" step="0.1" value="${cfg.feePct||0}"/></label>
      <label>변동폭 % <input id="vol" type="number" min="0.3" max="4" step="0.1" value="${cfg.volatilityPct||0.9}"/></label>
      <label><input id="tradeOn" type="checkbox" ${cfg.trading!==false?"checked":""}/> 거래 재개</label>
      <button class="pill gold" type="submit">설정 저장</button>
    </form>
    <form id="newForm" class="card row" style="margin-top:.7rem">
      <input id="newName" placeholder="새 종목 이름"/>
      <input id="newPrice" type="number" min="50" placeholder="가격"/>
      <button class="pill gold" type="submit">주식 추가</button>
    </form>
    <section class="card" style="margin-top:.7rem">${lines}</section>
    <form id="newsForm" class="card" style="margin-top:.7rem">
      <div class="row">
        <select id="newsKind"><option value="notice">공지</option><option value="event">이벤트</option><option value="market">시장</option><option value="stock">종목</option><option value="price">가격</option></select>
        <select id="newsStock"><option value="">종목 없음</option>${stockOpts}</select>
        <input id="newsTitle" placeholder="제목"/>
      </div>
      <textarea id="newsBody" placeholder="내용"></textarea>
      <button class="pill gold" type="submit">뉴스 올리기</button>
    </form>
    <section class="card" style="margin-top:.7rem"><span class="muted">이상·실패 거래</span>${flags||`<p class="muted">없어요.</p>`}</section>
    <section class="card" style="margin-top:.7rem"><span class="muted">사용자 자산</span>${people||`<p class="muted">없어요.</p>`}</section>
    <p id="amsg" class="muted"></p>`;
}
function paint(){
  const focus=document.activeElement;
  const focusId=focus&&focus.id;
  const caret=focus&&focus.selectionStart;
  const qtyVal=($("qty")&&$("qty").value)||"1";
  $("page").innerHTML=`
    ${stats()}
    ${meBlock()}
    ${newsBlock()}
    <h2>주식</h2>
    <div class="row" style="margin-bottom:.5rem"><input id="q" value="${esc(q)}" placeholder="종목 검색"/><span class="muted">수수료 ${market.feePct||0}% · ${market.trading?"거래 가능":"거래 중지"}</span></div>
    ${detail()}
    <div style="height:.7rem"></div>
    ${stockTable()}
    <h2>보유 주식</h2>
    ${holdings()||`<p class="muted">로그인하면 보유 주식이 보여요.</p>`}
    <h2>거래 내역</h2>
    ${history()}
    <h2>랭킹</h2>
    ${ranks()}
    ${me&&me.admin?`<h2>관리자</h2>${adminBlock()}`:""}
  `;
  const qEl=$("q"); if(qEl) qEl.oninput=()=>{ q=qEl.value; paint(); };
  const qty=$("qty"); if(qty && document.activeElement!==qty) qty.value=qtyVal;
  const buy=$("buy"), sell=$("sell");
  if(buy) buy.onclick=()=>order("buy");
  if(sell) sell.onclick=()=>order("sell");
  document.querySelectorAll("[data-open]").forEach(el=>el.onclick=()=>{ pick=el.dataset.open; paint(); });
  const setForm=$("setForm");
  if(setForm) setForm.onsubmit=ev=>{ ev.preventDefault(); adminPost({op:"settings", feePct:Number($("fee").value)||0, volatilityPct:Number($("vol").value)||0.9, trading:$("tradeOn").checked}); };
  const newForm=$("newForm");
  if(newForm) newForm.onsubmit=ev=>{ ev.preventDefault(); adminPost({op:"create", name:$("newName").value, price:Number($("newPrice").value)||0}); };
  const newsForm=$("newsForm");
  if(newsForm) newsForm.onsubmit=ev=>{ ev.preventDefault(); adminPost({op:"news", kind:$("newsKind").value, stockId:$("newsStock").value, title:$("newsTitle").value, body:$("newsBody").value}); };
  document.querySelectorAll("[data-act]").forEach(btn=>btn.onclick=()=>{
    const id=btn.parentElement.dataset.id;
    if(btn.dataset.act==="price") adminPost({op:"price", id, price:Number(btn.parentElement.querySelector("[data-price]").value)||0});
    else if(btn.dataset.act==="halt"){ const s=stockBy(id); adminPost({op:"halt", id, halted:!(s&&s.halted)}); }
    else if(btn.dataset.act==="delete" && confirm("이 종목을 삭제할까요?")) adminPost({op:"delete", id});
  });
  if(focusId){
    const el=$(focusId);
    if(el){ el.focus(); if(typeof caret==="number"){ try{ el.selectionStart=el.selectionEnd=caret; }catch(e){} } }
  }
}
async function order(side){
  if(!me||!me.authenticated){ location.href="/api/auth/discord?next=/market"; return; }
  if(me.minecraft==null){ const msg=$("msg"); if(msg) msg.textContent="마인크래프트 계정을 연동한 뒤 거래할 수 있어요."; return; }
  const qty=Math.max(1, Number(($("qty")||{}).value)||1);
  const r=await fetch("/api/stocks/trade",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:pick,side,qty})});
  const d=await r.json().catch(()=>({}));
  const msg=$("msg"); if(msg) msg.textContent=d.message||d.error||"실패";
  if(r.ok) setTimeout(load, 2000);
}
async function adminPost(body){
  const r=await fetch("/api/stocks/admin",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const d=await r.json().catch(()=>({}));
  const msg=$("amsg"); if(msg) msg.textContent=d.error||"저장했어요.";
  if(r.ok){ if(document.activeElement) document.activeElement.blur(); load(); }
}
async function load(){
  if(document.activeElement && document.activeElement.closest("#setForm,#newForm,#newsForm")) return;
  try{ const r=await fetch("/api/stocks"); if(r.ok) market=await r.json(); }catch(e){}
  try{ const r=await fetch("/api/me"); me=r.ok?await r.json():null; }catch(e){ me=null; }
  if(me&&me.authenticated){
    $("who").innerHTML=`<span class="pill">${esc((me.discord&&me.discord.username)||"로그인됨")}</span>`;
    try{ const r=await fetch("/api/stocks/me"); if(r.ok){ const d=await r.json(); account=d.account; trades=d.trades||[]; me.admin=!!d.admin; } }catch(e){}
    try{ const r=await fetch("/api/stocks/trades"); if(r.ok) trades=(await r.json()).trades||trades; }catch(e){}
    if(me.admin){ try{ const r=await fetch("/api/stocks/admin"); if(r.ok) admin=await r.json(); }catch(e){} }
  }else{
    account=null;
    $("who").innerHTML='<a class="pill gold" href="/api/auth/discord?next=/market">디스코드 로그인</a>';
  }
  try{ const r=await fetch("/api/stocks/news"); if(r.ok) news=(await r.json()).news||[]; }catch(e){}
  try{ const r=await fetch("/api/stocks/rank"); if(r.ok) rank=await r.json(); }catch(e){}
  paint();
}
load();
setInterval(load, 5000);
</script>
<p style="display:none">web __WEB_BUILD__</p>
</body></html>
"""
STOCKS_HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>WILDMC 증권</title>
<meta name="theme-color" content="#f4f4f1" />
<script>(function(){try{var t=localStorage.getItem("wm_theme");if(t!=="light"&&t!=="dark"){t=(window.matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light";}document.documentElement.setAttribute("data-theme",t);}catch(e){document.documentElement.setAttribute("data-theme","light");}})();</script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable-dynamic-subset.min.css" />
<link rel="preconnect" href="https://fonts.googleapis.com" /><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Black+Han+Sans&display=swap" />
<style>
:root,:root[data-theme="light"]{
  color-scheme:light;
  --bg:#f4f4f1; --card:#ffffff; --soft:#f0f0eb; --line:#e6e6df; --line2:#d4d4cb;
  --ink:#1c1d20; --ink-fg:#ffffff; --sub:#55585f; --mute:#8a8d94;
  --up:#2f6fe4; --up-bg:rgba(47,111,228,.10); --up-deep:#245fcf; --up-flash:rgba(47,111,228,.22);
  --down:#e5384a; --down-bg:rgba(229,56,74,.10); --down-deep:#d42a3c; --down-flash:rgba(229,56,74,.22);
  --ok:#14a06a; --warn:#b97a0b;
  --grid:rgba(20,20,20,.075); --grid2:rgba(20,20,20,.045); --axis:#8a8d94; --cross:#9a9ca3; --tip:#1c1d20;
  --shadow:0 1px 2px rgba(20,20,20,.04),0 10px 30px rgba(20,20,20,.045);
}
:root[data-theme="dark"]{
  color-scheme:dark;
  --bg:#1a1c21; --card:#22252b; --soft:#2a2d34; --line:#33373f; --line2:#454a56;
  --ink:#eceef2; --ink-fg:#1a1c21; --sub:#b0b5c0; --mute:#808694;
  --up:#5a9bff; --up-bg:rgba(90,155,255,.14); --up-deep:#7fb2ff; --up-flash:rgba(90,155,255,.30);
  --down:#ff5b6a; --down-bg:rgba(255,91,106,.13); --down-deep:#ff7480; --down-flash:rgba(255,91,106,.30);
  --ok:#3cd69a; --warn:#e8b04b;
  --grid:rgba(255,255,255,.07); --grid2:rgba(255,255,255,.04); --axis:#808694; --cross:#5d6372; --tip:#101216;
  --shadow:0 1px 2px rgba(0,0,0,.2),0 10px 30px rgba(0,0,0,.18);
}
:root{
  --ease:cubic-bezier(.2,.8,.2,1);--spring:cubic-bezier(.34,1.4,.5,1);
  --font:"Pretendard Variable",Pretendard,-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Noto Sans KR","Malgun Gothic",system-ui,sans-serif;
  --fat:"Black Han Sans","Pretendard Variable",Pretendard,"Apple SD Gothic Neo","Malgun Gothic",sans-serif;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--font);font-size:15px;line-height:1.5;-webkit-font-smoothing:antialiased;min-height:100vh;overflow-x:hidden}
button,input{font:inherit;color:inherit}
button{cursor:pointer}
:focus-visible{outline:2px solid var(--ink);outline-offset:2px}
.num{font-variant-numeric:tabular-nums;letter-spacing:-.01em}
.up{color:var(--up)}.down{color:var(--down)}.flat{color:var(--mute)}
.fat{font-family:var(--fat);font-weight:400;font-synthesis:none}

.shell{display:grid;grid-template-columns:minmax(0,1fr);max-width:1480px;margin:0 auto;padding:0 22px;gap:22px}
.page{min-width:0;padding:0 0 56px}
.rail{display:none}
@media (min-width:1620px){
  .shell{grid-template-columns:250px minmax(0,1fr) 250px;max-width:2100px;padding:0 28px}
  .rail{display:block;position:sticky;top:18px;align-self:start;margin-top:84px}
}

/* 상단 */
.bar{display:flex;align-items:center;justify-content:space-between;gap:14px;height:78px}
.brand{display:flex;align-items:center;gap:11px;font-family:var(--fat);font-weight:400;font-synthesis:none;font-size:25px;letter-spacing:-.01em;line-height:1}
.brand svg{width:34px;height:34px;flex:none}
.bar-r{display:flex;align-items:center;gap:12px;flex-wrap:wrap;justify-content:flex-end}
.me{display:inline-flex;align-items:center;gap:12px;height:52px;padding:0 20px 0 7px;border-radius:999px;background:var(--card);border:1px solid var(--line2)}
.me .who{display:flex;align-items:baseline;gap:9px;min-width:0}
.me .dn{font-family:var(--fat);font-weight:400;font-synthesis:none;font-size:21px;letter-spacing:0;line-height:1;white-space:nowrap}
.me .mn{font-size:15px;font-weight:700;color:var(--sub);white-space:nowrap}
.me .mn::before{content:"·";margin-right:9px;color:var(--mute)}
.av{position:relative;display:inline-grid;place-items:center;flex:none;width:30px;height:30px;border-radius:50%;overflow:hidden;background:var(--soft);color:var(--sub);font-weight:800;font-size:13px}
.av b{font-weight:800}
.av img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.av.lg{width:38px;height:38px;font-size:16px}
.chip{display:inline-flex;align-items:center;gap:8px;height:40px;padding:0 15px;border-radius:999px;background:var(--card);border:1px solid var(--line);font-size:14px;font-weight:700;color:var(--sub)}
.live i{width:8px;height:8px;border-radius:50%;background:var(--ok);animation:blink 2s infinite}
.live.off i{background:var(--down);animation:none}
@keyframes blink{50%{opacity:.35}}
.login{height:40px;padding:0 18px;border:0;border-radius:999px;background:var(--ink);color:var(--ink-fg);font-weight:800;font-size:14px}

/* 내 자산 (얇은 띠) */
.assets{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,2.2fr);background:var(--card);border-radius:18px;border:1px solid var(--line)}
.a-main{padding:18px 26px;border-right:1px solid var(--line)}
.a-main .lbl{font-size:13px;color:var(--mute);font-weight:700}
.a-main .big{margin-top:2px;font-size:34px;line-height:1.1;font-weight:800;letter-spacing:-.03em;display:flex;align-items:baseline;gap:7px}
.a-main .big small{font-size:15px;font-weight:700;color:var(--mute);letter-spacing:0}
.a-main .today{margin-top:8px;display:flex;align-items:center;gap:8px;font-size:13px;color:var(--mute);font-weight:600}
.pill{display:inline-flex;align-items:center;gap:4px;height:26px;padding:0 10px;border-radius:8px;font-weight:800;font-size:13px;background:var(--soft);color:var(--mute)}
.pill.up{background:var(--up-bg);color:var(--up-deep)}.pill.down{background:var(--down-bg);color:var(--down-deep)}
.a-stats{display:grid;grid-template-columns:repeat(3,1fr)}
.a-stats>div{padding:18px 24px;border-right:1px solid var(--line);min-width:0}
.a-stats>div:last-child{border-right:0}
.a-stats .lbl{font-size:13px;color:var(--mute);font-weight:700}
.a-stats b{display:block;margin-top:4px;font-size:23px;font-weight:800;letter-spacing:-.03em;white-space:nowrap}
.a-stats small{display:block;margin-top:3px;font-size:12px;color:var(--mute);min-height:18px}
.dotok{color:var(--ok)}

/* 숫자판 */
.odo{display:inline-flex;align-items:flex-start;font-variant-numeric:tabular-nums}
.od{display:inline-block;height:1.12em;line-height:1.12;overflow:hidden}
.dg{display:block;transition:transform .8s var(--ease)}
.dg i{display:block;height:1.12em;line-height:1.12;font-style:normal}
.sep{display:inline-block;line-height:1.12;padding:0 .02em}
.nomotion .dg{transition:none}

/* 본문: 차트가 주인공 */
.main{display:grid;grid-template-columns:250px minmax(0,1fr) 330px;gap:14px;margin-top:14px;align-items:start}
.main>*,.low>*,.assets>*{min-width:0}
.box{background:var(--card);border:1px solid var(--line);border-radius:18px}
.list{padding:10px}
.list h2,.sec h2{margin:10px 12px 8px;font-size:14px;font-weight:800;letter-spacing:.01em;color:var(--sub)}
.row{position:relative;display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:center;padding:13px 12px 13px 14px;border-radius:12px;cursor:pointer;transition:background .15s}
.row:hover{background:var(--soft)}
.row.on{background:var(--soft)}
.row.on::before{content:"";position:absolute;left:0;top:12px;bottom:12px;width:3px;border-radius:3px;background:var(--ink)}
.row b{display:block;font-size:16px;font-weight:800;letter-spacing:-.02em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.row .own{font-size:12px;color:var(--mute);margin-top:1px}
.row .px{text-align:right;font-size:16px;font-weight:800}
.row .pc{text-align:right;font-size:13px;font-weight:700;margin-top:1px}
.row .sp{display:none}
.halt{display:inline-block;margin-left:6px;padding:1px 7px;border-radius:5px;background:var(--down-bg);color:var(--down-deep);font-size:11px;font-weight:800;vertical-align:2px}
.fu{animation:fu 1s ease-out;border-radius:6px}.fd{animation:fd 1s ease-out;border-radius:6px}
@keyframes fu{0%{background:var(--up-flash)}100%{background:transparent}}
@keyframes fd{0%{background:var(--down-flash)}100%{background:transparent}}

.chart{padding:22px 24px 16px;min-width:0}
.c-head{display:flex;justify-content:space-between;align-items:flex-end;gap:14px;flex-wrap:wrap}
.c-name{font-family:var(--fat);font-weight:400;font-synthesis:none;font-size:22px;color:var(--sub);display:flex;align-items:center;gap:6px;letter-spacing:0}
.c-price{margin-top:4px;font-size:54px;line-height:1.08;font-weight:800;letter-spacing:-.04em;display:inline-flex;align-items:baseline;gap:8px;padding:0 6px;margin-left:-6px;border-radius:10px}
.c-price small{font-size:18px;font-weight:700;color:var(--mute);letter-spacing:0}
.c-chg{margin-top:4px;font-size:17px;font-weight:800}
.tabs{display:inline-flex;gap:2px;padding:4px;border-radius:12px;background:var(--bg);border:1px solid var(--line)}
.tabs button{border:0;background:transparent;border-radius:9px;padding:8px 16px;font-size:14px;font-weight:800;color:var(--mute);transition:background .15s,color .15s}
.tabs button:hover{color:var(--ink)}
.tabs button.on{background:var(--ink);color:var(--ink-fg)}
.cvw{position:relative;height:clamp(440px,60vh,700px);margin-top:14px}
.cvw canvas{position:absolute;inset:0;width:100%;height:100%;display:block;cursor:crosshair;touch-action:pan-y}
.stats{display:grid;grid-template-columns:repeat(4,1fr);margin-top:10px;border-top:1px solid var(--line);padding-top:14px;gap:10px}
.stats span{display:block;font-size:12px;color:var(--mute);font-weight:700}
.stats b{display:block;margin-top:2px;font-size:18px;font-weight:800}

/* 주문 */
.order{padding:22px;position:sticky;top:18px}
.order h2{margin:0 0 14px;font-family:var(--fat);font-weight:400;font-synthesis:none;font-size:21px;letter-spacing:0}
.seg{position:relative;display:grid;grid-template-columns:1fr 1fr;padding:4px;border-radius:12px;background:var(--bg);border:1px solid var(--line)}
.seg::before{content:"";position:absolute;top:4px;bottom:4px;left:4px;width:calc(50% - 4px);border-radius:9px;background:var(--up);transition:transform .3s var(--ease),background .3s}
.seg[data-side="sell"]::before{transform:translateX(100%);background:var(--down)}
.seg button{position:relative;z-index:1;border:0;background:transparent;height:44px;font-size:16px;font-weight:800;color:var(--mute);transition:color .2s}
.seg button.on{color:#fff}
.field{display:block;margin-top:16px}
.field>span{display:block;font-size:13px;font-weight:700;color:var(--sub);margin-bottom:6px}
.qty{display:grid;grid-template-columns:48px 1fr 48px;gap:8px}
.qty button{height:50px;border:1px solid var(--line2);background:var(--soft);border-radius:12px;font-size:21px;font-weight:600;transition:background .15s,transform .1s}
.qty button:hover{background:var(--line)}.qty button:active{transform:scale(.95)}
.qty input{width:100%;height:50px;text-align:center;font-size:21px;font-weight:800;border:1px solid var(--line2);border-radius:12px;background:var(--bg);-moz-appearance:textfield}
.qty input::-webkit-outer-spin-button,.qty input::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
.qty input:focus{outline:none;border-color:var(--ink)}
.quick{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:8px}
.quick button{height:38px;border:1px solid var(--line);border-radius:10px;background:var(--soft);font-size:14px;font-weight:800;color:var(--sub);transition:background .15s,transform .1s}
.quick button:hover{background:var(--line)}.quick button:active{transform:scale(.95)}
.quick button[data-max]{background:var(--ink);border-color:var(--ink);color:var(--ink-fg)}
.sum{margin-top:18px;padding-top:16px;border-top:1px solid var(--line);font-size:14px}
.sum div{display:flex;justify-content:space-between;padding:5px 0;color:var(--mute);font-weight:600}
.sum div b{color:var(--ink);font-weight:700}
.sum .tot{margin-top:6px;padding-top:12px;border-top:1px dashed var(--line2);color:var(--ink);font-weight:800;font-size:15px}
.sum .tot b{font-size:22px;font-weight:800}
.warn{min-height:22px;margin:8px 2px 0;font-size:13px;font-weight:700;color:var(--down-deep)}
.go{width:100%;height:56px;margin-top:6px;border:0;border-radius:13px;font-size:17px;font-weight:800;color:#fff;background:var(--up);transition:transform .12s var(--ease),filter .15s,opacity .2s}
.go.sell{background:var(--down)}
.go.ink{background:var(--ink);color:var(--ink-fg)}
.go:hover:not(:disabled){filter:brightness(1.08)}
.go:active:not(:disabled){transform:scale(.985)}
.go:disabled{opacity:.38;cursor:not-allowed}
.note{margin:12px 2px 0;font-size:12px;color:var(--mute);line-height:1.5}

/* 진행/완료 */
.prog{display:none;padding:6px 0 4px}
.order.busy .prog{display:block}
.order.busy .form{display:none}
.steps{position:relative;display:flex;justify-content:space-between;margin:22px 6px 18px}
.steps::before{content:"";position:absolute;left:12%;right:12%;top:19px;height:3px;border-radius:3px;background:var(--line)}
.steps .bar2{position:absolute;left:12%;top:19px;height:3px;border-radius:3px;background:var(--ink);width:0;transition:width .6s var(--ease)}
.step{position:relative;flex:1;text-align:center;font-size:13px;font-weight:700;color:var(--mute)}
.step i{display:grid;place-items:center;width:42px;height:42px;margin:0 auto 8px;border-radius:50%;background:var(--card);border:2px solid var(--line2);font-style:normal;font-weight:800;transition:all .3s var(--ease)}
.step.on{color:var(--ink)}.step.on i{border-color:var(--ink);animation:beat 1.1s infinite}
.step.done{color:var(--ink)}.step.done i{background:var(--ink);border-color:var(--ink);color:var(--ink-fg)}
@keyframes beat{50%{transform:scale(1.08)}}
.pmsg{text-align:center;font-size:14px;color:var(--sub);margin:0;font-weight:600}
.result{text-align:center;padding:14px 0 6px}
.result h3{margin:12px 0 4px;font-size:21px;font-weight:800;letter-spacing:-.02em}
.result p{margin:0;font-size:14px;color:var(--sub)}
.result .amt{margin-top:12px;font-size:26px;font-weight:800}
.check{width:72px;height:72px}
.check circle{fill:none;stroke-width:5;stroke-dasharray:200;stroke-dashoffset:200;animation:draw .7s .05s var(--ease) forwards}
.check path{fill:none;stroke-width:6;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:54;stroke-dashoffset:54;animation:draw .5s .6s var(--ease) forwards}
@keyframes draw{to{stroke-dashoffset:0}}
.check.ok circle,.check.ok path{stroke:var(--ok)}
.check.bad circle,.check.bad path{stroke:var(--down)}

/* 하단 */
.low{display:grid;grid-template-columns:1.4fr 1.2fr 1fr;gap:14px;margin-top:14px;align-items:start}
.sec{padding:10px 14px 14px;min-width:0}
.scroll{max-height:380px;overflow:auto;scrollbar-width:thin;scrollbar-color:var(--line2) transparent}
.empty{padding:34px 10px;text-align:center;color:var(--mute);font-size:14px;line-height:1.6}
.hold{display:grid;grid-template-columns:minmax(0,1.3fr) minmax(0,1fr) minmax(0,1fr) auto;gap:10px;align-items:center;padding:12px 6px;border-bottom:1px solid var(--line)}
.hold:last-child{border-bottom:0}
.hold.head{padding:4px 6px 8px;font-size:12px;color:var(--mute);font-weight:700}
.hold b{font-size:15px;font-weight:800;display:block}
.hold small{display:block;font-size:12px;color:var(--mute);margin-top:1px}
.hold .r{text-align:right}
.hold.pulse{animation:rowp 1.4s ease-out}
@keyframes rowp{0%{background:var(--soft)}100%{background:transparent}}
.mini{height:32px;padding:0 14px;border:0;border-radius:9px;background:var(--down-bg);color:var(--down-deep);font-weight:800;font-size:13px}
.mini:hover{filter:brightness(.94)}
.trade{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:11px;align-items:center;padding:11px 6px;border-bottom:1px solid var(--line)}
.trade:last-child{border-bottom:0}
.trade .who{display:flex;align-items:center;gap:9px;min-width:0}
.trade .who>div{min-width:0}
.tag{display:inline-block;min-width:42px;text-align:center;padding:3px 0;border-radius:7px;font-weight:800;font-size:12px}
.tag.buy{background:var(--up-bg);color:var(--up-deep)}.tag.sell{background:var(--down-bg);color:var(--down-deep)}
.trade b{display:block;font-size:14px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.trade small{display:block;font-size:12px;color:var(--mute);margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.st{font-size:13px;font-weight:800}.st.done{color:var(--ok)}.st.failed{color:var(--down-deep)}.st.pending,.st.processing{color:var(--warn)}
.news{padding:12px 6px;border-bottom:1px solid var(--line)}
.news:last-child{border-bottom:0}
.news b{display:block;font-size:14px;font-weight:800}
.news p{margin:3px 0 0;font-size:13px;color:var(--sub);line-height:1.5}
.news .k{display:inline-block;margin-right:6px;padding:1px 7px;border-radius:5px;background:var(--soft);color:var(--sub);font-size:11px;font-weight:800;vertical-align:1px}

/* 효과 */
.fly{position:fixed;left:0;top:0;z-index:9999;pointer-events:none;font-size:24px;will-change:transform,opacity}
.float{position:fixed;z-index:9999;pointer-events:none;font-weight:800;font-size:18px;animation:flt 1.6s var(--ease) forwards;text-shadow:0 1px 0 var(--card),0 0 8px var(--card)}
@keyframes flt{0%{opacity:0;transform:translateY(6px) scale(.8)}15%{opacity:1;transform:translateY(-6px) scale(1.1)}100%{opacity:0;transform:translateY(-52px)}}
.toast{position:fixed;left:50%;bottom:28px;z-index:9999;transform:translate(-50%,30px);opacity:0;padding:14px 22px;border-radius:12px;background:var(--ink);color:var(--ink-fg);font-weight:800;font-size:15px;box-shadow:0 14px 34px rgba(0,0,0,.28);transition:all .4s var(--ease);max-width:92vw}
.toast.on{transform:translate(-50%,0);opacity:1}
.skel{height:58px;margin:6px 0;border-radius:12px;background:linear-gradient(90deg,var(--soft),var(--line),var(--soft));background-size:200% 100%;animation:sk 1.3s infinite}
@keyframes sk{to{background-position:-200% 0}}

/* 양옆 패널 */
.pcard{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:18px 16px;margin-bottom:14px}
.pcard h3{margin:0 0 12px;font-size:13px;font-weight:800;letter-spacing:.02em;color:var(--sub);display:flex;align-items:center;justify-content:space-between;gap:8px}
.pcard h3 small{font-size:12px;font-weight:600;color:var(--mute);letter-spacing:0}
.idx{font-size:34px;font-weight:800;letter-spacing:-.03em;line-height:1.1}
.idx-s{margin-top:4px;font-size:12px;color:var(--mute);font-weight:600}
.meter{position:relative;height:6px;margin:16px 0 2px;border-radius:99px;background:linear-gradient(90deg,var(--down),var(--line2) 50%,var(--up))}
.meter i{position:absolute;top:50%;width:14px;height:14px;margin:-7px 0 0 -7px;border-radius:50%;background:var(--ink);border:3px solid var(--card);transition:left .8s var(--ease)}
.mv{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center;padding:9px 6px;border-radius:10px;cursor:pointer;transition:background .15s}
.mv:hover{background:var(--soft)}
.mv b{display:block;font-size:14px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.mv small{display:block;font-size:12px;color:var(--mute)}
.mv .r{text-align:right;font-size:14px;font-weight:800}
.kv{display:flex;justify-content:space-between;gap:10px;padding:7px 0;font-size:13px;color:var(--mute);font-weight:600;border-bottom:1px solid var(--line)}
.kv:last-child{border-bottom:0}.kv b{color:var(--ink);font-weight:700}
.rk-tabs{display:grid;grid-template-columns:repeat(4,1fr);gap:3px;padding:3px;border-radius:10px;background:var(--bg);border:1px solid var(--line);margin-bottom:8px}
.rk-tabs button{border:0;background:transparent;border-radius:7px;padding:6px 0;font-size:12px;font-weight:800;color:var(--mute)}
.rk-tabs button.on{background:var(--ink);color:var(--ink-fg)}
.rk{display:grid;grid-template-columns:30px minmax(0,1fr) auto;gap:9px;align-items:center;padding:8px 4px;border-bottom:1px solid var(--line)}
.rk:last-child{border-bottom:0}
.rk .n{position:absolute;opacity:0}
.rk b{display:block;font-size:14px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rk small{display:block;font-size:11px;color:var(--mute);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.rk .v{font-size:13px;font-weight:800;text-align:right}
.rk .rn{position:absolute;left:-1px;top:-3px;z-index:2;display:grid;place-items:center;width:15px;height:15px;border-radius:50%;background:var(--ink);color:var(--ink-fg);font-size:10px;font-weight:800}
.rk .av{overflow:visible}
.rk .av img{border-radius:50%}
.rk:nth-child(1) .rn{background:#f3c969}.rk:nth-child(2) .rn{background:#c9d1dc}.rk:nth-child(3) .rn{background:#d99a63}
.tip{font-size:13px;line-height:1.7;color:var(--sub)}.tip b{color:var(--ink)}
.fd-row{display:grid;grid-template-columns:30px minmax(0,1fr) auto;gap:9px;align-items:center;padding:8px 2px;border-bottom:1px solid var(--line)}
.fd-row:last-child{border-bottom:0}
.fd-row b{display:block;font-size:13px;font-weight:800;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fd-row small{display:block;font-size:11px;color:var(--mute);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.fd-row .t{font-size:11px;color:var(--mute);font-weight:700}

@media (max-width:1100px){
  .main{grid-template-columns:minmax(0,1fr)}
  .order{position:static}
  #rows{display:flex;gap:8px;overflow-x:auto;padding-bottom:4px}
  .list h2{display:none}
  .row{grid-template-columns:1fr;gap:2px;min-width:160px;flex:none;border:1px solid var(--line)}
  .row.on{border-color:var(--ink)}
  .low{grid-template-columns:1fr 1fr}.low>:first-child{grid-column:1/-1}
}
@media (max-width:780px){
  .shell{padding:0 14px}
  .bar{height:68px}
  .brand{font-size:21px}
  .me{height:44px;padding:0 14px 0 5px}.me .dn{font-size:17px}.me .mn{display:none}
  .assets{grid-template-columns:1fr}
  .a-main{border-right:0;border-bottom:1px solid var(--line);padding:18px 20px}
  .a-main .big{font-size:30px}.c-price{font-size:40px}
  .a-stats{grid-template-columns:1fr}
  .a-stats>div{border-right:0;border-bottom:1px solid var(--line);padding:14px 20px;display:flex;justify-content:space-between;align-items:baseline;gap:10px;flex-wrap:wrap}
  .a-stats>div:last-child{border-bottom:0}
  .a-stats b{margin:0;font-size:20px}.a-stats small{width:100%;margin:0}
  .cvw{height:340px}
  .chart{padding:18px 14px 12px}
  .stats{grid-template-columns:1fr 1fr}
  .low{grid-template-columns:1fr}
  .hold{grid-template-columns:minmax(0,1fr) minmax(0,1fr) auto}.hold .hm{display:none}
}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}

/* ===== v1.24 완전 개편: 밤/낮, 종목 스트립, 사이드 지갑 ===== */
body{transition:none}
html.tt body,html.tt .box,html.tt .pcard,html.tt .me,html.tt .chip,html.tt .tabs,html.tt .seg,html.tt .row,html.tt .hl,html.tt .qty input,html.tt .qty button,html.tt .quick button,html.tt .icon-btn,html.tt .rk-tabs,html.tt .hold,html.tt .trade,html.tt .news,html.tt .fd-row,html.tt .rk,html.tt .kv,html.tt .sum,html.tt .stats,html.tt .go.ink,html.tt .login{transition:background-color .5s ease,border-color .5s ease,color .5s ease,box-shadow .5s ease}
::view-transition-old(root),::view-transition-new(root){animation:none;mix-blend-mode:normal}
::view-transition-old(root){z-index:1}::view-transition-new(root){z-index:2}

.box,.pcard,.me,.chip{box-shadow:var(--shadow)}
.box,.pcard{border-radius:20px}
.brand svg{color:var(--ink)}
.brand .lg-a{fill:var(--up)}.brand .lg-b{fill:#fff;opacity:.92}.brand .lg-c{fill:var(--down)}

/* 상단 버튼 */
.icon-btn{position:relative;display:inline-flex;align-items:center;justify-content:center;gap:8px;height:44px;min-width:44px;padding:0 14px;border-radius:999px;border:1px solid var(--line2);background:var(--card);color:var(--ink);font-weight:800;font-size:14px;box-shadow:var(--shadow);overflow:hidden;transition:transform .2s var(--spring),background-color .2s,border-color .2s}
.icon-btn:hover{border-color:var(--ink)}
.icon-btn:active{transform:scale(.94)}
.icon-btn svg{width:20px;height:20px;flex:none}
.icon-btn.sq{width:44px;padding:0}
.th svg{position:absolute;inset:0;margin:auto;transition:transform .6s var(--spring),opacity .35s}
.th .i-moon{transform:rotate(-80deg) scale(.3);opacity:0}
html[data-theme="dark"] .th .i-sun{transform:rotate(80deg) scale(.3);opacity:0}
html[data-theme="dark"] .th .i-moon{transform:none;opacity:1}
.out:hover{color:var(--down-deep);border-color:var(--down)}
.out svg{transition:transform .3s var(--ease)}.out:hover svg{transform:translateX(3px)}
.me{height:48px}

/* 종목 스트립 */
.strip{position:relative;margin-top:2px;padding:8px;overflow-x:auto;scrollbar-width:none}
.strip::-webkit-scrollbar{display:none}
#rows{position:relative;z-index:1;display:grid;grid-auto-flow:column;grid-auto-columns:minmax(212px,1fr);gap:6px}
.hl{position:absolute;left:0;top:0;width:0;height:0;border-radius:14px;background:var(--soft);border:1px solid var(--line2);opacity:0;pointer-events:none;z-index:0;transition:transform .55s cubic-bezier(.3,.9,.2,1),width .55s cubic-bezier(.3,.9,.2,1),height .3s,opacity .3s}
.hl.on{opacity:1}
.row{position:relative;display:grid;grid-template-columns:minmax(0,1fr) 64px;grid-template-areas:"nm sp" "pp sp";gap:3px 10px;align-items:center;padding:13px 15px;border-radius:14px;border:1px solid transparent;background:transparent;transition:background-color .2s}
.row:hover{background:color-mix(in srgb,var(--soft) 60%,transparent)}
.row.on{background:transparent}.row.on::before{display:none}
.row>:nth-child(1){grid-area:nm;min-width:0}
.row>:nth-child(2){grid-area:sp}
.row>:nth-child(3){grid-area:pp;display:flex;align-items:baseline;gap:9px}
.row .sp{display:block;height:34px;opacity:.95}
.row .sp svg{width:100%;height:34px;display:block}
.row.draw .sp svg polyline{stroke-dasharray:200;stroke-dashoffset:200;animation:dash 1.2s var(--ease) .1s forwards}
@keyframes dash{to{stroke-dashoffset:0}}
.row b{font-size:15px}
.row .px{font-size:17px}.row .pc{margin-top:0;font-size:13px}

/* 본문 */
.main{grid-template-columns:minmax(0,1fr) 344px;gap:14px;margin-top:14px}
.side{display:grid;gap:14px;align-content:start;min-width:0}
.order{position:static}
.chart{padding:24px 26px 16px}
.cvw{height:clamp(420px,56vh,660px)}
.c-name{font-size:24px}
.c-price{font-size:58px}
.tabs{position:relative;background:var(--soft);border:0}
.tabs::before{content:"";position:absolute;top:4px;bottom:4px;left:0;width:var(--w,0);transform:translateX(var(--x,0));border-radius:9px;background:var(--ink);transition:transform .45s cubic-bezier(.3,.9,.2,1),width .45s cubic-bezier(.3,.9,.2,1)}
.tabs button{position:relative;z-index:1}
.tabs button.on{background:transparent;color:var(--ink-fg)}
.rk-tabs{position:relative;background:var(--soft);border:0}
.rk-tabs::before{content:"";position:absolute;top:3px;bottom:3px;left:0;width:var(--w,0);transform:translateX(var(--x,0));border-radius:7px;background:var(--ink);transition:transform .45s cubic-bezier(.3,.9,.2,1),width .45s cubic-bezier(.3,.9,.2,1)}
.rk-tabs button{position:relative;z-index:1}
.rk-tabs button.on{background:transparent;color:var(--ink-fg)}
.seg{background:var(--soft);border:0}
.seg::before{border-radius:10px}
.qty input,.qty button{background:var(--soft);border-color:transparent}
.qty input:focus{background:var(--card);border-color:var(--ink)}
.quick button{background:var(--soft);border-color:transparent}
.quick button[data-max]{background:var(--ink);color:var(--ink-fg)}

/* 지갑 */
.wallet{padding:22px 22px 8px}
.wallet .lbl{font-size:13px;color:var(--mute);font-weight:700}
.wallet .big{margin-top:2px;font-size:38px;line-height:1.1;font-weight:800;letter-spacing:-.035em;display:flex;align-items:baseline;gap:7px}
.wallet .big small{font-size:15px;font-weight:700;color:var(--mute);letter-spacing:0}
.wallet .today{margin-top:10px;display:flex;align-items:center;gap:8px;font-size:13px;color:var(--mute);font-weight:600}
.w-rows{margin-top:16px}
.w-rows>div{display:grid;grid-template-columns:1fr auto;align-items:baseline;gap:0 10px;padding:12px 0;border-top:1px solid var(--line)}
.w-rows .lbl{font-size:13px}
.w-rows b{font-size:18px;font-weight:800;letter-spacing:-.02em;white-space:nowrap}
.w-rows small{grid-column:1/-1;margin-top:2px;font-size:12px;color:var(--mute);min-height:16px}

/* 등장 애니메이션 */
.rv{animation:rv .8s var(--ease) both;animation-delay:calc(var(--i,0)*70ms)}
@keyframes rv{from{opacity:0;transform:translateY(14px)}}
.swap{animation:swap .55s var(--ease)}
@keyframes swap{from{opacity:0;transform:translateX(-10px)}}
.new{animation:newrow .9s var(--ease)}
@keyframes newrow{0%{opacity:0;transform:translateY(-10px);background:var(--soft)}40%{opacity:1}100%{background:transparent}}
.rip{position:relative;overflow:hidden}
.ripple{position:absolute;border-radius:50%;pointer-events:none;background:currentColor;opacity:.22;transform:scale(0);animation:ripple .65s var(--ease) forwards}
@keyframes ripple{to{transform:scale(1);opacity:0}}
.go{transition:transform .2s var(--spring),filter .15s,opacity .2s}
.chip.live i{box-shadow:0 0 0 0 currentColor}

@media (max-width:1100px){
  .main{grid-template-columns:minmax(0,1fr)}
  #rows{grid-auto-columns:minmax(190px,1fr)}
  #rows{display:grid}
  .row{min-width:0;border:1px solid transparent;grid-template-columns:minmax(0,1fr) 62px}
  .row.on{border-color:transparent}
}
@media (max-width:780px){
  #rows{grid-auto-columns:176px}
  .c-price{font-size:42px}.wallet .big{font-size:32px}
  .icon-btn.out span{display:none}.icon-btn.out{width:44px;padding:0}
  .bar{height:64px;gap:8px}.brand{font-size:19px;white-space:nowrap}.brand svg{width:28px;height:28px}
  .bar-r{gap:6px;flex-wrap:nowrap;min-width:0}.chip.live{display:none}.icon-btn{height:40px}.icon-btn.sq,.icon-btn.out{width:40px;min-width:40px}
  .me{height:40px;padding:0 12px 0 4px;min-width:0;max-width:44vw}.me .av.lg{width:32px;height:32px}.me .dn{font-size:16px;overflow:hidden;text-overflow:ellipsis}.me .who{min-width:0;overflow:hidden}.me .mn{display:none}
  .cvw{height:340px}
}

/* ===== v1.26 둥글고 심플하게: 크기·간격 균형 패치 ===== */
body{font-size:14px;line-height:1.5}
.shell{max-width:1360px;gap:20px;padding:0 22px}
.rv{animation-duration:.7s}
@keyframes rv{from{opacity:0;transform:translateY(10px)}}

/* 카드는 크고 부드럽게 */
.box,.pcard{border-radius:26px;box-shadow:var(--shadow)}
.strip,.me,.chip,.icon-btn{box-shadow:none}

/* 상단 */
.bar{height:68px}
.brand{font-size:22px;gap:10px}
.brand svg{width:30px;height:30px}
.logo-img{height:32px;width:auto;max-width:170px;object-fit:contain;border-radius:10px;display:block}
.logo-edit{display:none;align-items:center;gap:5px;height:30px;padding:0 12px;border:1px dashed var(--line2);border-radius:999px;background:transparent;color:var(--mute);font-size:12px;font-weight:700;margin-left:6px}
.logo-edit:hover{color:var(--ink);border-color:var(--ink)}
.logo-edit.on{display:inline-flex}
.bar-r{gap:8px}
.me{height:44px;padding:0 18px 0 5px;gap:10px;border-radius:999px;background:var(--card)}
.me .dn{font-family:var(--font);font-weight:800;font-size:15px;letter-spacing:-.01em}
.me .mn{font-size:13px}
.av{width:28px;height:28px;font-size:12px}
.av.lg{width:34px;height:34px;font-size:14px}
.chip{height:40px;padding:0 15px;border-radius:999px;font-size:13px}
.login{height:40px;padding:0 20px;border-radius:999px;font-size:13px}
.icon-btn{height:44px;min-width:44px;padding:0 16px;border-radius:999px;font-size:13px}
.icon-btn.sq{width:44px;padding:0}
.icon-btn svg{width:19px;height:19px}

/* 종목 스트립 */
.strip{padding:6px;margin-top:0;border-radius:30px}
#rows{grid-auto-columns:minmax(204px,1fr);gap:6px}
.hl{border-radius:24px}
.row{grid-template-columns:minmax(0,1fr) 56px;grid-template-areas:"nm sp" "pp pp";gap:4px 10px;padding:13px 17px;border-radius:24px}
.row>:nth-child(3){flex-wrap:wrap;column-gap:8px}
.row b{font-size:15px}.row .own{font-size:12px}
.row .px{font-size:16px}.row .pc{font-size:13px}
.row .sp,.row .sp svg{height:30px}
.halt{border-radius:999px;padding:1px 8px;font-size:11px}

/* 본문: 차트는 한 화면에 다 보이게 */
.main{grid-template-columns:minmax(0,1fr) 340px;gap:16px;margin-top:16px;align-items:start}
.side{gap:16px}
.chart{display:flex;flex-direction:column;padding:26px 28px 20px}
.c-head{align-items:flex-start}
.c-name{font-size:20px}
.c-price{font-size:46px;margin-top:4px;padding:0 6px;margin-left:-6px}
.c-price small{font-size:16px}
.c-chg{font-size:15px;margin-top:4px}
.tabs{border-radius:999px;padding:4px}
.tabs::before{top:4px;bottom:4px;border-radius:999px}
.tabs button{padding:7px 16px;font-size:13px;border-radius:999px}
.cvw{flex:none;height:clamp(300px,calc(100vh - 440px),480px);min-height:0;margin-top:12px}
.stats{margin-top:8px;padding-top:16px}
.stats span{font-size:12px}.stats b{font-size:16px}

/* 지갑 */
.wallet{padding:24px 24px 10px}
.wallet .lbl{font-size:13px}
.wallet .big{font-size:34px}.wallet .big small{font-size:14px}
.wallet .today{margin-top:10px;font-size:13px}
.pill{height:26px;font-size:13px;padding:0 12px;border-radius:999px}
.w-rows{margin-top:14px}
.w-rows>div{padding:12px 0}
.w-rows .lbl{font-size:13px}.w-rows b{font-size:16px}.w-rows small{font-size:12px;min-height:16px}

/* 주문 */
.order{padding:22px 24px 24px}
.order h2{font-size:18px;margin-bottom:14px}
.seg{border-radius:999px;padding:4px}
.seg::before{top:4px;bottom:4px;left:4px;width:calc(50% - 4px);border-radius:999px}
.seg button{height:40px;font-size:15px}
.field{margin-top:16px}.field>span{font-size:13px;margin-bottom:6px}
.qty{grid-template-columns:44px 1fr 44px;gap:8px}
.qty button{height:44px;border-radius:50%;font-size:20px}
.qty input{height:44px;border-radius:999px;font-size:18px}
.quick{gap:8px;margin-top:8px}
.quick button{height:34px;border-radius:999px;font-size:13px}
.sum{margin-top:16px;padding-top:14px;font-size:13px}
.sum div{padding:4px 0}
.sum .tot{font-size:14px;padding-top:10px}.sum .tot b{font-size:20px}
.warn{font-size:13px;min-height:20px;margin-top:6px}
.go{height:52px;font-size:16px;border-radius:999px;margin-top:4px}
.note{font-size:12px;margin-top:10px}
.step i{width:40px;height:40px}

/* 하단 */
.low{gap:16px;margin-top:16px}
.sec{padding:10px 20px 16px}
.list h2,.sec h2{font-size:14px;margin:12px 2px 6px}
.scroll{max-height:320px}
.empty{padding:28px 10px;font-size:13px}
.hold{padding:12px 4px}.hold b{font-size:14px}.hold small{font-size:12px}.hold.head{font-size:12px}
.mini{height:30px;padding:0 14px;border-radius:999px;font-size:13px}
.trade{padding:11px 4px}.trade b{font-size:14px}.trade small{font-size:12px}
.tag{font-size:12px;min-width:44px;padding:3px 10px;border-radius:999px}.st{font-size:13px}
.news{padding:12px 4px}.news b{font-size:14px}.news p{font-size:13px}
.news .k{font-size:11px;padding:1px 9px;border-radius:999px}
.toast{border-radius:999px;padding:14px 26px}
.skel{border-radius:24px}

/* 양옆 패널 */
.pcard{padding:20px 20px;margin-bottom:16px}
.pcard h3{font-size:13px;margin-bottom:12px}
.idx{font-size:30px}.idx-s{font-size:12px}
.meter{margin:14px 0 0;height:6px}
.meter i{width:14px;height:14px;margin:-7px 0 0 -7px;border-width:3px}
.mv{padding:9px 8px;border-radius:16px}.mv b{font-size:14px}.mv small{font-size:12px}.mv .r{font-size:14px}
.kv{font-size:13px;padding:7px 0}
.rk-tabs{border-radius:999px;padding:3px}
.rk-tabs::before{top:3px;bottom:3px;border-radius:999px}
.rk-tabs button{font-size:12px;padding:6px 0;border-radius:999px}
.rk{padding:8px 2px}.rk b{font-size:14px}.rk small{font-size:11px}.rk .v{font-size:13px}
.fd-row{padding:8px 2px}.fd-row b{font-size:13px}.fd-row small{font-size:11px}
.tip{font-size:13px;line-height:1.7}

@media (min-width:1620px){
  .shell{grid-template-columns:240px minmax(0,1fr) 240px;max-width:1920px;padding:0 26px}
  .rail{margin-top:68px}
}
@media (max-width:1100px){
  .main{grid-template-columns:minmax(0,1fr)}
  #rows{grid-auto-columns:minmax(180px,1fr)}
  .cvw{height:clamp(300px,46vh,420px)}
}
@media (max-width:780px){
  .shell{padding:0 14px;gap:14px}
  .bar{height:60px}.brand{font-size:19px}.brand svg{width:26px;height:26px}
  .me{height:40px;padding:0 12px 0 4px}.me .av.lg{width:30px;height:30px}.me .dn{font-size:14px}
  .icon-btn{height:40px}.icon-btn.sq,.icon-btn.out{width:40px;min-width:40px;padding:0}
  #rows{grid-auto-columns:170px}
  .chart{padding:20px 16px 14px}
  .c-price{font-size:36px}.wallet .big{font-size:30px}
  .cvw{height:280px}
  .box,.pcard{border-radius:22px}
  .logo-edit{display:none!important}
}

/* ===== v1.27 한 화면에 꽉 차게 (스크롤 없이 전부 보이기) ===== */
@media (min-width:1620px) and (min-height:940px){
  html,body{height:100%;overflow:hidden}
  .shell{height:100vh;height:100dvh;padding-top:0;padding-bottom:0;gap:18px;align-items:stretch}
  .page{display:grid;height:100vh;height:100dvh;padding:0 0 14px;gap:12px;
    grid-template-columns:260px minmax(0,1.25fr) minmax(0,1fr) 316px;
    grid-template-rows:auto auto minmax(0,1fr) clamp(190px,27vh,270px);
    grid-template-areas:"bar bar bar bar" "strip strip strip strip" "chart chart chart order" "wallet hold trades news"}
  .main,.side,.low{display:contents}
  .bar{grid-area:bar;height:56px}
  .strip{grid-area:strip;margin:0;padding:5px}
  .chart{grid-area:chart;min-height:0;min-width:0;padding:16px 22px 12px;overflow:hidden}
  .order{grid-area:order;min-height:0;min-width:0;padding:16px 18px 18px;overflow:auto;scrollbar-width:none}
  .order::-webkit-scrollbar{display:none}
  .wallet{grid-area:wallet;min-height:0;min-width:0;padding:14px 18px 10px;overflow:hidden}
  #holdBox{grid-area:hold}
  .low>.box:nth-child(2){grid-area:trades}
  .low>.box:nth-child(3){grid-area:news}
  .low>.box{min-height:0;min-width:0;display:flex;flex-direction:column;padding:8px 16px 10px;animation:rv .7s .35s var(--ease) both}
  .low>.box h2{margin:6px 2px 4px;flex:none}
  .low>.box .scroll{flex:1 1 auto;min-height:0;max-height:none}

  /* 상단·종목 줄 */
  .me,.chip,.icon-btn,.login{height:38px}
  .icon-btn{min-width:38px}.icon-btn.sq{width:38px}
  .row{padding:9px 16px;gap:2px 10px}
  .row .sp,.row .sp svg{height:26px}
  .row b{font-size:14px}.row .px{font-size:15px}

  /* 차트가 남는 높이를 전부 사용 */
  .c-name{font-size:17px}
  .c-price{font-size:38px;margin-top:0}
  .c-chg{font-size:14px;margin-top:2px}
  .tabs button{padding:6px 14px}
  .cvw{flex:1 1 auto;height:auto;min-height:0;margin-top:8px}
  .stats{margin-top:6px;padding-top:10px}.stats b{font-size:15px}

  /* 주문 칸 */
  .order .form{display:flex;flex-direction:column;min-height:100%}
  .order h2{font-size:16px;margin-bottom:10px}
  .seg button{height:36px}
  .field{margin-top:10px}.field>span{margin-bottom:4px}
  .qty{grid-template-columns:40px 1fr 40px}.qty button,.qty input{height:40px}
  .quick{margin-top:6px}.quick button{height:30px}
  .sum{margin-top:10px;padding-top:8px}.sum div{padding:3px 0}.sum .tot b{font-size:18px}
  .warn{min-height:16px;margin-top:2px;font-size:12px}
  .go{height:46px;margin-top:auto;flex:none}

  /* 지갑 */
  .wallet .lbl{font-size:12px}
  .wallet .big{font-size:28px}
  .wallet .today{margin-top:4px;font-size:12px}
  .w-rows{margin-top:6px}
  .w-rows>div{padding:6px 0}
  .w-rows b{font-size:15px}
  .w-rows small{font-size:11px;min-height:0;margin-top:0}

  /* 양옆 패널 */
  .rail{margin-top:56px;max-height:calc(100vh - 70px);max-height:calc(100dvh - 70px);overflow:auto;scrollbar-width:none;align-self:start;top:0}
  .rail::-webkit-scrollbar{display:none}
  .pcard{padding:12px 14px;margin-bottom:10px}
  .pcard h3{margin-bottom:8px}
  .idx{font-size:26px}
  .mv{padding:6px 6px}
  .kv{padding:5px 0}
  .rk{padding:5px 2px}.fd-row{padding:5px 2px}
}
/* ===== 디자인 다듬기 ===== */
body{background:radial-gradient(1200px 520px at 12% -10%,rgba(47,111,228,.07),transparent 60%),radial-gradient(900px 480px at 100% 0%,rgba(229,56,74,.05),transparent 55%),var(--bg);background-attachment:fixed}
:root[data-theme="dark"] body{background:radial-gradient(1200px 520px at 12% -10%,rgba(90,155,255,.10),transparent 60%),radial-gradient(900px 480px at 100% 0%,rgba(255,91,106,.07),transparent 55%),var(--bg);background-attachment:fixed}
.box,.assets{box-shadow:var(--shadow);border-color:transparent;border-radius:22px}
.me,.chip{box-shadow:0 1px 2px rgba(20,20,20,.04)}
.list .it,.list button{transition:transform .18s var(--ease),background .18s,box-shadow .18s}
.list .it:hover,.list button:hover{transform:translateY(-1px)}
.go{background:linear-gradient(135deg,var(--up),var(--up-deep));box-shadow:0 8px 20px -8px var(--up);letter-spacing:-.01em}
.go.sell{background:linear-gradient(135deg,var(--down),var(--down-deep));box-shadow:0 8px 20px -8px var(--down)}
.go:not(:disabled):hover{transform:translateY(-1px);filter:brightness(1.04)}
.go:not(:disabled):active{transform:translateY(0) scale(.99)}
.seg::before{box-shadow:0 4px 12px -4px currentColor}
.pill{border-radius:999px}
.pill.up{background:var(--up-bg)}.pill.down{background:var(--down-bg)}
.assets{background:linear-gradient(135deg,var(--card),var(--soft))}
::selection{background:var(--up-bg)}
/* 확대(좁은 화면)에서도 모든 종목이 한눈에 보이게 줄바꿈 */
@media (max-width:1100px){
  #rows{grid-auto-flow:row;grid-auto-columns:auto;grid-template-columns:repeat(auto-fit,minmax(170px,1fr))}
  .row{min-width:0}
  .strip{overflow-x:visible}
}
html{overflow-x:hidden}
img,svg,canvas{max-width:100%}
@media (max-width:1619px){
  .shell{display:flex;flex-direction:column}
  .page{order:1}
  .rail{display:grid!important;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;position:static!important;margin:0 0 14px!important;max-height:none!important;overflow:visible!important;order:2}
  .rail-r{order:3;padding-bottom:40px}
  .rail .pcard{margin-bottom:0}
}
/* 스크롤되는 칸은 얇은 스크롤바를 보여줘서 더 있다는 걸 알 수 있게 */
.scroll,.order,.rail{scrollbar-width:thin!important;scrollbar-color:var(--line2) transparent}
.scroll::-webkit-scrollbar,.order::-webkit-scrollbar,.rail::-webkit-scrollbar{display:block!important;width:6px;height:6px}
.scroll::-webkit-scrollbar-thumb,.order::-webkit-scrollbar-thumb,.rail::-webkit-scrollbar-thumb{background:var(--line2);border-radius:99px}
@media (max-width:1619px){
  .page{padding-bottom:14px!important}
  .low{align-items:stretch}
}
/* 중간 화면: 차트 카드가 옆 칸 높이만큼 늘어나 빈 공간이 없게 */
@media (min-width:1101px) and (max-width:1619px){
  .main>.chart{align-self:stretch;display:flex;flex-direction:column}
  .main>.chart .cvw{flex:1 1 auto;height:auto;min-height:320px}
}
/* 어떤 배율에서도 상단 이름이 잘리지 않게 */
.me .dn{overflow:visible!important;text-overflow:clip!important;white-space:normal;word-break:break-all}
.me{max-width:100%!important;height:auto!important;min-height:40px}
.me .who{overflow:visible!important}
</style>
</head>
<body>
<div class="shell">
<aside class="rail rail-l" aria-label="시장 현황">
  <div class="pcard">
    <h3>시장 지수 <small>실시간</small></h3>
    <div class="idx num" id="mAvg">—</div>
    <div class="idx-s" id="mAvgS">전 종목 평균 등락률</div>
    <div class="meter"><i id="mMeter" style="left:50%"></i></div>
  </div>
  <div class="pcard"><h3>급등 TOP</h3><div id="mUp"></div></div>
  <div class="pcard"><h3>급락 TOP</h3><div id="mDown"></div></div>
  <div class="pcard"><h3>시장 정보</h3><div id="mInfo"></div></div>
</aside>
<div class="page" id="app">
  <header class="bar rv" style="--i:0">
    <div class="brand"><span id="brandLogo" style="display:contents"><!--LOGO--><svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="11" fill="currentColor"/><path class="lg-a" d="M16 6l9 5v10l-9 5-9-5V11z"/><path class="lg-b" d="M16 6l9 5-9 5-9-5z"/><path class="lg-c" d="M16 16l9-5v10l-9 5z"/></svg><!--/LOGO--></span>WILDMC 증권<button type="button" class="logo-edit rip" id="logoEdit" title="서버 로고 변경">로고 변경</button><button type="button" class="logo-edit rip" id="logoReset" title="기본 로고로">기본</button><input type="file" id="logoFile" accept="image/*" hidden></div>
    <div class="bar-r">
      <span class="me" id="user" hidden></span>
      <button class="login rip" id="loginTop" hidden type="button">디스코드로 로그인</button>
      <span class="chip live off" id="live"><i></i><span id="liveT">연결 중</span></span>
      <button class="icon-btn sq th rip" id="theme" type="button" aria-label="밤낮 전환" title="밤 / 낮"><svg class="i-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.3M12 19.2v2.3M2.5 12h2.3M19.2 12h2.3M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M18.7 5.3l-1.6 1.6M6.9 17.1l-1.6 1.6"/></svg><svg class="i-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.5 14.2A8.6 8.6 0 0 1 9.8 3.5a8.6 8.6 0 1 0 10.7 10.7z"/></svg></button>
      <button class="icon-btn out rip" id="logout" type="button" title="로그아웃"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 4.5H6.5A2 2 0 0 0 4.5 6.5v11a2 2 0 0 0 2 2H9"/><path d="M15 8l4 4-4 4M19 12H9.5"/></svg><span>로그아웃</span></button>
    </div>
  </header>

  <section class="box strip rv" style="--i:1" aria-label="종목"><div class="hl" id="hl"></div><div id="rows"><div class="skel"></div><div class="skel"></div><div class="skel"></div><div class="skel"></div><div class="skel"></div></div></section>

  <section class="main">
    <section class="box chart rv" style="--i:2">
      <div class="c-head">
        <div id="cHead">
          <div class="c-name"><span id="cName">—</span><span id="cHalt"></span></div>
          <div class="c-price" id="cPriceBox"><span class="odo" id="cPrice"></span><small>돈</small></div>
          <div class="c-chg num" id="cChg"></div>
        </div>
        <div class="tabs" id="tabs"><button type="button" data-r="1m">1분</button><button type="button" data-r="5m" class="on">5분</button><button type="button" data-r="20m">20분</button><button type="button" data-r="1h">1시간</button></div>
      </div>
      <div class="cvw"><canvas id="cv"></canvas></div>
      <div class="stats num">
        <div><span>전일 종가</span><b id="sClose">—</b></div>
        <div><span>오늘 최고</span><b id="sHigh" class="up">—</b></div>
        <div><span>오늘 최저</span><b id="sLow" class="down">—</b></div>
        <div><span>오늘 거래량</span><b id="sVol">—</b></div>
      </div>
    </section>

    <div class="side">
      <section class="box wallet rv" style="--i:3" aria-label="내 자산">
        <div class="lbl">내 총 자산</div>
        <div class="big"><span class="odo" id="total" aria-live="off"></span><small>돈</small></div>
        <div class="today"><span class="pill" id="tPnl">—</span>오늘 손익</div>
        <div class="w-rows">
          <div id="boxMoney"><span class="lbl">보유 돈 (인게임)</span><b class="num" id="kMoney">—</b><small id="kMoneyS"></small></div>
          <div id="boxStock"><span class="lbl">주식 평가액</span><b class="num" id="kStock">0</b><small id="kStockS"></small></div>
          <div><span class="lbl">누적 손익</span><b class="num" id="kProfit">0</b><small id="kProfitS"></small></div>
        </div>
      </section>

      <aside class="box order rv" style="--i:4" id="order">
        <div class="form">
          <h2 id="oTitle">주문</h2>
          <div class="seg" id="seg" data-side="buy"><button type="button" data-side="buy" class="on">매수</button><button type="button" data-side="sell">매도</button></div>
          <label class="field"><span>수량</span>
            <div class="qty"><button type="button" id="qMinus" aria-label="수량 줄이기">−</button><input id="qIn" type="number" min="1" max="10000000" value="1" inputmode="numeric" /><button type="button" id="qPlus" aria-label="수량 늘리기">+</button></div>
          </label>
          <div class="quick"><button type="button" class="rip" data-add="1">+1</button><button type="button" class="rip" data-add="10">+10</button><button type="button" class="rip" data-add="100">+100</button><button type="button" class="rip" data-max="1">최대</button></div>
          <div class="sum num" id="sum"></div>
          <div class="warn" id="warn" role="status"></div>
          <button type="button" class="go rip" id="go">매수하기</button>
          <p class="note" id="note"></p>
        </div>
        <div class="prog" id="prog"></div>
      </aside>
    </div>
  </section>

  <section class="low rv" style="--i:5">
    <div class="box sec" id="holdBox"><h2>내 보유 종목</h2><div class="scroll" id="hold"></div></div>
    <div class="box sec"><h2>거래 내역</h2><div class="scroll" id="trades"></div></div>
    <div class="box sec"><h2>시장 소식</h2><div class="scroll" id="news"></div></div>
  </section>
</div>
<aside class="rail rail-r" aria-label="투자자 랭킹">
  <div class="pcard">
    <h3>투자자 랭킹 <small id="rkNote"></small></h3>
    <div class="rk-tabs" id="rkTabs"><button type="button" data-k="assets" class="on">자산</button><button type="button" data-k="rate">수익률</button><button type="button" data-k="profit">손익</button><button type="button" data-k="volume">거래량</button></div>
    <div id="rk"></div>
  </div>
  <div class="pcard"><h3>실시간 체결 <small>전체 유저</small></h3><div id="feed"></div></div>
  <div class="pcard"><h3>투자 가이드</h3><div class="tip">
    · 시세는 <b>5초</b>마다 바뀌어요.<br>
    · 거래한 돈은 마인크래프트 <b>인게임 돈</b>에서 바로 오가요.<br>
    · <b>최대</b> 버튼을 누르면 내 돈(매도는 보유 수량)에 맞춰 <b>전부</b> 주문해요.<br>
    · 파란색은 <b>상승</b>, 붉은색은 <b>하락</b>이에요.
  </div></div>
</aside>
</div>

<script>
(function(){
"use strict";
const $=id=>document.getElementById(id);
const RM=window.matchMedia&&matchMedia("(prefers-reduced-motion: reduce)").matches;
if(RM) document.body.classList.add("nomotion");
const esc=s=>String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");
const nf=n=>Math.round(Number(n)||0).toLocaleString("ko-KR");
const sgn=n=>n>0?"+":n<0?"-":"";
const sd=n=>sgn(n)+nf(Math.abs(n));
const dir=n=>n>0?"up":n<0?"down":"flat";
const avEl=(url,name,cls,extra)=>{ const l=esc((String(name||"?").trim()[0]||"?").toUpperCase()); return `<span class="av ${cls||""}"><b>${l}</b>${url?`<img src="${esc(url)}" alt="" loading="lazy" referrerpolicy="no-referrer" onerror="this.remove()">`:""}${extra||""}</span>`; };
/* 테마 */
const TH={};
function readTheme(){ const cs=getComputedStyle(document.documentElement), v=n=>cs.getPropertyValue(n).trim(); ["up","down","grid","grid2","axis","cross","tip","card","ink","sub","mute","line2","soft"].forEach(k=>TH[k]=v("--"+k)); const mt=document.querySelector('meta[name="theme-color"]'); if(mt) mt.content=v("--bg"); }
readTheme();
function slide(el){ if(!el) return; const on=el.querySelector(".on"); if(!on) return; el.style.setProperty("--x",on.offsetLeft+"px"); el.style.setProperty("--w",on.offsetWidth+"px"); }
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const FONT="'Pretendard Variable',Pretendard,'Apple SD Gothic Neo','Noto Sans KR','Malgun Gothic',sans-serif";
const MAXQ=10000000;
const RANGES=[["1m",12],["5m",60],["20m",240],["1h",720]];
const LOGIN="/api/auth/discord?next=/stocks";
const st={admin:false,logo:null,feed:[],rank:null,rkKey:"assets",stocks:[],cfg:{feePct:0,trading:true,tick:5},news:[],sel:"",range:"5m",side:"buy",qty:1,acct:null,trades:[],hist:{},histTs:{},busy:false,authed:true,pulse:"",sig:{}};

const cur=()=>st.stocks.find(s=>s.id===st.sel)||st.stocks[0]||null;
const holdOf=id=>{ const h=((st.acct||{}).holdings||[]).find(x=>x.id===id); return h?Number(h.qty)||0:0; };
const ago=ms=>{ if(!ms) return ""; const s=Math.max(0,Math.round((Date.now()-ms)/1000)); if(s<5) return "방금"; if(s<60) return s+"초 전"; if(s<3600) return Math.floor(s/60)+"분 전"; if(s<86400) return Math.floor(s/3600)+"시간 전"; return Math.floor(s/86400)+"일 전"; };
const hms=ts=>{ const d=new Date(ts),p=n=>String(n).padStart(2,"0"); return p(d.getHours())+":"+p(d.getMinutes())+":"+p(d.getSeconds()); };

/* ── 숫자판: 자릿수가 굴러가며 바뀐다 ── */
function odo(el,value){
  const txt=nf(value);
  if(el._txt===txt) return;
  const rebuild=el._len!==txt.length;
  if(rebuild){
    el.innerHTML=txt.split("").map(c=>/\d/.test(c)?`<span class="od" aria-hidden="true"><span class="dg" style="transform:translateY(0)">${"0123456789".split("").map(d=>"<i>"+d+"</i>").join("")}</span></span>`:`<span class="sep" aria-hidden="true">${c}</span>`).join("");
    el._len=txt.length;
  }
  el.setAttribute("aria-label",txt);
  const digs=el.querySelectorAll(".dg"); let k=digs.length;
  const apply=()=>{ let di=0; txt.split("").forEach(c=>{ if(/\d/.test(c)){ const g=digs[di++]; g.style.transitionDelay=RM?"0s":(Math.max(0,(digs.length-di))*0.03)+"s"; g.style.transform="translateY(-"+(Number(c)*1.12)+"em)"; } }); };
  if(rebuild&&!RM){ void el.offsetWidth; requestAnimationFrame(apply); } else apply();
  el._txt=txt;
}
function tween(el,to,fmt){
  if(!el) return; fmt=fmt||nf; to=Number(to)||0;
  const from=el._v==null?0:el._v; el._v=to; cancelAnimationFrame(el._r);
  if(from===to||RM){ el.textContent=fmt(to); return; }
  const t0=performance.now(); const step=t=>{ const p=Math.min(1,(t-t0)/800),e=1-Math.pow(1-p,3); el.textContent=fmt(from+(to-from)*e); if(p<1) el._r=requestAnimationFrame(step); else el.textContent=fmt(to); };
  el._r=requestAnimationFrame(step);
}
function flash(el,d){ if(!el||RM) return; el.classList.remove("fu","fd"); void el.offsetWidth; el.classList.add(d>0?"fu":"fd"); }
function toast(msg){ const t=document.createElement("div"); t.className="toast"; t.textContent=msg; document.body.appendChild(t); requestAnimationFrame(()=>t.classList.add("on")); setTimeout(()=>{ t.classList.remove("on"); setTimeout(()=>t.remove(),450); },2800); }
function flyCoins(a,b,n){
  if(RM||!a||!b) return; const ra=a.getBoundingClientRect(), rb=b.getBoundingClientRect();
  for(let i=0;i<n;i++){
    const el=document.createElement("div"); el.className="fly"; el.textContent="🪙"; document.body.appendChild(el);
    const sx=ra.left+ra.width*(.2+Math.random()*.6), sy=ra.top+ra.height/2, ex=rb.left+rb.width*(.2+Math.random()*.6), ey=rb.top+rb.height/2;
    const mx=(sx+ex)/2+(Math.random()-.5)*180, my=Math.min(sy,ey)-80-Math.random()*70;
    const an=el.animate([{transform:`translate(${sx}px,${sy}px) scale(.5)`,opacity:0},{transform:`translate(${mx}px,${my}px) scale(1.2)`,opacity:1,offset:.5},{transform:`translate(${ex}px,${ey}px) scale(.7)`,opacity:.1}],{duration:850+Math.random()*350,delay:i*70,easing:"cubic-bezier(.4,0,.2,1)",fill:"both"});
    an.onfinish=()=>el.remove();
  }
}
function floatText(anchor,text,color){ if(RM||!anchor) return; const r=anchor.getBoundingClientRect(); const el=document.createElement("div"); el.className="float"; el.textContent=text; el.style.color=color; el.style.left=(r.left+r.width/2-34)+"px"; el.style.top=(r.top)+"px"; document.body.appendChild(el); setTimeout(()=>el.remove(),1700); }

/* ── 차트 ── */
const ch={cv:$("cv"),cur:[],from:[],to:[],t0:0,shift:0,dur:650,revealT0:0,hover:-1};
const rangeN=()=>(RANGES.find(r=>r[0]===st.range)||RANGES[1])[1];
function pushSeries(reset){
  const to=(st.hist[st.sel]||[]).slice(-rangeN());
  if(reset||!ch.cur.length||RM){ ch.from=to.slice(); ch.cur=to.slice(); ch.to=to; ch.t0=0; ch.revealT0=performance.now(); return; }
  ch.from=ch.cur.slice(); ch.to=to; ch.shift=ch.from.length===to.length?1:0; ch.t0=performance.now();
}
function frameSeries(t){
  if(!ch.t0) return ch.to;
  const p=Math.min(1,(t-ch.t0)/ch.dur), e=1-Math.pow(1-p,3), from=ch.from, to=ch.to;
  const out=to.map((v,j)=>{ if(!from.length) return v; const k=Math.min(j+ch.shift,from.length-1); const fv=from[k]; return fv+(v-fv)*e; });
  if(p>=1) ch.t0=0; ch.cur=out; return out;
}
function rrect(g,x,y,w,h,r){ if(g.roundRect){ g.roundRect(x,y,w,h,r); } else g.rect(x,y,w,h); }
function draw(t){
  const cv=ch.cv; if(!cv) return false;
  const dpr=Math.min(2,window.devicePixelRatio||1), W=cv.clientWidth, H=cv.clientHeight; if(!W||!H) return true;
  if(cv.width!==Math.round(W*dpr)||cv.height!==Math.round(H*dpr)){ cv.width=Math.round(W*dpr); cv.height=Math.round(H*dpr); }
  const g=cv.getContext("2d"); g.setTransform(dpr,0,0,dpr,0,0); g.clearRect(0,0,W,H);
  const pts=frameSeries(t), n=pts.length; g.textBaseline="middle";
  if(n<2){ g.fillStyle=TH.mute; g.font="700 15px "+FONT; g.textAlign="center"; g.fillText("시세를 모으는 중이에요",W/2,H/2); return true; }
  const narrow=W<560, L=6, R=narrow?66:84, T=28, B=34, w=W-L-R, h=H-T-B;
  let mn=Math.min(...pts), mx=Math.max(...pts); const pad=(mx-mn)*.16||mx*.02||1; mn-=pad; mx+=pad;
  const X=i=>L+i/(n-1)*w, Y=v=>T+(1-(v-mn)/(mx-mn))*h;
  const up=pts[n-1]>=pts[0], col=up?TH.up:TH.down;
  const sel=cur(), end=(sel&&sel.updatedAt)||Date.now(), step=(st.cfg.tick||5)*1000;
  g.font="600 12px "+FONT; g.textAlign="left";
  for(let k=0;k<=5;k++){ const y=T+h*k/5; g.strokeStyle=TH.grid; g.lineWidth=1; g.beginPath(); g.moveTo(L,y); g.lineTo(L+w,y); g.stroke(); g.fillStyle=TH.axis; g.fillText(nf(mx-(mx-mn)*k/5),L+w+12,y); }
  g.font="600 11px "+FONT;
  const K=narrow?2:4; for(let k=0;k<=K;k++){ const i=Math.round((n-1)*k/K), x=X(i); if(k>0&&k<K){ g.strokeStyle=TH.grid2; g.beginPath(); g.moveTo(x,T); g.lineTo(x,T+h); g.stroke(); } g.fillStyle=TH.axis; g.textAlign=k===0?"left":k===K?"right":"center"; g.fillText(hms(end-(n-1-i)*step),x,H-12); }
  const rp=RM?1:Math.min(1,(t-ch.revealT0)/1000), re=1-Math.pow(1-rp,4);
  g.save(); g.beginPath(); g.rect(0,0,L+w*re+(rp>=1?R:0),H); g.clip();
  g.beginPath(); g.moveTo(X(0),Y(pts[0]));
  for(let i=1;i<n;i++){ const xm=(X(i-1)+X(i))/2, ym=(Y(pts[i-1])+Y(pts[i]))/2; g.quadraticCurveTo(X(i-1),Y(pts[i-1]),xm,ym); }
  g.lineTo(X(n-1),Y(pts[n-1]));
  g.lineWidth=2.6; g.lineJoin="round"; g.lineCap="round"; g.strokeStyle=col; g.stroke();
  g.lineTo(X(n-1),T+h); g.lineTo(X(0),T+h); g.closePath();
  const gr=g.createLinearGradient(0,T,0,T+h); gr.addColorStop(0,col+"38"); gr.addColorStop(1,col+"00"); g.fillStyle=gr; g.fill();
  g.restore();
  if(rp>=1){
    let iM=0,im=0; pts.forEach((v,i)=>{ if(v>pts[iM]) iM=i; if(v<pts[im]) im=i; });
    const mark=(i,label,above)=>{ const x=X(i), y=Y(pts[i]); g.beginPath(); g.arc(x,y,4,0,7); g.fillStyle=TH.card; g.fill(); g.lineWidth=2; g.strokeStyle=TH.sub; g.stroke(); g.font="700 11px "+FONT; const tw=g.measureText(label).width; const tx=Math.max(L+tw/2+2,Math.min(L+w-tw/2-2,x)); g.fillStyle=TH.sub; g.textAlign="center"; g.fillText(label,tx,y+(above?-15:16)); };
    if(iM!==im&&n>8){ mark(iM,"최고 "+nf(pts[iM]),true); mark(im,"최저 "+nf(pts[im]),false); }
    const ly=Y(pts[n-1]), lx=X(n-1);
    g.setLineDash([5,5]); g.strokeStyle=col+"99"; g.lineWidth=1; g.beginPath(); g.moveTo(L,ly); g.lineTo(L+w,ly); g.stroke(); g.setLineDash([]);
    const tag=nf(pts[n-1]); g.font="800 12px "+FONT; const tw=g.measureText(tag).width+16;
    g.fillStyle=col; g.beginPath(); rrect(g,L+w+4,ly-11,tw,22,11); g.fill(); g.fillStyle="#fff"; g.textAlign="left"; g.fillText(tag,L+w+12,ly);
    if(!RM){ const ph=(t%2000)/2000, e2=1-Math.pow(1-ph,2); g.beginPath(); g.arc(lx,ly,5+e2*15,0,7); g.strokeStyle=col; g.globalAlpha=(1-ph)*.5; g.lineWidth=2; g.stroke(); g.globalAlpha=1; }
    g.beginPath(); g.arc(lx,ly,6.5,0,7); g.fillStyle=TH.card; g.fill(); g.beginPath(); g.arc(lx,ly,4.4,0,7); g.fillStyle=col; g.fill();
  }
  if(ch.hover>=0&&ch.hover<n){
    const i=ch.hover, x=X(i), y=Y(pts[i]);
    g.strokeStyle=TH.cross; g.lineWidth=1; g.setLineDash([3,3]); g.beginPath(); g.moveTo(x,T); g.lineTo(x,T+h); g.moveTo(L,y); g.lineTo(L+w,y); g.stroke(); g.setLineDash([]);
    const ht=nf(pts[i]); g.font="800 12px "+FONT; const hw=g.measureText(ht).width+16; g.fillStyle=TH.tip; g.beginPath(); rrect(g,L+w+4,y-11,hw,22,11); g.fill(); g.fillStyle="#fff"; g.textAlign="left"; g.fillText(ht,L+w+12,y);
    g.beginPath(); g.arc(x,y,6.5,0,7); g.fillStyle=TH.card; g.fill(); g.beginPath(); g.arc(x,y,4.4,0,7); g.fillStyle=col; g.fill();
    const diff=pts[i]-pts[0], l1=hms(end-(n-1-i)*step), l2=nf(pts[i])+" 돈", l3=sd(diff)+" ("+(pts[0]?(diff/pts[0]*100).toFixed(2):"0.00")+"%)";
    g.font="800 14px "+FONT; const bw=Math.max(g.measureText(l2).width,g.measureText(l3).width,92)+26, bh=72;
    let bx=x+16; if(bx+bw>L+w-4) bx=x-16-bw; const by=Math.max(T,Math.min(T+h-bh,y-bh/2));
    g.fillStyle=TH.tip; g.beginPath(); rrect(g,bx,by,bw,bh,16); g.fill();
    g.textAlign="left"; g.fillStyle="#9aa1b0"; g.font="600 12px "+FONT; g.fillText(l1,bx+13,by+16);
    g.fillStyle="#fff"; g.font="800 15px "+FONT; g.fillText(l2,bx+13,by+37);
    g.fillStyle=diff>=0?"#ff8a94":"#8dbaff"; g.font="700 12px "+FONT; g.fillText(l3,bx+13,by+57);
  }
  return true;
}
const loop=t=>{ if(draw(t)!==false) requestAnimationFrame(loop); };
requestAnimationFrame(loop);
const hoverAt=e=>{ const r=ch.cv.getBoundingClientRect(), n=ch.cur.length; if(n<2) return; const R=r.width<560?66:84; const x=(e.clientX-r.left-6)/(r.width-6-R); ch.hover=Math.max(0,Math.min(n-1,Math.round(x*(n-1)))); };
ch.cv.addEventListener("pointermove",hoverAt); ch.cv.addEventListener("pointerdown",hoverAt); ch.cv.addEventListener("pointerleave",()=>{ ch.hover=-1; });

/* ── 데이터 ── */
async function jget(u){ const r=await fetch(u,{cache:"no-store"}); if(!r.ok) return {_status:r.status}; return await r.json(); }
function setLive(ok){ $("live").classList.toggle("off",!ok); $("liveT").textContent=ok?"실시간":"연결 끊김"; }
async function loadHist(id){ const d=await jget("/api/stocks/history?id="+encodeURIComponent(id)).catch(()=>null); if(!d||!d.history) return; st.hist[id]=d.history.slice(); st.histTs[id]=d.updatedAt||0; if(id===st.sel) pushSeries(true); }
async function loadList(){
  let d=null; try{ d=await jget("/api/stocks"); }catch(e){}
  if(!d||!d.stocks){ setLive(false); return; }
  setLive(true);
  const prev=new Map(st.stocks.map(s=>[s.id,s]));
  if(d.logo!==undefined&&d.logo!==st.logo){ st.logo=d.logo; if(st.logo||document.querySelector("#brandLogo .logo-img")) setLogo(st.logo); else logoBtns(); }
  st.stocks=d.stocks; st.cfg={feePct:Number(d.feePct)||0,trading:d.trading!==false,tick:Number(d.tickSeconds)||5}; st.news=d.news||[];
  if(!st.sel||!st.stocks.find(s=>s.id===st.sel)) st.sel=(st.stocks[0]||{}).id||"";
  paintList(prev); paintHead(); paintNews(); paintRails();
  const s=cur();
  if(s){ const h=st.hist[s.id]; if(!h) await loadHist(s.id); else if(s.updatedAt>(st.histTs[s.id]||0)){ h.push(s.price); if(h.length>720) h.shift(); st.histTs[s.id]=s.updatedAt; pushSeries(false); } }
  paintOrder(); paintHold();
}
async function pullMe(){
  let d=null; try{ d=await jget("/api/stocks/me"); }catch(e){}
  if(d&&d._status===401){ st.authed=false; st.acct=null; try{ if(!sessionStorage.getItem('wm_re')){ sessionStorage.setItem('wm_re','1'); location.reload(); return; } }catch(e){} }
  else if(d&&d.account){ try{ sessionStorage.removeItem("wm_re"); }catch(e){} st.authed=true; st.admin=!!d.admin; logoBtns(); st.acct=d.account; st.trades=d.trades||[]; }
  paintTop(); paintAcct(); paintHold(); paintTrades(); paintOrder();
}


/* ── 양옆 패널 / 시세 테이프 ── */
function paintRails(){
  const rows=st.stocks; if(!rows.length) return;
  const tape=$("tape"); const one=rows.map(s=>`<span><b>${esc(s.name)}</b><em class="num ${dir(s.changePct)}" style="font-style:normal">${nf(s.price)}</em><em class="num ${dir(s.changePct)}" style="font-style:normal">${s.changePct>0?"▲":s.changePct<0?"▼":"–"} ${Math.abs(s.changePct).toFixed(2)}%</em></span>`).join("");
  const sig=rows.map(s=>s.price).join(",");
  if(tape&&tape._sig!==sig){ tape._sig=sig; const rep=Math.max(2,Math.ceil(12/rows.length)); const half=one.repeat(rep); tape.innerHTML=half+half; }
  const avg=rows.reduce((a,s)=>a+(Number(s.changePct)||0),0)/rows.length;
  const ma=$("mAvg"); if(ma){ ma.className="idx num "+dir(avg); ma.textContent=(avg>0?"▲ ":avg<0?"▼ ":"")+Math.abs(avg).toFixed(2)+"%"; }
  const mm=$("mMeter"); if(mm) mm.style.left=(50+Math.max(-10,Math.min(10,avg))*4.5)+"%";
  const mv=s=>`<div class="mv" data-id="${esc(s.id)}"><div><b>${esc(s.name)}</b><small class="num">${nf(s.price)} 돈</small></div><div class="r num ${dir(s.changePct)}">${s.changePct>0?"+":""}${Number(s.changePct).toFixed(2)}%</div></div>`;
  const sorted=rows.slice().sort((a,b)=>b.changePct-a.changePct);
  const ups=sorted.filter(s=>s.changePct>0).slice(0,3), downs=sorted.slice().reverse().filter(s=>s.changePct<0).slice(0,3);
  const U=$("mUp"), D=$("mDown");
  if(U) U.innerHTML=ups.length?ups.map(mv).join(""):`<div class="empty" style="padding:14px 0;font-size:13px">상승 종목이 없어요.</div>`;
  if(D) D.innerHTML=downs.length?downs.map(mv).join(""):`<div class="empty" style="padding:14px 0;font-size:13px">하락 종목이 없어요.</div>`;
  document.querySelectorAll(".mv[data-id]").forEach(e=>e.onclick=()=>select(e.dataset.id));
  const I=$("mInfo"); if(I) I.innerHTML=`<div class="kv"><span>거래 상태</span><b class="${st.cfg.trading?"up":"down"}" style="color:${st.cfg.trading?"var(--ok)":"var(--down)"}">${st.cfg.trading?"거래 중":"중지"}</b></div><div class="kv"><span>수수료</span><b>${st.cfg.feePct}%</b></div><div class="kv"><span>시세 갱신</span><b>${st.cfg.tick}초</b></div><div class="kv"><span>상장 종목</span><b>${rows.length}개</b></div><div class="kv"><span>총 거래량</span><b>${nf(rows.reduce((a,s)=>a+(Number(s.volume)||0),0))}주</b></div>`;
}
const RKV={assets:r=>nf(r.assets),rate:r=>sgn(r.rate)+Math.abs(r.rate).toFixed(2)+"%",profit:r=>sd(r.profit),volume:r=>nf(r.volume)+"주"};
function paintRank(){
  const box=$("rk"); if(!box) return; const list=(st.rank&&st.rank[st.rkKey])||[];
  $("rkTabs").querySelectorAll("button").forEach(b=>b.classList.toggle("on",b.dataset.k===st.rkKey)); slide($("rkTabs"));
  if(!list.length){ box.innerHTML=`<div class="empty" style="padding:22px 0;font-size:13px">아직 랭킹이 없어요.<br>첫 거래의 주인공이 되어 보세요!</div>`; return; }
  box.innerHTML=list.slice(0,8).map((r,i)=>{ const v=RKV[st.rkKey](r); const c=st.rkKey==="rate"?dir(r.rate):st.rkKey==="profit"?dir(r.profit):""; return `<div class="rk">${avEl(r.avatar,r.discordName,"",`<i class="rn">${i+1}</i>`)}<div><b>${esc(r.discordName||"익명")}</b><small>${esc(r.minecraftName||"")}</small></div><span class="v num ${c}">${esc(v)}</span></div>`; }).join("");
}
function paintFeed(){
  const box=$("feed"); if(!box) return; const l=st.feed||[];
  const seen=st._seen||new Set(), first=!st._seen; st._seen=new Set(l.map(t=>t.id));
  box.innerHTML=l.length?l.slice(0,8).map(t=>`<div class="fd-row${!first&&!seen.has(t.id)?" new":""}">${avEl(t.avatar,t.discordName)}<div><b>${esc(t.discordName||"익명")}</b><small><span class="${t.side==="buy"?"up":"down"}">${t.side==="buy"?"매수":"매도"}</span> ${esc(t.name)} ${nf(t.qty)}주</small></div><span class="t">${ago(t.at)}</span></div>`).join(""):`<div class="empty" style="padding:18px 0;font-size:13px">아직 체결 내역이 없어요.</div>`;
}
async function loadFeed(){ let d=null; try{ d=await jget("/api/stocks/feed"); }catch(e){} if(d&&d.trades){ st.feed=d.trades; paintFeed(); } }
async function loadRank(){ let d=null; try{ d=await jget("/api/stocks/rank"); }catch(e){} if(d&&d.assets){ st.rank=d; paintRank(); } }
$("rkTabs").onclick=e=>{ const b=e.target.closest("button[data-k]"); if(!b) return; st.rkKey=b.dataset.k; paintRank(); };

/* ── 그리기 ── */
function spark(list,up){
  const pts=(list||[]).slice(-60).map(Number).filter(n=>n>0); if(pts.length<2) return "";
  const mn=Math.min(...pts), mx=Math.max(...pts), sp=Math.max(1,mx-mn);
  const d=pts.map((p,i)=>(i/(pts.length-1)*68).toFixed(1)+","+(29-(p-mn)/sp*26).toFixed(1)).join(" ");
  return `<svg viewBox="0 0 68 32" preserveAspectRatio="none" aria-hidden="true"><polyline fill="none" style="stroke:var(${up?"--up":"--down"})" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" points="${d}"/></svg>`;
}
function paintTop(){
  const u=$("user"), l=$("loginTop");
  if(st.authed&&st.acct){ const a=st.acct; const sig=(a.avatar||"")+"|"+a.discordName+"|"+(a.minecraftName||""); if(u._sig!==sig){ u._sig=sig; u.innerHTML=avEl(a.avatar,a.discordName,"lg")+`<span class="who"><b class="dn">${esc(a.discordName)}</b>${a.minecraftName?`<span class="mn">${esc(a.minecraftName)}</span>`:""}</span>`; } u.hidden=false; if(l) l.hidden=true; }
  else if(!st.authed){ u.hidden=true; if(l) l.hidden=false; }
}
function paintList(prev){
  const box=$("rows"); const ids=st.stocks.map(s=>s.id).join("|");
  if(box.dataset.ids!==ids){
    box.dataset.ids=ids;
    box.innerHTML=st.stocks.map(s=>`<div class="row" data-id="${esc(s.id)}" role="button" tabindex="0"><div><b>${esc(s.name)}<span class="h"></span></b><div class="own"></div></div><div class="sp"></div><div><div class="px num"></div><div class="pc num"></div></div></div>`).join("")||`<div class="empty">등록된 종목이 없어요.</div>`;
    box.querySelectorAll(".row").forEach(r=>{ r.classList.add("draw"); setTimeout(()=>r.classList.remove("draw"),1500); });
    box.querySelectorAll(".row").forEach(r=>{ r.onclick=()=>select(r.dataset.id); r.onkeydown=e=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); select(r.dataset.id); } }; });
  }
  st.stocks.forEach(s=>{
    const row=box.querySelector(`[data-id="${CSS.escape(s.id)}"]`); if(!row) return;
    row.classList.toggle("on",s.id===st.sel);
    const px=row.querySelector(".px"), pc=row.querySelector(".pc"), old=prev&&prev.get(s.id), t=nf(s.price);
    if(px.textContent!==t){ px.textContent=t; if(old&&old.price!==s.price) flash(px,s.price-old.price); }
    pc.textContent=(s.changePct>0?"▲ ":s.changePct<0?"▼ ":"")+Math.abs(s.changePct).toFixed(2)+"%"; pc.className="pc num "+dir(s.changePct);
    row.querySelector(".h").innerHTML=s.halted?'<span class="halt">중지</span>':"";
    const q=holdOf(s.id); row.querySelector(".own").textContent=q?"보유 "+nf(q)+"주":"보유 없음";
    const sp=spark(s.history,s.changePct>=0); if(row._sp!==sp){ row._sp=sp; row.querySelector(".sp").innerHTML=sp; }
  });
  moveHl();
}
function moveHl(){ const strip=document.querySelector(".strip"), hl=$("hl"), on=$("rows").querySelector(".row.on"); if(!strip||!hl||!on) return; const sr=strip.getBoundingClientRect(), r=on.getBoundingClientRect(); hl.style.width=r.width+"px"; hl.style.height=r.height+"px"; hl.style.transform=`translate(${r.left-sr.left+strip.scrollLeft}px,${r.top-sr.top+strip.scrollTop}px)`; hl.classList.add("on"); }
window.addEventListener("resize",()=>{ moveHl(); slide($("tabs")); slide($("rkTabs")); });
function paintHead(){
  const s=cur(); if(!s) return;
  $("cName").textContent=s.name; $("cHalt").innerHTML=s.halted?'<span class="halt">거래 중지</span>':"";
  const was=$("cPrice")._p; odo($("cPrice"),s.price); if(was!=null&&was!==s.price) flash($("cPriceBox"),s.price-was); $("cPrice")._p=s.price;
  const c=$("cChg"); c.className="c-chg num "+dir(s.change);
  c.textContent=(s.change>0?"▲ ":s.change<0?"▼ ":"")+nf(Math.abs(s.change))+" ("+sgn(s.changePct)+Math.abs(s.changePct).toFixed(2)+"%) 전일 대비";
  $("sClose").textContent=nf(s.prevClose); $("sHigh").textContent=nf(s.dayHigh); $("sLow").textContent=nf(s.dayLow); $("sVol").textContent=nf(s.volume)+"주";
}
function paintAcct(){
  const a=st.acct;
  if(!a){
    odo($("total"),0); $("kMoney").textContent="—"; $("kMoney")._v=null;
    $("kMoneyS").textContent=st.authed?"불러오는 중이에요":"로그인하면 불러와요";
    tween($("kStock"),0); $("kStockS").textContent=""; tween($("kProfit"),0); $("kProfitS").textContent="";
    const p=$("tPnl"); p.className="pill"; p.textContent="—"; return;
  }
  odo($("total"),a.assets);
  const p=$("tPnl"); p.className="pill "+dir(a.todayPnl); p.textContent=(a.todayPnl>0?"▲ ":a.todayPnl<0?"▼ ":"")+nf(Math.abs(a.todayPnl));
  const km=$("kMoney");
  if(a.moneyKnown){ tween(km,a.money); $("kMoneyS").innerHTML=`<span class="dotok">●</span> 마크 연동 · ${ago(a.moneyAt)}`; }
  else { km.textContent="—"; km._v=null; $("kMoneyS").textContent=a.linked?"마크 서버에서 불러오는 중이에요":"마인크래프트 계정 연동이 필요해요"; }
  tween($("kStock"),a.stockValue); $("kStockS").textContent=(a.holdings||[]).length+"종목 보유";
  const kp=$("kProfit"); kp.className="num "+dir(a.profit); tween(kp,a.profit,sd);
  $("kProfitS").textContent=a.basis?"수익률 "+sgn(a.rate)+Math.abs(a.rate).toFixed(2)+"% · 실현 "+sd(a.realized):"거래를 시작해 보세요";
}
function calc(){ const s=cur(); if(!s) return null; const gross=s.price*st.qty, fee=Math.round(gross*st.cfg.feePct/100); return {s,gross,fee,total:st.side==="buy"?gross+fee:Math.max(0,gross-fee)}; }
function maxQty(){ const s=cur(); if(!s) return 1; if(st.side==="sell") return Math.min(MAXQ,holdOf(s.id)); const a=st.acct; if(!a||!a.moneyKnown) return 1; let q=Math.max(0,Math.floor(a.money/(s.price*(1+st.cfg.feePct/100)))); const cost=n=>s.price*n+Math.round(s.price*n*st.cfg.feePct/100); while(q>0&&cost(q)>a.money) q--; while(cost(q+1)<=a.money) q++; return Math.min(MAXQ,q); }
function paintOrder(){
  if(st.busy) return;
  const o=calc(), go=$("go"); if(!o){ go.disabled=true; return; }
  const a=st.acct, hold=holdOf(o.s.id), buy=st.side==="buy";
  $("seg").dataset.side=st.side; $("seg").querySelectorAll("button").forEach(b=>b.classList.toggle("on",b.dataset.side===st.side));
  $("oTitle").textContent=o.s.name+" 주문";
  if(document.activeElement!==$("qIn")) $("qIn").value=st.qty;
  const after=a&&a.moneyKnown?(buy?a.money-o.total:a.money+o.total):null;
  $("sum").innerHTML=`<div><span>주문 단가</span><b>${nf(o.s.price)} 돈</b></div><div><span>수량</span><b>${nf(st.qty)}주</b></div><div><span>수수료 (${st.cfg.feePct}%)</span><b>${nf(o.fee)} 돈</b></div><div class="tot"><span>${buy?"총 결제 금액":"총 정산 금액"}</span><b class="${buy?"up":"down"}">${nf(o.total)} 돈</b></div>`+(after!=null?`<div><span>주문 후 보유 돈</span><b>${nf(Math.max(0,after))} 돈</b></div>`:"")+`<div><span>내 보유 수량</span><b>${nf(hold)}주</b></div>`;
  let warn="", lock=false;
  if(!st.cfg.trading){ warn="지금은 거래가 중지되어 있어요."; lock=true; }
  else if(o.s.halted){ warn="이 종목은 거래가 중지되어 있어요."; lock=true; }
  else if(buy&&a&&a.moneyKnown&&o.total>a.money){ warn="돈이 "+nf(o.total-a.money)+" 부족해요."; lock=true; }
  else if(!buy&&st.qty>hold){ warn=hold?"보유 수량("+nf(hold)+"주)보다 많아요.":"보유한 주식이 없어요."; lock=true; }
  $("warn").textContent=warn;
  go.className="go"+(buy?"":" sell");
  if(!st.authed){ go.className="go ink"; go.textContent="디스코드로 로그인"; go.disabled=false; go.dataset.mode="login"; $("note").textContent="로그인하면 내 돈으로 바로 거래할 수 있어요."; }
  else if(a&&!a.linked){ go.className="go ink"; go.textContent="마크 계정 연동 필요"; go.disabled=true; go.dataset.mode="none"; $("note").textContent="마인크래프트 계정이 연동되어야 거래할 수 있어요."; }
  else { go.dataset.mode="trade"; go.disabled=lock||st.qty<1; go.textContent=o.s.name+" "+nf(st.qty)+"주 "+(buy?"매수하기":"매도하기"); $("note").textContent="거래한 돈은 마인크래프트 인게임 돈에서 바로 빠지고 들어와요."; }
}
function paintHold(){
  const box=$("hold"); const list=(st.acct||{}).holdings||[]; const sig=JSON.stringify(list)+st.pulse+st.authed; if(st.sig.hold===sig) return; st.sig.hold=sig;
  if(!st.authed){ box.innerHTML=`<div class="empty">로그인하면 내 주식이 보여요.</div>`; return; }
  if(!list.length){ box.innerHTML=`<div class="empty">아직 가진 주식이 없어요.<br>왼쪽에서 종목을 골라 매수해 보세요.</div>`; return; }
  box.innerHTML=`<div class="hold head"><span>종목</span><span class="r hm">평가금액</span><span class="r">손익</span><span></span></div>`+list.map(h=>`<div class="hold${h.id===st.pulse?" pulse":""}" data-id="${esc(h.id)}"><div><b>${esc(h.name)}</b><small>${nf(h.qty)}주 · 평단 ${nf(h.avg)}</small></div><div class="r hm num"><b>${nf(h.value)}</b><small>현재 ${nf(h.price)}</small></div><div class="r num ${dir(h.pnl)}"><b>${sd(h.pnl)}</b><small class="${dir(h.pnl)}">${sgn(h.pnlPct)}${Math.abs(h.pnlPct).toFixed(2)}%</small></div><button type="button" class="mini" data-sell="${esc(h.id)}">매도</button></div>`).join("");
  box.querySelectorAll(".hold[data-id]").forEach(r=>r.onclick=e=>{ if(e.target.closest("button")) return; select(r.dataset.id); });
  box.querySelectorAll("[data-sell]").forEach(b=>b.onclick=()=>{ st.side="sell"; st.qty=Math.max(1,holdOf(b.dataset.sell)); select(b.dataset.sell); $("order").scrollIntoView({behavior:"smooth",block:"nearest"}); });
  if(st.pulse){ const keep=st.pulse; setTimeout(()=>{ if(st.pulse===keep){ st.pulse=""; st.sig.hold=""; } },1600); }
}
function paintTrades(){
  const box=$("trades"); const sig=JSON.stringify(st.trades.map(t=>[t.id,t.status]))+st.authed; if(st.sig.tr===sig) return; st.sig.tr=sig;
  if(!st.authed){ box.innerHTML=`<div class="empty">로그인하면 거래 내역이 보여요.</div>`; return; }
  if(!st.trades.length){ box.innerHTML=`<div class="empty">아직 거래 내역이 없어요.</div>`; return; }
  const SL={done:"완료",failed:"실패",pending:"대기 중",processing:"처리 중"};
  box.innerHTML=st.trades.slice(0,14).map(t=>`<div class="trade"><span class="tag ${t.side}">${t.side==="buy"?"매수":"매도"}</span><div class="who">${avEl(t.avatar,t.discordName)}<div><b>${esc(t.discordName||"")}${t.minecraftName?` <span style="color:var(--mute);font-weight:700">· ${esc(t.minecraftName)}</span>`:""}</b><small class="num">${esc(t.name)} ${nf(t.qty)}주 · ${nf(t.price)} 돈 · ${ago(t.at)}${t.status==="failed"&&t.error?" · "+esc(t.error):""}</small></div></div><span class="st ${t.status}">${SL[t.status]||esc(t.status)}</span></div>`).join("");
}
function paintNews(){
  const box=$("news"); const sig=JSON.stringify(st.news.map(n=>n.id)); if(st.sig.nw===sig) return; st.sig.nw=sig;
  const K={market:"시장",stock:"종목",price:"시세",notice:"공지",event:"이벤트"};
  box.innerHTML=st.news.length?st.news.slice(0,8).map(n=>`<div class="news"><b><span class="k">${K[n.kind]||"소식"}</span>${esc(n.title)}</b><p>${esc(n.body)}</p></div>`).join(""):`<div class="empty">새 소식이 없어요.</div>`;
}

/* ── 조작 ── */
async function select(id){ if(!id) return; if(id!==st.sel){ const hd=$("cHead"); if(hd){ hd.classList.remove("swap"); void hd.offsetWidth; hd.classList.add("swap"); } } st.sel=id; ch.hover=-1; if(!st.hist[id]) await loadHist(id); else pushSeries(true); paintList(null); paintHead(); paintOrder(); }
$("tabs").onclick=e=>{ const b=e.target.closest("button[data-r]"); if(!b) return; st.range=b.dataset.r; $("tabs").querySelectorAll("button").forEach(x=>x.classList.toggle("on",x===b)); slide($("tabs")); pushSeries(true); };
$("seg").onclick=e=>{ const b=e.target.closest("button[data-side]"); if(!b||st.busy) return; st.side=b.dataset.side; paintOrder(); };
const setQty=v=>{ st.qty=Math.max(1,Math.min(10000000,Math.floor(Number(v)||1))); paintOrder(); };
$("qMinus").onclick=()=>setQty(st.qty-1); $("qPlus").onclick=()=>setQty(st.qty+1);
$("qIn").oninput=e=>{ const v=Math.floor(Number(e.target.value)); if(v>=1){ st.qty=Math.min(10000000,v); paintOrder(); } };
$("qIn").onblur=()=>{ $("qIn").value=st.qty; };
document.querySelector(".quick").onclick=e=>{ const b=e.target.closest("button"); if(!b) return; if(b.dataset.max) setQty(Math.max(1,maxQty())); else setQty(st.qty+Number(b.dataset.add)); };
$("go").onclick=()=>{ const m=$("go").dataset.mode; if(m==="login"){ location.href=LOGIN; return; } if(m==="trade") void submit(); };
$("loginTop").onclick=()=>{ location.href=LOGIN; };

const STEPS=["주문 접수","마크 전달","돈 처리"];
function progUI(step,msg){
  const box=$("prog");
  if(!box.dataset.init){ box.dataset.init="1"; box.innerHTML=`<div class="steps"><div class="bar2" id="pBar"></div>${STEPS.map((s,i)=>`<div class="step" data-i="${i}"><i>${i+1}</i>${s}</div>`).join("")}</div><p class="pmsg" id="pMsg"></p>`; }
  box.querySelectorAll(".step").forEach(el=>{ const i=Number(el.dataset.i); el.classList.toggle("done",i<step); el.classList.toggle("on",i===step&&step<3); });
  $("pBar").style.width=(Math.min(step,2)/2*76)+"%"; $("pMsg").textContent=msg||"";
}
function resultUI(ok,title,sub,amt,amtCls){
  $("prog").innerHTML=`<div class="result"><svg class="check ${ok?"ok":"bad"}" viewBox="0 0 76 76" aria-hidden="true"><circle cx="38" cy="38" r="33"/>${ok?'<path d="M23 39l10 10 20-22"/>':'<path d="M27 27l22 22M49 27L27 49"/>'}</svg><h3>${esc(title)}</h3><p>${esc(sub||"")}</p>${amt?`<div class="amt num ${amtCls||""}">${esc(amt)}</div>`:""}</div>`;
  delete $("prog").dataset.init;
  if(!ok&&!RM) $("prog").animate([{transform:"translateX(0)"},{transform:"translateX(-8px)"},{transform:"translateX(8px)"},{transform:"translateX(-5px)"},{transform:"translateX(0)"}],{duration:420});
}
function endBusy(ms){ setTimeout(()=>{ st.busy=false; $("order").classList.remove("busy"); delete $("prog").dataset.init; paintOrder(); },ms); }
async function submit(){
  const s=cur(); if(!s||st.busy) return; st.busy=true; const side=st.side, qty=st.qty;
  $("order").classList.add("busy"); delete $("prog").dataset.init; progUI(0,"주문을 접수하고 있어요");
  let r,d={};
  try{ r=await fetch("/api/stocks/trade",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({id:s.id,side,qty})}); d=await r.json().catch(()=>({})); }
  catch(e){ r={ok:false}; d={error:"네트워크 연결을 확인하고 다시 시도해 주세요."}; }
  if(!r.ok){ if(r.status===401){ st.authed=false; } resultUI(false,"주문하지 못했어요",d.error||"잠시 후 다시 시도해 주세요."); endBusy(3000); return; }
  const id=d.trade.id; progUI(1,"마크 서버로 주문을 보냈어요");
  let trade=d.trade, acct=null; const t0=Date.now();
  while(Date.now()-t0<45000){
    await sleep(500); let x=null; try{ x=await jget("/api/stocks/trade-status?id="+id); }catch(e){}
    if(!x||!x.trade) continue; trade=x.trade; acct=x.account||acct;
    if(trade.status==="processing") progUI(2,"마크에서 돈을 처리하고 있어요");
    if(trade.status==="done"||trade.status==="failed") break;
  }
  if(trade.status!=="done"){ resultUI(false,"거래가 체결되지 않았어요",trade.error||"마크 서버가 응답하지 않아요. 서버가 켜져 있는지 확인해 주세요."); endBusy(3400); void pullMe(); return; }
  progUI(3,""); await sleep(RM?0:350);
  const buy=trade.side==="buy";
  resultUI(true,(buy?"매수":"매도")+" 완료",trade.name+" "+nf(trade.qty)+"주 · 체결가 "+nf(trade.price)+" 돈",(buy?"-":"+")+nf(trade.cost)+" 돈",buy?"up":"down");
  st.pulse=trade.stockId||s.id; st.sig.hold="";
  const n=Math.min(14,4+Math.round(trade.qty/3));
  if(buy) flyCoins($("boxMoney"),$("holdBox"),n); else flyCoins($("holdBox"),$("boxMoney"),n);
  floatText($("kMoney"),(buy?"-":"+")+nf(trade.cost),buy?"#ff6b76":"#6aa7ff");
  if(acct){ st.acct=acct; paintAcct(); }
  toast(trade.name+" "+nf(trade.qty)+"주 "+(buy?"매수":"매도")+" 완료");
  await pullMe(); endBusy(2400);
}

/* ── 서버 로고 ── */
const DEF_LOGO=`<svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="11" fill="currentColor"/><path class="lg-a" d="M16 6l9 5v10l-9 5-9-5V11z"/><path class="lg-b" d="M16 6l9 5-9 5-9-5z"/><path class="lg-c" d="M16 16l9-5v10l-9 5z"/></svg>`;
function setLogo(url){ const slot=$("brandLogo"); if(!slot) return; slot.innerHTML=url?`<img class="logo-img" src="${esc(url)}" alt="">`:DEF_LOGO; logoBtns(); }
function logoBtns(){ const e=$("logoEdit"), r=$("logoReset"); if(e) e.classList.toggle("on",!!st.admin); if(r) r.classList.toggle("on",!!st.admin&&!!st.logo); }
function shrink(file){ return new Promise((res,rej)=>{ const img=new Image(), u=URL.createObjectURL(file); img.onload=()=>{ const sc=Math.min(1,256/Math.max(img.width,img.height)); const c=document.createElement("canvas"); c.width=Math.max(1,Math.round(img.width*sc)); c.height=Math.max(1,Math.round(img.height*sc)); c.getContext("2d").drawImage(img,0,0,c.width,c.height); URL.revokeObjectURL(u); res(c.toDataURL("image/png")); }; img.onerror=()=>rej(new Error("이미지를 읽지 못했어요")); img.src=u; }); }
async function saveLogo(url){ const r=await fetch("/api/site-edit/save",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({settings:{site_logo_url:url}})}); if(!r.ok){ const k=await r.json().catch(()=>({})); throw new Error(k.error||"저장하지 못했어요"); } st.logo=url; setLogo(url); }
$("logoEdit").onclick=()=>$("logoFile").click();
$("logoReset").onclick=async()=>{ try{ await saveLogo(""); toast("기본 로고로 되돌렸어요"); }catch(err){ toast(err.message); } };
$("logoFile").onchange=async e=>{ const f=e.target.files&&e.target.files[0]; e.target.value=""; if(!f) return; try{ const data=await shrink(f); const r=await fetch("/api/site-edit/upload",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({data,filename:f.name})}); const j=await r.json().catch(()=>({})); if(!r.ok) throw new Error(j.error||"업로드하지 못했어요"); await saveLogo(j.url); toast("서버 로고를 바꿨어요"); }catch(err){ toast(err.message||"로고를 올리지 못했어요"); } };

/* ── 밤/낮 · 로그아웃 · 물결 ── */
function applyTheme(t,save){ document.documentElement.setAttribute("data-theme",t); if(save){ try{ localStorage.setItem("wm_theme",t); }catch(e){} } readTheme(); }
$("theme").onclick=e=>{
  const next=document.documentElement.getAttribute("data-theme")==="dark"?"light":"dark";
  const r=$("theme").getBoundingClientRect(), x=r.left+r.width/2, y=r.top+r.height/2, rad=Math.hypot(Math.max(x,innerWidth-x),Math.max(y,innerHeight-y));
  if(document.startViewTransition&&!RM){
    const tr=document.startViewTransition(()=>applyTheme(next,true));
    tr.ready.then(()=>{ document.documentElement.animate({clipPath:[`circle(0px at ${x}px ${y}px)`,`circle(${rad}px at ${x}px ${y}px)`]},{duration:750,easing:"cubic-bezier(.3,.8,.2,1)",pseudoElement:"::view-transition-new(root)"}); }).catch(()=>{});
  } else { const d=document.documentElement; d.classList.add("tt"); applyTheme(next,true); setTimeout(()=>d.classList.remove("tt"),700); }
};
$("logout").onclick=async()=>{ const b=$("logout"); b.disabled=true; b.style.opacity=".6"; try{ await fetch("/api/auth/logout",{method:"POST"}); }catch(e){} location.href="/stocks"; };
document.addEventListener("pointerdown",e=>{ const b=e.target.closest(".rip"); if(!b||b.disabled||RM) return; const r=b.getBoundingClientRect(), d=Math.max(r.width,r.height)*2.2, sp=document.createElement("span"); sp.className="ripple"; sp.style.cssText=`width:${d}px;height:${d}px;left:${e.clientX-r.left-d/2}px;top:${e.clientY-r.top-d/2}px`; b.appendChild(sp); setTimeout(()=>sp.remove(),700); });

/* ── 시작 ── */
(async()=>{
  paintAcct(); paintHold(); paintTrades();
  requestAnimationFrame(()=>{ slide($("tabs")); slide($("rkTabs")); }); if(document.fonts&&document.fonts.ready) document.fonts.ready.then(()=>{ slide($("tabs")); slide($("rkTabs")); moveHl(); });
  await pullMe(); await loadList(); void loadRank(); void loadFeed();
  setInterval(()=>{ if(!document.hidden) void loadList(); },2000);
  setInterval(()=>{ if(!document.hidden) void pullMe(); },2500);
  setInterval(()=>{ if(st.sel) void loadHist(st.sel); },30000);
  setInterval(()=>{ if(!document.hidden) void loadRank(); },15000);
  setInterval(()=>{ if(!document.hidden) void loadFeed(); },5000);
  setInterval(()=>{ if(st.acct&&st.acct.moneyKnown&&!st.busy){ $("kMoneyS").innerHTML=`<span class="dotok">●</span> 마크 연동 · ${ago(st.acct.moneyAt)}`; } },1000);
})();
})();
</script>
</body>
</html>
"""


STOCKS_LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>WILDMC 증권 · 로그인</title>
<meta name="theme-color" content="#f4f4f1" />
<script>(function(){try{var t=localStorage.getItem("wm_theme");if(t!=="light"&&t!=="dark"){t=(window.matchMedia&&matchMedia("(prefers-color-scheme: dark)").matches)?"dark":"light";}document.documentElement.setAttribute("data-theme",t);}catch(e){document.documentElement.setAttribute("data-theme","light");}})();</script>
<link rel="preconnect" href="https://fonts.googleapis.com" /><link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Black+Han+Sans&display=swap" />
<link rel="stylesheet" href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable-dynamic-subset.min.css" />
<style>
:root,:root[data-theme="light"]{--bg:#f4f4f1;--card:#fff;--line:#e6e6df;--line2:#d4d4cb;--ink:#1c1d20;--ink-fg:#fff;--sub:#55585f;--mute:#8a8d94;--up:#e5384a;--down:#2f6fe4;--shadow:0 1px 2px rgba(20,20,20,.04),0 18px 50px rgba(20,20,20,.08)}
:root[data-theme="dark"]{--bg:#1a1c21;--card:#22252b;--line:#33373f;--line2:#454a56;--ink:#eceef2;--ink-fg:#1a1c21;--sub:#b0b5c0;--mute:#808694;--up:#ff5b6a;--down:#5a9bff;--shadow:0 1px 2px rgba(0,0,0,.2),0 18px 50px rgba(0,0,0,.25)}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;display:grid;place-items:center;padding:20px;color:var(--ink);background:var(--bg);font-family:"Pretendard Variable",Pretendard,-apple-system,"Apple SD Gothic Neo","Noto Sans KR","Malgun Gothic",system-ui,sans-serif;-webkit-font-smoothing:antialiased;transition:background-color .5s,color .5s}
::view-transition-old(root),::view-transition-new(root){animation:none;mix-blend-mode:normal}
.card{width:min(400px,100%);padding:44px 30px 32px;text-align:center;border-radius:32px;border:1px solid var(--line);background:var(--card);box-shadow:var(--shadow);animation:in .8s cubic-bezier(.2,.8,.2,1) both;transition:background-color .5s,border-color .5s}
@keyframes in{from{opacity:0;transform:translateY(18px)}}
.logo-img{display:block;margin:0 auto 18px;height:60px;width:auto;max-width:220px;object-fit:contain;border-radius:14px;animation:in .8s .1s cubic-bezier(.2,.8,.2,1) both}
.logo{width:58px;height:58px;margin:0 auto 18px;display:block;color:var(--ink);animation:in .8s .1s cubic-bezier(.2,.8,.2,1) both}
.lg-a{fill:var(--up)}.lg-b{fill:#fff;opacity:.92}.lg-c{fill:var(--down)}
h1{margin:0;font-family:"Black Han Sans","Pretendard Variable",Pretendard,sans-serif;font-weight:400;font-synthesis:none;font-size:31px;letter-spacing:0;animation:in .8s .16s cubic-bezier(.2,.8,.2,1) both}
p{margin:10px 0 26px;font-size:15px;line-height:1.6;color:var(--sub);animation:in .8s .22s cubic-bezier(.2,.8,.2,1) both}
.btn{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;height:54px;border-radius:999px;border:0;background:#5865f2;color:#fff;font-size:17px;font-weight:800;text-decoration:none;transition:filter .15s,transform .2s cubic-bezier(.34,1.4,.5,1);animation:in .8s .28s cubic-bezier(.2,.8,.2,1) both}
.btn:hover{filter:brightness(1.1);transform:translateY(-1px)}.btn:active{transform:scale(.97)}
.btn svg{width:24px;height:24px;fill:#fff}
.foot{margin-top:16px;font-size:12px;color:var(--mute)}
.th{position:fixed;top:18px;right:18px;width:44px;height:44px;border-radius:50%;border:1px solid var(--line2);background:var(--card);color:var(--ink);cursor:pointer;box-shadow:var(--shadow);transition:transform .2s cubic-bezier(.34,1.4,.5,1)}
.th:active{transform:scale(.92)}
.th svg{position:absolute;inset:0;margin:auto;width:20px;height:20px;transition:transform .6s cubic-bezier(.34,1.4,.5,1),opacity .35s}
.th .i-moon{transform:rotate(-80deg) scale(.3);opacity:0}
html[data-theme="dark"] .th .i-sun{transform:rotate(80deg) scale(.3);opacity:0}
html[data-theme="dark"] .th .i-moon{transform:none;opacity:1}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<button class="th" id="th" type="button" aria-label="밤낮 전환"><svg class="i-sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4.2"/><path d="M12 2.5v2.3M12 19.2v2.3M2.5 12h2.3M19.2 12h2.3M5.3 5.3l1.6 1.6M17.1 17.1l1.6 1.6M18.7 5.3l-1.6 1.6M6.9 17.1l-1.6 1.6"/></svg><svg class="i-moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.5 14.2A8.6 8.6 0 0 1 9.8 3.5a8.6 8.6 0 1 0 10.7 10.7z"/></svg></button>
<main class="card">
  <!--LOGO--><svg class="logo" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="11" fill="currentColor"/><path class="lg-a" d="M16 6l9 5v10l-9 5-9-5V11z"/><path class="lg-b" d="M16 6l9 5-9 5-9-5z"/><path class="lg-c" d="M16 16l9-5v10l-9 5z"/></svg><!--/LOGO-->
  <h1>WILDMC 증권</h1>
  <p>디스코드로 로그인하면<br>실시간 시세와 거래를 이용할 수 있어요.</p>
  <a class="btn" href="/api/auth/discord?next=/stocks"><svg viewBox="0 0 127.14 96.36" aria-hidden="true"><path d="M107.7 8.07A105.15 105.15 0 0 0 81.47 0a72.06 72.06 0 0 0-3.36 6.83 97.68 97.68 0 0 0-29.11 0A72.37 72.37 0 0 0 45.64 0 105.89 105.89 0 0 0 19.39 8.09C2.79 32.65-1.71 56.6.54 80.21a105.73 105.73 0 0 0 32.17 16.15 77.7 77.7 0 0 0 6.89-11.11 68.42 68.42 0 0 1-10.85-5.18c.91-.66 1.8-1.34 2.66-2a75.57 75.57 0 0 0 64.32 0c.87.71 1.76 1.39 2.66 2a68.68 68.68 0 0 1-10.87 5.19 77 77 0 0 0 6.89 11.1 105.25 105.25 0 0 0 32.19-16.14c2.64-27.38-4.51-51.11-18.9-72.15zM42.45 65.69C36.18 65.69 31 60 31 53s5-12.74 11.43-12.74S54 46 53.89 53s-5.05 12.69-11.44 12.69zm42.24 0C78.41 65.69 73.25 60 73.25 53s5-12.74 11.44-12.74S96.23 46 96.12 53s-5.04 12.69-11.43 12.69z"/></svg>디스코드로 로그인</a>
  <div class="foot">로그인 후 자동으로 증권 화면으로 이동해요</div>
</main>
<script>
document.getElementById("th").onclick=function(e){var d=document.documentElement,n=d.getAttribute("data-theme")==="dark"?"light":"dark";var r=this.getBoundingClientRect(),x=r.left+r.width/2,y=r.top+r.height/2,R=Math.hypot(Math.max(x,innerWidth-x),Math.max(y,innerHeight-y));var set=function(){d.setAttribute("data-theme",n);try{localStorage.setItem("wm_theme",n);}catch(e){}};if(document.startViewTransition){var t=document.startViewTransition(set);t.ready.then(function(){d.animate({clipPath:["circle(0px at "+x+"px "+y+"px)","circle("+R+"px at "+x+"px "+y+"px)"]},{duration:750,easing:"cubic-bezier(.3,.8,.2,1)",pseudoElement:"::view-transition-new(root)"});}).catch(function(){});}else set();};
</script>
</body>
</html>
"""


def render_html() -> bytes:
    html = (
        SHELL.replace("__CSS__", ROUND_FONT_CSS + CSS)
        .replace("__WEB_BUILD__", WEB_VERSION)
        .replace("__PRODUCTS__", json.dumps(db.get("products", []), ensure_ascii=False))
    )
    return html.encode("utf-8")


LOTTERY_HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>WILDMC 복권</title>
<link href="https://fonts.googleapis.com/css2?family=Dongle:wght@400;700&family=Jua&display=swap" rel="stylesheet"/>
<style>
:root { color-scheme: dark; --bg:#0a0f0d; --gold:#d9b673; --gold2:#f0dfb5; --mint:#86d6aa; --text:#f4f0e6; --muted:#9fb0a6; --line:rgba(232,213,168,.16); --danger:#ef8a78; }
* { box-sizing: border-box; }
html, body { margin:0; background:#0a0f0d; color:var(--text); }
body { min-height:100vh; font-family:"Dongle","Jua","Malgun Gothic",sans-serif; font-size:1.28rem; line-height:1.45; background-image:radial-gradient(900px 500px at 8% -10%, rgba(125,206,160,.16), transparent 55%), radial-gradient(800px 480px at 100% 0%, rgba(217,182,115,.14), transparent 50%); }
a { color:inherit; }
button, input { font:inherit; color:inherit; }
.wrap { max-width:72rem; margin:0 auto; padding:1.4rem 1.2rem 3rem; }
.header { display:flex; align-items:center; justify-content:space-between; gap:.75rem; flex-wrap:wrap; margin-bottom:1.2rem; padding:.7rem .8rem .7rem 1.1rem; border-radius:28px; border:1px solid var(--line); background:rgba(18,28,24,.94); }
.brand { font-family:"Jua","Dongle",sans-serif; font-size:1.7rem; color:var(--gold2); text-decoration:none; }
.brand .dot { color:var(--mint); }
.pill { border-radius:999px; border:1px solid var(--line); background:rgba(255,255,255,.03); padding:.15rem .9rem; text-decoration:none; cursor:pointer; }
.pill.gold { background:var(--gold); color:#1a1408; border-color:transparent; }
h2 { font-family:"Jua","Dongle",sans-serif; font-size:1.7rem; margin:1.2rem 0 .4rem; color:var(--gold2); }
.grid { display:grid; grid-template-columns:repeat(3, minmax(0,1fr)); gap:.7rem; }
.card { background:rgba(18,28,24,.72); border:1px solid var(--line); border-radius:22px; padding:.9rem 1rem; }
.muted { color:var(--muted); }
.row { display:flex; gap:.5rem; flex-wrap:wrap; align-items:center; }
input { background:#0d120c; border:1px solid var(--line); border-radius:14px; padding:.35rem .7rem; }
table { width:100%; border-collapse:collapse; }
th, td { text-align:left; padding:.35rem .3rem; border-bottom:1px solid var(--line); }
.big { font-size:2rem; letter-spacing:.12em; }
.warn { color:var(--danger); }
@media (max-width: 800px) { .grid { grid-template-columns:1fr; } }
</style>
</head>
<body>
<div class="wrap">
<header class="header">
  <a class="brand" href="/">WILDMC <span class="dot">·</span> 복권</a>
  <div class="row"><a class="pill" href="/">상점</a><span id="who">확인 중</span></div>
</header>
<main id="page"></main>
</div>
<script>
const $=id=>document.getElementById(id);
let board=null, me=null, mine={tickets:[]}, past=[], admin=false, mode="auto", key="";
function won(n){ return Number(n||0).toLocaleString("ko-KR"); }
function cashLabel(n){ const c=Number(n)||0; const per=(board&&board.settings&&board.settings.wonPerCash)||10; return won(c)+"캐시 ("+won(c*per)+"원 상당)"; }
function esc(s){ return String(s==null?"":s).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;"); }
function left(ms){ const d=Math.max(0, Number(ms)||0); const s=Math.floor(d/1000); const h=Math.floor(s/3600), m=Math.floor((s%3600)/60), sec=s%60; return h+"시간 "+m+"분 "+sec+"초"; }
function rankName(rank){ return rank==1?"1등":rank==2?"2등":rank==3?"3등":"낙첨"; }
function paint(){
  if(!board||!board.round){ $("page").innerHTML="<p class='muted'>회차를 불러오는 중…</p>"; return; }
  const r=board.round, s=board.settings||{};
  const pots=(r.estimated||[]).map(p=>`<section class="card"><span class="muted">${p.rank}등 예상</span><b>${cashLabel(p.cash)}</b></section>`).join("");
  const mineRows=(mine.tickets||[]).map(t=>`<tr><td>${t.roundId}</td><td class="big">${esc(t.number)}</td><td>${t.mode==="auto"?"자동":"수동"}</td><td>${t.status==="pending"?"처리 중":t.status==="failed"?"실패":t.rank?rankName(t.rank):t.status==="drawn"?"낙첨":"추첨 전"}</td><td>${t.prize?cashLabel(t.prize):"—"}</td></tr>`).join("");
  const pastRows=(past||[]).map(p=>`<tr><td>${p.id}</td><td class="big">${esc(p.winning||"—")}</td><td>${won(p.sales)}캐시</td><td>${p.winners?`1등 ${p.winners[1]||0} · 2등 ${p.winners[2]||0} · 3등 ${p.winners[3]||0}`:""}</td><td>이월 ${won(p.carryOut)}</td></tr>`).join("");
  const adminBox=admin?`<h2>관리</h2><section class="card">
    <p class="${s.alert?"warn":"muted"}">${esc(s.alert||"환원율 알림 없음")}</p>
    <p>이번 주 판매 ${won(board.week&&board.week.sales)}캐시 · 지급 ${won(board.week&&board.week.paid)}캐시 · 소각 ${won(board.week&&board.week.burned)}캐시 · 환원율 ${board.week?board.week.rate:0}%</p>
    <div class="row">
      <label>가격 <input id="price" type="number" value="${s.price}"/></label>
      <label>하루 한도 <input id="limit" type="number" value="${s.dailyLimit}"/></label>
      <label>환원율 % <input id="rate" type="number" value="${s.returnRate}"/></label>
      <label>1등 상한 배수 <input id="cap" type="number" value="${s.firstCapMultiple}"/></label>
      <label>일 당첨 한도 <input id="wincap" type="number" value="${s.dailyWinCap}"/></label>
      <button class="pill gold" id="save" type="button">설정 저장</button>
      <button class="pill" id="halt" type="button">${s.enabled?"판매 중지":"판매 재개"}</button>
      <button class="pill" id="draw" type="button">지금 추첨</button>
    </div>
    <p id="amsg" class="muted"></p>
  </section>`:"";
  $("page").innerHTML=`
    <div class="grid">
      <section class="card"><span class="muted">1장 가격</span><b>${cashLabel(s.price)}</b></section>
      <section class="card"><span class="muted">오늘 남은 구매</span><b>${board.remaining}장</b><p class="muted">하루 ${s.dailyLimit}장 · 자정(KST) 초기화</p></section>
      <section class="card"><span class="muted">추첨까지</span><b id="count">${left((r.drawAt||0)-Date.now())}</b><p class="muted">${r.status==="selling"?"판매 중":"판매 마감"}</p></section>
    </div>
    <h2>${r.id}회차 · 판매 ${cashLabel(r.sales)}</h2>
    <div class="grid">${pots}</div>
    <p class="muted">환원율 ${s.returnRate}% · 1등 ${s.split1}% · 2등 ${s.split2}% · 3등 ${s.split3}% · 앞 2자리 이하는 낙첨</p>
    ${s.enabled?"":"<p class='warn'>판매가 중지되어 있어요.</p>"}
    <h2>구매</h2>
    <section class="card">
      <div class="row">
        <button class="pill ${mode==="auto"?"gold":""}" id="tabAuto" type="button">자동</button>
        <button class="pill ${mode==="manual"?"gold":""}" id="tabManual" type="button">수동</button>
      </div>
      <div class="row" style="margin-top:.7rem">
        ${mode==="auto"?`<label>장수 <input id="qty" type="number" min="1" max="${board.remaining||1}" value="1"/></label>`:`<label>번호 <input id="num" inputmode="numeric" maxlength="5" placeholder="00000"/></label>`}
        <button class="pill gold" id="buy" type="button">사기</button>
      </div>
      <p id="msg" class="muted"></p>
    </section>
    <h2>내 복권</h2>
    <div class="card" style="overflow:auto"><table><thead><tr><th>회차</th><th>번호</th><th>방식</th><th>결과</th><th>당첨금</th></tr></thead><tbody>${mineRows||"<tr><td colspan='5' class='muted'>아직 없어요.</td></tr>"}</tbody></table></div>
    <h2>지난 회차</h2>
    <div class="card" style="overflow:auto"><table><thead><tr><th>회차</th><th>당첨번호</th><th>판매</th><th>1~3등</th><th>이월</th></tr></thead><tbody>${pastRows||"<tr><td colspan='5' class='muted'>아직 없어요.</td></tr>"}</tbody></table></div>
    ${adminBox}`;
  const auto=$("tabAuto"), manual=$("tabManual");
  if(auto) auto.onclick=()=>{ mode="auto"; paint(); };
  if(manual) manual.onclick=()=>{ mode="manual"; paint(); };
  const buy=$("buy");
  if(buy) buy.onclick=()=>purchase();
  const save=$("save"), halt=$("halt"), draw=$("draw");
  if(save) save.onclick=()=>adminPost({op:"settings", price:Number($("price").value), dailyLimit:Number($("limit").value), returnRate:Number($("rate").value), firstCapMultiple:Number($("cap").value), dailyWinCap:Number($("wincap").value)});
  if(halt) halt.onclick=()=>adminPost({op:"halt", enabled:!(s.enabled)});
  if(draw) draw.onclick=()=>{ if(confirm("지금 회차를 추첨할까요?")) adminPost({op:"draw"}); };
}
async function purchase(){
  if(!me||!me.authenticated){ location.href="/api/auth/discord?next=/lottery"; return; }
  if(!me.minecraft){ $("msg").textContent="마인크래프트 계정을 연동한 뒤 살 수 있어요."; return; }
  if(!key) key=Math.random().toString(36).slice(2)+Date.now().toString(36);
  const body={mode, idempotencyKey:key};
  if(mode==="auto") body.count=Math.max(1, Number(($("qty")||{}).value)||1);
  else body.numbers=[String(($("num")||{}).value||"").padStart(5,"0")];
  const res=await fetch("/api/lottery/buy",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const data=await res.json().catch(()=>({}));
  const msg=$("msg"); if(msg) msg.textContent=data.message||data.error||"실패";
  if(res.ok){ key=""; setTimeout(load, 2000); }
}
async function adminPost(body){
  const res=await fetch("/api/lottery/admin",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  const data=await res.json().catch(()=>({}));
  const msg=$("amsg"); if(msg) msg.textContent=data.error||data.message||"저장했어요.";
  if(res.ok) load();
}
async function load(){
  try{ const r=await fetch("/api/me"); me=r.ok?await r.json():null; }catch(e){ me=null; }
  if(me&&me.authenticated){
    $("who").textContent=(me.discord&&me.discord.username)||"로그인됨";
    admin=!!me.canEditSite;
    try{ const r=await fetch("/api/lottery/me"); if(r.ok) mine=await r.json(); }catch(e){}
  }else{
    admin=false;
    $("who").innerHTML='<a class="pill gold" href="/api/auth/discord?next=/lottery">디스코드 로그인</a>';
  }
  try{ const r=await fetch("/api/lottery"); if(r.ok) board=await r.json(); }catch(e){}
  try{ const r=await fetch("/api/lottery/rounds"); if(r.ok) past=(await r.json()).rounds||[]; }catch(e){}
  paint();
}
load();
setInterval(()=>{ const el=$("count"); if(el&&board&&board.round) el.textContent=left((board.round.drawAt||0)-Date.now()); }, 1000);
setInterval(load, 8000);
</script>
<p style="display:none">web __WEB_BUILD__</p>
</body></html>
"""

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print(f"[http] {self.address_string()} {fmt % args}")

    def _json(self, code: int, payload: dict, set_cookie: str | None = None, clear_cookie: bool = False) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if set_cookie:
            self.send_header("Set-Cookie", cookie_header(set_cookie))
        if clear_cookie:
            self.send_header("Set-Cookie", cookie_header("", clear=True))
        cors(self)
        self.end_headers()
        self.wfile.write(body)

    def _set_cookie(self, token: str) -> None:
        self.send_header("Set-Cookie", cookie_header(token))

    def _clear_cookie(self) -> None:
        self.send_header("Set-Cookie", cookie_header("", clear=True))

    def _redirect(self, location: str, code: int = 302, set_cookie: str | None = None) -> None:
        self.send_response(code)
        self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", cookie_header(set_cookie))
        cors(self)
        self.end_headers()

    def _serve_file(self, filepath: Path, content_type: str) -> None:
        if not filepath.is_file():
            self.send_error(404)
            return
        data = filepath.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        cors(self)
        self.end_headers()
        self.wfile.write(data)

    def _market_html(self) -> None:
        body = MARKET_HTML.replace("__WEB_BUILD__", WEB_VERSION).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _stocks_html(self) -> None:
        # 디스코드 로그인을 하지 않았다면 로그인 창만 보여준다
        authed = is_discord_authenticated(get_session(self))
        page = STOCKS_HTML if authed else STOCKS_LOGIN_HTML
        with lock:
            logo = site_logo_url()
        if logo:
            from html import escape as _esc
            page = re.sub(r"<!--LOGO-->.*?<!--/LOGO-->", lambda m: '<img class="logo-img" src="' + _esc(logo, quote=True) + '" alt="">', page, flags=re.S)
        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _lottery_html(self) -> None:
        body = LOTTERY_HTML.replace("__WEB_BUILD__", WEB_VERSION).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _html(self) -> None:
        body = render_html()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        # 상품 이미지(base64) 업로드 허용 — 약 12MB
        if length > 14 * 1024 * 1024:
            return {"__error": "요청이 너무 큽니다. 이미지를 줄여 주세요."}
        try:
            raw = self.rfile.read(length).decode("utf-8")
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {"__error": "요청 본문을 읽지 못했습니다."}

    def _client_ip(self) -> str:
        xf = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return xf or (self.client_address[0] if self.client_address else "unknown")

    def _admin_locked(self) -> bool:
        return False

    def _admin_fail_hit(self) -> None:
        return

    def _admin_fail_clear(self) -> None:
        with lock:
            _admin_fail.clear()

    def _key_ok(self, provided: str, expected: str) -> bool:
        if not provided or not expected:
            return False
        a = provided.encode("utf-8")
        b = expected.encode("utf-8")
        if len(a) != len(b):
            hmac.compare_digest(a, a)
            return False
        return hmac.compare_digest(a, b)

    def _admin_ok(self) -> bool:
        key = (
            self.headers.get("x-admin-key")
            or self.headers.get("X-Admin-Key")
            or self.headers.get("x-api-key")
            or ""
        ).strip()
        if not key:
            return False
        if self._key_ok(key, ADMIN_KEY):
            return True
        if DESKTOP_KEY and self._key_ok(key, DESKTOP_KEY):
            return True
        # 앱 내장 고정키 — 호스트 .env 미동기화여도 데스크톱 연결 가능
        if self._key_ok(key, BUILTIN_DESKTOP_KEY):
            return True
        return False

    def _admin_auth_error(self) -> None:
        return self._json(401, {"error": "관리 키가 올바르지 않습니다."})

    def _handle_plugin_websocket(self) -> None:
        """ServerBridge /ws/plugin — RFC6455 (stdlib only)."""
        global plugin_online
        key = (self.headers.get("x-api-key") or self.headers.get("X-Api-Key") or "").strip()
        if key != PLUGIN_KEY:
            return self._json(401, {"error": "Unauthorized"})
        upgrade = (self.headers.get("Upgrade") or "").lower()
        connection = (self.headers.get("Connection") or "").lower()
        sec_key = (self.headers.get("Sec-WebSocket-Key") or "").strip()
        if upgrade != "websocket" or "upgrade" not in connection or not sec_key:
            return self._json(426, {"error": "WebSocket Upgrade required", "path": "/ws/plugin"})
        accept = _ws_accept_key(sec_key)
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        sock = self.connection
        with _plugin_ws_lock:
            _plugin_ws_sockets.add(sock)
        with lock:
            plugin_online = True
        print("[ws] plugin connected", flush=True)
        try:
            # greet
            _ws_send_frame(sock, json.dumps({"type": "HELLO", "payload": {"ok": True}}, ensure_ascii=False).encode("utf-8"))
            while True:
                frame = _ws_recv_frame(sock)
                if frame is None:
                    break
                opcode, data = frame
                if opcode == 0x8:  # close
                    break
                if opcode == 0x9:  # ping
                    _ws_send_frame(sock, data, opcode=0xA)
                    continue
                if opcode == 0xA:  # pong
                    continue
                if opcode == 0x1:
                    handle_plugin_ws_message(data.decode("utf-8", errors="ignore"))
                # binary ignored
        except Exception as exc:
            print(f"[ws] plugin error: {exc}", flush=True)
        finally:
            with _plugin_ws_lock:
                _plugin_ws_sockets.discard(sock)
            print("[ws] plugin disconnected", flush=True)
            try:
                sock.close()
            except Exception:
                pass


    def _wiki_html(self, edit: int) -> None:
        body = render_wiki_html(edit)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _admin_web_html(self) -> None:
        body = ADMIN_WEB_HTML.replace("__WEB_BUILD__", WEB_VERSION).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _decorate_html(self) -> None:
        body = DECORATE_HTML.replace("__WEB_BUILD__", WEB_VERSION).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        cors(self)
        self.end_headers()

    def do_GET(self) -> None:
        global plugin_online
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path == "/ws/plugin":
            return self._handle_plugin_websocket()

        if path in ("/lottery", "/lottery/"):
            return self._lottery_html()
        if path in ("/market", "/market/"):
            self.send_response(302)
            self.send_header("Location", "/stocks")
            self.end_headers()
            return
        if path in ("/stocks", "/stocks/"):
            return self._stocks_html()
        if path == "/wiki" or path == "/wiki/":
            return self._wiki_html(0)
        if path.startswith("/wiki/editor"):
            return self._wiki_html(1)
        if path.startswith("/wiki/p/"):
            return self._wiki_html(0)
        if path.startswith("/wiki/static/"):
            name = path[len("/wiki/static/"):]
            if ".." in name or name.startswith("/"):
                return self.send_error(403)
            fp = WIKI_STATIC / name
            ctype = {
                ".css": "text/css; charset=utf-8",
                ".js": "application/javascript; charset=utf-8",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".webp": "image/webp",
                ".gif": "image/gif",
                ".svg": "image/svg+xml",
            }.get(fp.suffix.lower(), "application/octet-stream")
            return self._serve_file(fp, ctype)
        if path.startswith("/wiki/uploads/"):
            name = path[len("/wiki/uploads/"):]
            if ".." in name or "/" in name or "\\" in name:
                return self.send_error(403)
            ext = name.rsplit(".", 1)[-1].lower()
            ctype = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp", "gif": "image/gif"}.get(ext, "application/octet-stream")
            return self._serve_file(WIKI_UPLOADS / name, ctype)
        if path == "/wiki/api/site":
            return self._json(200, load_wiki())
        if path == "/wiki/api/me":
            session = get_session(self)
            return self._json(
                200,
                {
                    "admin": can_edit_site(session),
                    "authenticated": is_discord_authenticated(session),
                    "discordId": (session or {}).get("discordId"),
                    "isTeamWildmc": is_team_wildmc(session),
                    "siteEditVia": site_edit_via(session),
                    "group": user_luckperms_group((session or {}).get("discordId")),
                },
            )
        if path == "/admin" or path == "/admin/":
            return self._admin_web_html()
        if path == "/decorate" or path == "/decorate/":
            return self._decorate_html()

        if path.startswith("/uploads/support/"):
            name = path.split("/uploads/support/", 1)[-1]
            if ".." in name or "/" in name or "\\" in name:
                return self.send_error(403)
            ext = name.rsplit(".", 1)[-1].lower()
            ctype = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp"}.get(ext, "application/octet-stream")
            return self._serve_file(SUPPORT_UPLOADS / name, ctype)

        if path.startswith("/uploads/products/"):
            name = path.split("/uploads/products/", 1)[-1]
            if ".." in name or "/" in name or "\\" in name:
                return self.send_error(403)
            ext = name.rsplit(".", 1)[-1].lower()
            ctype = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp", "gif": "image/gif"}.get(ext, "application/octet-stream")
            return self._serve_file(PRODUCT_UPLOADS / name, ctype)

        if path.startswith("/uploads/orders/"):
            name = path.split("/uploads/orders/", 1)[-1]
            if ".." in name or "/" in name or "\\" in name:
                return self.send_error(403)
            ext = name.rsplit(".", 1)[-1].lower()
            ctype = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg", "webp": "image/webp", "gif": "image/gif"}.get(ext, "application/octet-stream")
            return self._serve_file(ORDER_UPLOADS / name, ctype)

        if path == "/health":
            return self._json(
                200,
                {
                    "ok": True,
                    "siteName": SITE,
                    "appUrl": APP_URL,
                    "discordConfigured": discord_configured(),
                    "discordRedirectUri": DISCORD_REDIRECT_URI,
                    "adminAttemptsUnlimited": True,
                    "rateLimitDisabled": True,
                    "webBuild": WEB_VERSION,
                    "pluginWs": "/ws/plugin",
                    **get_stats(),
                },
            )
        if path == "/api/desktop/clear-lock":
            # 옛 서버 잠금 잔여 제거용 (인증 불필요 · 시도 제한 자체는 이미 비활성)
            with lock:
                _admin_fail.clear()
            return self._json(200, {"ok": True, "cleared": True, "adminAttemptsUnlimited": True})
        if path == "/api/desktop/connect":
            if not self._admin_ok():
                return self._admin_auth_error()
            # 내장 고정키로 연결된 경우는 .env 약함 검사 생략
            return self._json(
                200,
                {
                    "ok": True,
                    "siteName": SITE,
                    "appUrl": APP_URL,
                    "port": PORT,
                    "pluginOnline": plugin_online,
                    "https": APP_URL.startswith("https://"),
                    "message": "데스크탑 앱 연결 성공",
                },
            )
        if path == "/api/server/status":
            return self._json(200, get_stats())
        if path == "/api/products":
            return self._json(200, {"products": public_products()})
        if path == "/api/notices":
            return self._json(200, {"notices": public_notices()})
        if path == "/api/me":
            code, payload = me_payload(get_session(self))
            return self._json(code, payload)
        if path == "/api/alerts":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            with lock:
                items = [m for m in db.get("inbox", []) if m.get("discord_id") == did]
                unread_items = [m for m in items if not m.get("read")]
                unread = len(unread_items)
                unread_items.sort(key=lambda m: -int(m.get("created_at") or m.get("id") or 0))
                new_kinds: list[str] = []
                for m in unread_items[:8]:
                    k = str(m.get("kind") or "info")
                    if k not in new_kinds:
                        new_kinds.append(k)
                incoming = 0
                for f in db.get("friendships", []):
                    if not isinstance(f, dict):
                        continue
                    if f.get("status") == "pending" and str(f.get("to_id") or "") == did:
                        incoming += 1
                notices = public_notices()
                latest_notice = notices[0] if notices else None
                claimable_n = 0
                for c in public_claimable_coupons(did):
                    if c.get("claimed") or c.get("downloaded"):
                        continue
                    if int(c.get("remaining") or 0) <= 0:
                        continue
                    claimable_n += 1
                latest_chat_at = 0
                for m in db.get("chat_messages", []):
                    if not isinstance(m, dict):
                        continue
                    if str(m.get("to_id") or "") == did:
                        latest_chat_at = max(latest_chat_at, int(m.get("created_at") or 0))
            return self._json(
                200,
                {
                    "inboxUnread": unread,
                    "friendIncoming": incoming,
                    "latestNoticeId": safe_int((latest_notice or {}).get("id")),
                    "claimableCoupons": claimable_n,
                    "latestChatAt": latest_chat_at,
                    "newKinds": new_kinds,
                },
            )
        if path == "/api/auth/logout":
            token = get_session_token(self)
            if token:
                with lock:
                    db.get("sessions", {}).pop(token, None)
                    save_db(db)
            self.send_response(302)
            self.send_header("Location", "/admin")
            self._clear_cookie()
            cors(self)
            self.end_headers()
            return
        if path == "/api/store":
            settings = {k: v for k, v in (db.get("settings") or {}).items() if k not in PRIVATE_SETTING_KEYS}
            latest = public_notices()[:1]
            return self._json(
                200,
                {
                    "settings": settings,
                    "banners": [b for b in db.get("banners", []) if b.get("active", 1) != 0],
                    "products": public_products(),
                    "latestNotice": latest[0] if latest else None,
                    "theme": resolve_theme(settings),
                    "donors": donation_ranking(3),
                },
            )
        if path == "/api/site-edit/bootstrap":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "본 사이트 꾸미기 권한이 없습니다."})
            latest = public_notices()[:1]
            return self._json(
                200,
                site_edit_payload() | {"latestNotice": latest[0] if latest else None},
            )
        if path == "/api/site-edit/history":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "권한이 없습니다."})
            return self._json(200, {"items": site_edit_history_public()})
        if path == "/fonts/round.css":
            body = ROUND_FONT_CSS.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/css; charset=utf-8")
            self.send_header("Cache-Control", "public, max-age=604800")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/pay":
            product_id = int((qs.get("productId") or qs.get("product") or [0])[0] or 0)
            pay = payment_payload()
            custom_kind = str((qs.get("custom") or qs.get("kind") or [""])[0] or "").strip()
            custom_amount = safe_int((qs.get("amount") or [0])[0] or 0)
            if custom_kind:
                product = quote_custom_product(custom_kind, custom_amount)
                if not product:
                    return self._json(
                        400,
                        {
                            "error": f"커스텀 구매는 최소 {custom_min_won()}원입니다. 캐시는 {cash_per_won()}당 1원, 후원잼은 {gem_won_each()}원당 1개.",
                            "minWon": custom_min_won(),
                            "cashPerWon": cash_per_won(),
                            "gemWonEach": gem_won_each(),
                        },
                    )
                return self._json(200, {"enabled": payment_settings().get("enabled") != "0", "payment": pay, "product": product, "custom": True, "minWon": custom_min_won(), "cashPerWon": cash_per_won(), "gemWonEach": gem_won_each()})
            if not product_id:
                return self._json(200, {"enabled": payment_settings().get("enabled") != "0", "payment": pay})
            product = next((p for p in public_products() if safe_int(p.get("id")) == product_id), None)
            if not product:
                return self._json(404, {"error": "상품을 찾을 수 없습니다."})
            session = get_session(self)
            if session:
                product = apply_rank_price(product, buyer_shop_rank(str(session.get("discordId") or ""))) or product
            return self._json(200, {"enabled": payment_settings().get("enabled") != "0", "payment": pay, "product": product})
        if path.startswith("/api/pay/order/"):
            code = path.rsplit("/", 1)[-1]
            order = find_order_by_code(code)
            if not order:
                return self._json(404, {"error": "주문을 찾을 수 없습니다."})
            pay = payment_payload()
            pay["agencies"] = payment_agencies()
            return self._json(200, {"order": order, "payment": pay})
        if path == "/api/inbox":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            items = [m for m in db.get("inbox", []) if m.get("discord_id") == did]
            items.sort(key=lambda m: -int(m.get("id") or 0))
            unread = sum(1 for m in items if not m.get("read"))
            return self._json(200, {"items": items[:100], "unread": unread})
        if path == "/api/achievements":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            return self._json(200, achievements_payload(session["discordId"]))

        if path == "/api/admin/web/notices":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "Team. Wildmc 권한이 필요합니다."})
            return self._json(200, {"notices": list(reversed(db.get("notices", [])))[:50]})
        if path == "/api/friends":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            friends, incoming, outgoing = [], [], []
            for f in db.get("friendships", []):
                a, b = str(f.get("from_id") or ""), str(f.get("to_id") or "")
                st = f.get("status") or "pending"
                if st == "accepted" and did in (a, b):
                    other = b if a == did else a
                    friends.append({**(user_public(find_user(other)) or {"discord_id": other, "username": other}), "id": f.get("id")})
                elif st == "pending" and b == did:
                    incoming.append({"id": f.get("id"), "from_id": a, "username": (user_public(find_user(a)) or {}).get("username") or a})
                elif st == "pending" and a == did:
                    outgoing.append({"id": f.get("id"), "to_id": b, "username": (user_public(find_user(b)) or {}).get("username") or b})
            return self._json(200, {"friends": friends, "incoming": incoming, "outgoing": outgoing})
        if path == "/api/chat":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            other = str((qs.get("with") or [""])[0] or "")
            if not other or not are_friends(did, other):
                return self._json(403, {"error": "친구만 채팅할 수 있습니다."})
            msgs = [
                m for m in db.get("chat_messages", [])
                if {str(m.get("from_id")), str(m.get("to_id"))} == {did, other}
            ]
            msgs.sort(key=lambda m: int(m.get("created_at") or 0))
            return self._json(200, {"messages": msgs[-200:]})
        if path == "/api/support":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            items = [i for i in db.get("inquiries", []) if str(i.get("user_id") or "") == did]
            items.sort(key=lambda x: -int(x.get("id") or 0))
            return self._json(200, {"items": items[:50]})
        if path == "/api/reviews":
            pid = safe_int((qs.get("product_id") or [0])[0] or 0)
            session = get_session(self)
            did = str((session or {}).get("discordId") or "")
            rows = [r for r in db.get("reviews", []) if not r.get("hidden")]
            if pid > 0:
                rows = [r for r in rows if safe_int(r.get("product_id")) == pid]
            rows.sort(key=lambda r: -safe_int(r.get("created_at")))
            mine = next((r for r in rows if did and str(r.get("discord_id") or "") == did), None)
            return self._json(
                200,
                {
                    "reviews": [public_review(r) for r in rows[:80]],
                    "canWrite": bool(did and pid > 0 and user_purchased_product(did, pid)),
                    "myReview": public_review(mine) if mine else None,
                    "stats": (review_stats_map().get(pid) if pid else {"count": len(rows), "avg": 0}),
                },
            )
        if path == "/api/community":
            session = get_session(self)
            viewer = str((session or {}).get("discordId") or "")
            pid = safe_int((qs.get("id") or qs.get("post_id") or [0])[0] or 0)
            rows = [p for p in db.get("community_posts", []) if not p.get("hidden")]
            rows.sort(key=lambda p: -safe_int(p.get("created_at")))
            if pid > 0:
                post = next((p for p in rows if safe_int(p.get("id")) == pid), None)
                if not post:
                    return self._json(404, {"error": "글을 찾을 수 없습니다."})
                item = public_community_post(post, viewer)
                item["comments"] = nest_comments(item.get("comments") or [])
                return self._json(200, {"post": item})
            posts = []
            for p in rows[:80]:
                item = public_community_post(p, viewer)
                item["comments"] = nest_comments(item.get("comments") or [])
                posts.append(item)
            return self._json(200, {"posts": posts})
        if path == "/api/admin/inquiries":
            if not self._admin_ok():
                return self._admin_auth_error()
            items = list(reversed(db.get("inquiries", [])))
            return self._json(200, {"items": items[:200], "open": sum(1 for i in items if i.get("status") == "open")})
        if path == "/api/admin/chat":
            if not self._admin_ok():
                return self._admin_auth_error()
            did = str((qs.get("discordId") or [""])[0] or "").strip()
            user = find_user(did) if did else None
            if not user:
                return self._json(404, {"error": "해당 유저를 찾을 수 없습니다."})
            return self._json(
                200,
                {
                    "thread": admin_chat_thread(did),
                    "user": {
                        "discord_id": did,
                        "discord_username": user.get("discord_username") or did,
                        "minecraft_name": user.get("minecraft_name"),
                    },
                },
            )
        if path == "/api/patch-notes":
            shop = list(reversed(db.get("shop_changes") or []))[:60]
            notes = db.get("web_patch_notes") if isinstance(db.get("web_patch_notes"), list) else PATCH_NOTES
            return self._json(200, {"version": WEB_VERSION, "web": notes, "shop": shop, "manual": isinstance(db.get("web_patch_notes"), list)})
        if path == "/api/donations/month":
            month = str((qs.get("month") or [""])[0] or "").strip() or None
            return self._json(200, month_donation_report(month))
        if path == "/api/me/purchases":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            return self._json(200, user_purchase_summary(str(session.get("discordId") or "")))
        if path == "/api/admin/patch-notes":
            if not self._admin_ok():
                return self._admin_auth_error()
            notes = db.get("web_patch_notes") if isinstance(db.get("web_patch_notes"), list) else PATCH_NOTES
            return self._json(200, {"notes": notes, "version": (notes[0].get("version") if notes else WEB_VERSION)})
        if path == "/api/lottery":
            session = get_session(self)
            did = str((session or {}).get("discordId") or "")
            with lock:
                current = ensure_lottery_round()
                settings = lottery_settings()
                used = lottery_tickets_today(did) if did else 0
                payload = {
                    "round": lottery_round_public(current, db.get("lottery_tickets") or []),
                    "settings": lottery_settings_public(),
                    "remaining": max(0, int(settings["daily_limit"]) - used) if did else int(settings["daily_limit"]),
                    "week": lottery_week_stats() if can_edit_site(session) else None,
                }
                save_db(db)
            return self._json(200, payload)
        if path == "/api/lottery/me":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = str(session.get("discordId") or "")
            with lock:
                tickets = [lottery_ticket_public(row) for row in reversed(db.get("lottery_tickets") or []) if str(row.get("discord_id") or "") == did][:80]
            return self._json(200, {"tickets": tickets})
        if path == "/api/lottery/rounds":
            with lock:
                rows = [lottery_round_public(row, db.get("lottery_tickets") or []) for row in reversed(db.get("lottery_rounds") or []) if row.get("status") == "drawn"][:20]
            return self._json(200, {"rounds": rows})
        if path == "/api/lottery/admin":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "관리자만 볼 수 있어요."})
            with lock:
                return self._json(200, {
                    "settings": lottery_settings_public(),
                    "week": lottery_week_stats(),
                    "rounds": [lottery_round_public(row, db.get("lottery_tickets") or []) for row in reversed(db.get("lottery_rounds") or [])][:20],
                    "jobs": [
                        {"id": row.get("id"), "kind": row.get("kind"), "amount": row.get("amount"), "status": row.get("status"), "error": row.get("error") or ""}
                        for row in reversed(db.get("lottery_jobs") or [])
                    ][:40],
                })
        if path == "/api/plugin/lottery-jobs":
            if (self.headers.get("x-api-key") or "") != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            plugin_online = True
            with lock:
                expire_lottery_jobs()
                pending = []
                for job in db.get("lottery_jobs") or []:
                    if str(job.get("status") or "") != "pending":
                        continue
                    job["status"] = "processing"
                    pending.append({
                        "id": job.get("id"),
                        "minecraftName": job.get("minecraft_name"),
                        "kind": job.get("kind"),
                        "amount": job.get("amount"),
                    })
                    if len(pending) >= 20:
                        break
                if pending:
                    save_db(db)
            return self._json(200, {"jobs": pending})
        if path == "/api/stocks":
            with lock:
                ensure_stocks()
                cfg = stock_fee_config()
                rows = [stock_public(s) for s in db.get("stocks") or []]
                ups = [r for r in sorted(rows, key=lambda r: -float(r.get("changePct") or 0)) if float(r.get("changePct") or 0) > 0][:3]
                downs = [r for r in sorted(rows, key=lambda r: float(r.get("changePct") or 0)) if float(r.get("changePct") or 0) < 0][:3]
                news = [news_public(n) for n in reversed(db.get("stock_news") or []) if isinstance(n, dict)][:5]
            return self._json(200, {
                "stocks": rows,
                "tickSeconds": 5,
                "feePct": cfg["feePct"],
                "volatilityPct": round(cfg["volatility"] * 100, 2),
                "trading": cfg["trading"],
                "leaders": {"up": ups, "down": downs},
                "news": news,
                "logo": site_logo_url(),
            })
        if path == "/api/stocks/history":
            sid = (qs.get("id") or [""])[0]
            with lock:
                ensure_stocks()
                row = find_stock(sid)
                if not row:
                    return self._json(404, {"error": "없는 종목이에요."})
                hist = [safe_int(x) for x in (row.get("history") or [])][-720:]
                data = stock_public(row)
            return self._json(200, {"id": data["id"], "name": data["name"], "tickSeconds": 5, "updatedAt": data["updatedAt"], "history": hist})
        if path == "/api/stocks/trade-status":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = str(session.get("discordId") or "")
            tid = safe_int((qs.get("id") or ["0"])[0])
            with lock:
                expire_stock_trades()
                trade = next((t for t in db.get("stock_trades") or [] if safe_int(t.get("id")) == tid and str(t.get("discord_id") or "") == did), None)
                if not trade:
                    return self._json(404, {"error": "거래를 찾을 수 없어요."})
                _wu = find_user(did)
                if _wu is not None:
                    _wu["stock_watch_at"] = now_ms()
                account = stock_account(did)
                save_db(db)
            return self._json(200, {"trade": trade_public(trade), "account": account})
        if path == "/api/stocks/news":
            with lock:
                items = [news_public(n) for n in reversed(db.get("stock_news") or []) if isinstance(n, dict)][:40]
            return self._json(200, {"news": items})
        if path == "/api/stocks/rank":
            with lock:
                board = stock_rankings()
            return self._json(200, board)
        if path == "/api/stocks/feed":
            with lock:
                feed = []
                for t in reversed(db.get("stock_trades") or []):
                    if str(t.get("status") or "") != "done":
                        continue
                    pub = trade_public(t)
                    feed.append({
                        "id": pub["id"], "discordName": pub["discordName"], "avatar": pub["avatar"],
                        "name": pub["name"], "side": pub["side"], "qty": pub["qty"],
                        "price": pub["price"], "at": pub["at"],
                    })
                    if len(feed) >= 30:
                        break
            return self._json(200, {"trades": feed})
        if path == "/api/stocks/trades":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = str(session.get("discordId") or "")
            with lock:
                trades = [trade_public(t) for t in reversed(db.get("stock_trades") or []) if str(t.get("discord_id") or "") == did][:80]
            return self._json(200, {"trades": trades})
        if path == "/api/stocks/admin":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "관리자만 볼 수 있어요."})
            with lock:
                ensure_stocks()
                cfg = stock_fee_config()
                trades = [trade_public(t) for t in reversed(db.get("stock_trades") or []) if isinstance(t, dict)][:80]
                flagged = [t for t in trades if t.get("flag") or t.get("status") == "failed"]
                accounts = []
                seen: set[str] = set()
                for t in db.get("stock_trades") or []:
                    seen.add(str(t.get("discord_id") or ""))
                for h in db.get("stock_holdings") or []:
                    if safe_int(h.get("qty")) > 0:
                        seen.add(str(h.get("discord_id") or ""))
                seen.discard("")
                for did in seen:
                    accounts.append(stock_account(did))
                stocks = [stock_public(s) for s in db.get("stocks") or []]
            return self._json(200, {
                "config": {"feePct": cfg["feePct"], "volatilityPct": round(cfg["volatility"] * 100, 2), "trading": cfg["trading"]},
                "stocks": stocks,
                "trades": trades,
                "flagged": flagged,
                "accounts": accounts,
            })
        if path == "/api/stocks/me":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = str(session.get("discordId") or "")
            with lock:
                expire_stock_trades()
                _wu = find_user(did)
                if _wu is not None:
                    _wu["stock_watch_at"] = now_ms()
                account = stock_account(did)
                trades = [trade_public(t) for t in reversed(db.get("stock_trades") or []) if str(t.get("discord_id") or "") == did][:20]
            return self._json(200, {"admin": can_edit_site(session), "account": account, "holdings": account["holdings"], "trades": trades})
        if path == "/api/admin/stocks":
            if not self._admin_ok():
                return self._admin_auth_error()
            with lock:
                ensure_stocks()
                rows = [stock_public(s) for s in db.get("stocks") or []]
            return self._json(200, {"stocks": rows, "tickSeconds": 5})
        if path == "/api/admin/promo-codes":
            if not self._admin_ok():
                return self._admin_auth_error()
            rows = list(reversed(db.get("promo_codes") or []))
            return self._json(200, {"codes": [promo_public(r) for r in rows if isinstance(r, dict)]})
        if path == "/api/admin/donations":
            if not self._admin_ok():
                return self._admin_auth_error()
            month = str((qs.get("month") or [""])[0] or "").strip() or None
            return self._json(200, month_donation_report(month))
        if path == "/api/admin/activity-logs":
            if not self._admin_ok():
                return self._admin_auth_error()
            limit = min(800, max(20, safe_int((qs.get("limit") or [300])[0] or 300)))
            q = str((qs.get("q") or [""])[0] or "").strip().lower()
            action_f = str((qs.get("action") or [""])[0] or "").strip()
            items = list(reversed(db.get("activity_logs", [])))
            if action_f:
                items = [x for x in items if str(x.get("action") or "") == action_f]
            if q:
                items = [
                    x
                    for x in items
                    if q in str(x.get("summary") or "").lower()
                    or q in str(x.get("username") or "").lower()
                    or q in str(x.get("detail") or "").lower()
                    or q in str(x.get("discord_id") or "").lower()
                    or q in str(x.get("minecraft_name") or "").lower()
                    or q in str(x.get("group") or "").lower()
                    or q in str(x.get("target_name") or "").lower()
                ]
            return self._json(
                200,
                {
                    "logs": items[:limit],
                    "actionLabels": ACTION_LABELS_KO,
                },
            )
        if path == "/api/admin/reviews":
            if not self._admin_ok():
                return self._admin_auth_error()
            rows = list(reversed(db.get("reviews", [])))
            return self._json(200, {"reviews": [public_review(r, admin=True) for r in rows[:300]]})
        if path == "/api/admin/community":
            if not self._admin_ok():
                return self._admin_auth_error()
            posts = []
            for p in reversed(db.get("community_posts", [])):
                item = public_community_post(p, "", admin=True)
                item["comments"] = nest_comments(item.get("comments") or [])
                posts.append(item)
            return self._json(200, {"posts": posts[:200]})

        if path == "/api/coupons/wallet":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            product_id = safe_int((qs.get("productId") or qs.get("product") or [0])[0] or 0) or None
            price = None
            if product_id:
                product = next((p for p in public_products() if safe_int(p.get("id")) == product_id), None)
                if product:
                    price = safe_int(product.get("price"))
            return self._json(
                200,
                {"coupons": wallet_coupons_for(session["discordId"], product_id, price)},
            )
        if path == "/api/coupons/claimable":
            session = get_session(self)
            did = session["discordId"] if session else None
            return self._json(200, {"coupons": public_claimable_coupons(did)})
        if path == "/api/auth/discord":
            if not discord_configured():
                return self._redirect("/login?error=discord_config")
            nxt = (qs.get("next") or ["/"])[0]
            if not str(nxt).startswith("/"):
                nxt = "/"
            state = secrets.token_urlsafe(16)
            with lock:
                db.setdefault("oauth_states", {})[state] = {"next": nxt, "at": now_ms()}
                save_db(db)
            params = urlencode(
                {
                    "client_id": DISCORD_CLIENT_ID,
                    "redirect_uri": DISCORD_REDIRECT_URI,
                    "response_type": "code",
                    "scope": "identify guilds.members.read",
                    "state": state,
                }
            )
            return self._redirect(f"https://discord.com/api/oauth2/authorize?{params}")
        if path in DISCORD_CALLBACK_PATHS or path.rstrip("/") in DISCORD_CALLBACK_PATHS:
            code = (qs.get("code") or [""])[0]
            if not code:
                return self._redirect("/login?error=oauth")
            if not discord_configured():
                return self._redirect("/login?error=discord_config")
            token_data, token_err = discord_http_json(
                "https://discord.com/api/oauth2/token",
                method="POST",
                data={
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": DISCORD_REDIRECT_URI,
                },
            )
            if not token_data or not token_data.get("access_token"):
                print(f"[discord oauth] token exchange failed: {token_err} redirect_uri={DISCORD_REDIRECT_URI}", flush=True)
                return self._redirect("/login?error=token")
            user_data, user_err = discord_http_json(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {token_data['access_token']}"},
            )
            if not user_data or not user_data.get("id"):
                print(f"[discord oauth] user fetch failed: {user_err}", flush=True)
                return self._redirect("/login?error=user")
            username = user_data.get("global_name") or user_data.get("username") or "discord"
            avatar = user_data.get("avatar")
            discord_id = str(user_data["id"])
            role_ids = fetch_discord_member_roles(discord_id, str(token_data.get("access_token") or ""))
            token = secrets.token_urlsafe(32)
            state = (qs.get("state") or [""])[0]
            nxt = "/panel"
            with lock:
                db.setdefault("sessions", {})[token] = {
                    "discordId": discord_id,
                    "username": username,
                    "avatar": avatar,
                    "discordRoles": role_ids,
                    "createdAt": now_ms(),
                }
                upsert_user(discord_id, discord_username=username, discord_avatar=avatar, discord_roles=role_ids)
                unlock_achievement(discord_id, "welcome")
                st = (db.get("oauth_states") or {}).pop(state, None) if state else None
                if isinstance(st, dict) and str(st.get("next") or "").startswith("/"):
                    nxt = str(st["next"])
                save_db(db)
            return self._redirect(nxt, set_cookie=token)
        if path.startswith("/api/plugin/commands"):
            if (self.headers.get("x-api-key") or "") != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            plugin_online = True
            rows = [c for c in db.get("command_queue", []) if not c.get("processed")][:20]
            return self._json(200, {"commands": [{"id": c["id"], "command": c["command"]} for c in rows]})
        if path == "/api/plugin/stock-trades":
            if (self.headers.get("x-api-key") or "") != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            plugin_online = True
            with lock:
                expire_stock_trades()
                pending = []
                for trade in db.get("stock_trades") or []:
                    if str(trade.get("status") or "") != "pending":
                        continue
                    trade["status"] = "processing"
                    pending.append(
                        {
                            "id": trade.get("id"),
                            "minecraftName": trade.get("minecraft_name"),
                            "uuid": str((find_user(str(trade.get("discord_id") or "")) or {}).get("minecraft_uuid") or ""),
                            "side": trade.get("side"),
                            "cost": trade.get("cost"),
                            "qty": trade.get("qty"),
                            "name": trade.get("name"),
                        }
                    )
                    if len(pending) >= 20:
                        break
                if pending:
                    save_db(db)
                cutoff = now_ms() - 150000
                watch = [
                    {"name": u.get("minecraft_name"), "uuid": str(u.get("minecraft_uuid") or "")}
                    for u in db.get("users") or []
                    if u.get("minecraft_name") and safe_int(u.get("stock_watch_at")) > cutoff
                ][:50]
            return self._json(200, {"trades": pending, "watch": watch})
        if path == "/api/plugin/stats":
            if (self.headers.get("x-api-key") or "") != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            with lock:
                metrics = dict(server_metrics)
                logs = list(console_logs[-200:])
            return self._json(200, {"ok": True, "stats": metrics, "console": logs, "pluginOnline": plugin_online})
        if path.startswith("/api/admin/"):
            return self._admin_get(path)
        if path.startswith("/api"):
            return self._json(404, {"error": "not found"})
        return self._html()

    def _admin_get(self, path: str) -> None:
        if not self._admin_ok():
            return self._admin_auth_error()
        if path == "/api/admin/stats":
            return self._json(200, admin_stats())
        if path == "/api/admin/products":
            return self._json(200, {"products": db.get("products", [])})
        if path == "/api/admin/banners":
            return self._json(200, {"banners": db.get("banners", [])})
        if path == "/api/admin/notices":
            return self._json(200, {"notices": db.get("notices", [])})
        if path == "/api/admin/settings":
            return self._json(200, {"settings": db.get("settings", {})})
        if path == "/api/admin/payment":
            return self._json(200, {"settings": db.get("payment", {})})
        if path == "/api/admin/orders":
            orders = list(reversed(db.get("orders", [])))
            return self._json(200, {"orders": orders, "counts": order_counts()})
        if path == "/api/admin/users":
            users = db.get("users", [])
            if not isinstance(users, list):
                users = []
            bags = db.get("user_achievements", {}) or {}
            total = len(ACHIEVEMENTS)
            enriched = []
            for u in users:
                if not isinstance(u, dict):
                    continue
                did = str(u.get("discord_id") or "").strip()
                if not did:
                    continue
                unlocked_n = len(bags.get(did) or {})
                row = dict(u)
                row["discord_id"] = did
                row["discord_username"] = u.get("discord_username") or u.get("username") or did
                row["achievements_unlocked"] = unlocked_n
                row["achievements_total"] = total
                enriched.append(row)
            enriched.sort(
                key=lambda x: (
                    0 if x.get("minecraft_uuid") else 1,
                    str(x.get("discord_username") or "").lower(),
                )
            )
            unlinked = [u for u in enriched if not u.get("minecraft_uuid")]
            linked = [u for u in enriched if u.get("minecraft_uuid")]
            return self._json(
                200,
                {
                    "loggedIn": enriched,
                    "unlinked": unlinked,
                    "linked": linked,
                    "users": enriched,
                    "counts": {
                        "loggedIn": len(enriched),
                        "unlinked": len(unlinked),
                        "linked": len(linked),
                    },
                },
            )
        if path == "/api/admin/coupons":
            rows = list(reversed(db.get("coupons", [])))
            return self._json(200, {"coupons": rows})
        if path == "/api/admin/achievements":
            qs = parse_qs(urlparse(self.path).query)
            did = str((qs.get("discordId") or qs.get("discord_id") or [""])[0] or "").strip()
            catalog = [
                {
                    "id": a["id"],
                    "title": a["title"],
                    "desc": a["desc"],
                    "icon": a.get("icon") or "🏆",
                    "category": a.get("category") or "기본",
                    "secret": bool(a.get("secret")),
                }
                for a in ACHIEVEMENTS
            ]
            unlocked_ids = []
            if did:
                unlocked_ids = sorted((db.get("user_achievements", {}).get(did) or {}).keys())
            return self._json(200, {"achievements": catalog, "unlocked": unlocked_ids, "discordId": did or None})
        return self._json(404, {"error": "not found"})

    def _admin_mutate(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)
        if not path.startswith("/api/admin/"):
            return self._json(404, {"error": "not found"})
        if not self._admin_ok():
            return self._admin_auth_error()
        # DELETE도 id를 body로 받을 수 있게 함 (프록시가 쿼리를 버리는 경우 대비)
        body = self._read_json() if method != "DELETE" or int(self.headers.get("Content-Length") or 0) > 0 else {}
        if isinstance(body, dict) and body.get("__error"):
            return self._json(400, {"error": body["__error"]})
        now = int(datetime.now(timezone.utc).timestamp() * 1000)

        with lock:
            if path == "/api/admin/upload" and method == "POST":
                raw = str(body.get("data") or body.get("image") or "")
                filename = str(body.get("filename") or "upload.png")
                if not raw:
                    return self._json(400, {"error": "이미지 데이터가 없습니다."})
                try:
                    url = save_product_image(raw, filename)
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                log_activity("admin", "product_image_upload", page="/admin/products", detail=url)
                save_db(db)
                return self._json(200, {"ok": True, "url": url})

            if path == "/api/admin/products":
                if method == "DELETE":
                    pid = int((qs.get("id") or [0])[0] or 0)
                    old = next((p for p in db.get("products", []) if safe_int(p.get("id")) == pid), None)
                    db["products"] = [p for p in db.get("products", []) if safe_int(p.get("id")) != pid]
                    if old and old.get("active", 1) != 0:
                        record_shop_change("removed", str(old.get("name") or ""), "판매 종료")
                    log_activity(
                        "desktop-admin",
                        "product_delete",
                        page="/admin/products",
                        detail=f"#{pid} {(old or {}).get('name') or ''}",
                        target_id=str(pid),
                        target_name=str((old or {}).get("name") or ""),
                        ip=self._client_ip(),
                        meta={"product": old},
                    )
                    save_db(db)
                    return self._json(200, {"ok": True})
                if method == "POST":
                    if not str(body.get("name") or "").strip():
                        return self._json(400, {"error": "상품명은 필수입니다."})
                    try:
                        image_url = normalize_product_image_url(body.get("image_data") or body.get("image_url"))
                    except ValueError as e:
                        return self._json(400, {"error": str(e)})
                    item = {
                        "id": next_id(db.get("products", [])),
                        "name": str(body.get("name") or "").strip(),
                        "description": (body.get("description") or "") or None,
                        "price": int(body.get("price") or 0),
                        "currency": body.get("currency") or "KRW",
                        "image_url": image_url,
                        "badge": body.get("badge") or None,
                        "category": body.get("category") or None,
                        "rank_group": body.get("rank_group") or None,
                        "price_for": clean_price_for(body.get("price_for")),
                        "cash_amount": max(0, safe_int(body.get("cash_amount"))),
                        "gem_amount": max(0, safe_int(body.get("gem_amount"))),
                        "voucher_count": max(0, min(99, safe_int(body.get("voucher_count")))),
                        "active": 0 if body.get("active") == 0 else 1,
                        "featured": 1 if body.get("featured") else 0,
                        "sort_order": int(body.get("sort_order") or 0),
                    }
                    db.setdefault("products", []).append(item)
                    if item["active"]:
                        record_shop_change("added", item["name"], product_summary(item))
                    log_activity(
                        "desktop-admin",
                        "product_create",
                        page="/admin/products",
                        detail=(
                            f"{item['name']} · {item['price']}원"
                            f"{' · 이미지' if image_url else ''}"
                            f"{(' · 랭크 ' + item['rank_group']) if item.get('rank_group') else ''}"
                        ),
                        target_id=str(item["id"]),
                        target_name=item["name"],
                        ip=self._client_ip(),
                        meta={
                            "price": item["price"],
                            "category": item.get("category"),
                            "rank_group": item.get("rank_group"),
                            "cash_amount": item.get("cash_amount"),
                            "gem_amount": item.get("gem_amount"),
                            "image_url": image_url,
                        },
                    )
                    save_db(db)
                    return self._json(200, {"ok": True, "id": item["id"], "image_url": image_url})
                if method == "PUT":
                    pid = int(body.get("id") or 0)
                    for p in db.get("products", []):
                        if safe_int(p.get("id")) == pid:
                            before = {
                                "name": p.get("name"),
                                "price": p.get("price"),
                                "image_url": p.get("image_url"),
                                "rank_group": p.get("rank_group"),
                                "active": p.get("active"),
                                "description": p.get("description"),
                                "cash_amount": p.get("cash_amount"),
                                "gem_amount": p.get("gem_amount"),
                                "voucher_count": p.get("voucher_count"),
                            }
                            p.update({k: body[k] for k in body if k not in ("id", "image_data", "image_url")})
                            if "name" in body:
                                p["name"] = str(body.get("name") or "").strip()
                            if "cash_amount" in body:
                                p["cash_amount"] = max(0, safe_int(body.get("cash_amount")))
                            if "gem_amount" in body:
                                p["gem_amount"] = max(0, safe_int(body.get("gem_amount")))
                            if "voucher_count" in body:
                                p["voucher_count"] = max(0, min(99, safe_int(body.get("voucher_count"))))
                            if "price_for" in body:
                                p["price_for"] = clean_price_for(body.get("price_for"))
                            if "image_data" in body or "image_url" in body:
                                try:
                                    p["image_url"] = normalize_product_image_url(
                                        body.get("image_data") if body.get("image_data") else body.get("image_url")
                                    )
                                except ValueError as e:
                                    return self._json(400, {"error": str(e)})
                            p["active"] = 0 if body.get("active") == 0 else p.get("active", 1)
                            shop_change = product_change(before, p)
                            if shop_change:
                                record_shop_change(shop_change[0], str(p.get("name") or ""), shop_change[1])
                            changed = []
                            for k in ("name", "price", "image_url", "rank_group", "active"):
                                if before.get(k) != p.get(k):
                                    changed.append(f"{k}:{before.get(k)!r}→{p.get(k)!r}")
                            log_activity(
                                "desktop-admin",
                                "product_update",
                                page="/admin/products",
                                detail=f"#{pid} {p.get('name')} · " + (", ".join(changed) or "저장"),
                                target_id=str(pid),
                                target_name=str(p.get("name") or ""),
                                ip=self._client_ip(),
                                meta={"before": before, "after": {k: p.get(k) for k in before}},
                            )
                            save_db(db)
                            return self._json(200, {"ok": True, "image_url": p.get("image_url")})
                    return self._json(404, {"error": "상품을 찾을 수 없습니다."})

            if path == "/api/admin/banners":
                if method == "POST":
                    try:
                        image_url = normalize_product_image_url(body.get("image_data") or body.get("image_url")) or ""
                    except ValueError as e:
                        return self._json(400, {"error": str(e)})
                    item = {
                        "id": next_id(db.get("banners", [])),
                        "title": str(body.get("title") or "").strip(),
                        "subtitle": body.get("subtitle") or "",
                        "image_url": image_url,
                        "link_url": body.get("link_url") or "",
                        "cta_label": body.get("cta_label") or "바로가기",
                        "active": 0 if body.get("active") == 0 else 1,
                        "sort_order": int(body.get("sort_order") or 0),
                    }
                    db.setdefault("banners", []).append(item)
                    save_db(db)
                    log_activity(
                        "desktop-admin",
                        "site_decorate",
                        page="/admin/banners",
                        detail=f"히어로 등록 · {item.get('title')}",
                        result="ok",
                    )
                    return self._json(200, {"ok": True, "id": item["id"]})
                if method == "PUT":
                    bid = int(body.get("id") or 0)
                    for b in db.get("banners", []):
                        if int(b.get("id") or 0) == bid:
                            patch = {k: body[k] for k in body if k not in ("id", "image_data", "image_url")}
                            b.update(patch)
                            if "image_data" in body or "image_url" in body:
                                try:
                                    b["image_url"] = (
                                        normalize_product_image_url(
                                            body.get("image_data") if body.get("image_data") else body.get("image_url")
                                        )
                                        or ""
                                    )
                                except ValueError as e:
                                    return self._json(400, {"error": str(e)})
                            save_db(db)
                            log_activity(
                                "desktop-admin",
                                "site_decorate",
                                page="/admin/banners",
                                detail=f"히어로 수정 · {b.get('title')}",
                                result="ok",
                            )
                            return self._json(200, {"ok": True})
                    return self._json(404, {"error": "배너를 찾을 수 없습니다."})

            if path == "/api/admin/notices":
                if method == "DELETE":
                    nid = int((qs.get("id") or [0])[0] or 0)
                    db["notices"] = [n for n in db.get("notices", []) if int(n.get("id") or 0) != nid]
                    save_db(db)
                    return self._json(200, {"ok": True})
                if method == "POST":
                    if not str(body.get("title") or "").strip() or not str(body.get("body") or "").strip():
                        return self._json(400, {"error": "제목과 내용을 입력하세요."})
                    item = {
                        "id": next_id(db.get("notices", [])),
                        "title": str(body.get("title") or "").strip(),
                        "body": str(body.get("body") or "").strip(),
                        "pinned": 1 if body.get("pinned") else 0,
                        "active": 0 if body.get("active") == 0 else 1,
                        "created_at": now,
                    }
                    db.setdefault("notices", []).append(item)
                    # 전체 유저 우편함으로 공지 알림 → 웹 알림음 트리거
                    for u in db.get("users", []):
                        if not isinstance(u, dict):
                            continue
                        uid = str(u.get("discord_id") or "")
                        if uid:
                            send_mail(uid, f"새 공지 · {item['title']}", item["body"][:400], "notice", "/notice")
                    save_db(db)
                    return self._json(200, {"ok": True, "id": item["id"]})
                if method == "PUT":
                    nid = int(body.get("id") or 0)
                    for n in db.get("notices", []):
                        if int(n.get("id") or 0) == nid:
                            n["title"] = str(body.get("title") or n.get("title") or "").strip()
                            n["body"] = str(body.get("body") or n.get("body") or "").strip()
                            if "pinned" in body:
                                n["pinned"] = 1 if body.get("pinned") else 0
                            if "active" in body:
                                n["active"] = 0 if body.get("active") == 0 else 1
                            save_db(db)
                            return self._json(200, {"ok": True})
                    return self._json(404, {"error": "공지를 찾을 수 없습니다."})

            if path == "/api/admin/stocks/nudge" and method == "POST":
                sid = str(body.get("id") or body.get("name") or "").strip()
                direction = str(body.get("direction") or "").strip()
                if direction not in ("up", "down"):
                    return self._json(400, {"error": "direction 은 up 또는 down 입니다."})
                row = nudge_stock(sid, direction)
                if not row:
                    return self._json(404, {"error": "종목을 찾을 수 없습니다."})
                return self._json(200, {"ok": True, "stock": row})

            if path == "/api/admin/promo-codes" and method == "POST":
                item = build_promo(body if isinstance(body, dict) else {})
                if not (item.get("cash") or item.get("gem") or item.get("coupon_percent") or item.get("rank_group")):
                    return self._json(400, {"error": "캐시, 잼, 할인 쿠폰, 랭크 중 하나를 넣어 주세요."})
                rows = db.setdefault("promo_codes", [])
                if any(normalize_coupon_code(r.get("code") or "") == item["code"] for r in rows if isinstance(r, dict)):
                    return self._json(400, {"error": "이미 있는 코드입니다."})
                item["id"] = next_id(rows)
                rows.append(item)
                save_db(db)
                return self._json(200, {"ok": True, "code": promo_public(item)})
            if path == "/api/admin/promo-codes" and method == "DELETE":
                pid = safe_int((body or {}).get("id"))
                before = list(db.get("promo_codes") or [])
                db["promo_codes"] = [r for r in before if safe_int((r or {}).get("id")) != pid]
                if len(db["promo_codes"]) == len(before):
                    return self._json(404, {"error": "코드를 찾을 수 없습니다."})
                save_db(db)
                return self._json(200, {"ok": True})

            if path == "/api/admin/patch-notes" and method == "PUT":
                raw = body.get("notes") if isinstance(body.get("notes"), list) else []
                cleaned = []
                for item in raw[:40]:
                    if not isinstance(item, dict):
                        continue
                    def lines(key: str) -> list[str]:
                        val = item.get(key) or []
                        if isinstance(val, str):
                            val = [x.strip() for x in val.splitlines()]
                        return [str(x).strip() for x in val if str(x).strip()][:30]
                    version = str(item.get("version") or "").strip()[:40]
                    if not version:
                        continue
                    cleaned.append(
                        {
                            "version": version,
                            "date": str(item.get("date") or "")[:20],
                            "title": str(item.get("title") or "")[:120],
                            "added": lines("added"),
                            "changed": lines("changed"),
                            "removed": lines("removed"),
                        }
                    )
                db["web_patch_notes"] = cleaned
                save_db(db)
                return self._json(200, {"ok": True, "notes": cleaned, "version": cleaned[0]["version"] if cleaned else ""})

            if path == "/api/admin/donations/bonus" and method == "POST":
                ids = body.get("discordIds") or body.get("ids") or []
                if isinstance(ids, str):
                    ids = [x.strip() for x in ids.split(",") if x.strip()]
                kind = str(body.get("kind") or "coupon")
                amount = safe_int(body.get("amount") or body.get("value") or 10)
                direction = "take" if str(body.get("direction") or "give") == "take" else "give"
                if kind not in ("coupon", "cash", "gem"):
                    return self._json(400, {"error": "보너스 종류는 coupon, cash, gem 입니다."})
                if direction == "take" and kind == "coupon":
                    return self._json(400, {"error": "쿠폰은 빼기할 수 없어요."})
                granted = grant_support_bonus([str(x) for x in ids], kind, amount, direction)
                save_db(db)
                return self._json(200, {"ok": True, "granted": granted, "count": len(granted)})

            if path == "/api/admin/settings" and method == "PUT":
                settings = body.get("settings") if isinstance(body.get("settings"), dict) else body
                prev = dict(db.get("settings") or {})
                db.setdefault("settings", {}).update({str(k): str(v) for k, v in settings.items()})
                changed_keys = [k for k in settings if str(prev.get(k, "")) != str(settings.get(k, ""))]
                old_ids = {x.strip() for x in str(prev.get("admin_discord_ids") or "").replace(";", ",").split(",") if x.strip()}
                new_ids = {x.strip() for x in str((db.get("settings") or {}).get("admin_discord_ids") or "").replace(";", ",").split(",") if x.strip()}
                added = sorted(new_ids - old_ids)
                removed = sorted(old_ids - new_ids)
                for did in added:
                    u = find_user(did)
                    log_activity(
                        "desktop-admin",
                        "site_edit_grant",
                        page="/admin/settings",
                        detail="Team. Wildmc 권한 부여 (사이트 편집)",
                        target_id=did,
                        target_name=str((u or {}).get("discord_username") or did),
                        ip=self._client_ip(),
                    )
                for did in removed:
                    u = find_user(did)
                    log_activity(
                        "desktop-admin",
                        "site_edit_revoke",
                        page="/admin/settings",
                        detail="Team. Wildmc 권한 회수 (사이트 편집)",
                        target_id=did,
                        target_name=str((u or {}).get("discord_username") or did),
                        ip=self._client_ip(),
                    )
                log_activity(
                    "desktop-admin",
                    "settings_save",
                    page="/admin/settings",
                    detail=("변경: " + ", ".join(changed_keys[:20])) if changed_keys else "사이트 설정 저장",
                    ip=self._client_ip(),
                    meta={"changed": changed_keys[:40]},
                )
                save_db(db)
                return self._json(200, {"ok": True})

            if path == "/api/admin/payment" and method == "PUT":
                settings = body.get("settings") if isinstance(body.get("settings"), dict) else body
                db.setdefault("payment", {}).update({str(k): str(v) if not isinstance(v, str) else v for k, v in settings.items()})
                log_activity(
                    "desktop-admin",
                    "payment_save",
                    page="/admin/payment",
                    detail=f"은행 {(db.get('payment') or {}).get('bank_name') or '—'} · 계좌 {(db.get('payment') or {}).get('bank_account') or '—'}",
                    ip=self._client_ip(),
                )
                save_db(db)
                return self._json(200, {"ok": True})

            if path == "/api/admin/orders" and method == "PUT":
                oid = int(body.get("id") or 0)
                status = str(body.get("status") or "")
                allowed = {"pending", "paid", "fulfilled", "cancelled", "refunded"}
                if status not in allowed:
                    return self._json(400, {"error": "invalid status"})
                order = next((o for o in db.get("orders", []) if int(o.get("id") or 0) == oid), None)
                if not order:
                    return self._json(404, {"error": "주문을 찾을 수 없습니다."})
                prev_status = str(order.get("status") or "")
                order["status"] = status
                order["updated_at"] = now
                if status in ("paid", "fulfilled") and not order.get("paid_at"):
                    order["paid_at"] = now
                if status == "fulfilled":
                    order["fulfilled_at"] = now
                if body.get("adminNote"):
                    order["admin_note"] = body.get("adminNote")
                did = order.get("discord_id")
                if did:
                    if status == "paid":
                        send_mail(did, "입금이 확인되었습니다", f"{order.get('product_name')} 주문의 입금이 확인되었습니다. 곧 지급됩니다.", "order_paid", f"/pay/order/{order.get('order_code')}")
                        unlock_achievement(did, "first_payment")
                    elif status == "fulfilled":
                        send_mail(did, "구매가 완료되었습니다", f"{order.get('product_name')} 지급이 완료되었습니다.", "order_done", f"/pay/order/{order.get('order_code')}")
                        unlock_achievement(did, "first_payment")
                restored_code = restore_order_coupon(order) if status in ("cancelled", "refunded") else None
                if did and status == "cancelled":
                    cancel_msg = f"{order.get('product_name')} 주문이 취소되었습니다."
                    if restored_code:
                        cancel_msg += f"\n사용한 쿠폰 {restored_code} 이(가) 복구되어 다시 쓸 수 있어요."
                    send_mail(did, "주문이 취소되었습니다", cancel_msg, "order_cancel", f"/pay/order/{order.get('order_code')}")
                product = order_product(order)
                products = order_line_products(order)
                target_mc = str(order.get("gift_minecraft_name") or order.get("minecraft_name") or "")
                if status == "fulfilled" and products and target_mc:
                    holder = find_user_by_minecraft_name(target_mc)
                    if not order.get("prev_luckperms_group"):
                        prev_group = shop_viewer_rank((holder or {}).get("luckperms_group")) or "default"
                        order["prev_luckperms_group"] = prev_group
                    granted = list(order.get("granted_commands") or [])
                    for prod in products:
                        granted.extend(queue_product_fulfillment(prod, target_mc, str(order.get("order_code") or "")))
                        if str(prod.get("rank_group") or "") == "울트라" or "울트라" in str(prod.get("name") or ""):
                            unlock_achievement(did, "ultra_buyer")
                    if granted:
                        order["granted_commands"] = granted
                tickets = sum(nick_ticket_units(prod, order) for prod in products)
                ticket_user = did
                if status == "fulfilled" and order.get("gift") and target_mc:
                    gifted = find_user_by_minecraft_name(target_mc)
                    if gifted:
                        ticket_user = str(gifted.get("discord_id") or did)
                if status == "fulfilled" and ticket_user and tickets > 0 and not order.get("tickets_granted"):
                    grant_nick_tickets(ticket_user, tickets, str(order.get("order_code") or ""))
                    order["tickets_granted"] = tickets
                    send_mail(
                        ticket_user,
                        f"닉네임 변경권 {tickets}장이 지급되었습니다",
                        "프로필에서 사용을 누르면 닉네임 변경 코드가 나와요.",
                        "order_done",
                        "/panel",
                    )
                if status == "refunded":
                    order["refunded_at"] = now
                    revoke_order_tickets(order)
                    if prev_status == "fulfilled" and target_mc and not order.get("refund_queued"):
                        restore = str(order.get("prev_luckperms_group") or "default").strip() or "default"
                        granted = [str(c) for c in (order.get("granted_commands") or []) if str(c).strip()]
                        if granted:
                            for cmd in granted:
                                rev = reverse_grant_command(cmd, restore)
                                if rev:
                                    queue_command(rev, f"refund:order:{order.get('order_code')}", "admin-refund")
                        elif products:
                            for prod in products:
                                queue_product_refund(prod, target_mc, str(order.get("order_code") or ""), restore)
                        apply_minecraft_rank(target_mc, restore)
                        order["refund_queued"] = 1
                    if did:
                        refund_msg = f"{order.get('product_name')} 주문이 환불되었습니다."
                        if restored_code:
                            refund_msg += f"\n사용한 쿠폰 {restored_code} 이(가) 복구되어 다시 쓸 수 있어요."
                        send_mail(did, "환불이 완료되었습니다", refund_msg, "order_cancel", f"/pay/order/{order.get('order_code')}")
                log_activity(
                    "desktop-admin",
                    "order_status",
                    page="/admin/orders",
                    detail=(
                        f"{order.get('order_code')} · {order.get('product_name')} · "
                        f"{order.get('price')}원 → {status}"
                        f"{(' · 마크 ' + str(order.get('minecraft_name'))) if order.get('minecraft_name') else ''}"
                    ),
                    target_id=str(order.get("discord_id") or ""),
                    target_name=str(order.get("discord_username") or order.get("buyer_name") or ""),
                    result=status,
                    ip=self._client_ip(),
                    meta={
                        "order_code": order.get("order_code"),
                        "product_name": order.get("product_name"),
                        "price": order.get("price"),
                        "status": status,
                        "minecraft_name": order.get("minecraft_name"),
                        "coupon_restored": restored_code,
                    },
                )
                save_db(db)
                return self._json(200, {"ok": True, "couponRestored": restored_code, "ticketsGranted": order.get("tickets_granted")})

            if path == "/api/admin/chat" and method == "POST":
                did = str(body.get("discordId") or body.get("discord_id") or "").strip()
                text = str(body.get("body") or body.get("message") or "").strip()
                images_raw = body.get("images") or []
                if isinstance(images_raw, str):
                    images_raw = [images_raw]
                if not did:
                    return self._json(400, {"error": "discordId가 필요합니다."})
                if not text and not images_raw:
                    return self._json(400, {"error": "메시지 또는 사진을 입력하세요."})
                if not find_user(did):
                    return self._json(404, {"error": "해당 유저를 찾을 수 없습니다."})
                row = admin_chat_thread(did, create=True)
                urls = save_support_images(images_raw, f"adm{row['id']}") if images_raw else []
                row.setdefault("replies", []).append({"from": "admin", "body": (text or "(사진)")[:4000], "images": urls, "at": now})
                row["status"] = "replied"
                send_mail(did, "관리자 메시지", (text or "사진이 도착했습니다.")[:300], "support", f"/support?id={row['id']}")
                log_activity(
                    "desktop-admin",
                    "admin_chat",
                    page="/admin/chat",
                    target_id=did,
                    target_name=str(row.get("username") or did),
                    detail=(text or "(사진)")[:200],
                    ip=self._client_ip(),
                )
                save_db(db)
                return self._json(200, {"ok": True, "thread": row})

            if path == "/api/admin/users/unlink-minecraft" and method == "POST":
                did = str(body.get("discordId") or body.get("discord_id") or "").strip()
                if not did:
                    return self._json(400, {"error": "discordId가 필요합니다."})
                user = unlink_minecraft(did)
                if not user:
                    return self._json(404, {"error": "해당 유저를 찾을 수 없습니다."})
                send_mail(
                    did,
                    "마인크래프트 연동이 해제되었습니다",
                    "관리자가 마크 계정 연동을 해제했습니다. 다시 /인증 으로 연동할 수 있습니다.",
                    "unlink",
                    "/link",
                )
                save_db(db)
                return self._json(200, {"ok": True, "discordId": did})

            if path == "/api/admin/users/set-group" and method == "POST":
                did = str(body.get("discordId") or body.get("discord_id") or "").strip()
                group = str(body.get("group") or body.get("rank") or TEAM_WILDMC_GROUP).strip() or TEAM_WILDMC_GROUP
                if not did:
                    return self._json(400, {"error": "discordId가 필요합니다."})
                try:
                    result = grant_luckperms_group(did, group, requested_by="desktop-admin")
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                send_mail(
                    did,
                    f"역할 부여 · {group}",
                    f"관리자가 LuckPerms 그룹 「{group}」을(를) 부여했습니다. 서버에 접속해 있으면 잠시 후 반영됩니다.",
                    "role_grant",
                    "/panel",
                )
                save_db(db)
                return self._json(200, {"ok": True, **result})

            if path == "/api/admin/users/logout" and method == "POST":
                did = str(body.get("discordId") or body.get("discord_id") or "").strip()
                if not did:
                    return self._json(400, {"error": "discordId가 필요합니다."})
                if not find_user(did):
                    return self._json(404, {"error": "해당 유저를 찾을 수 없습니다."})
                cleared = clear_user_sessions(did)
                save_db(db)
                return self._json(200, {"ok": True, "discordId": did, "clearedSessions": cleared})

            if path == "/api/admin/users/delete" and method == "POST":
                did = str(body.get("discordId") or body.get("discord_id") or "").strip()
                if not did:
                    return self._json(400, {"error": "discordId가 필요합니다."})
                if not find_user(did):
                    return self._json(404, {"error": "해당 유저를 찾을 수 없습니다."})
                result = delete_user_account(did)
                save_db(db)
                return self._json(200, {"ok": True, "discordId": did, **result})

            if path == "/api/admin/achievements/reset" and method == "POST":
                did = str(body.get("discordId") or body.get("discord_id") or "").strip()
                if not did:
                    return self._json(400, {"error": "discordId가 필요합니다."})
                if not find_user(did):
                    return self._json(404, {"error": "해당 유저를 찾을 수 없습니다."})
                bags = db.setdefault("user_achievements", {})
                cleared = len(bags.get(did) or {})
                bags[did] = {}
                send_mail(
                    did,
                    "도전과제가 초기화되었습니다",
                    "관리자가 도전과제를 초기화했습니다. 다시 모아 보세요!",
                    "achievement_reset",
                    "/achievements",
                )
                save_db(db)
                return self._json(200, {"ok": True, "cleared": cleared, "discordId": did})

            if path == "/api/admin/achievements/grant" and method == "POST":
                did = str(body.get("discordId") or body.get("discord_id") or "").strip()
                ach_id = str(body.get("achievementId") or body.get("id") or "").strip()
                notify = body.get("notify", True)
                if not did:
                    return self._json(400, {"error": "지급할 유저(discordId)가 필요합니다."})
                if not ach_id:
                    return self._json(400, {"error": "지급할 도전과제(achievementId)가 필요합니다."})
                if ach_id not in ACH_BY_ID:
                    return self._json(400, {"error": f"존재하지 않는 도전과제입니다: {ach_id}"})
                if not find_user(did):
                    return self._json(404, {"error": "해당 유저를 찾을 수 없습니다. 웹에 한 번 이상 로그인한 계정만 지급할 수 있습니다."})
                bag = db.get("user_achievements", {}).get(did) or {}
                if ach_id in bag:
                    return self._json(200, {"ok": True, "already": True, "achievementId": ach_id, "title": ACH_BY_ID[ach_id]["title"]})
                unlocked = unlock_achievement(did, ach_id, notify=bool(notify))
                # 시즌 개별 지급 시 수집가 조건도 검사
                extra = []
                if ach_id in THEME_SEASON_ACH_IDS:
                    bag2 = db.get("user_achievements", {}).get(did) or {}
                    if all(x in bag2 for x in THEME_SEASON_ACH_IDS):
                        col = unlock_achievement(did, "theme_collector", notify=bool(notify))
                        if col:
                            extra.append(col)
                    if "theme_first" not in bag2:
                        first = unlock_achievement(did, "theme_first", notify=bool(notify))
                        if first:
                            extra.append(first)
                save_db(db)
                return self._json(
                    200,
                    {
                        "ok": True,
                        "already": False,
                        "achievementId": ach_id,
                        "unlocked": unlocked,
                        "extra": extra,
                    },
                )

            
            if path == "/api/admin/inquiries" and method == "PUT":
                iid = safe_int(body.get("id"))
                reply = str(body.get("reply") or body.get("body") or "").strip()
                status = str(body.get("status") or "").strip()
                row = next((i for i in db.get("inquiries", []) if safe_int(i.get("id")) == iid), None)
                if not row:
                    return self._json(404, {"error": "문의를 찾을 수 없습니다."})
                images_raw = body.get("images") or body.get("image") or []
                if isinstance(images_raw, str):
                    images_raw = [images_raw]
                urls = save_support_images(images_raw, f"adm{iid}") if images_raw else []
                if reply or urls:
                    row.setdefault("replies", []).append({
                        "from": "admin",
                        "body": (reply or "(사진)")[:4000],
                        "images": urls,
                        "at": now_ms(),
                    })
                    row["status"] = "replied"
                    send_mail(
                        str(row.get("user_id") or ""),
                        f"문의 답변 · {row.get('subject') or ''}",
                        reply or "사진 답변이 도착했습니다.",
                        "support",
                        "/support",
                    )
                    log_activity("admin", "inquiry_reply", page="/admin", target_id=str(row.get("user_id") or ""), detail=(reply or "image")[:200])
                if status in ("open", "replied", "closed"):
                    row["status"] = status
                save_db(db)
                return self._json(200, {"ok": True, "item": row})

            if path == "/api/admin/broadcast" and method == "POST":
                title = str(body.get("title") or "").strip()
                body_text = str(body.get("body") or body.get("message") or "").strip()
                link = str(body.get("link_url") or body.get("link") or "").strip() or None
                if not title or not body_text:
                    return self._json(400, {"error": "제목과 내용을 입력하세요."})
                users = db.get("users", [])
                sent = 0
                for u in users:
                    if not isinstance(u, dict):
                        continue
                    did = str(u.get("discord_id") or "").strip()
                    if not did:
                        continue
                    send_mail(did, title, body_text, "broadcast", link)
                    sent += 1
                save_db(db)
                return self._json(200, {"ok": True, "sent": sent})

            if path == "/api/admin/coupons":
                if method == "DELETE":
                    cid = int((qs.get("id") or [0])[0] or body.get("id") or 0)
                    if not cid:
                        return self._json(400, {"error": "삭제할 쿠폰 id가 필요합니다."})
                    before = len(db.get("coupons", []))
                    # 선착순 부모면 발급된 개인 쿠폰도 함께 제거
                    child_ids = {
                        int(c.get("id") or 0)
                        for c in db.get("coupons", [])
                        if int(c.get("claim_parent_id") or 0) == cid
                    }
                    remove_ids = {cid} | child_ids
                    db["coupons"] = [
                        c for c in db.get("coupons", []) if int(c.get("id") or 0) not in remove_ids
                    ]
                    if len(db["coupons"]) == before:
                        return self._json(404, {"error": "쿠폰을 찾을 수 없습니다."})
                    db["coupon_claims"] = [
                        c
                        for c in db.get("coupon_claims", [])
                        if int(c.get("parent_id") or 0) not in remove_ids
                        and int(c.get("issued_coupon_id") or 0) not in remove_ids
                    ]
                    db["coupon_redemptions"] = [
                        r
                        for r in db.get("coupon_redemptions", [])
                        if int(r.get("coupon_id") or 0) not in remove_ids
                    ]
                    save_db(db)
                    return self._json(
                        200,
                        {"ok": True, "deleted": sorted(remove_ids), "removedChildren": len(child_ids)},
                    )
                if method == "POST":
                    code = normalize_coupon_code(body.get("code") or "")
                    if not code:
                        code = generate_code(2, 4).replace("-", "")
                    if find_coupon(code):
                        return self._json(400, {"error": "이미 존재하는 쿠폰 코드입니다."})
                    ctype = str(body.get("type") or "percent")
                    if ctype not in ("percent", "fixed"):
                        return self._json(400, {"error": "type은 percent 또는 fixed 여야 합니다."})
                    value = coupon_value_from_body(ctype, body.get("value"))
                    if ctype == "percent" and (value <= 0 or value > 100):
                        return self._json(400, {"error": "할인율은 1~100 사이여야 합니다. 예: 50 = 50% 할인"})
                    if ctype == "fixed" and value <= 0:
                        return self._json(400, {"error": "할인 금액은 1원 이상이어야 합니다."})
                    pids = body.get("product_ids") if isinstance(body.get("product_ids"), list) else []
                    try:
                        pids = [int(x) for x in pids if str(x).strip() != ""]
                    except Exception:
                        pids = []
                    item = {
                        "id": next_id(db.get("coupons", [])),
                        "code": code,
                        "name": str(body.get("name") or "").strip() or code,
                        "type": ctype,
                        "value": value,
                        "max_uses": int(body.get("max_uses") or 0),
                        "used_count": 0,
                        "claimed_count": 0,
                        "per_user": int(body.get("per_user") if body.get("per_user") is not None else 1),
                        "min_price": int(body.get("min_price") or 0),
                        "product_ids": pids,
                        "active": 0 if body.get("active") == 0 else 1,
                        "expires_at": parse_optional_ts(body.get("expires_at")),
                        "register_until": parse_optional_ts(body.get("register_until")),
                        "assigned_discord_id": str(body.get("assigned_discord_id") or body.get("discordId") or "").strip() or None,
                        "single_use": 1 if body.get("single_use") else 0,
                        "claimable": 1 if body.get("claimable") else 0,
                        "note": str(body.get("note") or "").strip() or None,
                        "created_at": now,
                    }
                    if item["single_use"]:
                        item["max_uses"] = 1
                        item["per_user"] = 1
                    if item["claimable"]:
                        item["assigned_discord_id"] = None
                        item["single_use"] = 0
                        if item["max_uses"] <= 0:
                            return self._json(400, {"error": "선착순 쿠폰은 받을 수 있는 인원(최대 사용)을 1명 이상으로 설정하세요."})
                        item["per_user"] = 1
                    db.setdefault("coupons", []).append(item)
                    save_db(db)
                    return self._json(200, {"ok": True, "coupon": item})
                if method == "PUT":
                    cid = int(body.get("id") or 0)
                    for c in db.get("coupons", []):
                        if int(c.get("id") or 0) != cid:
                            continue
                        if "name" in body:
                            c["name"] = str(body.get("name") or "").strip() or c.get("name")
                        if "type" in body and body.get("type") in ("percent", "fixed"):
                            c["type"] = body.get("type")
                        if "value" in body:
                            c["value"] = coupon_value_from_body(str(c.get("type") or "percent"), body.get("value"))
                        if c.get("type") == "percent" and (float(c.get("value") or 0) <= 0 or float(c.get("value") or 0) > 100):
                            return self._json(400, {"error": "할인율은 1~100 사이여야 합니다. 예: 50 = 50% 할인"})
                        if "max_uses" in body:
                            c["max_uses"] = int(body.get("max_uses") or 0)
                        if "per_user" in body:
                            c["per_user"] = int(body.get("per_user") or 0)
                        if "min_price" in body:
                            c["min_price"] = int(body.get("min_price") or 0)
                        if "product_ids" in body and isinstance(body.get("product_ids"), list):
                            try:
                                c["product_ids"] = [int(x) for x in body.get("product_ids") if str(x).strip() != ""]
                            except Exception:
                                pass
                        if "active" in body:
                            c["active"] = 0 if body.get("active") == 0 else 1
                        if "expires_at" in body:
                            c["expires_at"] = parse_optional_ts(body.get("expires_at"))
                        if "register_until" in body:
                            c["register_until"] = parse_optional_ts(body.get("register_until"))
                        if "assigned_discord_id" in body or "discordId" in body:
                            c["assigned_discord_id"] = str(body.get("assigned_discord_id") or body.get("discordId") or "").strip() or None
                        if "single_use" in body:
                            c["single_use"] = 1 if body.get("single_use") else 0
                            if c["single_use"]:
                                c["max_uses"] = 1
                                c["per_user"] = 1
                        if "claimable" in body:
                            c["claimable"] = 1 if body.get("claimable") else 0
                            if c["claimable"]:
                                c["assigned_discord_id"] = None
                                c["single_use"] = 0
                                c["per_user"] = 1
                                if int(c.get("max_uses") or 0) <= 0:
                                    return self._json(400, {"error": "선착순 쿠폰은 받을 수 있는 인원을 1명 이상으로 설정하세요."})
                        if "note" in body:
                            c["note"] = str(body.get("note") or "").strip() or None
                        if "code" in body:
                            new_code = normalize_coupon_code(body.get("code") or "")
                            if new_code and new_code != normalize_coupon_code(c.get("code") or ""):
                                if find_coupon(new_code):
                                    return self._json(400, {"error": "이미 존재하는 쿠폰 코드입니다."})
                                c["code"] = new_code
                        save_db(db)
                        return self._json(200, {"ok": True, "coupon": c})
                    return self._json(404, {"error": "쿠폰을 찾을 수 없습니다."})

            if path == "/api/admin/coupons/issue" and method == "POST":
                did = str(body.get("discordId") or body.get("assigned_discord_id") or "").strip()
                if not did:
                    return self._json(400, {"error": "지급할 유저(discordId)가 필요합니다."})
                ctype = str(body.get("type") or "percent")
                if ctype not in ("percent", "fixed"):
                    return self._json(400, {"error": "type은 percent 또는 fixed 여야 합니다."})
                value = coupon_value_from_body(ctype, body.get("value"))
                if ctype == "percent" and (value <= 0 or value > 100):
                    return self._json(400, {"error": "할인율은 1~100 사이여야 합니다."})
                if ctype == "fixed" and value <= 0:
                    return self._json(400, {"error": "할인 금액은 1원 이상이어야 합니다."})
                count = max(1, min(20, int(body.get("count") or 1)))
                pids = body.get("product_ids") if isinstance(body.get("product_ids"), list) else []
                try:
                    pids = [int(x) for x in pids if str(x).strip() != ""]
                except Exception:
                    pids = []
                user = find_user(did)
                uname = (user or {}).get("discord_username") or did
                base_name = str(body.get("name") or "").strip() or f"일회용 쿠폰 ({uname})"
                created = []
                for i in range(count):
                    code = normalize_coupon_code(body.get("code") or "") if count == 1 and body.get("code") else ""
                    if not code:
                        for _ in range(12):
                            code = generate_code(2, 4).replace("-", "")
                            if not find_coupon(code):
                                break
                    if find_coupon(code):
                        return self._json(400, {"error": "쿠폰 코드 생성에 실패했습니다. 다시 시도하세요."})
                    item = {
                        "id": next_id(db.get("coupons", [])),
                        "code": code,
                        "name": base_name if count == 1 else f"{base_name} #{i + 1}",
                        "type": ctype,
                        "value": value,
                        "max_uses": 1,
                        "used_count": 0,
                        "per_user": 1,
                        "min_price": int(body.get("min_price") or 0),
                        "product_ids": pids,
                        "active": 1,
                        "expires_at": parse_optional_ts(body.get("expires_at")),
                        "register_until": parse_optional_ts(body.get("register_until")),
                        "assigned_discord_id": did,
                        "single_use": 1,
                        "note": str(body.get("note") or "").strip() or f"개인 지급 → {uname}",
                        "created_at": now,
                    }
                    db.setdefault("coupons", []).append(item)
                    add_to_wallet(did, item, code)
                    created.append(item)
                    disc_label = f"{value}%" if ctype == "percent" else f"{int(value):,}원"
                    send_mail(
                        did,
                        f"일회용 쿠폰이 도착했습니다 · {disc_label}",
                        f"쿠폰이 내 쿠폰함에 다운로드되었습니다.\n코드: {code}\n할인: {disc_label}\n결제 시 자동 적용하거나 직접 고를 수 있습니다.",
                        "coupon",
                        "/shop",
                    )
                save_db(db)
                return self._json(200, {"ok": True, "coupons": created, "codes": [c["code"] for c in created]})

            if path == "/api/admin/reviews":
                rid = safe_int((qs.get("id") or [0])[0] or body.get("id"))
                row = next((r for r in db.get("reviews", []) if safe_int(r.get("id")) == rid), None)
                if not row:
                    return self._json(404, {"error": "리뷰를 찾을 수 없습니다."})
                if method == "DELETE":
                    db["reviews"] = [r for r in db.get("reviews", []) if safe_int(r.get("id")) != rid]
                    log_activity("desktop-admin", "review_delete", page="/admin/reviews", detail=str(rid), target_id=str(row.get("discord_id") or ""))
                    save_db(db)
                    return self._json(200, {"ok": True})
                if method == "PUT":
                    if "hidden" in body:
                        row["hidden"] = 1 if body.get("hidden") else 0
                    if body.get("body") is not None:
                        row["body"] = clean_user_text(body.get("body"), 800)
                    save_db(db)
                    return self._json(200, {"ok": True, "review": public_review(row, admin=True)})
                return self._json(405, {"error": "지원하지 않는 방법입니다."})

            if path == "/api/admin/community":
                kind = str((qs.get("type") or [""])[0] or body.get("type") or "post").strip()
                cid = safe_int((qs.get("id") or [0])[0] or body.get("id"))
                if kind == "comment":
                    row = next((c for c in db.get("community_comments", []) if safe_int(c.get("id")) == cid), None)
                    if not row:
                        return self._json(404, {"error": "댓글을 찾을 수 없습니다."})
                    db["community_comments"] = [c for c in db.get("community_comments", []) if safe_int(c.get("id")) != cid]
                    log_activity("desktop-admin", "community_delete", page="/admin/community", detail=f"comment:{cid}")
                    save_db(db)
                    return self._json(200, {"ok": True})
                row = next((p for p in db.get("community_posts", []) if safe_int(p.get("id")) == cid), None)
                if not row:
                    return self._json(404, {"error": "글을 찾을 수 없습니다."})
                db["community_posts"] = [p for p in db.get("community_posts", []) if safe_int(p.get("id")) != cid]
                db["community_comments"] = [c for c in db.get("community_comments", []) if safe_int(c.get("post_id")) != cid]
                log_activity("desktop-admin", "community_delete", page="/admin/community", detail=f"post:{cid}")
                save_db(db)
                return self._json(200, {"ok": True})

            if path == "/api/admin/activity-logs" and method == "DELETE":
                ids = body.get("ids") if isinstance(body.get("ids"), list) else []
                result = purge_data("activity_logs", [safe_int(x) for x in ids], bool(body.get("all")))
                log_activity("desktop-admin", "data_purge", page="/admin/activity", detail=f"logs {result['removed']}")
                save_db(db)
                return self._json(200, {"ok": True, **result})

            if path == "/api/admin/orders" and method == "DELETE":
                ids = body.get("ids") if isinstance(body.get("ids"), list) else []
                oid = safe_int((qs.get("id") or [0])[0] or body.get("id"))
                if oid:
                    ids = list(ids) + [oid]
                result = purge_data("orders", [safe_int(x) for x in ids], bool(body.get("all")))
                log_activity("desktop-admin", "data_purge", page="/admin/orders", detail=f"orders {result['removed']}")
                save_db(db)
                return self._json(200, {"ok": True, **result})

            if path == "/api/admin/data" and method in ("POST", "DELETE"):
                target = str(body.get("target") or (qs.get("target") or [""])[0] or "")
                ids = body.get("ids") if isinstance(body.get("ids"), list) else []
                try:
                    result = purge_data(target, [safe_int(x) for x in ids], bool(body.get("all")))
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                log_activity("desktop-admin", "data_purge", page="/admin/data", detail=f"{target} {result['removed']}")
                save_db(db)
                return self._json(200, {"ok": True, **result})

        return self._json(
            404,
            {
                "error": "지원하지 않는 관리 API입니다. website1의 WILDMC-web.py를 최신 ZIP으로 교체한 뒤 재시작하세요.",
            },
        )

    def do_POST(self) -> None:
        global plugin_online, server_metrics
        if urlparse(self.path).path.startswith("/api/admin/"):
            return self._admin_mutate("POST")
        path = urlparse(self.path).path
        body = self._read_json()

        if path == "/api/site-edit/upload":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "권한이 없습니다."})
            raw = str((body or {}).get("data") or (body or {}).get("image") or "")
            filename = str((body or {}).get("filename") or "hero.png")
            if not raw:
                return self._json(400, {"error": "이미지 데이터가 없습니다."})
            try:
                url = save_product_image(raw, filename)
            except ValueError as e:
                return self._json(400, {"error": str(e)})
            log_activity(
                session.get("discordId"),
                "site_decorate",
                page="/decorate",
                detail=f"히어로 이미지 업로드 · {url}",
                result="ok",
            )
            save_db(db)
            return self._json(200, {"ok": True, "url": url})

        if path == "/api/site-edit/save":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "권한이 없습니다."})
            if not isinstance(body, dict):
                return self._json(400, {"error": "잘못된 요청입니다."})
            settings_in = body.get("settings") if isinstance(body.get("settings"), dict) else {}
            banner_in = body.get("banner") if isinstance(body.get("banner"), dict) else {}
            with lock:
                if not db.get("site_edit_history"):
                    record_site_edit(None, "편집 전 원래 상태")
                try:
                    changed = apply_site_edit(settings_in, banner_in)
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                label = describe_site_changes(changed)
                if changed:
                    record_site_edit(session, label)
                save_db(db)
                log_activity(
                    session.get("discordId"),
                    "site_decorate",
                    page="/decorate",
                    detail=label,
                    result="ok",
                    meta={"changed": changed},
                )
                return self._json(200, site_edit_payload() | {"changed": changed})

        if path == "/api/site-edit/restore":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "권한이 없습니다."})
            hid = safe_int((body or {}).get("id"))
            with lock:
                item = next((h for h in db.get("site_edit_history") or [] if safe_int(h.get("id")) == hid), None)
                if not item:
                    return self._json(404, {"error": "저장 기록을 찾을 수 없습니다."})
                settings = db.setdefault("settings", {})
                snap = item.get("settings") or {}
                for k in SITE_EDIT_SETTING_KEYS:
                    if k in snap:
                        settings[k] = snap[k]
                    else:
                        settings.pop(k, None)
                target = ensure_primary_banner()
                for k in SITE_BANNER_FIELDS:
                    target[k] = (item.get("banner") or {}).get(k) or ""
                label = f"#{hid} 버전으로 복원"
                record_site_edit(session, label)
                save_db(db)
                log_activity(session.get("discordId"), "site_decorate", page="/decorate", detail=label, result="ok")
                return self._json(200, site_edit_payload())

        m = re.match(r"^/api/pay/order/([^/]+)/proof$", path or "")
        if m:
            session = get_session(self)
            if not session or str(session.get("discordId", "")).startswith("local_"):
                return self._json(401, {"error": "로그인이 필요합니다."})
            order = find_order_by_code(m.group(1))
            if not order:
                return self._json(404, {"error": "주문을 찾을 수 없습니다."})
            if str(order.get("discord_id") or "") != str(session.get("discordId") or ""):
                return self._json(403, {"error": "본인 주문만 사진을 첨부할 수 있습니다."})
            if order.get("status") == "cancelled":
                return self._json(400, {"error": "취소된 주문에는 사진을 첨부할 수 없습니다."})
            images_raw = (body or {}).get("images") or (body or {}).get("image") or []
            if isinstance(images_raw, str):
                images_raw = [images_raw]
            if not images_raw:
                return self._json(400, {"error": "사진을 선택하세요."})
            with lock:
                order = find_order_by_code(m.group(1)) or order
                existing = list(order.get("images") or [])
                room = max(0, 6 - len(existing))
                if room <= 0:
                    return self._json(400, {"error": "사진은 주문당 최대 6장까지입니다."})
                urls = save_order_images(images_raw[:room], f"ord{str(order.get('order_code') or '').replace('-', '')}")
                order["images"] = existing + urls
                order["updated_at"] = now_ms()
                save_db(db)
                log_activity(
                    session.get("discordId"),
                    "order_proof",
                    page=f"/pay/order/{order.get('order_code')}",
                    detail=f"입금 사진 {len(urls)}장 · {order.get('order_code')}",
                    target_id=str(order.get("id") or ""),
                    result="ok",
                )
                return self._json(200, {"ok": True, "images": order["images"]})

        m = re.match(r"^/api/pay/order/([^/]+)/refund$", path or "")
        if m:
            return self._json(400, {"error": "구매 시 환불은 불가합니다."})

        if path == "/wiki/api/logout":
            token = get_session_token(self)
            if token:
                with lock:
                    db.get("sessions", {}).pop(token, None)
                    save_db(db)
            return self._json(200, {"ok": True}, clear_cookie=True)
        if path == "/api/admin/web/notices":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "Team. Wildmc 권한이 필요합니다."})
            title = str(body.get("title") or "").strip()
            body_text = str(body.get("body") or "").strip()
            if not title or not body_text:
                return self._json(400, {"error": "제목과 내용을 입력하세요."})
            with lock:
                item = {
                    "id": next_id(db.get("notices", [])),
                    "title": title,
                    "body": body_text,
                    "pinned": 1 if body.get("pinned") else 0,
                    "active": 0 if body.get("active") == 0 else 1,
                    "created_at": now_ms(),
                }
                db.setdefault("notices", []).append(item)
                for u in db.get("users", []):
                    if not isinstance(u, dict):
                        continue
                    uid = str(u.get("discord_id") or "")
                    if uid:
                        send_mail(uid, f"새 공지 · {title}", body_text[:400], "notice", "/notice")
                log_activity(
                    session.get("discordId"),
                    "admin_web_notice",
                    page="/admin",
                    detail=title,
                )
                save_db(db)
            return self._json(200, {"ok": True, "notice": item})
        if path == "/wiki/api/login":
            # 비밀번호 로그인 제거 → 디스코드만
            return self._json(410, {"error": "디스코드 로그인을 이용해 주세요.", "discord": "/api/auth/discord?next=/wiki/editor"})
        if path == "/wiki/api/site":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "권한이 없습니다. Discord 로그인 후 Team. Wildmc 그룹이 필요합니다."})
            d = body
            if not isinstance(d, dict) or "site" not in d or not isinstance(d.get("blocks"), list):
                return self._json(400, {"error": "잘못된 데이터"})
            with lock:
                save_wiki(d)
                log_activity(
                    session.get("discordId"),
                    "wiki_save",
                    page="/wiki/editor",
                    detail="위키 사이트 저장",
                )
                save_db(db)
            return self._json(200, {"ok": True})
        if path == "/wiki/api/upload":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "권한 없음 · Team. Wildmc 필요"})
            # multipart not supported here — accept base64 JSON {filename, data}
            raw = str(body.get("data") or body.get("image") or "")
            filename = str(body.get("filename") or "upload.png")
            if ";base64," in raw:
                b64 = raw.split(";base64,", 1)[1]
            else:
                b64 = raw
            try:
                buf = base64.b64decode(b64)
            except Exception:
                return self._json(400, {"error": "이미지 데이터가 올바르지 않습니다."})
            if len(buf) > 12 * 1024 * 1024:
                return self._json(400, {"error": "파일이 너무 커요 (최대 12MB)"})
            ext = Path(filename).suffix.lower()
            if ext not in (".png", ".jpg", ".jpeg", ".gif", ".webp"):
                ext = ".png"
            name = secrets.token_hex(6) + ext
            WIKI_UPLOADS.mkdir(parents=True, exist_ok=True)
            (WIKI_UPLOADS / name).write_bytes(buf)
            with lock:
                log_activity(session.get("discordId"), "wiki_upload", page="/wiki/editor", detail=name)
                save_db(db)
            return self._json(200, {"url": f"/wiki/uploads/{name}"})

        if path == "/api/activity":
            session = get_session(self)
            did = session["discordId"] if session else None
            with lock:
                log_activity(
                    did,
                    str(body.get("action") or "event"),
                    page=str(body.get("page") or ""),
                    detail=str(body.get("detail") or "")[:500],
                    target_id=str(body.get("target_id") or ""),
                    target_name=str(body.get("target_name") or ""),
                )
                save_db(db)
            return self._json(200, {"ok": True})
        if path == "/api/friends/request":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            target = find_user_by_name(str(body.get("username") or body.get("discord_id") or ""))
            if not target:
                return self._json(404, {"error": "해당 닉네임의 유저를 찾을 수 없습니다. (사이트 로그인 이력이 있어야 합니다)"})
            tid = str(target.get("discord_id") or "")
            if tid == did:
                return self._json(400, {"error": "자기 자신에게는 친구 요청을 보낼 수 없습니다."})
            if are_friends(did, tid):
                return self._json(400, {"error": "이미 친구입니다."})
            with lock:
                for f in db.get("friendships", []):
                    a, b = str(f.get("from_id") or ""), str(f.get("to_id") or "")
                    if {a, b} == {did, tid} and f.get("status") in ("pending", "accepted"):
                        return self._json(400, {"error": "이미 요청했거나 친구입니다."})
                item = {
                    "id": next_id(db.get("friendships", [])),
                    "from_id": did,
                    "to_id": tid,
                    "status": "pending",
                    "created_at": now_ms(),
                }
                db.setdefault("friendships", []).append(item)
                send_mail(tid, "친구 요청이 도착했습니다", f"{(find_user(did) or {}).get('discord_username') or did} 님이 친구를 요청했습니다.", "friend", "/friends")
                log_activity(did, "friend_request", page="/friends", target_id=tid, target_name=str(target.get("discord_username") or ""), detail="친구 요청 전송")
                save_db(db)
            return self._json(200, {"ok": True, "id": item["id"]})
        if path == "/api/friends/respond":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            fid = safe_int(body.get("id"))
            accept = bool(body.get("accept"))
            with lock:
                row = next((f for f in db.get("friendships", []) if safe_int(f.get("id")) == fid), None)
                if not row or str(row.get("to_id")) != did:
                    return self._json(404, {"error": "요청을 찾을 수 없습니다."})
                row["status"] = "accepted" if accept else "rejected"
                other = str(row.get("from_id") or "")
                if accept:
                    send_mail(other, "친구 요청이 수락되었습니다", f"{(find_user(did) or {}).get('discord_username') or did} 님이 친구 요청을 수락했습니다.", "friend", "/friends")
                    log_activity(did, "friend_accept", page="/friends", target_id=other, detail="친구 수락")
                else:
                    log_activity(did, "friend_reject", page="/friends", target_id=other, detail="친구 거절")
                save_db(db)
            return self._json(200, {"ok": True})
        if path == "/api/chat":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            to = str(body.get("to") or "").strip()
            msg = str(body.get("body") or "").strip()
            if not to or not msg:
                return self._json(400, {"error": "상대와 메시지를 입력하세요."})
            if len(msg) > 2000:
                return self._json(400, {"error": "메시지가 너무 깁니다."})
            if not are_friends(did, to):
                return self._json(403, {"error": "친구만 채팅할 수 있습니다."})
            with lock:
                item = {
                    "id": next_id(db.get("chat_messages", [])),
                    "from_id": did,
                    "to_id": to,
                    "body": msg,
                    "created_at": now_ms(),
                    "read": 0,
                }
                db.setdefault("chat_messages", []).append(item)
                from_name = (find_user(did) or {}).get("discord_username") or did
                send_mail(to, f"새 채팅 · {from_name}", msg[:120], "chat", f"/friends?with={did}")
                log_activity(did, "chat_send", page="/friends", target_id=to, target_name=str((find_user(to) or {}).get("discord_username") or ""), detail=msg[:200])
                save_db(db)
            return self._json(200, {"ok": True, "message": item})
        if path == "/api/support":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            subject = str(body.get("subject") or "").strip() or "문의"
            msg = str(body.get("body") or "").strip()
            images_raw = body.get("images") or body.get("image") or []
            if isinstance(images_raw, str):
                images_raw = [images_raw]
            if not msg and not images_raw:
                return self._json(400, {"error": "내용 또는 사진을 입력하세요."})
            uname = (find_user(did) or {}).get("discord_username") or session.get("username") or did
            with lock:
                iid = next_id(db.get("inquiries", []))
                urls = save_support_images(images_raw, f"inq{iid}")
                item = {
                    "id": iid,
                    "user_id": did,
                    "username": uname,
                    "subject": subject[:120],
                    "body": (msg or "(사진)")[:4000],
                    "images": urls,
                    "status": "open",
                    "created_at": now_ms(),
                    "replies": [],
                }
                db.setdefault("inquiries", []).append(item)
                send_mail(did, "문의가 접수되었습니다", f"{subject}\n관리자가 확인 후 답변합니다.", "support", "/support")
                log_activity(did, "inquiry_create", page="/support", detail=subject)
                save_db(db)
            return self._json(200, {"ok": True, "item": item})
        if path == "/api/support/reply":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            iid = safe_int(body.get("id"))
            msg = str(body.get("body") or body.get("reply") or "").strip()
            images_raw = body.get("images") or body.get("image") or []
            if isinstance(images_raw, str):
                images_raw = [images_raw]
            if not msg and not images_raw:
                return self._json(400, {"error": "내용 또는 사진을 입력하세요."})
            with lock:
                row = next((i for i in db.get("inquiries", []) if safe_int(i.get("id")) == iid), None)
                if not row:
                    return self._json(404, {"error": "문의를 찾을 수 없습니다."})
                if str(row.get("user_id") or "") != did:
                    return self._json(403, {"error": "본인 문의만 답글할 수 있습니다."})
                urls = save_support_images(images_raw, f"rep{iid}_{str(did)[-4:]}")
                reply = {"from": "user", "body": (msg or "(사진)")[:4000], "images": urls, "at": now_ms()}
                row.setdefault("replies", []).append(reply)
                if row.get("status") == "closed":
                    row["status"] = "open"
                log_activity(did, "inquiry_reply", page="/support", detail=str(iid))
                save_db(db)
            return self._json(200, {"ok": True, "reply": reply})
        if path == "/api/reviews":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = str(session.get("discordId") or "")
            pid = safe_int(body.get("product_id"))
            rating = max(1, min(5, safe_int(body.get("rating"), 5)))
            text = clean_user_text(body.get("body"), 800)
            if pid <= 0:
                return self._json(400, {"error": "상품을 선택해주세요."})
            if not text:
                return self._json(400, {"error": "리뷰 내용을 입력해주세요."})
            product = next((p for p in db.get("products", []) if safe_int(p.get("id")) == pid), None)
            if not product:
                return self._json(404, {"error": "상품을 찾을 수 없습니다."})
            with lock:
                if not user_purchased_product(did, pid):
                    return self._json(403, {"error": "이 상품을 구매한 사람만 리뷰를 쓸 수 있어요."})
                author = session_author(session)
                rows = db.setdefault("reviews", [])
                row = next((r for r in rows if str(r.get("discord_id") or "") == did and safe_int(r.get("product_id")) == pid), None)
                if row:
                    row["rating"] = rating
                    row["body"] = text
                    row["updated_at"] = now_ms()
                    row["username"] = author["username"]
                    row["avatar"] = author.get("avatar")
                    row["hidden"] = 0
                else:
                    row = {
                        "id": next_id(rows),
                        "product_id": pid,
                        "product_name": product.get("name") or "",
                        "discord_id": did,
                        "username": author["username"],
                        "avatar": author.get("avatar"),
                        "minecraft_name": author.get("minecraft_name"),
                        "rating": rating,
                        "body": text,
                        "created_at": now_ms(),
                        "updated_at": now_ms(),
                        "hidden": 0,
                    }
                    rows.append(row)
                log_activity(did, "review_write", page="/shop", detail=f"{product.get('name')} ★{rating}", target_id=str(pid))
                save_db(db)
            return self._json(200, {"ok": True, "review": public_review(row)})
        if path == "/api/community":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = str(session.get("discordId") or "")
            title = clean_user_text(body.get("title"), 80)
            text = clean_user_text(body.get("body"), 2000)
            if not title or not text:
                return self._json(400, {"error": "제목과 내용을 입력해주세요."})
            with lock:
                author = session_author(session)
                rows = db.setdefault("community_posts", [])
                row = {
                    "id": next_id(rows),
                    "discord_id": did,
                    "username": author["username"],
                    "avatar": author.get("avatar"),
                    "title": title,
                    "body": text,
                    "likes": [],
                    "created_at": now_ms(),
                    "hidden": 0,
                }
                rows.append(row)
                log_activity(did, "community_post", page="/community", detail=title)
                save_db(db)
            return self._json(200, {"ok": True, "post": public_community_post(row, did)})
        if path == "/api/community/like":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = str(session.get("discordId") or "")
            pid = safe_int(body.get("post_id") or body.get("id"))
            with lock:
                row = next((p for p in db.get("community_posts", []) if safe_int(p.get("id")) == pid and not p.get("hidden")), None)
                if not row:
                    return self._json(404, {"error": "글을 찾을 수 없습니다."})
                likes = [str(x) for x in (row.get("likes") or [])]
                if did in likes:
                    likes = [x for x in likes if x != did]
                    liked = False
                else:
                    likes.append(did)
                    liked = True
                row["likes"] = likes
                log_activity(did, "community_like", page="/community", detail=str(pid), result="on" if liked else "off")
                save_db(db)
            return self._json(200, {"ok": True, "liked": liked, "likes": len(likes)})
        if path == "/api/community/comment":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = str(session.get("discordId") or "")
            pid = safe_int(body.get("post_id"))
            parent_id = safe_int(body.get("parent_id")) or 0
            text = clean_user_text(body.get("body"), 800)
            if not text:
                return self._json(400, {"error": "댓글을 입력해주세요."})
            with lock:
                post = next((p for p in db.get("community_posts", []) if safe_int(p.get("id")) == pid and not p.get("hidden")), None)
                if not post:
                    return self._json(404, {"error": "글을 찾을 수 없습니다."})
                if parent_id:
                    parent = next((c for c in db.get("community_comments", []) if safe_int(c.get("id")) == parent_id), None)
                    if not parent or safe_int(parent.get("post_id")) != pid:
                        return self._json(404, {"error": "댓글을 찾을 수 없습니다."})
                    # 대댓글은 한 단계만 — 부모의 부모면 최상위 댓글에 붙인다
                    if safe_int(parent.get("parent_id")):
                        parent_id = safe_int(parent.get("parent_id"))
                author = session_author(session)
                rows = db.setdefault("community_comments", [])
                row = {
                    "id": next_id(rows),
                    "post_id": pid,
                    "parent_id": parent_id or None,
                    "discord_id": did,
                    "username": author["username"],
                    "avatar": author.get("avatar"),
                    "body": text,
                    "created_at": now_ms(),
                    "hidden": 0,
                }
                rows.append(row)
                log_activity(did, "community_comment", page="/community", detail=str(pid))
                save_db(db)
            return self._json(200, {"ok": True, "comment": public_comment(row)})


        key = self.headers.get("x-api-key") or self.headers.get("X-Api-Key")

        if path == "/api/auth/local":
            return self._json(410, {"error": "로컬 로그인은 더 이상 사용할 수 없습니다. 디스코드로 로그인하세요."})

        if path == "/api/auth/logout":
            token = get_session_token(self)
            if token:
                with lock:
                    db.get("sessions", {}).pop(token, None)
                    save_db(db)
            return self._json(200, {"ok": True}, clear_cookie=True)

        if path == "/api/achievements/claim":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            ach_id = str(body.get("id") or "").strip()
            if ach_id not in EGG_IDS:
                return self._json(400, {"error": "이스터에그 도전과제만 직접 청구할 수 있습니다."})
            with lock:
                unlocked = unlock_achievement(session["discordId"], ach_id)
                save_db(db)
            if not unlocked:
                return self._json(200, {"ok": True, "already": True})
            return self._json(200, {"ok": True, "unlocked": unlocked})

        if path == "/api/achievements/theme-visit":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            req_theme = str(body.get("themeId") or body.get("id") or "").strip()
            if not req_theme or req_theme == "default":
                return self._json(400, {"error": "시즌 테마가 아닙니다."})
            if req_theme not in THEME_ACH_BY_THEME:
                return self._json(400, {"error": "알 수 없는 테마입니다."})
            current = resolve_theme(db.get("settings") or {})
            if str(current.get("id") or "") != req_theme:
                return self._json(400, {"error": "현재 적용 중인 테마와 다릅니다. (치팅 방지)"})
            with lock:
                unlocked = try_unlock_theme_visit(session["discordId"], req_theme)
                if unlocked:
                    save_db(db)
            return self._json(200, {"ok": True, "unlocked": unlocked, "already": not unlocked})

        if path == "/api/achievements/calendar-check":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            unlocked: list[dict] = []
            now = datetime.now(timezone(timedelta(hours=9)))
            with lock:
                # 개발자 생일: 매년 8월 28일
                if now.month == 8 and now.day == 28:
                    u = unlock_achievement(session["discordId"], "dev_birthday")
                    if u:
                        unlocked.append(u)
                if unlocked:
                    save_db(db)
            return self._json(200, {"ok": True, "unlocked": unlocked, "date": now.strftime("%Y-%m-%d")})

        if path == "/api/link-code":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            return self._json(
                410,
                {
                    "error": "이제 마크에서 /인증 으로 코드를 받은 뒤 사이트에서 입력하세요.",
                    "redirect": "/link",
                },
            )

        if path == "/api/link-verify":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            code = str(body.get("code") or "").strip().upper().replace(" ", "")
            if not code:
                return self._json(400, {"error": "코드를 입력해주세요."})
            discord_id = session["discordId"]
            with lock:
                row = next(
                    (
                        c
                        for c in db.get("auth_codes", [])
                        if str(c.get("code") or "").upper() == code
                        and c.get("direction") == "mc_to_web"
                    ),
                    None,
                )
                if not row:
                    return self._json(404, {"error": "앗, 이 코드는 유효하지 않는 것같아요! 다시 확인 부탁드려요!"})
                if row.get("used"):
                    return self._json(400, {"error": "앗, 이미 사용된 코드인 것같아요."})
                if int(row.get("expires_at") or 0) < now_ms():
                    return self._json(400, {"error": "앗, 이 인증코드는 만료된 코드같아요! 다시 확인 부탁드려요!"})
                uuid = str(row.get("minecraft_uuid") or "")
                name = str(row.get("minecraft_name") or "")
                group = row.get("luckperms_group")
                if not uuid or not name:
                    return self._json(400, {"error": "코드 정보가 올바르지 않아요."})
                existing = next((u for u in db.get("users", []) if u.get("minecraft_uuid") == uuid), None)
                if existing and existing.get("discord_id") != discord_id:
                    return self._json(409, {"error": "앗, 이미 연동된 계정인 것같아요!"})
                current = find_user(discord_id)
                current_uuid = str((current or {}).get("minecraft_uuid") or "").strip()
                if current_uuid and current_uuid != uuid:
                    return self._json(200, {"ok": True, "kept": True, "message": "이미 연동된 마인크래프트 계정은 그대로 유지돼요.", "minecraftUuid": current_uuid, "minecraftName": (current or {}).get("minecraft_name")})
                row["used"] = 1
                row["discord_id"] = discord_id
                ts = now_ms()
                upsert_user(
                    discord_id,
                    minecraft_uuid=uuid,
                    minecraft_name=name,
                    luckperms_group=group,
                    linked_at=ts,
                )
                db.setdefault("player_cache", {})[uuid] = {
                    "minecraft_name": name,
                    "luckperms_group": group,
                    "online": 1,
                    "updated_at": ts,
                }
                unlock_achievement(discord_id, "link_mc")
                unlock_achievement(discord_id, "code_issue")
                link_code = grant_personal_coupon(discord_id, "연동 40% 할인", 40, "link40")
                if link_code:
                    send_mail(discord_id, "연동 할인 쿠폰", f"계정 연동 보상으로 40% 할인 쿠폰 {link_code} 이 지급되었습니다.", "coupon", "/coupon")
                dc_name = str(session.get("username") or (find_user(discord_id) or {}).get("discord_username") or discord_id)
                queue_player_chat(name, f"({discord_id} {dc_name})계정과 연동 성공했어요!")
                save_db(db)
            return self._json(
                200,
                {
                    "ok": True,
                    "message": "마인크래프트 계정과 디스코드 계정 연동에 성공하였어요!",
                    "minecraftUuid": uuid,
                    "minecraftName": name,
                },
            )

        if path == "/api/pay":
            if payment_settings().get("enabled") == "0":
                return self._json(403, {"error": "현재 결제가 비활성화되어 있습니다."})
            session = get_session(self)
            if not session or str(session.get("discordId", "")).startswith("local_"):
                return self._json(401, {"error": "디스코드 로그인 후 구매할 수 있습니다."})
            user = find_user(session["discordId"])
            if not user or not user.get("minecraft_uuid"):
                return self._json(403, {"error": "마인크래프트 계정 연동 후 구매할 수 있습니다."})
            product_id = int(body.get("productId") or 0)
            buyer_name = str(body.get("buyerName") or "").strip()
            custom_kind = str(body.get("customKind") or body.get("custom") or "").strip()
            custom_amount = safe_int(body.get("customAmount") or body.get("amount"))
            cart_raw = body.get("cartItems") or body.get("cart") or None
            if not buyer_name:
                return self._json(400, {"error": "입금자명은 필수입니다."})
            if len(buyer_name) > 40:
                return self._json(400, {"error": "입금자명이 너무 깁니다."})
            product = None
            cart_lines = None
            cart_total = 0
            cart_title = ""
            viewer_rank = buyer_shop_rank(str(session.get("discordId") or ""))
            if cart_raw:
                cart_lines, cart_total, cart_title = resolve_cart_items(cart_raw, viewer_rank)
                if cart_lines is None:
                    return self._json(400, {"error": cart_title or "장바구니를 확인할 수 없습니다."})
                product = {
                    "id": 0,
                    "name": cart_title,
                    "price": cart_total,
                    "currency": "KRW",
                    "cash_amount": sum(safe_int(x.get("cash_amount")) * safe_int(x.get("qty"), 1) for x in cart_lines),
                    "gem_amount": sum(safe_int(x.get("gem_amount")) * safe_int(x.get("qty"), 1) for x in cart_lines),
                    "voucher_count": sum(safe_int(x.get("voucher_count")) * safe_int(x.get("qty"), 1) for x in cart_lines),
                    "rank_group": None,
                }
            elif custom_kind:
                product = quote_custom_product(custom_kind, custom_amount)
                if not product:
                    return self._json(400, {"error": f"커스텀 구매는 최소 {custom_min_won()}원입니다."})
            else:
                if not product_id:
                    return self._json(400, {"error": "상품과 입금자명은 필수입니다."})
                product = next((p for p in public_products() if safe_int(p.get("id")) == product_id), None)
            if not product:
                return self._json(404, {"error": "상품을 찾을 수 없습니다."})
            if not cart_lines and not custom_kind:
                product = apply_rank_price(product, viewer_rank) or product
            coupon_code = str(body.get("couponCode") or body.get("coupon") or "").strip()
            pricing = None
            with lock:
                order_code = make_order_code()
                if coupon_code:
                    _c, pricing, err = validate_coupon_for_order(
                        coupon_code,
                        product=product,
                        discord_id=session["discordId"],
                        consume=True,
                        order_code=order_code,
                    )
                    if err:
                        return self._json(400, {"error": err})
                original = int(product.get("price") or 0)
                final_price = int(pricing["final"]) if pricing else original
                discount = int(pricing["discount"]) if pricing else 0
                ts = now_ms()
                gift_name = str(body.get("giftMinecraftName") or body.get("giftName") or "").strip()
                own_name = str(body.get("minecraftName") or "").strip() or user.get("minecraft_name")
                mc_name = gift_name or own_name
                dc_name = str(body.get("discordUsername") or "").strip() or session.get("username") or user.get("discord_username")
                order = {
                    "id": next_id(db.get("orders", [])),
                    "order_code": order_code,
                    "product_id": product_id if not custom_kind and not cart_lines else 0,
                    "product_name": product.get("name"),
                    "price": final_price,
                    "original_price": original,
                    "discount_amount": discount,
                    "coupon_code": (pricing or {}).get("code"),
                    "coupon_id": (pricing or {}).get("couponId"),
                    "currency": product.get("currency") or "KRW",
                    "buyer_name": buyer_name,
                    "minecraft_name": mc_name,
                    "gift": 1 if gift_name else 0,
                    "gift_minecraft_name": gift_name or None,
                    "custom_kind": None if cart_lines else product.get("custom_kind"),
                    "custom_amount": 0 if cart_lines else (custom_amount if custom_kind else 0),
                    "cash_amount": safe_int(product.get("cash_amount")),
                    "gem_amount": safe_int(product.get("gem_amount")),
                    "voucher_count": safe_int(product.get("voucher_count")),
                    "rank_group": None if cart_lines else product.get("rank_group"),
                    "cart_lines": cart_lines,
                    "discord_id": session["discordId"],
                    "discord_username": dc_name,
                    "status": "pending",
                    "memo": str(body.get("memo") or "").strip() or None,
                    "admin_note": None,
                    "images": [],
                    "created_at": ts,
                    "updated_at": ts,
                    "paid_at": None,
                    "fulfilled_at": None,
                }
                images_raw = body.get("images") or body.get("image") or []
                if isinstance(images_raw, str):
                    images_raw = [images_raw]
                if images_raw:
                    order["images"] = save_order_images(images_raw, f"ord{order_code.replace('-', '')}")
                db.setdefault("orders", []).append(order)
                price_line = f"{final_price:,}원"
                if discount:
                    price_line = f"{original:,}원 → {final_price:,}원 (쿠폰 {pricing.get('code')} -{discount:,}원)"
                send_mail(
                    session["discordId"],
                    "주문이 접수되었습니다",
                    f"{product.get('name')} · {price_line}",
                    "order",
                    f"/pay/order/{order_code}",
                )
                unlock_achievement(session["discordId"], "first_order")
                save_db(db)
            return self._json(200, {"ok": True, "id": order["id"], "orderCode": order_code, "redirect": f"/pay/order/{order_code}", "price": order["price"], "discount": discount})

        if path == "/api/codes/redeem":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            with lock:
                message, err = redeem_promo_code(str(session.get("discordId") or ""), str(body.get("code") or ""))
                if err:
                    return self._json(400, {"error": err})
                save_db(db)
            return self._json(200, {"ok": True, "message": message})

        if path == "/api/stocks/trade":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            user = find_user(str(session.get("discordId") or ""))
            mc = str((user or {}).get("minecraft_name") or "").strip()
            if not mc:
                return self._json(400, {"error": "마인크래프트 계정을 연동한 뒤 거래할 수 있어요."})
            with lock:
                trade, err = create_stock_trade(
                    str(session.get("discordId") or ""),
                    mc,
                    str(body.get("id") or body.get("name") or ""),
                    str(body.get("side") or ""),
                    max(0, safe_int(body.get("qty"), 1)),
                )
                if err:
                    return self._json(400, {"error": err})
                save_db(db)
            return self._json(200, {"ok": True, "trade": trade_public(trade), "message": "마크 서버에서 돈을 처리하는 중이에요."})

        if path == "/api/lottery/buy":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            user = find_user(str(session.get("discordId") or ""))
            mc = str((user or {}).get("minecraft_name") or "").strip()
            if not mc:
                return self._json(400, {"error": "마인크래프트 계정을 연동한 뒤 살 수 있어요."})
            mode = str(body.get("mode") or "auto")
            numbers = body.get("numbers") if isinstance(body.get("numbers"), list) else []
            if mode == "auto":
                count = max(1, min(100, safe_int(body.get("count"), 1)))
                numbers = [lottery_auto_number() for _ in range(count)]
            with lock:
                job, err = create_lottery_purchase(
                    str(session.get("discordId") or ""),
                    mc,
                    "auto" if mode == "auto" else "manual",
                    [str(n) for n in numbers],
                    str(body.get("idempotencyKey") or ""),
                )
                if err:
                    return self._json(400, {"error": err})
                save_db(db)
            return self._json(200, {"ok": True, "jobId": (job or {}).get("id"), "message": "마크 서버에서 캐시를 확인하는 중이에요."})

        if path == "/api/lottery/admin":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "관리자만 바꿀 수 있어요."})
            op = str(body.get("op") or "")
            with lock:
                settings = db.setdefault("lottery_settings", {})
                if op == "halt":
                    settings["enabled"] = 1 if body.get("enabled") else 0
                    save_db(db)
                    return self._json(200, {"ok": True, "message": "판매 상태를 바꿨어요."})
                if op == "settings":
                    splits = [safe_int(body.get("split1"), lottery_settings()["split1"]), safe_int(body.get("split2"), lottery_settings()["split2"]), safe_int(body.get("split3"), lottery_settings()["split3"])]
                    if "split1" not in body:
                        splits = [lottery_settings()["split1"], lottery_settings()["split2"], lottery_settings()["split3"]]
                    if sum(splits) != 100:
                        return self._json(400, {"error": "1~3등 배분 합계는 100이어야 해요."})
                    for key, field in (("price", "price"), ("dailyLimit", "daily_limit"), ("returnRate", "return_rate"), ("firstCapMultiple", "first_cap_multiple"), ("dailyWinCap", "daily_win_cap")):
                        if key in body:
                            settings[field] = safe_int(body.get(key))
                    if "split1" in body:
                        settings["split1"], settings["split2"], settings["split3"] = splits
                    save_db(db)
                    return self._json(200, {"ok": True, "message": "설정을 저장했어요.", "settings": lottery_settings_public()})
                if op == "draw":
                    current = ensure_lottery_round()
                    drawn, err = draw_lottery_round(safe_int(current.get("id")))
                    if err:
                        return self._json(400, {"error": err})
                    save_db(db)
                    return self._json(200, {"ok": True, "message": f"{(drawn or {}).get('winning')} 번호로 추첨했어요.", "round": lottery_round_public(drawn or {}, db.get("lottery_tickets") or [])})
                return self._json(400, {"error": "알 수 없는 작업이에요."})

        if path == "/api/stocks/admin":
            session = get_session(self)
            if not can_edit_site(session):
                return self._json(403, {"error": "관리자만 바꿀 수 있어요."})
            with lock:
                result, err = stock_admin_apply(body)
                if err:
                    return self._json(400, {"error": err})
                save_db(db)
            return self._json(200, result or {"ok": True})

        if path == "/api/coupons/validate":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            product_id = int(body.get("productId") or 0)
            custom_kind = str(body.get("customKind") or "").strip()
            custom_amount = safe_int(body.get("customAmount") or body.get("amount"))
            cart_total = safe_int(body.get("cartTotal") or body.get("price"))
            product = None
            if custom_kind:
                product = quote_custom_product(custom_kind, custom_amount)
            elif product_id:
                product = next((p for p in public_products() if safe_int(p.get("id")) == product_id), None)
            elif cart_total > 0:
                product = {"id": 0, "name": "장바구니", "price": cart_total, "currency": "KRW"}
            if not product:
                return self._json(404, {"error": "상품을 찾을 수 없습니다."})
            with lock:
                _c, pricing, err = validate_coupon_for_order(
                    str(body.get("code") or ""),
                    product=product,
                    discord_id=session["discordId"],
                    consume=False,
                )
            if err:
                return self._json(400, {"error": err})
            return self._json(200, {"ok": True, "pricing": pricing})

        if path == "/api/coupons/claim":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            parent_id = int(body.get("id") or body.get("couponId") or 0)
            if parent_id <= 0:
                return self._json(400, {"error": "쿠폰 id가 필요합니다."})
            with lock:
                parent = next((c for c in db.get("coupons", []) if int(c.get("id") or 0) == parent_id), None)
                if not parent or int(parent.get("claimable") or 0) != 1:
                    return self._json(404, {"error": "선착순 쿠폰을 찾을 수 없습니다."})
                if int(parent.get("active", 1) or 0) == 0:
                    return self._json(400, {"error": "비활성화된 쿠폰입니다."})
                reg = int(parent.get("register_until") or 0)
                if reg and reg < now_ms():
                    return self._json(400, {"error": "쿠폰 받기 기간이 마감되었습니다."})
                exp = int(parent.get("expires_at") or 0)
                if exp and exp < now_ms():
                    return self._json(400, {"error": "쿠폰 사용 기간이 만료되었습니다."})
                if user_already_claimed(did, parent_id):
                    return self._json(400, {"error": "이미 받은 쿠폰입니다."})
                if claim_slots_remaining(parent) <= 0:
                    return self._json(400, {"error": "선착순이 마감되었습니다."})
                code = ""
                for _ in range(12):
                    code = generate_code(2, 4).replace("-", "")
                    if not find_coupon(code):
                        break
                if not code or find_coupon(code):
                    return self._json(500, {"error": "쿠폰 코드 생성에 실패했습니다. 다시 시도하세요."})
                ctype = str(parent.get("type") or "percent")
                value = parent.get("value")
                item = {
                    "id": next_id(db.get("coupons", [])),
                    "code": code,
                    "name": parent.get("name") or code,
                    "type": ctype,
                    "value": value,
                    "max_uses": 1,
                    "used_count": 0,
                    "claimed_count": 0,
                    "per_user": 1,
                    "min_price": int(parent.get("min_price") or 0),
                    "product_ids": list(parent.get("product_ids") or []),
                    "active": 1,
                    "expires_at": parent.get("expires_at"),
                    "register_until": parent.get("register_until"),
                    "assigned_discord_id": did,
                    "single_use": 1,
                    "claimable": 0,
                    "claim_parent_id": parent_id,
                    "note": f"선착순 수령 · 부모 #{parent_id}",
                    "created_at": now_ms(),
                }
                db.setdefault("coupons", []).append(item)
                add_to_wallet(did, item, item.get("code"))
                parent["claimed_count"] = int(parent.get("claimed_count") or 0) + 1
                db.setdefault("coupon_claims", []).append(
                    {
                        "id": next_id(db.get("coupon_claims", [])),
                        "parent_id": parent_id,
                        "discord_id": did,
                        "issued_code": code,
                        "issued_coupon_id": item["id"],
                        "created_at": now_ms(),
                    }
                )
                disc_label = f"{value}%" if ctype == "percent" else f"{int(value):,}원"
                send_mail(
                    did,
                    f"선착순 쿠폰을 받았습니다 · {disc_label}",
                    f"쿠폰이 내 쿠폰함에 다운로드되었습니다.\n코드: {code}\n할인: {disc_label}\n결제 시 자동 적용하거나 직접 고를 수 있습니다.",
                    "coupon",
                    "/shop",
                )
                save_db(db)
            return self._json(
                200,
                {
                    "ok": True,
                    "code": code,
                    "coupon": item,
                    "remaining": claim_slots_remaining(parent),
                },
            )


        if path == "/api/nick/rank":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            ok, err, nick = validate_nick(str(body.get("nick") or ""))
            if not ok:
                return self._json(400, {"error": err})
            user = find_user(session["discordId"])
            if not user or not user.get("minecraft_uuid") or not user.get("minecraft_name"):
                return self._json(400, {"error": "마인크래프트 계정이 연동되지 않았습니다. 디스코드에서 인증을 완료해주세요."})
            group = user.get("luckperms_group")
            cache = db.get("player_cache", {}).get(user["minecraft_uuid"]) or {}
            if cache.get("luckperms_group"):
                group = cache["luckperms_group"]
            player_name = cache.get("minecraft_name") or user.get("minecraft_name")
            if not can_change_nick_by_rank(group):
                return self._json(403, {"error": f"닉네임 변경이 가능한 랭크가 아닙니다. ({', '.join(RANK_GROUPS)}) · 상점에서 닉네임 변경권을 살 수 있어요."})
            command = f"nick {nick} {player_name}"
            with lock:
                queue_command(command, "rank_nick", session["discordId"])
                unlock_achievement(session["discordId"], "nick_change")
                save_db(db)
            return self._json(200, {"ok": True, "message": "닉네임 변경을 완료했어요. 확인 부탁드려요.", "command": command})

        if path == "/api/nick/ticket":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            did = session["discordId"]
            user = find_user(did)
            if not user or not user.get("minecraft_uuid") or not user.get("minecraft_name"):
                return self._json(400, {"error": "마인크래프트 계정이 연동되지 않았습니다."})
            with lock:
                ensure_nick_tickets_from_orders()
                ticket = next(
                    (t for t in db.get("nick_tickets", []) if str(t.get("discord_id") or "") == did and not t.get("used_at")),
                    None,
                )
                if not ticket:
                    return self._json(400, {"error": "보유한 닉네임 변경권이 없습니다. 상점에서 구매한 뒤 지급완료가 되어야 해요."})
                code = generate_code()
                expires = now_ms() + 600000
                ticket["used_at"] = now_ms()
                ticket["issued_code"] = code
                db.setdefault("nick_vouchers", []).append(
                    {
                        "id": next_id(db.get("nick_vouchers", [])),
                        "code": code,
                        "minecraft_uuid": user.get("minecraft_uuid"),
                        "minecraft_name": user.get("minecraft_name"),
                        "expires_at": expires,
                        "used": 0,
                        "created_at": now_ms(),
                        "source": "shop",
                    }
                )
                log_activity(did, "nick_ticket_use", page="/panel", detail=f"코드 발급 {code}")
                save_db(db)
                left = nick_ticket_count(did)
            return self._json(
                200,
                {"ok": True, "code": code, "expiresAt": expires, "left": left, "message": f"코드 {code} 가 나왔어요. 10분 안에 아래 칸에서 닉네임을 바꾸세요."},
            )

        if path == "/api/nick/voucher":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요해요."})
            ok, err, nick = validate_nick(str(body.get("nick") or ""))
            if not ok:
                return self._json(400, {"error": err})
            user = find_user(session["discordId"])
            if not user or not user.get("minecraft_uuid") or not user.get("minecraft_name"):
                return self._json(400, {"error": "마인크래프트 계정과 디스코드 계정 연동이 필요해요."})
            if not str(body.get("code") or "").strip():
                return self._json(400, {"error": "사용을 눌러 코드를 받은 뒤, 그 코드를 넣어 주세요."})
            voucher = next((v for v in db.get("nick_vouchers", []) if str(v.get("code") or "").upper() == str(body.get("code")).strip().upper()), None)
            if not voucher:
                return self._json(404, {"error": "앗, 이 코드는 유효하지 않는 것같아요!"})
            if voucher.get("used"):
                return self._json(400, {"error": "이미 사용된 코드입니다."})
            if int(voucher.get("expires_at") or 0) < now_ms():
                return self._json(400, {"error": "만료된 코드입니다. (10분)"})
            if voucher.get("minecraft_uuid") != user.get("minecraft_uuid"):
                return self._json(403, {"error": "이 코드는 연동된 마인크래프트 계정과 일치하지 않습니다."})
            cache = db.get("player_cache", {}).get(user["minecraft_uuid"]) or {}
            player_name = cache.get("minecraft_name") or user.get("minecraft_name")
            command = f"nick {nick} {player_name}"
            with lock:
                voucher["used"] = 1
                queue_command(command, "voucher_nick", session["discordId"])
                unlock_achievement(session["discordId"], "nick_change")
                save_db(db)
            return self._json(200, {"ok": True, "message": "닉네임 변경권 사용이 완료되었습니다.", "command": command})

        if path == "/api/bot/auth-code":
            if key != BOT_KEY:
                return self._json(401, {"error": "Unauthorized"})
            discord_id = str(body.get("discordId") or "")
            if not discord_id:
                return self._json(400, {"error": "discordId required"})
            code = "".join(secrets.choice(ALPHABET) for _ in range(8))
            expires = now_ms() + 600000
            with lock:
                db.setdefault("auth_codes", []).append(
                    {
                        "code": code,
                        "direction": "web_to_mc",
                        "discord_id": discord_id,
                        "expires_at": expires,
                        "used": 0,
                        "created_at": now_ms(),
                    }
                )
                save_db(db)
            return self._json(200, {"code": code, "expiresAt": expires})

        if path == "/api/plugin/auth/issue":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            uuid = str(body.get("uuid") or "").strip()
            name = str(body.get("name") or "").strip()
            group = body.get("group")
            if not uuid or not name:
                return self._json(400, {"ok": False, "error": "uuid, name required"})
            linked = next((u for u in db.get("users", []) if str(u.get("minecraft_uuid") or "") == uuid), None)
            if linked and str(linked.get("discord_id") or "").strip():
                return self._json(
                    200,
                    {
                        "ok": True,
                        "linked": True,
                        "code": "",
                        "message": f"{linked_account_label(linked)}계정과 연동되어 있어요.",
                    },
                )
            code = six_digit_code()
            expires = now_ms() + 600000
            with lock:
                # 같은 플레이어의 미사용 코드 만료 처리
                for c in db.setdefault("auth_codes", []):
                    if (
                        c.get("direction") == "mc_to_web"
                        and str(c.get("minecraft_uuid") or "") == uuid
                        and not c.get("used")
                    ):
                        c["used"] = 1
                        c["superseded"] = 1
                db["auth_codes"].append(
                    {
                        "code": code,
                        "direction": "mc_to_web",
                        "minecraft_uuid": uuid,
                        "minecraft_name": name,
                        "luckperms_group": group,
                        "discord_id": None,
                        "expires_at": expires,
                        "used": 0,
                        "created_at": now_ms(),
                    }
                )
                if len(db["auth_codes"]) > 5000:
                    db["auth_codes"] = db["auth_codes"][-4000:]
                save_db(db)
            return self._json(200, {"ok": True, "code": code, "expiresAt": expires})

        if path == "/api/plugin/auth/verify":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            code = str(body.get("code") or "").strip().upper()
            uuid = str(body.get("uuid") or "")
            name = str(body.get("name") or "")
            group = body.get("group")
            if not code or not uuid or not name:
                return self._json(400, {"ok": False, "error": "code, uuid, name required"})
            with lock:
                row = next(
                    (
                        c
                        for c in db.get("auth_codes", [])
                        if str(c.get("code") or "").upper() == code
                        and c.get("direction") != "mc_to_web"
                    ),
                    None,
                )
                if not row:
                    return self._json(
                        404,
                        {
                            "ok": False,
                            "error": "웹에서 발급한 코드가 아닙니다. /인증 만 입력해 코드를 받은 뒤 사이트에서 인증하세요.",
                        },
                    )
                if row.get("used"):
                    return self._json(400, {"ok": False, "error": "이미 사용된 인증코드입니다."})
                if int(row.get("expires_at") or 0) < now_ms():
                    return self._json(400, {"ok": False, "error": "만료된 인증코드입니다."})
                existing = next((u for u in db.get("users", []) if u.get("minecraft_uuid") == uuid), None)
                if existing and existing.get("discord_id") != row.get("discord_id"):
                    return self._json(409, {"ok": False, "error": "이미 다른 디스코드 계정과 연동된 마인크래프트 계정입니다."})
                current = find_user(str(row.get("discord_id") or ""))
                current_uuid = str((current or {}).get("minecraft_uuid") or "").strip()
                if current_uuid and current_uuid != uuid:
                    return self._json(200, {"ok": True, "kept": True, "message": "이미 연동된 마인크래프트 계정은 그대로 유지됩니다."})
                row["used"] = 1
                ts = now_ms()
                upsert_user(
                    row["discord_id"],
                    minecraft_uuid=uuid,
                    minecraft_name=name,
                    luckperms_group=group,
                    linked_at=ts,
                )
                db.setdefault("player_cache", {})[uuid] = {
                    "minecraft_name": name,
                    "luckperms_group": group,
                    "online": 1,
                    "updated_at": ts,
                }
                unlock_achievement(row["discord_id"], "link_mc")
                save_db(db)
            return self._json(200, {"ok": True, "discordId": row["discord_id"], "message": "디스코드 인증이 완료되었습니다."})

        if path == "/api/plugin/player/status":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            players = body.get("players") if isinstance(body.get("players"), list) else []
            with lock:
                plugin_online = True
                ts = now_ms()
                today = seoul_date()
                seen_uuids: set[str] = set()
                for p in players:
                    uid = str(p.get("uuid"))
                    seen_uuids.add(uid)
                    was_online = live_players.get(uid, {}).get("online")
                    live_players[uid] = {
                        "uuid": uid,
                        "name": str(p.get("name")),
                        "online": p.get("online", True) is not False,
                    }
                    prev_cache = (db.get("player_cache") or {}).get(uid) or {}
                    cache_row = {
                        "minecraft_name": str(p.get("name")),
                        "luckperms_group": p.get("group") or prev_cache.get("luckperms_group"),
                        "online": 1 if p.get("online", True) is not False else 0,
                        "updated_at": ts,
                    }
                    linked = next((u for u in db.get("users") or [] if str(u.get("minecraft_uuid") or "") == uid), None)
                    for field, user_key, at_key in (
                        ("cash", "minecraft_cash", "minecraft_cash_at"),
                        ("gem", "minecraft_gem", "minecraft_gem_at"),
                        ("money", "minecraft_money", "minecraft_money_at"),
                    ):
                        if p.get(field) is not None:
                            amount = max(0, safe_int(p.get(field)))
                            cache_row[field] = amount
                            if linked:
                                linked[user_key] = amount
                                linked[at_key] = ts
                        elif prev_cache.get(field) is not None:
                            cache_row[field] = prev_cache.get(field)
                    db.setdefault("player_cache", {})[uid] = cache_row
                    if p.get("online", True) is not False and not was_online:
                        db.setdefault("joins", []).append({"uuid": uid, "name": str(p.get("name")), "at": ts, "date": today})
                        if len(db["joins"]) > 5000:
                            db["joins"] = db["joins"][-4000:]
                for uid, lp in list(live_players.items()):
                    if uid not in seen_uuids and lp.get("online"):
                        lp["online"] = False
                        cache = db.setdefault("player_cache", {}).get(uid, {})
                        cache["online"] = 0
                        cache["updated_at"] = ts
                save_db(db)
            return self._json(200, {"ok": True})

        if path == "/api/plugin/heartbeat":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            stats = body.get("stats") if isinstance(body.get("stats"), dict) else body
            with lock:
                plugin_online = True
                server_metrics = dict(stats)
                server_metrics["updatedAt"] = now_ms()
                if isinstance(stats.get("players"), list):
                    ts = now_ms()
                    for p in stats["players"]:
                        if not isinstance(p, dict):
                            continue
                        uid = str(p.get("uuid") or "")
                        if not uid:
                            continue
                        live_players[uid] = {
                            "uuid": uid,
                            "name": str(p.get("name") or ""),
                            "online": p.get("online", True) is not False,
                        }
            return self._json(200, {"ok": True})

        if path == "/api/plugin/console":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            lines = body.get("lines") if isinstance(body.get("lines"), list) else []
            with lock:
                plugin_online = True
                for line in lines:
                    if not isinstance(line, dict):
                        continue
                    console_logs.append(
                        {
                            "level": str(line.get("level") or "INFO"),
                            "message": str(line.get("message") or ""),
                            "at": int(line.get("at") or now_ms()),
                        }
                    )
                if len(console_logs) > 2000:
                    console_logs[:] = console_logs[-1500:]
            return self._json(200, {"ok": True, "count": len(lines)})

        if path == "/api/plugin/nickname/ticket":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            uuid = str(body.get("uuid") or "")
            name = str(body.get("name") or "")
            if not uuid or not name:
                return self._json(400, {"error": "uuid, name required"})
            code = generate_code()
            expires = now_ms() + 600000
            with lock:
                db.setdefault("nick_vouchers", []).append(
                    {
                        "id": next_id(db.get("nick_vouchers", [])),
                        "code": code,
                        "minecraft_uuid": uuid,
                        "minecraft_name": name,
                        "expires_at": expires,
                        "used": 0,
                        "created_at": now_ms(),
                    }
                )
                save_db(db)
            return self._json(200, {"code": code, "expiresAt": expires})

        if path == "/api/plugin/nickname/result":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            return self._json(200, {"ok": True})

        if path == "/api/plugin/economy/sync":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            with lock:
                plugin_online = True
                hit = apply_economy_balances(body.get("balances"))
                if hit:
                    save_db(db)
            return self._json(200, {"ok": True, "updated": hit})

        if path == "/api/plugin/stocks/trade":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            uuid = str(body.get("uuid") or "").strip()
            name = str(body.get("name") or "").strip()
            side = "buy" if str(body.get("side") or "") in ("buy", "매수") else "sell" if str(body.get("side") or "") in ("sell", "매도") else ""
            with lock:
                user = next(
                    (
                        u
                        for u in db.get("users") or []
                        if (uuid and str(u.get("minecraft_uuid") or "") == uuid)
                        or (name and str(u.get("minecraft_name") or "").lower() == name.lower())
                    ),
                    None,
                )
                if not user:
                    return self._json(404, {"error": "디스코드와 연동된 계정이 아니에요. 사이트에서 연동한 뒤 거래해 주세요."})
                trade, err = create_stock_trade(
                    str(user.get("discord_id") or ""),
                    str(user.get("minecraft_name") or name),
                    str(body.get("stock") or body.get("id") or ""),
                    side,
                    max(0, safe_int(body.get("qty"), 1)),
                )
                if err:
                    return self._json(400, {"error": err})
                save_db(db)
            return self._json(200, {"ok": True, "message": "주문을 넣었어요. 돈은 잠시 후 마크에서 처리됩니다.", "trade": trade_public(trade)})

        if path == "/api/plugin/lottery-jobs":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            job_id = safe_int(body.get("id"))
            ok = bool(body.get("ok"))
            error = str(body.get("error") or "")
            cash = safe_int(body.get("cash")) if body.get("cash") is not None else None
            with lock:
                job = finish_lottery_job(job_id, ok, error, cash)
                if not job:
                    return self._json(404, {"error": "복권 작업을 찾을 수 없습니다."})
                save_db(db)
            return self._json(200, {"ok": True, "status": job.get("status")})

        if path == "/api/plugin/stock-trades":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            trade_id = safe_int(body.get("id"))
            ok = bool(body.get("ok"))
            error = str(body.get("error") or "")
            cash = safe_int(body.get("money")) if body.get("money") is not None else (safe_int(body.get("cash")) if body.get("cash") is not None else None)
            with lock:
                trade = finish_stock_trade(trade_id, ok, error, cash)
                if not trade:
                    return self._json(404, {"error": "거래를 찾을 수 없습니다."})
                save_db(db)
            return self._json(200, {"ok": True, "status": trade.get("status")})

        if path == "/api/plugin/commands":
            if key != PLUGIN_KEY:
                return self._json(401, {"error": "Unauthorized"})
            ids = body.get("ids") if isinstance(body.get("ids"), list) else []
            if not ids:
                return self._json(400, {"error": "ids required"})
            with lock:
                ts = now_ms()
                for cid in ids:
                    for c in db.get("command_queue", []):
                        if int(c.get("id") or 0) == int(cid):
                            c["processed"] = 1
                            c["processed_at"] = ts
                save_db(db)
            return self._json(200, {"ok": True})

        return self._json(404, {"error": "not found"})

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/inbox":
            session = get_session(self)
            if not session:
                return self._json(401, {"error": "로그인이 필요합니다."})
            body = self._read_json()
            did = session["discordId"]
            with lock:
                if body.get("all"):
                    for m in db.get("inbox", []):
                        if m.get("discord_id") == did:
                            m["read"] = 1
                elif body.get("id"):
                    for m in db.get("inbox", []):
                        if int(m.get("id") or 0) == int(body["id"]) and m.get("discord_id") == did:
                            m["read"] = 1
                save_db(db)
            return self._json(200, {"ok": True})
        return self._admin_mutate("PUT")

    def do_DELETE(self) -> None:
        return self._admin_mutate("DELETE")


KST = timezone(timedelta(hours=9))

LOTTERY_DEFAULTS = {
    "price": 1000,
    "daily_limit": 10,
    "return_rate": 40,
    "first_cap_multiple": 500,
    "daily_win_cap": 100000,
    "draw_weekday": 5,
    "draw_hour": 20,
    "draw_minute": 0,
    "close_minutes": 10,
    "enabled": 1,
    "split1": 60,
    "split2": 25,
    "split3": 15,
    "won_per_cash": 10,
    "alert": "",
}


def seoul_now() -> datetime:
    return datetime.now(KST)


def lottery_settings() -> dict:
    raw = db.get("lottery_settings") if isinstance(db.get("lottery_settings"), dict) else {}
    out = dict(LOTTERY_DEFAULTS)
    out.update(raw)
    out["price"] = max(1, safe_int(out.get("price"), 1000))
    out["daily_limit"] = max(1, min(100, safe_int(out.get("daily_limit"), 10)))
    out["return_rate"] = max(0, min(100, safe_int(out.get("return_rate"), 40)))
    out["first_cap_multiple"] = max(1, safe_int(out.get("first_cap_multiple"), 500))
    out["daily_win_cap"] = max(0, safe_int(out.get("daily_win_cap"), 100000))
    out["draw_weekday"] = max(0, min(6, safe_int(out.get("draw_weekday"), 5)))
    out["draw_hour"] = max(0, min(23, safe_int(out.get("draw_hour"), 20)))
    out["draw_minute"] = max(0, min(59, safe_int(out.get("draw_minute"), 0)))
    out["close_minutes"] = max(0, min(180, safe_int(out.get("close_minutes"), 10)))
    out["enabled"] = 1 if safe_int(out.get("enabled"), 1) else 0
    out["split1"] = max(0, safe_int(out.get("split1"), 60))
    out["split2"] = max(0, safe_int(out.get("split2"), 25))
    out["split3"] = max(0, safe_int(out.get("split3"), 15))
    out["won_per_cash"] = max(1, safe_int(out.get("won_per_cash"), 10))
    out["alert"] = str(out.get("alert") or "")
    return out


def lottery_match_rank(number: str, winning: str) -> int | None:
    number = str(number or "").zfill(5)[-5:]
    winning = str(winning or "").zfill(5)[-5:]
    if len(number) != 5 or len(winning) != 5:
        return None
    if number == winning:
        return 1
    if number[:4] == winning[:4]:
        return 2
    if number[:3] == winning[:3]:
        return 3
    return None


def lottery_draw_number() -> tuple[str, str]:
    token = secrets.token_bytes(8)
    number = int.from_bytes(token[:4], "big") % 100000
    return f"{number:05d}", token.hex()


def lottery_auto_number() -> str:
    return f"{secrets.randbelow(100000):05d}"


def lottery_settle(
    sales: int,
    carry_in: int,
    price: int,
    return_rate: int,
    splits: tuple[int, int, int],
    cap_multiple: int,
    numbers: list[str],
    winning: str,
    owners: list[str] | None = None,
    daily_already: dict[str, int] | None = None,
    daily_cap: int = 0,
) -> dict:
    owners = owners or [""] * len(numbers)
    daily_already = dict(daily_already or {})
    pool = max(0, int(carry_in) + int(int(sales) * int(return_rate) / 100))
    raw = [pool * int(part) // 100 for part in splits]
    carry = pool - sum(raw)
    cap = max(0, int(price) * int(cap_multiple))
    if cap and raw[0] > cap:
        carry += raw[0] - cap
        raw[0] = cap
    ranks: list[int | None] = []
    groups: dict[int, list[int]] = {1: [], 2: [], 3: []}
    for index, number in enumerate(numbers):
        rank = lottery_match_rank(number, winning)
        ranks.append(rank)
        if rank:
            groups[rank].append(index)
    prizes = [0] * len(numbers)
    for rank, indexes in groups.items():
        pot = raw[rank - 1]
        if not indexes:
            carry += pot
            continue
        each = pot // len(indexes)
        carry += pot - each * len(indexes)
        for index in indexes:
            prizes[index] = each
    if daily_cap > 0:
        gained = dict(daily_already)
        for index, prize in enumerate(prizes):
            if prize <= 0:
                continue
            owner = owners[index]
            room = max(0, daily_cap - int(gained.get(owner, 0)))
            if prize > room:
                carry += prize - room
                prizes[index] = room
            gained[owner] = int(gained.get(owner, 0)) + prizes[index]
    return {"pool": pool, "pots": raw, "ranks": ranks, "prizes": prizes, "carry_out": carry}


def lottery_draw_at(now: datetime, settings: dict, after: datetime | None = None) -> datetime:
    base = (after or now).astimezone(KST)
    weekday = int(settings["draw_weekday"])
    days = (weekday - base.weekday()) % 7
    target = base.replace(hour=int(settings["draw_hour"]), minute=int(settings["draw_minute"]), second=0, microsecond=0) + timedelta(days=days)
    if target <= base:
        target += timedelta(days=7)
    return target


def seoul_day_start_ms(now: datetime | None = None) -> int:
    current = (now or seoul_now()).astimezone(KST)
    start = current.replace(hour=0, minute=0, second=0, microsecond=0)
    return int(start.timestamp() * 1000)


def lottery_round_public(row: dict, tickets: list[dict] | None = None) -> dict:
    settings = lottery_settings()
    won = int(settings["won_per_cash"])
    sales = safe_int(row.get("sales"))
    pool = safe_int(row.get("carry_in")) + sales * int(settings["return_rate"]) // 100
    pots = [
        pool * int(settings["split1"]) // 100,
        pool * int(settings["split2"]) // 100,
        pool * int(settings["split3"]) // 100,
    ]
    cap = int(settings["price"]) * int(settings["first_cap_multiple"])
    if cap and pots[0] > cap:
        pots[0] = cap
    winners = {1: 0, 2: 0, 3: 0}
    for ticket in tickets or []:
        if safe_int(ticket.get("round_id")) != safe_int(row.get("id")):
            continue
        rank = safe_int(ticket.get("rank"))
        if rank in winners:
            winners[rank] += 1
    return {
        "id": row.get("id"),
        "status": row.get("status") or "selling",
        "sales": sales,
        "salesWon": sales * won,
        "carryIn": safe_int(row.get("carry_in")),
        "carryOut": safe_int(row.get("carry_out")),
        "winning": row.get("winning") or "",
        "drawAt": safe_int(row.get("draw_at")),
        "closesAt": safe_int(row.get("closes_at")),
        "estimated": [{"rank": i + 1, "cash": pots[i], "won": pots[i] * won} for i in range(3)],
        "winners": winners,
        "paid": safe_int(row.get("paid")),
        "drawToken": row.get("draw_token") or "",
    }


def ensure_lottery_round() -> dict:
    settings = lottery_settings()
    rows = db.setdefault("lottery_rounds", [])
    now = seoul_now()
    now_ms_value = int(now.timestamp() * 1000)
    open_row = next((row for row in rows if row.get("status") in ("selling", "closed") and safe_int(row.get("draw_at")) > now_ms_value), None)
    if open_row:
        return open_row
    draw = lottery_draw_at(now, settings)
    close = draw - timedelta(minutes=int(settings["close_minutes"]))
    carry = 0
    drawn = [row for row in rows if row.get("status") == "drawn"]
    if drawn:
        carry = safe_int(drawn[-1].get("carry_out"))
    row = {
        "id": next_id(rows),
        "status": "selling",
        "opens_at": now_ms_value,
        "closes_at": int(close.timestamp() * 1000),
        "draw_at": int(draw.timestamp() * 1000),
        "sales": 0,
        "winning": "",
        "carry_in": carry,
        "carry_out": 0,
        "paid": 0,
        "draw_token": "",
    }
    rows.append(row)
    return row


def lottery_tickets_today(discord_id: str) -> int:
    start = seoul_day_start_ms()
    count = 0
    for ticket in db.get("lottery_tickets") or []:
        if str(ticket.get("discord_id") or "") != discord_id:
            continue
        if str(ticket.get("status") or "") == "failed":
            continue
        if safe_int(ticket.get("created_at")) >= start:
            count += 1
    return count


def lottery_log(kind: str, detail: str, discord_id: str = "") -> None:
    rows = db.setdefault("cash_transactions", [])
    rows.append({
        "id": next_id(rows),
        "kind": kind,
        "discord_id": discord_id,
        "detail": detail[:300],
        "at": now_ms(),
    })
    if len(rows) > 4000:
        del rows[:-3000]


def create_lottery_purchase(discord_id: str, minecraft_name: str, mode: str, numbers: list[str], idempotency_key: str) -> tuple[dict | None, str | None]:
    settings = lottery_settings()
    if not settings["enabled"]:
        return None, "지금은 복권 판매가 중지되어 있어요."
    key = str(idempotency_key or "").strip()[:80]
    if key:
        for job in db.get("lottery_jobs") or []:
            if str(job.get("idempotency_key") or "") == key and str(job.get("discord_id") or "") == discord_id:
                return job, None
    if mode not in ("manual", "auto"):
        return None, "수동 또는 자동만 살 수 있어요."
    cleaned: list[str] = []
    for number in numbers:
        text = str(number or "").strip()
        if not re.fullmatch(r"\d{5}", text):
            return None, "번호는 숫자 5자리여야 해요."
        cleaned.append(text)
    if not cleaned:
        return None, "번호를 입력해 주세요."
    if len(cleaned) > int(settings["daily_limit"]):
        return None, f"한 번에 {settings['daily_limit']}장까지만 살 수 있어요."
    used = lottery_tickets_today(discord_id)
    if used + len(cleaned) > int(settings["daily_limit"]):
        return None, f"오늘 구매 한도는 {settings['daily_limit']}장이에요. 남은 수량 {max(0, int(settings['daily_limit']) - used)}장."
    for job in db.get("lottery_jobs") or []:
        if str(job.get("discord_id") or "") == discord_id and str(job.get("status") or "") in ("pending", "processing") and job.get("kind") == "take":
            return None, "처리 중인 구매가 있어요. 끝난 뒤에 다시 사 주세요."
    current = ensure_lottery_round()
    now_value = now_ms()
    if now_value >= safe_int(current.get("closes_at")) or current.get("status") != "selling":
        return None, "이번 회차 판매가 마감됐어요."
    price = int(settings["price"])
    cost = price * len(cleaned)
    tickets = db.setdefault("lottery_tickets", [])
    ticket_ids = []
    for number in cleaned:
        ticket = {
            "id": next_id(tickets),
            "round_id": current["id"],
            "discord_id": discord_id,
            "minecraft_name": minecraft_name,
            "number": number,
            "mode": mode,
            "status": "pending",
            "rank": None,
            "prize": 0,
            "paid": 0,
            "created_at": now_value,
        }
        tickets.append(ticket)
        ticket_ids.append(ticket["id"])
    jobs = db.setdefault("lottery_jobs", [])
    job = {
        "id": next_id(jobs),
        "kind": "take",
        "discord_id": discord_id,
        "minecraft_name": minecraft_name,
        "amount": cost,
        "round_id": current["id"],
        "ticket_ids": ticket_ids,
        "status": "pending",
        "error": "",
        "idempotency_key": key,
        "attempts": 0,
        "created_at": now_value,
    }
    jobs.append(job)
    return job, None


def finish_lottery_job(job_id: int, ok: bool, error: str = "", cash: int | None = None) -> dict | None:
    job = next((row for row in db.get("lottery_jobs") or [] if safe_int(row.get("id")) == job_id), None)
    if not job or str(job.get("status") or "") not in ("pending", "processing"):
        return job
    tickets = {safe_int(row.get("id")): row for row in db.get("lottery_tickets") or []}
    if ok:
        job["status"] = "done"
        job["error"] = ""
        if job.get("kind") == "take":
            current = next((row for row in db.get("lottery_rounds") or [] if safe_int(row.get("id")) == safe_int(job.get("round_id"))), None)
            if current:
                current["sales"] = safe_int(current.get("sales")) + safe_int(job.get("amount"))
            for ticket_id in job.get("ticket_ids") or []:
                ticket = tickets.get(safe_int(ticket_id))
                if ticket and ticket.get("status") == "pending":
                    ticket["status"] = "confirmed"
            lottery_log("lottery_buy", f"-{job.get('amount')}캐시 복권 {len(job.get('ticket_ids') or [])}장", str(job.get("discord_id") or ""))
        else:
            for ticket_id in job.get("ticket_ids") or []:
                ticket = tickets.get(safe_int(ticket_id))
                if ticket:
                    ticket["paid"] = 1
            current = next((row for row in db.get("lottery_rounds") or [] if safe_int(row.get("id")) == safe_int(job.get("round_id"))), None)
            if current:
                current["paid"] = safe_int(current.get("paid")) + safe_int(job.get("amount"))
            lottery_log("lottery_prize", f"+{job.get('amount')}캐시 복권 당첨", str(job.get("discord_id") or ""))
    else:
        job["attempts"] = safe_int(job.get("attempts")) + 1
        job["error"] = error or "마크에서 캐시 처리에 실패했어요."
        if job.get("kind") == "give" and job["attempts"] < 5:
            job["status"] = "pending"
        else:
            job["status"] = "failed"
            if job.get("kind") == "take":
                for ticket_id in job.get("ticket_ids") or []:
                    ticket = tickets.get(safe_int(ticket_id))
                    if ticket and ticket.get("status") == "pending":
                        ticket["status"] = "failed"
    if cash is not None:
        remember_minecraft_cash(str(job.get("minecraft_name") or ""), cash)
    return job


def expire_lottery_jobs() -> None:
    now_value = now_ms()
    for job in db.get("lottery_jobs") or []:
        if str(job.get("status") or "") != "pending":
            continue
        if now_value - safe_int(job.get("created_at")) < 90000:
            continue
        finish_lottery_job(safe_int(job.get("id")), False, "마크 서버가 응답하지 않았어요. 서버가 켜져 있는지 확인해 주세요.")


def draw_lottery_round(round_id: int | None = None) -> tuple[dict | None, str | None]:
    rows = db.setdefault("lottery_rounds", [])
    current = None
    if round_id:
        current = next((row for row in rows if safe_int(row.get("id")) == round_id), None)
    else:
        now_value = now_ms()
        current = next((row for row in rows if row.get("status") in ("selling", "closed") and safe_int(row.get("draw_at")) <= now_value), None)
    if not current:
        return None, "추첨할 회차가 없어요."
    if current.get("status") == "drawn":
        return current, None
    pending = [job for job in db.get("lottery_jobs") or [] if safe_int(job.get("round_id")) == safe_int(current.get("id")) and job.get("kind") == "take" and job.get("status") in ("pending", "processing")]
    if pending and not round_id and now_ms() < safe_int(current.get("draw_at")) + 120000:
        return None, "구매 처리가 끝나기를 기다리는 중이에요."
    for job in pending:
        finish_lottery_job(safe_int(job.get("id")), False, "추첨이 시작되어 이 구매는 취소됐어요.")
    settings = lottery_settings()
    winning, token = lottery_draw_number()
    tickets = [row for row in db.get("lottery_tickets") or [] if safe_int(row.get("round_id")) == safe_int(current.get("id")) and row.get("status") == "confirmed"]
    start = seoul_day_start_ms()
    already: dict[str, int] = {}
    for row in db.get("lottery_tickets") or []:
        if row.get("status") != "drawn" or safe_int(row.get("created_at")) < start:
            continue
        owner = str(row.get("discord_id") or "")
        already[owner] = already.get(owner, 0) + safe_int(row.get("prize"))
    settled = lottery_settle(
        safe_int(current.get("sales")),
        safe_int(current.get("carry_in")),
        int(settings["price"]),
        int(settings["return_rate"]),
        (int(settings["split1"]), int(settings["split2"]), int(settings["split3"])),
        int(settings["first_cap_multiple"]),
        [str(row.get("number") or "") for row in tickets],
        winning,
        [str(row.get("discord_id") or "") for row in tickets],
        already,
        int(settings["daily_win_cap"]),
    )
    payouts: dict[str, dict] = {}
    for index, ticket in enumerate(tickets):
        rank = settled["ranks"][index]
        prize = settled["prizes"][index]
        ticket["status"] = "drawn"
        ticket["rank"] = rank
        ticket["prize"] = prize
        if prize > 0:
            owner = str(ticket.get("discord_id") or "")
            bucket = payouts.setdefault(owner, {"name": ticket.get("minecraft_name") or "", "amount": 0, "ids": []})
            bucket["amount"] += prize
            bucket["ids"].append(ticket["id"])
    jobs = db.setdefault("lottery_jobs", [])
    for owner, bucket in payouts.items():
        jobs.append({
            "id": next_id(jobs),
            "kind": "give",
            "discord_id": owner,
            "minecraft_name": bucket["name"],
            "amount": bucket["amount"],
            "round_id": current["id"],
            "ticket_ids": bucket["ids"],
            "status": "pending",
            "error": "",
            "idempotency_key": f"prize-{current['id']}-{owner}",
            "attempts": 0,
            "created_at": now_ms(),
        })
    current["status"] = "drawn"
    current["winning"] = winning
    current["draw_token"] = token
    current["carry_out"] = settled["carry_out"]
    sales = safe_int(current.get("sales"))
    paid_assigned = sum(settled["prizes"])
    rate = (paid_assigned / sales * 100) if sales else 0
    if sales and rate > int(settings["return_rate"]):
        db.setdefault("lottery_settings", {})["alert"] = f"{current['id']}회차 환원율 {rate:.1f}%가 설정 {settings['return_rate']}%를 넘었어요."
    else:
        db.setdefault("lottery_settings", {})["alert"] = ""
    lottery_log("lottery_draw", f"{current['id']}회 당첨번호 {winning} 지급예정 {paid_assigned}")
    ensure_lottery_round()
    return current, None


def lottery_housekeeping() -> None:
    with lock:
        expire_lottery_jobs()
        ensure_lottery_round()
        now_value = now_ms()
        for row in db.get("lottery_rounds") or []:
            if row.get("status") == "selling" and now_value >= safe_int(row.get("closes_at")):
                row["status"] = "closed"
        due = next((row for row in db.get("lottery_rounds") or [] if row.get("status") in ("selling", "closed") and safe_int(row.get("draw_at")) <= now_value), None)
        if due:
            draw_lottery_round()
        save_db(db)


def lottery_ticket_public(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "roundId": row.get("round_id"),
        "number": row.get("number") or "",
        "mode": row.get("mode") or "",
        "status": row.get("status") or "",
        "rank": row.get("rank"),
        "prize": safe_int(row.get("prize")),
        "paid": 1 if row.get("paid") else 0,
        "at": safe_int(row.get("created_at")),
    }


def lottery_week_stats() -> dict:
    start = int((seoul_now() - timedelta(days=7)).timestamp() * 1000)
    sales = 0
    paid = 0
    for row in db.get("lottery_rounds") or []:
        if row.get("status") == "drawn" and safe_int(row.get("draw_at")) >= start:
            sales += safe_int(row.get("sales"))
            paid += safe_int(row.get("paid"))
        elif row.get("status") in ("selling", "closed"):
            sales += safe_int(row.get("sales"))
    return {
        "sales": sales,
        "paid": paid,
        "burned": max(0, sales - paid),
        "rate": round(paid / sales * 100, 2) if sales else 0,
    }


def lottery_settings_public() -> dict:
    settings = lottery_settings()
    return {
        "price": settings["price"],
        "dailyLimit": settings["daily_limit"],
        "returnRate": settings["return_rate"],
        "firstCapMultiple": settings["first_cap_multiple"],
        "dailyWinCap": settings["daily_win_cap"],
        "closeMinutes": settings["close_minutes"],
        "enabled": settings["enabled"],
        "split1": settings["split1"],
        "split2": settings["split2"],
        "split3": settings["split3"],
        "wonPerCash": settings["won_per_cash"],
        "alert": settings["alert"],
        "drawWeekday": settings["draw_weekday"],
        "drawHour": settings["draw_hour"],
        "drawMinute": settings["draw_minute"],
    }


def lottery_loop() -> None:
    while True:
        time.sleep(20)
        try:
            lottery_housekeeping()
        except Exception:
            continue


def main() -> None:
    import sys
    sys.stdout.reconfigure(encoding="utf-8")
    ensure_runtime_defaults()
    save_db(db)
    threading.Thread(target=stock_ticker, name="stock-ticker", daemon=True).start()
    threading.Thread(target=lottery_loop, name="lottery", daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.request_queue_size = 128
    # 느린 클라/프록시에서도 연결이 너무 빨리 끊기지 않도록
    server.timeout = 120
    print("========================================", flush=True)
    print(f" {SITE} online", flush=True)
    print(f" python {Path(__file__).name}", flush=True)
    print(f" http://localhost:{PORT}", flush=True)
    print(f" discord oauth: {'on' if discord_configured() else 'off'}", flush=True)
    print(f" redirect: {DISCORD_REDIRECT_URI}", flush=True)
    print(" rate-limit: OFF (adminAttemptsUnlimited)", flush=True)
    print("----------------------------------------", flush=True)
    print(" 데스크톱 관리키 (앱에 그대로 입력)", flush=True)
    print(f" {DESKTOP_KEY}", flush=True)
    print("----------------------------------------", flush=True)
    if WEAK_ADMIN:
        sug = secrets.token_urlsafe(32)
        print(" !! ADMIN_API_KEY 가 너무 약합니다. .env 에 아래로 바꾸세요:", flush=True)
        print(f"    ADMIN_API_KEY={sug}", flush=True)
    print(f" desktop connect: GET /api/desktop/connect  (header x-admin-key)", flush=True)
    print(f" plugin API key: …{(PLUGIN_KEY[-4:] if len(PLUGIN_KEY) >= 4 else '????')}", flush=True)
    print(f" plugin ws: /ws/plugin", flush=True)
    print("========================================", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
