#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OSINTZ v2.1 - multi-source OSINT console
Modules: email, IP, phone, TikTok region, Discord ID, crypto, usernames.

Install : pip install requests dnspython phonenumbers
Run     : python osintz.py
CLI     : python osintz.py -m tiktok -t @charlidamelio
          python osintz.py -m phone -t "+1 415 555 2671" --save
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote

try:
    import requests
except ImportError:
    sys.exit("[!] missing dependency -> pip install requests")

try:
    import dns.resolver
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

try:
    import phonenumbers
    from phonenumbers import carrier as pn_carrier
    from phonenumbers import geocoder as pn_geocoder
    from phonenumbers import timezone as pn_tz
    HAVE_PN = True
except ImportError:
    HAVE_PN = False


# ═══════════════════════════════════════════════════════════════ 1. THEME / UI
RESET = "\033[0m"
BOLD = "\033[1m"
_ANSI = re.compile(r"\033\[[0-9;]*m")

TRUECOLOR = not (os.name == "nt" and not os.getenv("WT_SESSION"))


def _esc(r, g, b):
    if TRUECOLOR:
        return f"\033[38;2;{r};{g};{b}m"
    idx = 16 + 36 * round(r / 255 * 5) + 6 * round(g / 255 * 5) + round(b / 255 * 5)
    return f"\033[38;5;{idx}m"


def _hex(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def _lerp(c1, c2, t):
    return tuple(round(a + (b - a) * t) for a, b in zip(c1, c2))


class T:
    """palette - deep red theme"""
    a1 = _esc(220, 38, 38)       # red
    a2 = _esc(185, 28, 28)       # dark red
    a3 = _esc(153, 27, 27)       # deeper red
    a4 = _esc(127, 29, 29)       # deepest red
    good = _esc(74, 222, 128)    # kept green for positive status
    warn = _esc(251, 191, 36)    # kept amber for warnings
    bad = _esc(248, 113, 113)    # bright red for errors
    text = _esc(229, 231, 235)
    white = _esc(255, 255, 255)
    mute = _esc(196, 181, 181)   # warm muted grey
    dim = _esc(87, 60, 60)       # dark warm grey
    r = RESET
    b = BOLD


GRAD = ["#f87171", "#dc2626", "#991b1b", "#7f1d1d"]


def grad(text, stops=GRAD, bold=False):
    """per-character horizontal gradient"""
    if not text:
        return ""
    if not TRUECOLOR:
        return _esc(*_hex(stops[0])) + (BOLD if bold else "") + text + RESET
    pts = [_hex(s) for s in stops]
    n = max(1, len(text) - 1)
    out = [BOLD if bold else ""]
    for i, ch in enumerate(text):
        t = i / n
        seg = min(int(t * (len(pts) - 1)), len(pts) - 2)
        lt = t * (len(pts) - 1) - seg
        out.append(_esc(*_lerp(pts[seg], pts[seg + 1], lt)) + ch)
    out.append(RESET)
    return "".join(out)


def vlen(s):
    return len(_ANSI.sub("", s))


def wipe():
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def rule(char="─", width=74, color=None, stops=GRAD):
    print("  " + grad(char * width, stops) if color is None else f"  {color}{char * width}{RESET}")


def frame(title, rows, width=78, color=None):
    """rounded panel with titled top border"""
    color = color or T.a2
    top = (f"{color}╭─ {RESET}{grad(title, GRAD, bold=True)} "
           f"{color}{'─' * max(2, width - 5 - vlen(title))}╮{RESET}")
    print(top)
    for row in rows:
        pad = width - 3 - vlen(row)
        print(f"{color}│{RESET} {row}{' ' * max(0, pad)}{color}│{RESET}")
    print(f"{color}╰{'─' * (width - 2)}╯{RESET}")


def section(title, glyph="◈"):
    print(f"\n  {grad(glyph + ' ' + title.upper(), GRAD, bold=True)} "
          f"{T.dim}{'─' * max(2, 66 - len(title))}{RESET}")


def kv(label, value, pad=22, dot=True):
    dots = f"{T.dim}{'.' * max(2, pad - len(str(label)) - 1)}{RESET}" if dot else ""
    print(f"   {T.mute}{label}{RESET} {dots} {value}")


def ok(msg):   print(f"   {T.good}✔{RESET} {T.text}{msg}{RESET}")
def warn(msg): print(f"   {T.warn}!{RESET} {T.text}{msg}{RESET}")
def err(msg):  print(f"   {T.bad}✖{RESET} {T.bad}{msg}{RESET}")
def note(msg): print(f"   {T.dim}·{RESET} {T.mute}{msg}{RESET}")
def hit(msg):  print(f"   {T.good}✔{RESET} {msg}")


def ask(label="input"):
    try:
        return input(f"  {grad('❯', GRAD, bold=True)} {T.mute}{label}{RESET} "
                     f"{T.dim}›{RESET} ").strip()
    except EOFError:
        return ""


def pause():
    try:
        input(f"\n   {T.dim}↵ enter to return to the menu{RESET}")
    except EOFError:
        pass


def bar(done, total, width=30):
    filled = int(width * done / max(1, total))
    return (f"{T.a1}{'█' * filled}{T.dim}{'░' * (width - filled)}{RESET} "
            f"{T.text}{done}/{total}{RESET}")


class Spin:
    """single-line spinner for blocking calls"""
    FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, msg="querying sources"):
        self.msg = msg
        self._stop = threading.Event()

    def __enter__(self):
        if not sys.stdout.isatty():
            return self

        def run():
            i = 0
            while not self._stop.is_set():
                sys.stdout.write(f"\r   {T.a1}{self.FRAMES[i % 10]}{RESET} "
                                 f"{T.mute}{self.msg}{RESET}\033[K")
                sys.stdout.flush()
                i += 1
                time.sleep(0.08)
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

        self._t = threading.Thread(target=run, daemon=True)
        self._t.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if sys.stdout.isatty():
            self._t.join(timeout=0.6)
        return False


def banner():
    art = [
        " ██████╗ ███████╗██╗███╗   ██╗████████╗███████╗",
        "██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝╚══███╔╝",
        "██║   ██║███████╗██║██╔██╗ ██║   ██║     ███╔╝ ",
        "██║   ██║╚════██║██║██║╚██╗██║   ██║    ███╔╝  ",
        "╚██████╔╝███████║██║██║ ╚████║   ██║   ███████╗",
        " ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝",
    ]
    print()
    pts = [_hex(s) for s in GRAD]
    for i, line in enumerate(art):
        t = i / (len(art) - 1)
        seg = min(int(t * (len(pts) - 1)), len(pts) - 2)
        col = _esc(*_lerp(pts[seg], pts[seg + 1], t * (len(pts) - 1) - seg))
        print(f"  {col}{line}{RESET}")
    print()
    print(f"  {T.dim}├{RESET} {grad('MULTI-SOURCE INTELLIGENCE CONSOLE', GRAD, bold=True)} "
          f"{T.dim}v2.1{RESET}")
    print(f"  {T.dim}├{RESET} {T.mute}email · ip · phone · tiktok · discord · crypto · "
          f"usernames{RESET}")
    print(f"  {T.dim}├{RESET} {T.mute}made by {RESET}"
          f"{grad('zyx', ['#f87171', '#991b1b'], bold=True)}")
    print(f"  {T.dim}╰{RESET} {T.dim}{datetime.now().strftime('%A %d %B %Y · %H:%M')}{RESET}")
    rule()


# ═══════════════════════════════════════════════════════════════ 2. CORE
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

S = requests.Session()
S.headers.update({"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})

RESULTS_DIR = "osintz_results"
CFG = {
    "autosave": False,
    "hibp_key": os.getenv("HIBP_API_KEY", "").strip(),
    "discord_token": os.getenv("DISCORD_TOKEN", "").strip(),
    "region": os.getenv("DEFAULT_REGION", "US").strip().upper(),
    "numverify": os.getenv("NUMVERIFY_KEY", "").strip(),
}


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json(url, **kw):
    kw.setdefault("timeout", 12)
    try:
        r = S.get(url, **kw)
    except requests.RequestException as e:
        return None, e.__class__.__name__
    if r.status_code != 200:
        return None, f"HTTP {r.status_code}"
    try:
        return r.json(), None
    except ValueError:
        return None, "invalid JSON"


def maybe_save(res):
    if not CFG["autosave"]:
        return
    os.makedirs(RESULTS_DIR, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(res.get("target")))[:40]
    path = os.path.join(RESULTS_DIR, f"{res['module']}_{slug}_{int(time.time())}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2, ensure_ascii=False, default=str)
    note(f"result saved → {path}")


# ISO-3166 alpha-2 -> country name (for flags + readable regions)
_ISO_RAW = (
    "AD:Andorra,AE:United Arab Emirates,AF:Afghanistan,AG:Antigua and Barbuda,"
    "AI:Anguilla,AL:Albania,AM:Armenia,AO:Angola,AQ:Antarctica,AR:Argentina,"
    "AS:American Samoa,AT:Austria,AU:Australia,AW:Aruba,AX:Åland Islands,"
    "AZ:Azerbaijan,BA:Bosnia and Herzegovina,BB:Barbados,BD:Bangladesh,BE:Belgium,"
    "BF:Burkina Faso,BG:Bulgaria,BH:Bahrain,BI:Burundi,BJ:Benin,BL:Saint Barthélemy,"
    "BM:Bermuda,BN:Brunei,BO:Bolivia,BQ:Caribbean Netherlands,BR:Brazil,BS:Bahamas,"
    "BT:Bhutan,BW:Botswana,BY:Belarus,BZ:Belize,CA:Canada,CD:DR Congo,"
    "CF:Central African Republic,CG:Congo,CH:Switzerland,CI:Côte d'Ivoire,"
    "CK:Cook Islands,CL:Chile,CM:Cameroon,CN:China,CO:Colombia,CR:Costa Rica,CU:Cuba,"
    "CV:Cape Verde,CW:Curaçao,CY:Cyprus,CZ:Czechia,DE:Germany,DJ:Djibouti,"
    "DK:Denmark,DM:Dominica,DO:Dominican Republic,DZ:Algeria,EC:Ecuador,EE:Estonia,"
    "EG:Egypt,EH:Western Sahara,ER:Eritrea,ES:Spain,ET:Ethiopia,FI:Finland,FJ:Fiji,"
    "FK:Falkland Islands,FM:Micronesia,FO:Faroe Islands,FR:France,GA:Gabon,"
    "GB:United Kingdom,GD:Grenada,GE:Georgia,GF:French Guiana,GG:Guernsey,GH:Ghana,"
    "GI:Gibraltar,GL:Greenland,GM:Gambia,GN:Guinea,GP:Guadeloupe,"
    "GQ:Equatorial Guinea,GR:Greece,GT:Guatemala,GU:Guam,GW:Guinea-Bissau,GY:Guyana,"
    "HK:Hong Kong,HN:Honduras,HR:Croatia,HT:Haiti,HU:Hungary,ID:Indonesia,IE:Ireland,"
    "IL:Israel,IM:Isle of Man,IN:India,IQ:Iraq,IR:Iran,IS:Iceland,IT:Italy,JE:Jersey,"
    "JM:Jamaica,JO:Jordan,JP:Japan,KE:Kenya,KG:Kyrgyzstan,KH:Cambodia,KI:Kiribati,"
    "KM:Comoros,KN:Saint Kitts and Nevis,KP:North Korea,KR:South Korea,KW:Kuwait,"
    "KY:Cayman Islands,KZ:Kazakhstan,LA:Laos,LB:Lebanon,LC:Saint Lucia,"
    "LI:Liechtenstein,LK:Sri Lanka,LR:Liberia,LS:Lesotho,LT:Lithuania,LU:Luxembourg,"
    "LV:Latvia,LY:Libya,MA:Morocco,MC:Monaco,MD:Moldova,ME:Montenegro,"
    "MF:Saint Martin,MG:Madagascar,MH:Marshall Islands,MK:North Macedonia,ML:Mali,"
    "MM:Myanmar,MN:Mongolia,MO:Macao,MP:Northern Mariana Islands,MQ:Martinique,"
    "MR:Mauritania,MS:Montserrat,MT:Malta,MU:Mauritius,MV:Maldives,MW:Malawi,"
    "MX:Mexico,MY:Malaysia,MZ:Mozambique,NA:Namibia,NC:New Caledonia,NE:Niger,"
    "NG:Nigeria,NI:Nicaragua,NL:Netherlands,NO:Norway,NP:Nepal,NR:Nauru,NZ:New Zealand,"
    "OM:Oman,PA:Panama,PE:Peru,PF:French Polynesia,PG:Papua New Guinea,PH:Philippines,"
    "PK:Pakistan,PL:Poland,PR:Puerto Rico,PS:Palestine,PT:Portugal,PW:Palau,"
    "PY:Paraguay,QA:Qatar,RE:Réunion,RO:Romania,RS:Serbia,RU:Russia,RW:Rwanda,"
    "SA:Saudi Arabia,SB:Solomon Islands,SC:Seychelles,SD:Sudan,SE:Sweden,"
    "SG:Singapore,SI:Slovenia,SK:Slovakia,SL:Sierra Leone,SM:San Marino,SN:Senegal,"
    "SO:Somalia,SR:Suriname,SS:South Sudan,ST:São Tomé and Príncipe,SV:El Salvador,"
    "SX:Sint Maarten,SY:Syria,SZ:Eswatini,TC:Turks and Caicos,TD:Chad,TG:Togo,"
    "TH:Thailand,TJ:Tajikistan,TL:Timor-Leste,TM:Turkmenistan,TN:Tunisia,TO:Tonga,"
    "TR:Türkiye,TT:Trinidad and Tobago,TV:Tuvalu,TW:Taiwan,TZ:Tanzania,UA:Ukraine,"
    "UG:Uganda,US:United States,UY:Uruguay,UZ:Uzbekistan,VA:Vatican City,"
    "VC:Saint Vincent and the Grenadines,VE:Venezuela,VG:British Virgin Islands,"
    "VI:U.S. Virgin Islands,VN:Vietnam,VU:Vanuatu,WS:Samoa,YE:Yemen,ZA:South Africa,"
    "ZM:Zambia,ZW:Zimbabwe"
)
ISO = dict(p.split(":", 1) for p in _ISO_RAW.split(",") if ":" in p)


def flag(cc):
    cc = (cc or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc)


def country(cc):
    if not cc:
        return "unknown"
    cc = cc.upper()
    return f"{cc} {flag(cc)} {ISO.get(cc, 'unrecognised code')}"


def begin(title, target):
    print()
    frame("TARGET", [
        f"{T.mute}query{RESET}   {T.white}{BOLD}{str(target)[:58]}{RESET}",
        f"{T.mute}module{RESET}  {T.a1}{title}{RESET}",
        f"{T.mute}started{RESET} {T.text}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        f"{RESET}",
    ], color=T.a3)


# ═══════════════════════════════════════════════════════════════ 3. EMAIL OSINT
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "temp-mail.org",
    "tempmail.com", "throwawaymail.com", "yopmail.com", "sharklasers.com",
    "trashmail.com", "getnada.com", "dispostable.com", "maildrop.cc",
    "fakeinbox.com", "spam4.me", "grr.la", "mailnesia.com", "tempr.email",
    "discard.email", "emailondeck.com", "moakt.com",
}


def _dns(domain, rtype):
    if not HAVE_DNS:
        return None
    try:
        return [a.to_text().strip('"')
                for a in dns.resolver.resolve(domain, rtype, lifetime=6)]
    except Exception:
        return None


def _vcard_fn(entity):
    v = entity.get("vcardArray")
    if not v or len(v) < 2:
        return None
    for item in v[1]:
        if item and item[0] == "fn":
            return item[3]
    return None


def _rdap(domain):
    data, _ = _json(f"https://rdap.org/domain/{quote(domain)}", timeout=15)
    if not data:
        return None
    out = {}
    for ev in data.get("events", []):
        out[ev.get("eventAction")] = ev.get("eventDate")
    for ent in data.get("entities", []):
        if "registrar" in ent.get("roles", []):
            out["registrar"] = _vcard_fn(ent)
            break
    return out


def _gravatar(md5):
    data, _ = _json(f"https://gravatar.com/{md5}.json")
    if data and data.get("entry"):
        return data["entry"][0]
    try:
        if requests.get(f"https://www.gravatar.com/avatar/{md5}?d=404",
                        headers={"User-Agent": UA}, timeout=10).status_code == 200:
            return {"avatar_only": True}
    except requests.RequestException:
        pass
    return None


def email_osint(target: str) -> dict:
    res = {"module": "email", "target": target, "ts": now_iso(), "data": {}}
    begin("EMAIL OSINT", target)
    if not EMAIL_RE.match(target):
        err("invalid syntax - expected user@domain.tld")
        return res

    local, domain = target.rsplit("@", 1)
    domain = domain.lower()
    d = res["data"]
    d.update(local_part=local, domain=domain)

    section("identity")
    kv("email", f"{T.white}{target}{RESET}")
    kv("syntax", f"{T.good}valid{RESET}")
    kv("local part", local)
    kv("domain", domain)
    kv("length", f"{len(target)} chars")

    section("domain records", "◉")
    if HAVE_DNS:
        mx = _dns(domain, "MX")
        d["mx"] = mx
        kv("MX", ", ".join(mx[:4]) if mx else f"{T.warn}none{RESET}")
        a_rec = _dns(domain, "A")
        kv("A", ", ".join(a_rec[:3]) if a_rec else "none")
        ns = _dns(domain, "NS")
        kv("NS", ", ".join(ns[:3]) if ns else "none")
        txt = _dns(domain, "TXT") or []
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        kv("SPF", spf[0][:56] if spf else f"{T.warn}missing{RESET}")
        dmarc = _dns("_dmarc." + domain, "TXT") or []
        kv("DMARC", dmarc[0][:56] if dmarc else f"{T.warn}missing{RESET}")
    else:
        warn("dnspython missing → pip install dnspython")
        try:
            kv("A", socket.gethostbyname(domain))
        except OSError:
            kv("A", f"{T.bad}unresolved{RESET}")

    section("reputation", "◉")
    kv("disposable", f"{T.bad}yes{RESET}" if domain in DISPOSABLE
       else f"{T.good}no{RESET}")
    with Spin("querying RDAP registry"):
        reg = _rdap(domain)
    if reg:
        kv("registrar", str(reg.get("registrar") or "n/a")[:44])
        kv("registered", str(reg.get("registration") or "n/a")[:24])
        kv("expires", str(reg.get("expiration") or "n/a")[:24])
    else:
        kv("rdap", f"{T.dim}no data{RESET}")

    section("identity footprint")
    md5 = hashlib.md5(target.strip().lower().encode()).hexdigest()
    kv("gravatar hash", md5)
    with Spin("checking gravatar"):
        g = _gravatar(md5)
    if g and g.get("avatar_only"):
        ok("gravatar avatar exists (no public profile)")
    elif g:
        d["gravatar"] = {k: g.get(k) for k in
                         ("displayName", "profileUrl", "aboutMe", "currentLocation")}
        ok(f"gravatar profile · {g.get('displayName') or 'unnamed'}")
        for k in ("aboutMe", "currentLocation", "profileUrl"):
            if g.get(k):
                kv(k, str(g[k])[:56])
        for acc in (g.get("accounts") or [])[:8]:
            kv("linked", f"{acc.get('domain')} → {acc.get('username')} "
                         f"{T.good + '(verified)' + RESET if acc.get('verified') else ''}")
        for url in (g.get("urls") or [])[:5]:
            kv("url", str(url.get("value"))[:56])
    else:
        note("no gravatar profile")

    er, er_err = _json(f"https://emailrep.io/{quote(target)}",
                       headers={"Accept": "application/json"})
    if er:
        rep = er.get("reputation")
        col = T.good if rep == "high" else (T.warn if rep == "medium" else T.bad)
        kv("emailrep", f"{col}{rep}{RESET} · suspicious={er.get('suspicious')}")
        kv("references", er.get("references"))
        det = er.get("details") or {}
        flags = [k for k in ("profiles", "disposable", "spam", "free_provider",
                             "deliverable", "blacklisted", "new_domain")
                 if det.get(k)]
        kv("flags", ", ".join(flags) if flags else "none")
    else:
        note(f"emailrep: {er_err or 'no data'}")

    section("breach exposure", "◉")
    if not CFG["hibp_key"]:
        note("set a HIBP key in [8] Settings for live breach data")
    else:
        with Spin("querying haveibeenpwned"):
            data, e = _json(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(target)}"
                f"?truncateResponse=false",
                headers={"hibp-api-key": CFG["hibp_key"], "user-agent": UA}, timeout=20)
        if e == "HTTP 404":
            ok(f"{T.good}not present in any HIBP breach{RESET}")
        elif data:
            d["breaches"] = [b.get("Name") for b in data]
            hit(f"{T.bad}{len(data)} breach(es){RESET}")
            for b in data[:12]:
                kv(str(b.get("Name"))[:22],
                   f"{b.get('BreachDate')} · {b.get('PwnCount', 0):,} accounts")
        else:
            warn(f"hibp: {e}")

    section("pivots")
    q = quote(target, safe="")
    kv("google", f"https://www.google.com/search?q=%22{q}%22")
    kv("linkedin", f"https://www.linkedin.com/search/results/all/?keywords={q}")
    kv("hunter", f"https://hunter.io/email-verifier/{target}")
    kv("dehashed", f"https://dehashed.com/search?query=%22{q}%22")
    return res


# ═══════════════════════════════════════════════════════════════ 4. IP TRACKER
IP_FIELDS = ("status,message,continent,country,countryCode,region,regionName,city,"
             "district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,"
             "reverse,mobile,proxy,hosting,query")


def ip_osint(target: str) -> dict:
    res = {"module": "ip", "target": target, "ts": now_iso(), "data": {}}
    begin("IP TRACKER", target)
    d = res["data"]

    t = target.strip().strip("[]")
    try:
        ip = str(ipaddress.ip_address(t))
    except ValueError:
        try:
            ip = socket.gethostbyname(t)
            ok(f"resolved {t} → {ip}")
        except OSError:
            err("not an IP and the hostname does not resolve")
            return res

    addr = ipaddress.ip_address(ip)
    d.update(ip=ip, version=addr.version)

    section("address")
    kv("ip", f"{T.white}{BOLD}{ip}{RESET}")
    kv("version", f"IPv{addr.version}")
    kv("scope", "private / reserved"
       if (addr.is_private or addr.is_reserved or addr.is_loopback) else "public")
    try:
        kv("reverse dns", socket.gethostbyaddr(ip)[0])
    except OSError:
        kv("reverse dns", f"{T.dim}none{RESET}")

    section("geolocation", "◉")
    with Spin("querying geolocation"):
        data, e = _json(f"http://ip-api.com/json/{ip}?fields={IP_FIELDS}")
    if not data or data.get("status") != "success":
        warn(f"ip-api: {(data or {}).get('message') or e}")
    else:
        for k in ("country", "countryCode", "regionName", "city", "zip", "lat",
                  "lon", "isp", "org", "as", "asname", "timezone", "currency",
                  "reverse", "mobile", "proxy", "hosting"):
            d[k] = data.get(k)
        kv("country", country(data.get("countryCode")))
        kv("region", f"{data.get('regionName')} / {data.get('city')}")
        kv("postal", data.get("zip") or "n/a")
        kv("coordinates", f"{data.get('lat')}, {data.get('lon')}")
        kv("timezone", f"{data.get('timezone')} · {data.get('currency')}")
        kv("map", f"{T.a1}https://www.google.com/maps?q="
                  f"{data.get('lat')},{data.get('lon')}{RESET}")

        section("network", "◉")
        kv("isp", data.get("isp"))
        kv("org", data.get("org"))
        kv("asn", f"{data.get('as')}  {data.get('asname') or ''}")
        kv("ptr", data.get("reverse") or "none")

        section("anonymity signals", "◉")

        def yn(v, bad=True):
            col = (T.bad if v else T.good) if bad else (T.a1 if v else T.good)
            return f"{col}{'yes' if v else 'no'}{RESET}"

        kv("proxy / vpn", yn(data.get("proxy")))
        kv("hosting / dc", yn(data.get("hosting")))
        kv("mobile", yn(data.get("mobile"), bad=False))
        if data.get("proxy") or data.get("hosting"):
            warn("server infrastructure detected - geo is approximate")

    section("pivots")
    kv("shodan", f"https://www.shodan.io/host/{ip}")
    kv("censys", f"https://search.censys.io/hosts/{ip}")
    kv("abuseipdb", f"https://www.abuseipdb.com/check/{ip}")
    kv("virustotal", f"https://www.virustotal.com/gui/ip-address/{ip}")
    kv("bgp", f"https://bgp.he.net/ip/{ip}")
    return res


# ═════════════════════════════════════════════════════════════ 5. PHONE INTEL
PHONE_TYPES = {
    0: "PREMIUM_RATE", 1: "TOLL_FREE", 2: "MOBILE", 3: "FIXED_LINE",
    4: "FIXED_LINE_OR_MOBILE", 5: "SHARED_COST", 6: "VOIP",
    7: "PERSONAL_NUMBER", 8: "PAGER", 9: "UAN", 10: "VOICEMAIL", 27: "UNKNOWN",
}

DIAL = {
    "1": "US", "7": "RU", "20": "EG", "27": "ZA", "30": "GR", "31": "NL",
    "32": "BE", "33": "FR", "34": "ES", "36": "HU", "39": "IT", "40": "RO",
    "41": "CH", "43": "AT", "44": "GB", "45": "DK", "46": "SE", "47": "NO",
    "48": "PL", "49": "DE", "51": "PE", "52": "MX", "54": "AR", "55": "BR",
    "56": "CL", "57": "CO", "58": "VE", "60": "MY", "61": "AU", "62": "ID",
    "63": "PH", "64": "NZ", "65": "SG", "66": "TH", "81": "JP", "82": "KR",
    "84": "VN", "86": "CN", "90": "TR", "91": "IN", "92": "PK", "93": "AF",
    "94": "LK", "95": "MM", "98": "IR", "212": "MA", "213": "DZ", "216": "TN",
    "218": "LY", "234": "NG", "254": "KE", "255": "TZ", "256": "UG",
    "351": "PT", "353": "IE", "358": "FI", "370": "LT", "371": "LV",
    "372": "EE", "380": "UA", "381": "RS", "385": "HR", "420": "CZ",
    "421": "SK", "961": "LB", "962": "JO", "966": "SA", "971": "AE",
    "972": "IL", "973": "BH", "974": "QA", "977": "NP", "880": "BD",
    "886": "TW",
}


def _phone_guess(e164):
    """fallback country guess when phonenumbers is not installed"""
    digits = e164.lstrip("+")
    for ln in (3, 2, 1):
        if digits[:ln] in DIAL:
            return DIAL[digits[:ln]]
    return None


def phone_osint(target: str) -> dict:
    res = {"module": "phone", "target": target, "ts": now_iso(), "data": {}}
    begin("PHONE INTEL", target)
    d = res["data"]

    raw = target.strip()
    region = CFG.get("region") or "US"
    m = re.match(r"^([A-Za-z]{2})\s*[: ]\s*(.+)$", raw)
    if m and m.group(1).upper() in ISO:
        region, raw = m.group(1).upper(), m.group(2)

    digits = re.sub(r"[^\d+]", "", raw)
    if digits.startswith("00"):
        digits = "+" + digits[2:]

    section("input")
    kv("raw", target)
    kv("normalised", digits)
    kv("default region", country(region))

    if not HAVE_PN:
        warn("phonenumbers not installed → pip install phonenumbers (full data)")
        if not digits.startswith("+"):
            err("prefix the number with its country code, e.g. +44...")
            return res
        cc = _phone_guess(digits)
        section("best effort")
        kv("e164", digits)
        kv("country", country(cc))
        kv("note", f"{T.dim}install phonenumbers for carrier / line type{RESET}")
        d.update(e164=digits, country=cc)
        _phone_pivots(digits)
        return res

    try:
        num = phonenumbers.parse(digits, None if digits.startswith("+") else region)
    except phonenumbers.NumberParseException as e:
        err(f"parse failed: {e}")
        return res

    valid = phonenumbers.is_valid_number(num)
    possible = phonenumbers.is_possible_number(num)
    ptype = PHONE_TYPES.get(phonenumbers.number_type(num), "UNKNOWN")
    cc = phonenumbers.region_code_for_number(num)
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)

    d.update(e164=e164, country=cc, type=ptype, valid=valid)
    res["data"] = d

    section("validation", "◉")
    kv("valid", f"{T.good}yes{RESET}" if valid
       else f"{T.bad}no{RESET} {T.dim}(possible={possible}){RESET}")
    kv("country code", f"+{num.country_code}")
    kv("national number", num.national_number)

    section("country / region", "◉")
    kv("region", f"{T.white}{BOLD}{country(cc)}{RESET}")
    geo = pn_geocoder.description_for_number(num, "en")
    if geo:
        kv("area", geo)
    zones = pn_tz.time_zones_for_number(num)
    kv("timezone", ", ".join(zones) if zones else "n/a")

    section("carrier / line", "◉")
    car = pn_carrier.name_for_number(num, "en")
    kv("carrier", car if car else f"{T.dim}not in bundled data (ported number?){RESET}")
    col = {"MOBILE": T.a1, "FIXED_LINE": T.text, "VOIP": T.warn,
           "TOLL_FREE": T.a2}.get(ptype, T.mute)
    kv("line type", f"{col}{ptype}{RESET}")
    if ptype == "VOIP":
        warn("voip range - often used for virtual / burner numbers")

    live = None
    if CFG["numverify"]:
        with Spin("querying numverify"):
            live, _ = _json(f"http://apilayer.net/api/validate?access_key="
                            f"{CFG['numverify']}&number={e164}&format=1")
        if live and live.get("valid"):
            kv("live carrier", live.get("carrier") or "unknown")
            kv("live line", live.get("line_type") or "unknown")
            kv("live location", live.get("location") or "unknown")
    elif ptype in ("MOBILE", "FIXED_LINE_OR_MOBILE"):
        note("add a numverify key in [8] Settings for live carrier data")

    section("formats", "◉")
    kv("e164", e164)
    kv("international", phonenumbers.format_number(
        num, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
    kv("national", phonenumbers.format_number(
        num, phonenumbers.PhoneNumberFormat.NATIONAL))
    kv("rfc3966", phonenumbers.format_number(
        num, phonenumbers.PhoneNumberFormat.RFC3966))

    _phone_pivots(re.sub(r"\D", "", e164))
    return res


def _phone_pivots(plain_digits):
    section("pivots", "◉")
    kv("whatsapp", f"{T.a1}https://wa.me/{plain_digits}{RESET}")
    kv("telegram", f"https://t.me/+{plain_digits}")
    kv("truecaller", f"https://www.truecaller.com/search/int/{plain_digits}")
    kv("sync.me", f"https://sync.me/search/?number={plain_digits}")
    kv("google", f"https://www.google.com/search?q=%22{plain_digits}%22")
    kv("reputation", f"https://www.shouldianswer.com/phone-number/{plain_digits}")
    note("whatsapp / telegram links only resolve if that number is registered")


# ═════════════════════════════════════════════════════════ 6. TIKTOK REGION
TIKTOK_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")


def _tiktok_rehydrate(html):
    m = re.search(r'<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>',
                  html, re.S)
    if not m:
        return {}
    try:
        return json.loads(m.group(1))
    except ValueError:
        return {}


def _tiktok_regex(html):
    """last-resort scrape of the SSR payload"""
    grab = lambda pat: (re.search(pat, html) or [None, None])[1]  # noqa: E731
    return {
        "uniqueId": grab(r'"uniqueId":"([^"]+)"'),
        "nickname": grab(r'"nickname":"([^"]*)"'),
        "region": grab(r'"region":"([A-Za-z]{2})"'),
        "signature": grab(r'"signature":"([^"]*)"'),
        "verified": grab(r'"verified":(true|false)') == "true",
        "followerCount": grab(r'"followerCount":(\d+)'),
    }


def _tiktok_fallback_api(user):
    data, _ = _json(f"https://www.tikwm.com/api/user/info?unique_id={quote(user)}")
    if not data or data.get("code") != 0:
        return None
    block = data.get("data") or {}
    u = block.get("user") or {}
    st = block.get("stats") or {}
    return {
        "uniqueId": u.get("uniqueId"),
        "nickname": u.get("nickname"),
        "region": u.get("region"),
        "signature": u.get("signature"),
        "verified": u.get("verified"),
        "followerCount": st.get("followerCount") or u.get("followerCount"),
        "followingCount": st.get("followingCount"),
        "heartCount": st.get("heartCount") or st.get("heart"),
        "videoCount": st.get("videoCount"),
        "privateAccount": u.get("privateAccount"),
        "secUid": u.get("secUid"),
        "_source": "tikwm mirror",
    }


def tiktok_osint(target: str) -> dict:
    res = {"module": "tiktok", "target": target, "ts": now_iso(), "data": {}}
    user = target.strip().lstrip("@").split("?")[0].split("/")[-1].strip()
    begin("TIKTOK COUNTRY", "@" + user)
    d = res["data"]

    if not re.fullmatch(r"[A-Za-z0-9._]{1,24}", user):
        err("invalid tiktok handle (letters, digits, dot, underscore)")
        return res

    profile, source = None, None
    with Spin("fetching tiktok profile"):
        try:
            r = requests.get(f"https://www.tiktok.com/@{user}", timeout=15,
                             headers={"User-Agent": TIKTOK_UA,
                                      "Accept-Language": "en-US,en;q=0.9"})
        except requests.RequestException as e:
            r = None
            warn(f"network: {e.__class__.__name__}")
        if r is not None and r.status_code == 200:
            scope = _tiktok_rehydrate(r.text).get("__DEFAULT_SCOPE__", {})
            detail = scope.get("webapp.user-detail", {}) or {}
            info = detail.get("userInfo") or {}
            u = info.get("user") or {}
            st = info.get("stats") or {}
            if u:
                profile = {
                    "id": u.get("id"), "uniqueId": u.get("uniqueId"),
                    "nickname": u.get("nickname"), "region": u.get("region"),
                    "signature": u.get("signature"), "verified": u.get("verified"),
                    "privateAccount": u.get("privateAccount"),
                    "secUid": u.get("secUid"),
                    "avatar": u.get("avatarLarger") or u.get("avatarMedium"),
                    "followerCount": st.get("followerCount"),
                    "followingCount": st.get("followingCount"),
                    "heartCount": st.get("heartCount") or st.get("heart"),
                    "videoCount": st.get("videoCount"),
                    "createTime": u.get("createTime") or st.get("createTime"),
                    "_source": "tiktok web payload",
                }
                source = "tiktok web payload"
            else:
                scraped = _tiktok_regex(r.text)
                if scraped.get("uniqueId"):
                    profile, source = scraped, "html scrape (low confidence)"
        if not profile:
            profile = _tiktok_fallback_api(user)
            if profile:
                source = profile.get("_source", "mirror")

    if not profile:
        err("profile not found, private, or tiktok blocked the request")
        note("retry later or verify the handle in a browser")
        return res

    region = (profile.get("region") or "").strip().upper()

    # headline country card
    print()
    if region:
        cc_name = ISO.get(region, "unrecognised code")
        frame("COUNTRY / REGION", [
            f"{T.mute}region{RESET}     {T.a1}{BOLD}{region}{RESET}  "
            f"{flag(region)}  {T.white}{BOLD}{cc_name}{RESET}",
            f"{T.mute}flag{RESET}       {flag(region) * 3}",
            f"{T.mute}source{RESET}     {T.text}{source}{RESET}",
            f"{T.mute}meaning{RESET}    {T.dim}self-declared account region from "
            f"tiktok metadata{RESET}",
        ], color=T.a3)
    else:
        frame("COUNTRY / REGION", [
            f"{T.mute}region{RESET}     {T.warn}not disclosed{RESET}",
            f"{T.mute}source{RESET}     {T.text}{source}{RESET}",
            f"{T.mute}note{RESET}       {T.dim}tiktok hid the region field for this "
            f"account{RESET}",
        ], color=T.a3)
    d["region"] = region or None
    d["region_name"] = ISO.get(region) if region else None

    section("profile", "◉")
    kv("handle", f"@{profile.get('uniqueId') or user}")
    if profile.get("nickname"):
        kv("nickname", profile["nickname"])
    if profile.get("id"):
        kv("user id", profile["id"])
    if profile.get("verified") is not None:
        kv("verified", f"{T.a1}yes{RESET}" if profile.get("verified")
           else "no")
    if profile.get("privateAccount") is not None:
        kv("private", "yes" if profile.get("privateAccount") else "no")
    if profile.get("signature"):
        kv("bio", str(profile["signature"])[:60])

    section("stats", "◉")
    for label, key in (("followers", "followerCount"), ("following", "followingCount"),
                       ("likes", "heartCount"), ("videos", "videoCount")):
        val = profile.get(key)
        if isinstance(val, (int, float)):
            kv(label, f"{int(val):,}")
        elif isinstance(val, str) and val.isdigit():
            kv(label, f"{int(val):,}")
    created = profile.get("createTime")
    if created:
        try:
            ts = datetime.fromtimestamp(int(created), tz=timezone.utc)
            kv("account created", ts.strftime("%Y-%m-%d"))
        except (ValueError, OSError, TypeError):
            pass
    if profile.get("secUid"):
        kv("sec uid", str(profile["secUid"])[:40] + "...")

    section("region context", "◉")
    if region:
        kv("interpretation", f"{ISO.get(region, region)} app-store / signup region")
        warn("region ≠ physical location - vpn and travel both change it")
    else:
        note("switch the account to a public profile and retry for region data")

    section("pivots")
    kv("profile", f"{T.a1}https://www.tiktok.com/@{user}{RESET}")
    kv("urlebird", f"https://urlebird.com/user/{user}/")
    kv("tiktok stats", f"https://tokcount.com/?user={user}")
    kv("google", f"https://www.google.com/search?q=site%3Atiktok.com+%22%40{user}%22")
    return res


# ═══════════════════════════════════════════════════════════ 7. DISCORD ID
DISCORD_EPOCH = 1420070400000
BADGES = {
    0: "Discord Staff", 1: "Partner Server Owner", 2: "HypeSquad Events",
    3: "Bug Hunter L1", 6: "HypeSquad Bravery", 7: "HypeSquad Brilliance",
    8: "HypeSquad Balance", 9: "Early Supporter", 14: "Bug Hunter L2",
    16: "Verified Bot", 17: "Early Verified Bot Dev", 18: "Certified Moderator",
    22: "Active Developer",
}


def _badges(f):
    return [n for b, n in BADGES.items() if f & (1 << b)]


def _discord_api(uid):
    if CFG["discord_token"]:
        data, e = _json(f"https://discord.com/api/v10/users/{uid}",
                        headers={"Authorization": f"Bot {CFG['discord_token']}"})
        if data:
            return data, "bot token"
        warn(f"discord api: {e}")
    data, _ = _json(f"https://japi.rest/discord/v1/user/{uid}")
    if data:
        return (data.get("data") or data), "public mirror"
    return None, None


def discord_osint(target: str) -> dict:
    res = {"module": "discord", "target": target, "ts": now_iso(), "data": {}}
    begin("DISCORD ID", target)
    m = re.search(r"(\d{15,21})", target)
    if not m:
        err("no snowflake found - paste a 17-20 digit user id")
        return res
    uid = int(m.group(1))
    d = res["data"]
    d["id"] = str(uid)

    created = datetime.fromtimestamp(((uid >> 22) + DISCORD_EPOCH) / 1000,
                                     tz=timezone.utc)
    age = (datetime.now(timezone.utc) - created).days

    section("snowflake decode")
    kv("id", str(uid))
    kv("created (utc)", created.strftime("%Y-%m-%d %H:%M:%S"))
    kv("account age", f"{age:,} days ({age / 365:.1f} yrs)")
    kv("worker / process", f"{(uid >> 17) & 0x1F} / {(uid >> 12) & 0x1F}")
    kv("increment", uid & 0xFFF)
    d["created"] = created.isoformat()

    section("profile", "◉")
    with Spin("querying discord"):
        prof, src = _discord_api(uid)
    if not prof:
        warn("live lookup unavailable (rate limit / no token)")
    else:
        note(f"source: {src}")
        kv("username", f"{T.white}{BOLD}{prof.get('username') or '?'}{RESET}")
        if prof.get("global_name") or prof.get("display_name"):
            kv("display name", prof.get("global_name") or prof.get("display_name"))
        kv("bot", "yes" if prof.get("bot") else "no")
        av = prof.get("avatar")
        if av and str(av).startswith("http"):
            kv("avatar", av)
        elif av:
            kv("avatar", f"https://cdn.discordapp.com/avatars/{uid}/{av}.png?size=512")
        flags = prof.get("public_flags")
        if isinstance(flags, int):
            kv("badges", ", ".join(_badges(flags)) or "none")
        elif prof.get("public_flags_array"):
            kv("badges", ", ".join(map(str, prof["public_flags_array"])))
        d["profile"] = {k: prof.get(k) for k in
                        ("username", "global_name", "bot", "avatar")}

    section("pivots")
    kv("profile", f"{T.a1}https://discord.com/users/{uid}{RESET}")
    kv("lookup", f"https://discordlookup.com/user/{uid}")
    kv("prefill", f"https://discord.id/?prefill={uid}")
    return res


# ══════════════════════════════════════════════════════════ 8. CRYPTO TRACER
def detect_chain(a: str):
    a = a.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", a):
        return "ETH"
    if re.fullmatch(r"bc1[a-zA-Z0-9]{25,62}", a):
        return "BTC"
    if re.fullmatch(r"[13][1-9A-HJ-NP-Za-km-z]{25,34}", a):
        return "BTC"
    if re.fullmatch(r"ltc1[a-zA-Z0-9]{25,62}", a):
        return "LTC"
    if re.fullmatch(r"[LM][1-9A-HJ-NP-Za-km-z]{26,33}", a):
        return "LTC"
    if re.fullmatch(r"D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}", a):
        return "DOGE"
    if re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", a):
        return "TRX"
    if re.fullmatch(r"[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}", a):
        return "XMR"
    if 32 <= len(a) <= 44 and re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]+", a):
        return "SOL"
    return None


EXPLORERS = {
    "BTC": [("mempool", "https://mempool.space/address/{}"),
            ("blockchain.com", "https://www.blockchain.com/explorer/addresses/btc/{}"),
            ("oxt", "https://oxt.me/address/{}"),
            ("arkham", "https://intel.arkm.com/explorer/address/{}")],
    "ETH": [("etherscan", "https://etherscan.io/address/{}"),
            ("ethplorer", "https://ethplorer.io/address/{}"),
            ("arkham", "https://intel.arkm.com/explorer/address/{}"),
            ("breadcrumbs", "https://www.breadcrumbs.app/")],
    "LTC": [("blockchair", "https://blockchair.com/litecoin/address/{}"),
            ("blockcypher", "https://live.blockcypher.com/ltc/address/{}")],
    "DOGE": [("blockchair", "https://blockchair.com/dogecoin/address/{}"),
             ("dogechain", "https://dogechain.info/address/{}")],
    "TRX": [("tronscan", "https://tronscan.org/#/address/{}"),
            ("trxplorer", "https://trxplorer.io/address/{}")],
    "SOL": [("solscan", "https://solscan.io/account/{}"),
            ("solana.fm", "https://solana.fm/address/{}")],
    "XMR": [("xmrchain", "https://xmrchain.net/search?value={}")],
}


def _btc(a):
    out = {}
    d, e = _json(f"https://mempool.space/api/address/{a}")
    if not d:
        return {"error": e}
    ch, mp = d.get("chain_stats", {}), d.get("mempool_stats", {})
    recv = ch.get("funded_txo_sum", 0) + mp.get("funded_txo_sum", 0)
    sent = ch.get("spent_txo_sum", 0) + mp.get("spent_txo_sum", 0)
    out.update(received=recv, spent=sent, balance=recv - sent, unit="BTC", div=1e8,
               tx_count=ch.get("tx_count", 0) + mp.get("tx_count", 0),
               pending=mp.get("tx_count", 0))
    price, _ = _json("https://mempool.space/api/v1/prices")
    if price and price.get("USD"):
        out["usd"] = out["balance"] / 1e8 * price["USD"]
    txs, _ = _json(f"https://mempool.space/api/address/{a}/txs")
    if txs:
        out["recent"] = [t.get("txid", "")[:26] for t in txs[:5]]
    return out


def _eth(a):
    out = {}
    d, e = _json(f"https://api.ethplorer.io/getAddressInfo/{a}?apiKey=freekey")
    if not d:
        bc, _ = _json(f"https://api.blockchair.com/ethereum/dashboards/address/{a}")
        if not bc:
            return {"error": e}
        node = (bc.get("data") or {}).get(a.lower()) or {}
        out.update(balance=int(node.get("address", {}).get("balance", 0)),
                   unit="ETH", div=1e18)
        out["tx_count"] = node.get("address", {}).get("transaction_count")
        return out
    eth = d.get("ETH") or {}
    out.update(balance=float(eth.get("balance") or 0), unit="ETH", div=1)
    rate = (eth.get("price") or {}).get("rate")
    if rate:
        out["usd"] = out["balance"] * float(rate)
    out["tx_count"] = d.get("countTxs")
    toks = []
    for t in (d.get("tokens") or [])[:8]:
        ti = t.get("tokenInfo") or {}
        dec = ti.get("decimals")
        try:
            amt = int(t.get("balance", 0)) / 10 ** int(dec) if dec not in (None, "") else None
        except (TypeError, ValueError):
            amt = None
        toks.append((ti.get("symbol") or "?", amt))
    out["tokens"] = toks
    return out


def _blockchair(a, chain):
    slug = {"LTC": "litecoin", "DOGE": "dogecoin"}[chain]
    d, e = _json(f"https://api.blockchair.com/{slug}/dashboards/address/{a}?limit=1")
    if not d:
        return {"error": e}
    node = (d.get("data") or {}).get(a)
    if not node:
        return {"error": "address not indexed"}
    x = node.get("address", {})
    out = {"balance": x.get("balance", 0), "received": x.get("received", 0),
           "spent": x.get("spent", 0), "tx_count": x.get("transaction_count", 0),
           "unit": chain, "div": 1e8,
           "first_seen": x.get("first_seen_receiving"),
           "last_seen": x.get("last_seen_receiving")}
    out["recent"] = [t[:26] for t in (node.get("transactions") or [])[:5]]
    return out


def _trx(a):
    d, e = _json(f"https://apilist.tronscanapi.com/api/account?address={a}")
    if not d:
        return {"error": e}
    if not d.get("address"):
        return {"error": "address inactive / not indexed"}
    out = {"balance": d.get("balance", 0), "unit": "TRX", "div": 1e6,
           "tx_count": d.get("transactions")}
    created = d.get("date_created")
    if created:
        try:
            out["first_seen"] = datetime.fromtimestamp(
                created / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
        except (ValueError, OSError):
            pass
    toks = []
    for t in (d.get("trc20token_balances") or [])[:8]:
        try:
            amt = int(t.get("balance", 0)) / 10 ** int(t.get("tokenDecimal") or 6)
        except (TypeError, ValueError):
            amt = None
        toks.append((t.get("tokenAbbr") or t.get("tokenName") or "?", amt))
    out["tokens"] = toks
    return out


def _sol(a):
    rpc = "https://api.mainnet-beta.solana.com"
    try:
        r = S.post(rpc, json={"jsonrpc": "2.0", "id": 1, "method": "getBalance",
                              "params": [a, {"commitment": "confirmed"}]}, timeout=15)
        j = r.json()
        if "result" not in j:
            return {"error": str(j.get("error") or "rpc error")}
        lamports = j["result"]["value"]
        out = {"balance": lamports / 1e9, "unit": "SOL", "div": 1}
        r2 = S.post(rpc, json={"jsonrpc": "2.0", "id": 1,
                               "method": "getSignaturesForAddress",
                               "params": [a, {"limit": 1000}]}, timeout=20)
        sigs = r2.json().get("result") or []
        out["tx_count"] = len(sigs)
        out["recent"] = [s.get("signature", "")[:22] for s in sigs[:5]]
        return out
    except (requests.RequestException, ValueError) as e:
        return {"error": str(e)}


def crypto_osint(target: str) -> dict:
    res = {"module": "crypto", "target": target, "ts": now_iso(), "data": {}}
    begin("CRYPTO TRACER", target)
    addr = target.strip()
    chain = detect_chain(addr)
    d = res["data"]

    section("chain detection")
    kv("address", addr)
    if not chain:
        err("unrecognised address format (BTC / ETH / LTC / DOGE / TRX / SOL / XMR)")
        return res
    kv("asset", f"{T.white}{BOLD}{chain}{RESET}")
    d["chain"] = chain

    section("on-chain summary", "◉")
    info = {}
    if chain != "XMR":
        with Spin(f"querying {chain} indexer"):
            if chain == "BTC":
                info = _btc(addr)
            elif chain == "ETH":
                info = _eth(addr)
            elif chain in ("LTC", "DOGE"):
                info = _blockchair(addr, chain)
            elif chain == "TRX":
                info = _trx(addr)
            elif chain == "SOL":
                info = _sol(addr)

    if chain == "XMR":
        note("monero balances require a view key - validation only")
    elif info.get("error"):
        warn(f"provider error: {info['error']}")
    else:
        div, unit = info.get("div") or 1, info.get("unit", chain)
        bal = (info.get("balance") or 0) / div
        line = f"{bal:,.8f}".rstrip("0").rstrip(".") + f" {unit}"
        if info.get("usd") is not None:
            line += f"  {T.good}(≈ ${info['usd']:,.2f}){RESET}"
        kv("balance", f"{T.white}{BOLD}{line}{RESET}")
        if info.get("received") is not None:
            kv("received", f"{info['received'] / div:,.8f} {unit}")
        if info.get("spent") is not None:
            kv("spent", f"{info['spent'] / div:,.8f} {unit}")
        if info.get("tx_count") is not None:
            kv("transactions", info["tx_count"])
        if info.get("pending"):
            kv("pending", info["pending"])
        if info.get("first_seen"):
            kv("first seen", str(info["first_seen"])[:24])
        if info.get("last_seen"):
            kv("last active", str(info["last_seen"])[:24])
        for sym, amt in (info.get("tokens") or []):
            if amt:
                kv("token", f"{sym} · {amt:,.4f}")
        d.update({k: v for k, v in info.items() if k != "tokens"})

    section("recent activity", "◉")
    recent = info.get("recent") if isinstance(info, dict) else None
    if recent:
        for h in recent:
            kv("tx", h + "...")
    else:
        note("no recent transaction sample")

    section("explorers / tracers")
    for name, tpl in EXPLORERS.get(chain, []):
        kv(name, tpl.format(addr) if "{}" in tpl else tpl)
    note("for graph tracing feed the address into breadcrumbs.app or arkham")
    return res


# ══════════════════════════════════════════════════════ 9. USERNAME FINDER
SITES = {
    "GitHub":       {"url": "https://github.com/{}"},
    "GitLab":       {"url": "https://gitlab.com/{}"},
    "Codeberg":     {"url": "https://codeberg.org/{}"},
    "PyPI":         {"url": "https://pypi.org/user/{}/"},
    "npm":          {"url": "https://www.npmjs.com/~{}"},
    "Docker Hub":   {"url": "https://hub.docker.com/u/{}"},
    "Hugging Face": {"url": "https://huggingface.co/{}"},
    "Keybase":      {"url": "https://keybase.io/{}", "missing": "couldn't find that user"},
    "Hacker News":  {"url": "https://news.ycombinator.com/user?id={}", "missing": "no such user"},
    "Reddit":       {"url": "https://www.reddit.com/user/{}", "missing": "page not found"},
    "Telegram":     {"url": "https://t.me/{}", "found": "tgme_page_title"},
    "Steam":        {"url": "https://steamcommunity.com/id/{}", "missing": "could not be found"},
    "YouTube":      {"url": "https://www.youtube.com/@{}"},
    "Twitch":       {"url": "https://www.twitch.tv/{}"},
    "TikTok":       {"url": "https://www.tiktok.com/@{}"},
    "Instagram":    {"url": "https://www.instagram.com/{}/"},
    "Pinterest":    {"url": "https://www.pinterest.com/{}/"},
    "SoundCloud":   {"url": "https://soundcloud.com/{}"},
    "Medium":       {"url": "https://medium.com/@{}"},
    "Dev.to":       {"url": "https://dev.to/{}"},
    "Hashnode":     {"url": "https://hashnode.com/@{}"},
    "Behance":      {"url": "https://www.behance.net/{}"},
    "Dribbble":     {"url": "https://dribbble.com/{}"},
    "Flickr":       {"url": "https://www.flickr.com/people/{}"},
    "Vimeo":        {"url": "https://vimeo.com/{}"},
    "Mastodon":     {"url": "https://mastodon.social/@{}"},
    "Tumblr":       {"url": "https://{}.tumblr.com/"},
    "Linktree":     {"url": "https://linktr.ee/{}"},
    "About.me":     {"url": "https://about.me/{}"},
    "TryHackMe":    {"url": "https://tryhackme.com/p/{}", "missing": "user not found"},
    "Bugcrowd":     {"url": "https://bugcrowd.com/{}"},
}


def _probe(name, spec, user):
    url = spec["url"].format(quote(user, safe=""))
    try:
        r = requests.get(url, timeout=10, allow_redirects=True,
                         headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
    except requests.RequestException as e:
        return name, url, "?", e.__class__.__name__
    body = r.text.lower()
    if r.status_code == 404:
        return name, url, "-", "404"
    if r.status_code != 200:
        return name, url, "?", f"HTTP {r.status_code}"
    if spec.get("found"):
        return ((name, url, "+", "marker hit") if spec["found"].lower() in body
                else (name, url, "-", "marker absent"))
    if spec.get("missing") and spec["missing"].lower() in body:
        return name, url, "-", "not-found marker"
    return name, url, "+", "200"


def username_osint(target: str) -> dict:
    user = target.strip().lstrip("@")
    res = {"module": "username", "target": user, "ts": now_iso(), "data": {}}
    begin("USERNAME FINDER", user)
    if not re.fullmatch(r"[A-Za-z0-9._\-]{1,40}", user):
        err("use 1-40 chars: letters, digits, dot, dash, underscore")
        return res

    section("sweep", "◉")
    total = len(SITES)
    hits, unknown, done = [], [], 0
    print(f"   {T.dim}probing {total} platforms · 16 workers{RESET}\n")
    sys.stdout.write("   " + bar(0, total))
    sys.stdout.flush()

    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = [pool.submit(_probe, n, s, user) for n, s in SITES.items()]
        for fut in as_completed(futs):
            name, url, state, detail = fut.result()
            done += 1
            if state == "+":
                hits.append((name, url))
                sys.stdout.write("\r\033[K")
                hit(f"{T.text}{name:<15}{RESET} {T.a1}{url}{RESET}")
            elif state == "?":
                unknown.append(name)
                sys.stdout.write("\r\033[K")
                print(f"   {T.warn}?{RESET} {T.text}{name:<15}{RESET} {T.dim}{detail}{RESET}")
            sys.stdout.write("   " + bar(done, total))
            sys.stdout.flush()
    sys.stdout.write("\n")

    section("summary", "◉")
    rate = len(hits) / total * 100
    kv("platforms", total)
    kv("hits", f"{T.good}{len(hits)}{RESET} ({rate:.0f}%)")
    kv("inconclusive", ", ".join(unknown) if unknown else "none")
    if rate < 15:
        note("low hit rate - uncommon handle or platforms rate-limited us")
    res["data"] = {"found": dict(hits), "unknown": unknown,
                   "hit_rate": round(rate, 1)}

    section("pivots")
    q = quote(user, safe="")
    kv("google", f"https://www.google.com/search?q=%22{q}%22")
    kv("whatsmyname", f"https://whatsmyname.app/?q={q}")
    kv("maigret", f"maigret {user} --html")
    kv("sherlock", f"sherlock {user} --print-found")
    warn("verify hits manually - some platforms serve identical 200 pages")
    return res


# ═══════════════════════════════════════════════════════════════════ 10. APP
MENU = [
    ("1", "Email OSINT",     "MX · SPF · DMARC · gravatar · breaches"),
    ("2", "IP Tracker",      "geo · ASN · proxy · reverse DNS"),
    ("3", "Phone Intel",     "carrier · region · line type · socials"),
    ("4", "TikTok Country",  "region · flag · stats · profile"),
    ("5", "Discord ID",      "snowflake · profile · badges"),
    ("6", "Crypto Tracer",   "BTC · ETH · LTC · DOGE · TRX · SOL"),
    ("7", "Username Finder", f"{len(SITES)} platforms · concurrent"),
    ("8", "Settings",        "autosave · keys · phone region"),
    ("0", "Exit",            ""),
]


def render_menu():
    rows = []
    for num, name, desc in MENU:
        left = f"{T.a2}[{num}]{RESET} {T.white}{BOLD}{name}{RESET}"
        gap = max(1, 24 - vlen(left))
        rows.append(left + " " * gap + f"{T.mute}{desc[:46]}{RESET}")
    rows.append("")
    state = f"{T.good}on{RESET}" if CFG["autosave"] else f"{T.dim}off{RESET}"
    rows.append(f"{T.mute}autosave{RESET} {state}   {T.dim}│{RESET}   "
                f"{T.mute}region{RESET} {T.text}{CFG['region']}{RESET}")
    frame("MODULES", rows, width=78, color=T.a1)


SETTINGS = [
    ("1", "Toggle autosave"),
    ("2", "HaveIBeenPwned API key"),
    ("3", "Discord bot token"),
    ("4", "Default phone region"),
    ("5", "Numverify API key"),
    ("0", "Back"),
]


def settings():
    while True:
        wipe()
        banner()
        rows = [f"{T.a2}[{n}]{RESET} {T.white}{BOLD}{label}{RESET}"
                for n, label in SETTINGS]
        rows.append("")
        rows.append(f"{T.mute}autosave{RESET}  "
                    f"{(T.good + 'on') if CFG['autosave'] else (T.dim + 'off')}{RESET}")
        rows.append(f"{T.mute}hibp{RESET}      "
                    f"{'set' if CFG['hibp_key'] else 'not set'}")
        rows.append(f"{T.mute}discord{RESET}   "
                    f"{'set' if CFG['discord_token'] else 'not set'}")
        rows.append(f"{T.mute}region{RESET}    {CFG['region']} {flag(CFG['region'])}")
        rows.append(f"{T.mute}numverify{RESET} "
                    f"{'set' if CFG['numverify'] else 'not set'}")
        frame("SETTINGS", rows, width=78, color=T.a3)

        c = ask("setting")
        if c in ("0", "", "q"):
            return
        if c == "1":
            CFG["autosave"] = not CFG["autosave"]
        elif c == "2":
            CFG["hibp_key"] = ask("hibp key").strip()
        elif c == "3":
            CFG["discord_token"] = ask("bot token").strip()
        elif c == "4":
            cc = ask("iso region, e.g. US / GB / DE").strip().upper()
            if cc in ISO:
                CFG["region"] = cc
            else:
                warn("unknown ISO code")
                time.sleep(1)
        elif c == "5":
            CFG["numverify"] = ask("numverify key").strip()


RUNNERS = {
    "1": ("email address", email_osint),
    "2": ("ip or hostname", ip_osint),
    "3": ("phone number (+country code)", phone_osint),
    "4": ("tiktok @handle", tiktok_osint),
    "5": ("discord user id", discord_osint),
    "6": ("wallet address", crypto_osint),
    "7": ("username", username_osint),
}


def interactive():
    while True:
        wipe()
        banner()
        render_menu()
        choice = ask("choice")
        if choice in ("0", "q", "quit", "exit"):
            print(f"\n   {grad('session closed.', GRAD, bold=True)}\n")
            return
        if choice == "8":
            settings()
            continue
        if choice not in RUNNERS:
            warn("pick 0-8")
            time.sleep(0.7)
            continue
        label, fn = RUNNERS[choice]
        target = ask(label)
        if not target:
            warn("empty input")
            time.sleep(0.6)
            continue
        t0 = time.time()
        try:
            res = fn(target)
            maybe_save(res)
        except KeyboardInterrupt:
            print()
            warn("scan interrupted")
            continue
        print()
        rule(char="─", width=74, color=T.dim)
        print(f"   {T.mute}finished in{RESET} {T.text}{time.time() - t0:.1f}s{RESET}  "
              f"{T.dim}·{RESET}  {T.mute}module{RESET} {T.a1}{res.get('module')}{RESET}")
        pause()


def cli():
    ap = argparse.ArgumentParser(prog="osintz.py", description="OSINTZ v2.1")
    ap.add_argument("-m", "--module",
                    choices=["email", "ip", "phone", "tiktok", "discord",
                             "crypto", "username"])
    ap.add_argument("-t", "--target")
    ap.add_argument("--save", action="store_true")
    a = ap.parse_args()
    if not (a.module and a.target):
        interactive()
        return
    if a.save:
        CFG["autosave"] = True
    fns = {"email": email_osint, "ip": ip_osint, "phone": phone_osint,
           "tiktok": tiktok_osint, "discord": discord_osint,
           "crypto": crypto_osint, "username": username_osint}
    maybe_save(fns[a.module](a.target))


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        print(f"\n   {grad('interrupted.', GRAD, bold=True)}")
