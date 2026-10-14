#!/usr/bin/env python3
"""Servidor web todo-en-uno: User-Agents + escáner + exportación + análisis UA avanzado.

Uso: python3 servidor_web_scan.py [puerto]

Páginas:
  http://localhost:8080/            -> panel de User-Agents
  http://localhost:8080/scan        -> formulario de escaneo
  http://localhost:8080/ua-lab      -> laboratorio interactivo de User-Agents
  /api/ua/parse                     -> analiza el UA que envíes (JSON)
  /api/scan/<id>/report.md|.html    -> descarga el reporte
"""
import json
import random
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from enumeracion import (
    resolver_dns, whois, subdominios_crtsh,
    PUERTOS_COMUNES, SUBDOMINIOS_COMUNES, dominio_base,
)
from cabeceras_seguridad import CABECERAS, CABECERAS_INFO

# --- ua-parser (opcional, con fallback) ---
try:
    from ua_parser import parse as ua_parse
    UA_PARSER_OK = True
except ImportError:
    UA_PARSER_OK = False


# ============================================================
#  Almacenes globales
# ============================================================
escaneos = {}
lock = threading.Lock()
_contador = [0]

registro_ua = []
lock_ua = threading.Lock()
contador_ua = [0]
LOG_UA = "useragents.log"

# --- Lista de UA realistas para rotación ---
USER_AGENTS_ROTACION = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
]


def ua_aleatorio():
    return random.choice(USER_AGENTS_ROTACION)


def _nuevo_sid():
    with lock:
        _contador[0] += 1
        return str(_contador[0])


def add_log(sid, msg):
    with lock:
        if sid in escaneos:
            escaneos[sid]["log"].append(f"[{datetime.now():%H:%M:%S}] {msg}")


def guardar(sid, clave, valor):
    with lock:
        if sid in escaneos:
            escaneos[sid]["resultados"][clave] = valor


def finalizar(sid, estado="completado", error=None):
    with lock:
        if sid in escaneos:
            escaneos[sid]["estado"] = estado
            escaneos[sid]["fin"] = datetime.now().strftime("%H:%M:%S")
            if error:
                escaneos[sid]["error"] = error


# ============================================================
#  User-Agent: análisis (con ua-parser o fallback)
# ============================================================
def _clasificar_tipo(navegador, so, ua):
    u = ua.lower()
    if navegador.lower() in ("curl", "wget", "python-urllib", "python-requests",
                              "python", "go-http-client", "okhttp", "java"):
        return "Herramienta"
    if any(k in navegador.lower() for k in ("bot", "spider", "crawler", "scanner")):
        return "Bot"
    if "mobile" in u or so in ("Android", "iOS"):
        return "Móvil"
    if navegador == "Desconocido":
        return "Desconocido"
    return "Escritorio"


def analizar_ua_avanzado(ua):
    """Análisis profesional. Usa ua-parser si está disponible, si no, fallback."""
    if not ua:
        ua = "(sin User-Agent)"

    if UA_PARSER_OK:
        try:
            r = ua_parse(ua)
            navegador = r.user_agent.family or "Desconocido"
            version = r.user_agent.major or "—"
            so_parts = [r.os.family or "—"]
            if r.os.major:
                so_parts.append(r.os.major)
            if r.os.minor:
                so_parts.append(r.os.minor)
            so = " ".join(p for p in so_parts if p and p != "—") or "—"
            dispositivo = r.device.family or "—"
            return {
                "navegador": navegador,
                "version": version,
                "so": so,
                "dispositivo": dispositivo,
                "tipo": _clasificar_tipo(navegador, so, ua),
                "motor": UA_PARSER_OK and getattr(r.user_agent, "family", ""),
                "ua": ua,
                "motor_parseo": "ua-parser",
            }
        except Exception:
            pass

    # Fallback simple
    u = ua.lower()
    if "edg/" in u or "edge/" in u: nav, ver = "Edge", "—"
    elif "opr/" in u or "opera" in u: nav, ver = "Opera", "—"
    elif "firefox" in u: nav, ver = "Firefox", "—"
    elif "chrome" in u or "crios" in u: nav, ver = "Chrome", "—"
    elif "safari" in u: nav, ver = "Safari", "—"
    elif "curl" in u: nav, ver = "curl", "—"
    elif "wget" in u: nav, ver = "Wget", "—"
    elif "python" in u: nav, ver = "Python", "—"
    else: nav, ver = "Desconocido", "—"

    if "windows" in u: so = "Windows"
    elif "android" in u: so = "Android"
    elif "iphone" in u or "ipad" in u: so = "iOS"
    elif "mac os" in u or "macintosh" in u: so = "macOS"
    elif "linux" in u or "x11" in u: so = "Linux"
    else: so = "—"

    return {
        "navegador": nav, "version": ver, "so": so, "dispositivo": "—",
        "tipo": _clasificar_tipo(nav, so, ua),
        "ua": ua, "motor_parseo": "fallback",
    }


# Alias de compatibilidad con el resto del código
analizar_ua = analizar_ua_avanzado


def capturar_ua(handler, ruta):
    ua = handler.headers.get("User-Agent", "(sin User-Agent)")
    info = analizar_ua_avanzado(ua)
    with lock_ua:
        contador_ua[0] += 1
        entrada = {
            "hora": datetime.now().strftime("%H:%M:%S"),
            "ip": handler.client_address[0],
            "metodo": handler.command,
            "ruta": ruta,
            "ua": ua,
            "navegador": info["navegador"],
            "version": info["version"],
            "so": info["so"],
            "dispositivo": info["dispositivo"],
            "tipo": info["tipo"],
        }
        registro_ua.append(entrada)
        del registro_ua[:-100]
        total = contador_ua[0]
    linea = f"{datetime.now():%Y-%m-%d %H:%M:%S} | {entrada['ip']} | {handler.command} {ruta} | UA: {ua}"
    try:
        with open(LOG_UA, "a", encoding="utf-8") as f:
            f.write(linea + "\n")
    except OSError:
        pass


# ============================================================
#  Cabeceras de seguridad (con rotación de UA)
# ============================================================
def analizar_cabeceras(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    res = {"url": url, "seguridad": [], "info": [], "score": 0,
           "total": len(CABECERAS), "estado": None, "error": None,
           "ua_usado": None}
    ua_usado = ua_aleatorio()
    res["ua_usado"] = ua_usado
    try:
        req = urllib.request.Request(url, headers={"User-Agent": ua_usado})
        resp = urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError as e:
        resp = e
    except Exception as e:
        res["error"] = str(e)
        return res

    cab = {k.lower(): v for k, v in resp.headers.items()}
    res["estado"] = getattr(resp, "status", None) or getattr(resp, "code", None)
    presentes = 0
    for nombre, desc in CABECERAS.items():
        valor = cab.get(nombre.lower())
        if valor:
            presentes += 1
        res["seguridad"].append({
            "nombre": nombre, "desc": desc,
            "valor": valor[:160] if valor else None, "ok": bool(valor),
        })
    res["score"] = presentes
    for nombre in CABECERAS_INFO:
        if nombre.lower() in cab:
            res["info"].append({"nombre": nombre, "valor": cab[nombre.lower()]})
    return res


def escanear_puertos_dict(ip):
    def probe(puerto):
        try:
            with socket.create_connection((ip, puerto), timeout=4) as s:
                banner = ""
                try:
                    if puerto in (80, 8000, 8080):
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    lineas = s.recv(200).decode(errors="ignore").strip().splitlines()
                    banner = lineas[0] if lineas else ""
                except OSError:
                    pass
                try:
                    servicio = socket.getservbyport(puerto)
                except OSError:
                    servicio = "desconocido"
                return {"puerto": puerto, "servicio": servicio, "banner": banner}
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=50) as ex:
        rs = list(ex.map(probe, PUERTOS_COMUNES))
    return [r for r in rs if r]


def fuerza_bruta_dict(dominio):
    base = dominio_base(dominio)
    aleatorio = f"zz-no-existe-{int(time.time())}.{base}"
    ip_comodin = None
    try:
        ip_comodin = socket.gethostbyname(aleatorio)
    except socket.gaierror:
        pass

    def probar(sub):
        nombre = f"{sub}.{base}"
        try:
            return {"nombre": nombre, "ip": socket.gethostbyname(nombre)}
        except socket.gaierror:
            return None

    encontrados = []
    with ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(probar, SUBDOMINIOS_COMUNES):
            if r and r["ip"] != ip_comodin:
                encontrados.append(r)
    return {"comodin": ip_comodin, "encontrados": encontrados}


# ============================================================
#  Ejecutor de escaneo (hilo aparte)
# ============================================================
def ejecutar_escaneo(sid, target, tipos):
    try:
        add_log(sid, f"Objetivo: {target}")
        add_log(sid, f"Técnicas: {', '.join(tipos)}")
        url = target if target.startswith(("http://", "https://")) else "http://" + target

        if "cabeceras" in tipos:
            add_log(sid, "→ Analizando cabeceras (UA rotativo)...")
            r = analizar_cabeceras(url)
            guardar(sid, "cabeceras", r)
            if r.get("error"):
                add_log(sid, f"  ✗ {r['error']}")
            else:
                add_log(sid, f"  HTTP {r['estado']} · {r['score']}/{r['total']} presentes")
                add_log(sid, f"  UA usado: {r['ua_usado'][:60]}...")

        dominio = urlparse(url).hostname or target

        if "pasiva" in tipos:
            add_log(sid, "→ DNS lookup...")
            guardar(sid, "dns", resolver_dns(dominio))
            add_log(sid, "→ WHOIS (puede tardar)...")
            w = whois(dominio)
            guardar(sid, "whois", w[:5000] if isinstance(w, str) else str(w))
            add_log(sid, "→ Subdominios desde crt.sh...")
            subs = subdominios_crtsh(dominio)
            guardar(sid, "subdominios_crtsh", subs)
            add_log(sid, f"  {len(subs)} entradas de crt.sh")

        if "activa" in tipos:
            try:
                ip = socket.gethostbyname(dominio)
            except socket.gaierror as e:
                add_log(sid, f"  ✗ No se pudo resolver {dominio}: {e}")
                finalizar(sid, "error", f"No se pudo resolver {dominio}")
                return
            guardar(sid, "ip", ip)
            add_log(sid, f"→ IP: {ip}. Escaneando puertos...")
            puertos = escanear_puertos_dict(ip)
            guardar(sid, "puertos", puertos)
            add_log(sid, f"  {len(puertos)} puertos abiertos")
            add_log(sid, "→ Fuerza bruta de subdominios...")
            fb = fuerza_bruta_dict(dominio)
            guardar(sid, "subdominios_bruta", fb)
            if fb["comodin"]:
                add_log(sid, f"  [!] DNS comodín: {fb['comodin']}")
            add_log(sid, f"  {len(fb['encontrados'])} subdominios válidos")

        add_log(sid, "✓ Escaneo finalizado")
        finalizar(sid, "completado")
    except Exception as e:
        add_log(sid, f"✗ Excepción: {e}")
        finalizar(sid, "error", str(e))


# ============================================================
#  Reportes
# ============================================================
def _esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def generar_markdown(sid):
    with lock:
        d = escaneos.get(sid)
    if not d:
        return None
    r = d["resultados"]
    L = []
    L.append(f"# Reporte de Escaneo — {d['target']}\n")
    L.append("| Campo | Valor |")
    L.append("|---|---|")
    L.append(f"| **ID** | `{sid}` |")
    L.append(f"| **Objetivo** | `{d['target']}` |")
    L.append(f"| **Inicio** | {d['inicio']} |")
    L.append(f"| **Fin** | {d.get('fin') or '—'} |")
    L.append(f"| **Estado** | {d['estado']} |")
    L.append(f"| **Técnicas** | {', '.join(d['tipos'])} |\n")

    if "cabeceras" in r:
        c = r["cabeceras"]
        L.append("## Cabeceras de seguridad\n")
        if c.get("error"):
            L.append(f"> ⚠ **Error**: {c['error']}\n")
        else:
            L.append(f"- **URL**: `{c['url']}`")
            L.append(f"- **Estado HTTP**: {c['estado']}")
            L.append(f"- **Puntuación**: {c['score']}/{c['total']}")
            L.append(f"- **User-Agent usado**: `{c.get('ua_usado','—')}`\n")
            L.append("| Cabecera | Estado | Valor | Propósito |")
            L.append("|---|---|---|---|")
            for x in c["seguridad"]:
                st = "✔" if x["ok"] else "✘"
                val = (x["valor"] or "—").replace("|", "\\|")
                L.append(f"| `{x['nombre']}` | {st} | {val} | {x['desc']} |")
            L.append("")
            if c["info"]:
                L.append("### ⚠ Información filtrada\n")
                L.append("| Cabecera | Valor |")
                L.append("|---|---|")
                for x in c["info"]:
                    L.append(f"| `{x['nombre']}` | `{x['valor']}` |")
                L.append("")

    if "dns" in r:
        L.append("## DNS\n")
        L.append("```json")
        L.append(json.dumps(r["dns"], indent=2, ensure_ascii=False))
        L.append("```\n")
    if "whois" in r:
        L.append("## WHOIS\n")
        L.append("```")
        L.append(r["whois"])
        L.append("```\n")
    if "subdominios_crtsh" in r:
        arr = r["subdominios_crtsh"]
        L.append(f"## Subdominios (crt.sh) — {len(arr)} entradas\n")
        for s in arr:
            L.append(f"- `{s}`")
        L.append("")
    if "puertos" in r:
        L.append("## Puertos abiertos\n")
        L.append(f"**IP**: `{r.get('ip','—')}`\n")
        if r["puertos"]:
            L.append("| Puerto | Servicio | Banner |")
            L.append("|---|---|---|")
            for p in r["puertos"]:
                banner = (p["banner"] or "—").replace("|", "\\|")
                L.append(f"| **{p['puerto']}/tcp** | {p['servicio']} | `{banner}` |")
            L.append("")
        else:
            L.append("_Sin puertos abiertos._\n")
    if "subdominios_bruta" in r:
        b = r["subdominios_bruta"]
        L.append("## Subdominios por fuerza bruta\n")
        if b.get("comodin"):
            L.append(f"> ⚠ **DNS comodín**: `{b['comodin']}`\n")
        if b["encontrados"]:
            L.append("| Subdominio | IP |")
            L.append("|---|---|")
            for x in b["encontrados"]:
                L.append(f"| `{x['nombre']}` | `{x['ip']}` |")
            L.append("")
        else:
            L.append("_Sin subdominios válidos._\n")

    L.append("---")
    L.append(f"_Generado el {datetime.now():%Y-%m-%d %H:%M:%S}_")
    return "\n".join(L)


def generar_html(sid):
    with lock:
        d = escaneos.get(sid)
    if not d:
        return None
    r = d["resultados"]
    P = [f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<title>Reporte — {_esc(d['target'])}</title><style>
body{{font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;max-width:1000px;margin:0 auto;padding:30px;background:#f8f9fc;color:#1b2333}}
h1{{color:#5b6cff;border-bottom:3px solid #5b6cff;padding-bottom:10px}}
h2{{margin-top:34px;border-bottom:1px solid #e3e8f2;padding-bottom:6px}}
h3{{color:#6b7690;font-size:16px;margin-top:20px}}
table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:14px}}
th{{text-align:left;background:#eef1fb;padding:10px;border:1px solid #e3e8f2}}
td{{padding:8px 10px;border:1px solid #e3e8f2;vertical-align:top}}
code,pre{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}}
pre{{background:#0b1020;color:#c9d3ff;padding:14px;border-radius:8px;overflow-x:auto;max-height:400px}}
code{{background:#eef1fb;padding:2px 6px;border-radius:4px}}td code{{background:transparent;padding:0}}
.meta{{background:#fff;border:1px solid #e3e8f2;border-radius:10px;padding:16px;margin:16px 0}}
.meta p{{margin:6px 0}}.ok{{color:#18c5a3;font-weight:700}}.no{{color:#e74c3c;font-weight:700}}
.warn{{background:#fff3cd;border-left:4px solid #ffc107;padding:10px 14px;border-radius:6px;margin:10px 0}}
.tag{{display:inline-block;padding:3px 10px;border-radius:99px;background:#eef1fb;border:1px solid #e3e8f2;font-size:12px;font-weight:600}}
footer{{margin-top:40px;padding-top:20px;border-top:1px solid #e3e8f2;color:#6b7690;font-size:13px;text-align:center}}
</style></head><body><h1>🔍 Reporte de Escaneo</h1>
<div class="meta">
<p><b>Objetivo:</b> <code>{_esc(d['target'])}</code></p>
<p><b>ID:</b> <code>{_esc(sid)}</code></p>
<p><b>Inicio:</b> {_esc(d['inicio'])} · <b>Fin:</b> {_esc(d.get('fin') or '—')}</p>
<p><b>Estado:</b> <span class="tag">{_esc(d['estado'])}</span></p>
<p><b>Técnicas:</b> {_esc(', '.join(d['tipos']))}</p></div>"""]

    if "cabeceras" in r:
        c = r["cabeceras"]
        P.append("<h2>Cabeceras de seguridad</h2>")
        if c.get("error"):
            P.append(f'<div class="warn">Error: {_esc(c["error"])}</div>')
        else:
            P.append(f'<p>URL: <code>{_esc(c["url"])}</code> · HTTP: <b>{c["estado"]}</b> · Puntuación: <b>{c["score"]}/{c["total"]}</b></p>')
            P.append(f'<p>User-Agent usado: <code>{_esc(c.get("ua_usado","—"))}</code></p>')
            P.append('<table><thead><tr><th>Cabecera</th><th>Estado</th><th>Valor</th><th>Propósito</th></tr></thead><tbody>')
            for x in c["seguridad"]:
                st = '<span class="ok">✔</span>' if x["ok"] else '<span class="no">✘</span>'
                P.append(f'<tr><td><code>{_esc(x["nombre"])}</code></td><td>{st}</td><td>{_esc(x["valor"] or "—")}</td><td>{_esc(x["desc"])}</td></tr>')
            P.append('</tbody></table>')
            if c["info"]:
                P.append('<h3>⚠ Información filtrada</h3><table><thead><tr><th>Cabecera</th><th>Valor</th></tr></thead><tbody>')
                for x in c["info"]:
                    P.append(f'<tr><td><code>{_esc(x["nombre"])}</code></td><td><code>{_esc(x["valor"])}</code></td></tr>')
                P.append('</tbody></table>')

    if "dns" in r:
        P.append(f'<h2>DNS</h2><pre>{_esc(json.dumps(r["dns"], indent=2, ensure_ascii=False))}</pre>')
    if "whois" in r:
        P.append(f'<h2>WHOIS</h2><pre>{_esc(r["whois"])}</pre>')
    if "subdominios_crtsh" in r:
        arr = r["subdominios_crtsh"]
        P.append(f'<h2>Subdominios (crt.sh) — {len(arr)}</h2>')
        P.append('<pre>' + _esc("\n".join(arr)) + '</pre>' if arr else '<p>Sin resultados.</p>')
    if "puertos" in r:
        P.append("<h2>Puertos abiertos</h2>")
        P.append(f'<p>IP: <code>{_esc(r.get("ip","—"))}</code> · {len(r["puertos"])} puertos</p>')
        if r["puertos"]:
            P.append('<table><thead><tr><th>Puerto</th><th>Servicio</th><th>Banner</th></tr></thead><tbody>')
            for p in r["puertos"]:
                P.append(f'<tr><td><b>{p["puerto"]}/tcp</b></td><td>{_esc(p["servicio"])}</td><td><code>{_esc(p["banner"] or "—")}</code></td></tr>')
            P.append('</tbody></table>')
        else:
            P.append('<p>Sin puertos abiertos.</p>')
    if "subdominios_bruta" in r:
        b = r["subdominios_bruta"]
        P.append("<h2>Subdominios por fuerza bruta</h2>")
        if b.get("comodin"):
            P.append(f'<div class="warn">⚠ DNS comodín: <code>{_esc(b["comodin"])}</code></div>')
        if b["encontrados"]:
            P.append('<table><thead><tr><th>Subdominio</th><th>IP</th></tr></thead><tbody>')
            for x in b["encontrados"]:
                P.append(f'<tr><td><code>{_esc(x["nombre"])}</code></td><td><code>{_esc(x["ip"])}</code></td></tr>')
            P.append('</tbody></table>')
        else:
            P.append('<p>Sin subdominios válidos.</p>')

    P.append(f'<footer>Generado el {datetime.now():%Y-%m-%d %H:%M:%S}</footer></body></html>')
    return "".join(P)


# ============================================================
#  Plantillas HTML
# ============================================================
CSS = """
:root{--bg:#f4f6fb;--card:#fff;--tx:#1b2333;--mu:#6b7690;--bd:#e3e8f2;--ac:#5b6cff;--ac2:#18c5a3;--cod:#eef1fb;--err:#e74c3c;--ok:#18c5a3}
@media(prefers-color-scheme:dark){:root{--bg:#0e1220;--card:#171d30;--tx:#e8ecf8;--mu:#8e9ab8;--bd:#252d47;--ac:#7c89ff;--ac2:#2dd4b4;--cod:#0f1424}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
header{background:linear-gradient(135deg,var(--ac),var(--ac2));color:#fff;padding:36px 20px 70px}
.w{max-width:1100px;margin:0 auto;padding:0 20px}
h1{margin:0 0 6px;font-size:clamp(24px,4vw,34px)}header p{margin:0;opacity:.9}
nav{background:var(--card);border-bottom:1px solid var(--bd);padding:0 20px}
nav .w{display:flex;gap:8px}
nav a{color:var(--tx);text-decoration:none;padding:14px 18px;font-weight:600;border-bottom:3px solid transparent}
nav a.on{color:var(--ac);border-bottom-color:var(--ac)}
main{margin-top:-46px;padding:20px 0 50px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:16px;padding:22px;box-shadow:0 6px 24px rgba(20,30,70,.07);margin-bottom:18px}
.card h2{margin:0 0 14px;font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--mu)}
input[type=text],input[type=url],textarea{width:100%;padding:12px 14px;border:1px solid var(--bd);border-radius:10px;background:var(--cod);color:var(--tx);font:inherit;font-size:15px}
textarea{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;resize:vertical}
label.chk{display:flex;gap:10px;align-items:center;padding:8px 0}
fieldset{border:1px solid var(--bd);border-radius:10px;padding:12px 16px;margin:14px 0}
legend{padding:0 8px;color:var(--mu);font-size:13px;font-weight:600}
button,.btn-dl{background:var(--ac);color:#fff;border:0;padding:12px 22px;border-radius:10px;font:inherit;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block}
.btn-dl{background:var(--ac2);margin-right:10px}
button:hover,.btn-dl:hover{filter:brightness(1.1)}
button:disabled{opacity:.5;cursor:not-allowed}
code,.ua{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
.ua{background:var(--cod);border:1px solid var(--bd);border-radius:10px;padding:12px;word-break:break-all}
pre{background:var(--cod);border:1px solid var(--bd);border-radius:10px;padding:12px;overflow-x:auto;font-size:12px;max-height:400px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--mu);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--bd);white-space:nowrap}
td{padding:8px 10px;border-bottom:1px solid var(--bd);vertical-align:top}
td.u{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-all;color:var(--mu)}
.ok{color:var(--ok);font-weight:700}.no{color:var(--err);font-weight:700}
.tag{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;background:var(--cod);border:1px solid var(--bd)}
.log{background:#0b1020;color:#c9d3ff;border-radius:10px;padding:14px;font:12px/1.6 ui-monospace,Menlo,Consolas,monospace;max-height:280px;overflow:auto;white-space:pre-wrap}
.hidden{display:none}.sub{color:var(--mu);font-size:14px}
.chips{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}
.chip{background:var(--cod);border:1px solid var(--bd);border-radius:12px;padding:8px 14px}
.chip small{display:block;color:var(--mu);font-size:12px}.chip b{font-size:17px}
"""

NAV = """
<nav><div class="w">
  <a href="/" class="{ua_on}">🕵️ User-Agents</a>
  <a href="/scan" class="{scan_on}">🔍 Escáner</a>
  <a href="/ua-lab" class="{lab_on}">🧪 Lab UA</a>
</div></nav>
"""

PAGINA_UA = """<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Capturador de User-Agent</title><style>%CSS%</style></head><body>
<header><div class="w"><h1>🕵️ Capturador de User-Agent</h1>
<p>Cada petición HTTP revela información del cliente que la envía.</p></div></header>
%NAV%
<main class="w">
<section class="card"><h2>Tu cliente ahora mismo</h2>
<div class="chips" id="yo-chips"></div>
<div class="ua" id="yo-ua">Cargando…</div></section>
<section class="card"><h2>Historial (últimas 100)</h2>
<div style="overflow-x:auto"><table>
<thead><tr><th>Hora</th><th>IP</th><th>Ruta</th><th>Navegador</th><th>Versión</th><th>Sistema</th><th>Dispositivo</th><th>Tipo</th><th>User-Agent</th></tr></thead>
<tbody id="filas"><tr><td colspan="9" class="sub" style="text-align:center;padding:26px">Esperando peticiones…</td></tr></tbody>
</table></div></section>
</main>
<script>
function chip(t,v){const d=document.createElement('div');d.className='chip';
  const s=document.createElement('small');s.textContent=t;const b=document.createElement('b');b.textContent=v||'—';
  d.append(s,b);return d}
async function cargar(){
  try{
    const r=await fetch('/api/registro',{cache:'no-store'});const d=await r.json();
    const yo=d.yo;
    const c=document.getElementById('yo-chips');c.replaceChildren(
      chip('Navegador',yo.navegador),chip('Versión',yo.version),chip('Sistema',yo.so),
      chip('Dispositivo',yo.dispositivo),chip('Tipo',yo.tipo));
    document.getElementById('yo-ua').textContent=yo.ua;
    const tb=document.getElementById('filas');tb.innerHTML='';
    if(!d.registros.length){tb.innerHTML='<tr><td colspan="9" class="sub" style="text-align:center;padding:26px">Esperando peticiones…</td></tr>';return}
    d.registros.slice().reverse().forEach(x=>{
      const tr=document.createElement('tr');
      [x.hora,x.ip,x.metodo+' '+x.ruta,x.navegador,x.version,x.so,x.dispositivo,x.tipo].forEach(v=>{
        const td=document.createElement('td');td.textContent=v||'—';tr.appendChild(td)});
      const td=document.createElement('td');td.className='u';td.textContent=x.ua;tr.appendChild(td);
      tb.appendChild(tr);
    });
  }catch(e){}
}
cargar();setInterval(cargar,2000);
</script></body></html>"""

PAGINA_SCAN = """<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Escáner Web</title><style>%CSS%</style></head><body>
<header><div class="w"><h1>🔍 Escáner Web</h1>
<p>Análisis de cabeceras + enumeración pasiva/activa desde el navegador.</p></div></header>
%NAV%
<main class="w">

<section class="card"><h2>Nuevo escaneo</h2>
<form id="form">
  <label class="sub">Objetivo (dominio o URL)</label>
  <input type="text" id="target" placeholder="scanme.nmap.org" required>
  <fieldset><legend>Técnicas a ejecutar</legend>
    <label class="chk"><input type="checkbox" value="cabeceras" checked> Análisis de cabeceras de seguridad</label>
    <label class="chk"><input type="checkbox" value="pasiva" checked> Enumeración pasiva (DNS + WHOIS + crt.sh)</label>
    <label class="chk"><input type="checkbox" value="activa"> Enumeración activa (puertos + subdominios)</label>
  </fieldset>
  <button type="submit" id="btn">▶ Iniciar escaneo</button>
  <span class="sub" id="msg" style="margin-left:12px"></span>
</form></section>

<section class="card hidden" id="estado-card"><h2>Estado</h2>
<div class="sub" id="estado-txt">—</div>
<div class="log" id="log"></div></section>

<section class="card hidden" id="acciones"><h2>📥 Exportar reporte</h2>
<p class="sub" style="margin-top:0">Descarga el reporte completo con todos los hallazgos.</p>
<a id="btn-md" class="btn-dl" href="#" download>⬇ Markdown (.md)</a>
<a id="btn-html" class="btn-dl" href="#" download>⬇ HTML (.html)</a></section>

<section class="card hidden" id="res-cabeceras"><h2>Cabeceras de seguridad</h2><div id="cab-body"></div></section>
<section class="card hidden" id="res-dns"><h2>DNS</h2><pre id="dns-body"></pre></section>
<section class="card hidden" id="res-whois"><h2>WHOIS</h2><pre id="whois-body"></pre></section>
<section class="card hidden" id="res-subs"><h2>Subdominios (crt.sh)</h2><div id="subs-body"></div></section>
<section class="card hidden" id="res-puertos"><h2>Puertos abiertos</h2><div id="puertos-body"></div></section>
<section class="card hidden" id="res-bruta"><h2>Subdominios por fuerza bruta</h2><div id="bruta-body"></div></section>

</main>
<script>
const form=document.getElementById('form'),btn=document.getElementById('btn'),msg=document.getElementById('msg');
let poll=null;
form.addEventListener('submit',async ev=>{
  ev.preventDefault();
  const target=document.getElementById('target').value.trim();
  const tipos=[...form.querySelectorAll('input[type=checkbox]:checked')].map(c=>c.value);
  if(!tipos.length){msg.textContent='Selecciona al menos una técnica';return}
  btn.disabled=true;msg.textContent='Iniciando…';
  ['cabeceras','dns','whois','subs','puertos','bruta'].forEach(k=>document.getElementById('res-'+k).classList.add('hidden'));
  document.getElementById('acciones').classList.add('hidden');
  document.getElementById('log').textContent='';
  try{
    const r=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,tipos})});
    const d=await r.json();
    if(!d.id){msg.textContent='Error: '+(d.error||'desconocido');btn.disabled=false;return}
    msg.textContent='En curso…';
    document.getElementById('estado-card').classList.remove('hidden');
    seguir(d.id);
  }catch(e){msg.textContent='Error: '+e;btn.disabled=false}
});
function seguir(id){
  if(poll)clearInterval(poll);
  poll=setInterval(async()=>{
    try{
      const r=await fetch('/api/scan/'+id,{cache:'no-store'});const d=await r.json();
      render(d);
      if(d.estado==='completado'||d.estado==='error'){
        clearInterval(poll);poll=null;btn.disabled=false;
        msg.textContent=d.estado==='completado'?'✓ Completado':'✗ Error';
        activarDescargas(id,d.target);
      }
    }catch(e){}
  },1000);
}
function activarDescargas(id,target){
  const slug=target.replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,60);
  const ts=new Date().toISOString().slice(0,19).replace(/[:T]/g,'-');
  const md=document.getElementById('btn-md'),h=document.getElementById('btn-html');
  md.href='/api/scan/'+id+'/report.md';md.setAttribute('download','reporte_'+slug+'_'+ts+'.md');
  h.href='/api/scan/'+id+'/report.html';h.setAttribute('download','reporte_'+slug+'_'+ts+'.html');
  document.getElementById('acciones').classList.remove('hidden');
}
function render(d){
  document.getElementById('estado-txt').innerHTML=
    '<span class="tag">'+d.estado+'</span> &nbsp; Objetivo: <b>'+d.target+'</b> &nbsp; Inicio: '+d.inicio+(d.fin?' &nbsp; Fin: '+d.fin:'');
  document.getElementById('log').textContent=(d.log||[]).join('\\n');
  const R=d.resultados||{};
  if(R.cabeceras){
    const c=R.cabeceras;document.getElementById('res-cabeceras').classList.remove('hidden');
    let html='';
    if(c.error){html='<div class="sub">Error: '+c.error+'</div>';}
    else{
      html+='<div class="sub" style="margin-bottom:12px">URL: <code>'+c.url+'</code> · HTTP: <b>'+c.estado+'</b> · Puntuación: <b>'+c.score+'/'+c.total+'</b><br>UA usado: <code style="word-break:break-all">'+c.ua_usado+'</code></div>';
      html+='<table><thead><tr><th>Cabecera</th><th>Estado</th><th>Valor</th><th>Propósito</th></tr></thead><tbody>';
      c.seguridad.forEach(x=>{html+='<tr><td><code>'+x.nombre+'</code></td><td class="'+(x.ok?'ok':'no')+'">'+(x.ok?'✔':'✘')+'</td><td class="u">'+(x.valor||'—')+'</td><td class="sub">'+x.desc+'</td></tr>'});
      html+='</tbody></table>';
      if(c.info.length){
        html+='<h3 style="margin-top:18px;color:var(--err)">⚠ Información filtrada</h3><table><thead><tr><th>Cabecera</th><th>Valor</th></tr></thead><tbody>';
        c.info.forEach(x=>{html+='<tr><td><code>'+x.nombre+'</code></td><td class="u">'+x.valor+'</td></tr>'});
        html+='</tbody></table>';
      }
    }
    document.getElementById('cab-body').innerHTML=html;
  }
  if(R.dns){document.getElementById('res-dns').classList.remove('hidden');document.getElementById('dns-body').textContent=JSON.stringify(R.dns,null,2)}
  if(R.whois){document.getElementById('res-whois').classList.remove('hidden');document.getElementById('whois-body').textContent=R.whois}
  if(R.subdominios_crtsh){
    document.getElementById('res-subs').classList.remove('hidden');
    const arr=R.subdominios_crtsh;
    document.getElementById('subs-body').innerHTML='<div class="sub" style="margin-bottom:10px">'+arr.length+' entradas</div>'+(arr.length?'<pre>'+arr.join('\\n')+'</pre>':'<div class="sub">Sin resultados</div>');
  }
  if(R.puertos){
    document.getElementById('res-puertos').classList.remove('hidden');
    let html='<div class="sub" style="margin-bottom:10px">IP: <code>'+R.ip+'</code> · '+R.puertos.length+' puertos</div>';
    if(R.puertos.length){
      html+='<table><thead><tr><th>Puerto</th><th>Servicio</th><th>Banner</th></tr></thead><tbody>';
      R.puertos.forEach(p=>{html+='<tr><td><b>'+p.puerto+'/tcp</b></td><td>'+p.servicio+'</td><td class="u">'+(p.banner||'—')+'</td></tr>'});
      html+='</tbody></table>';
    }else{html+='<div class="sub">Ningún puerto común abierto</div>'}
    document.getElementById('puertos-body').innerHTML=html;
  }
  if(R.subdominios_bruta){
    document.getElementById('res-bruta').classList.remove('hidden');
    const b=R.subdominios_bruta;let html='';
    if(b.comodin)html+='<div class="sub" style="color:var(--err)">⚠ DNS comodín: '+b.comodin+'</div>';
    if(b.encontrados.length){
      html+='<table><thead><tr><th>Subdominio</th><th>IP</th></tr></thead><tbody>';
      b.encontrados.forEach(x=>{html+='<tr><td><code>'+x.nombre+'</code></td><td class="u">'+x.ip+'</td></tr>'});
      html+='</tbody></table>';
    }else{html+='<div class="sub">Sin subdominios válidos</div>'}
    document.getElementById('bruta-body').innerHTML=html;
  }
}
</script></body></html>"""

PAGINA_LAB = """<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lab User-Agent</title><style>%CSS%</style></head><body>
<header><div class="w"><h1>🧪 Laboratorio de User-Agents</h1>
<p>Pega cualquier User-Agent y observa cómo se analiza en detalle.</p></div></header>
%NAV%
<main class="w">
<section class="card"><h2>Analizar User-Agent</h2>
  <p class="sub" style="margin-top:0">Motor: <b id="motor">—</b></p>
  <textarea id="ua-input" rows="3" placeholder="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ..."></textarea>
  <div style="margin-top:12px">
    <button id="btn-analizar">🔬 Analizar</button>
  </div>
</section>

<section class="card"><h2>Ejemplos predefinidos</h2>
<div class="chips" id="ejemplos"></div>
</section>

<section class="card hidden" id="res-card"><h2>Resultado del análisis</h2>
  <div class="chips" id="res-chips"></div>
  <div class="ua" id="res-ua"></div>
  <h3 style="color:var(--mu);font-size:13px;text-transform:uppercase;letter-spacing:.08em;margin-top:20px">JSON crudo</h3>
  <pre id="res-json"></pre>
</section>
</main>
<script>
const EJEMPLOS=[
  ['Chrome Windows','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'],
  ['Firefox Linux','Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0'],
  ['Safari iPhone','Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'],
  ['Safari iPad','Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'],
  ['Edge Windows','Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'],
  ['curl','curl/8.4.0'],
  ['Wget','Wget/1.21.3'],
  ['python-requests','python-requests/2.31.0'],
  ['Googlebot','Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'],
  ['Nikto','Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:map_codes)'],
  ['sqlmap','sqlmap/1.7.2#stable (http://sqlmap.org)'],
  ['Vacio',''],
];
function chip(t,v){const d=document.createElement('div');d.className='chip';
  const s=document.createElement('small');s.textContent=t;const b=document.createElement('b');b.textContent=v||'—';
  d.append(s,b);return d}
const ej=document.getElementById('ejemplos');
EJEMPLOS.forEach(([n,v])=>{
  const b=document.createElement('button');b.className='tag';b.style.cursor='pointer';b.textContent=n;
  b.onclick=()=>{document.getElementById('ua-input').value=v;analizar()};
  ej.appendChild(b);
});
async function analizar(){
  const ua=document.getElementById('ua-input').value;
  const r=await fetch('/api/ua/parse',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ua})});
  const d=await r.json();
  document.getElementById('res-card').classList.remove('hidden');
  const c=document.getElementById('res-chips');c.replaceChildren(
    chip('Navegador',d.navegador),chip('Versión',d.version),chip('Sistema',d.so),
    chip('Dispositivo',d.dispositivo),chip('Tipo',d.tipo));
  document.getElementById('res-ua').textContent=d.ua;
  document.getElementById('res-json').textContent=JSON.stringify(d,null,2);
}
document.getElementById('btn-analizar').onclick=analizar;
// Autocompletar con el UA del navegador
document.getElementById('ua-input').value=navigator.userAgent;
fetch('/api/motor').then(r=>r.json()).then(d=>{document.getElementById('motor').textContent=d.motor}).catch(()=>{});
</script></body></html>"""


def pagina_ua():
    return PAGINA_UA.replace("%CSS%", CSS).replace("%NAV%", NAV.format(ua_on="on", scan_on="", lab_on=""))


def pagina_scan():
    return PAGINA_SCAN.replace("%CSS%", CSS).replace("%NAV%", NAV.format(ua_on="", scan_on="on", lab_on=""))


def pagina_lab():
    return PAGINA_LAB.replace("%CSS%", CSS).replace("%NAV%", NAV.format(ua_on="", scan_on="", lab_on="on"))


# ============================================================
#  Servidor HTTP
# ============================================================
class Handler(BaseHTTPRequestHandler):
    server_version = "EscannerWeb/2.0"

    def _send(self, code, ctype, body=b""):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, obj, code=200):
        self._send(code, "application/json; charset=utf-8",
                   json.dumps(obj, ensure_ascii=False).replace("<", "\\u003c").encode())

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return {}

    # ------- GET -------
    def do_GET(self):
        ruta = self.path.split("?")[0]

        if ruta == "/api/registro":
            ua = self.headers.get("User-Agent", "")
            with lock_ua:
                regs = list(registro_ua)
                total = contador_ua[0]
            return self._send_json({
                "yo": analizar_ua_avanzado(ua),
                "registros": regs,
                "total": total,
            })

        if ruta == "/api/motor":
            return self._send_json({
                "motor": "ua-parser" if UA_PARSER_OK else "fallback (instala: pip install ua-parser)"
            })

        if ruta.startswith("/api/scan/"):
            resto = ruta[len("/api/scan/"):]
            if "/" in resto:
                sid, fmt = resto.split("/", 1)
            else:
                sid, fmt = resto, ""
            with lock:
                d = escaneos.get(sid)
            if not d:
                return self._send_json({"error": "no encontrado"}, 404)
            if fmt == "report.md":
                md = generar_markdown(sid) or "# Reporte no disponible\n"
                return self._send(200, "text/markdown; charset=utf-8", md.encode())
            if fmt == "report.html":
                html = generar_html(sid) or "<h1>Reporte no disponible</h1>"
                return self._send(200, "text/html; charset=utf-8", html.encode())
            return self._send_json(d)

        if ruta == "/scan":
            capturar_ua(self, ruta)
            return self._send(200, "text/html; charset=utf-8", pagina_scan().encode())
        if ruta == "/ua-lab":
            capturar_ua(self, ruta)
            return self._send(200, "text/html; charset=utf-8", pagina_lab().encode())
        if ruta == "/favicon.ico":
            return self._send(204, "image/x-icon")
        if ruta == "/":
            capturar_ua(self, ruta)
            return self._send(200, "text/html; charset=utf-8", pagina_ua().encode())
        self._send(404, "text/plain; charset=utf-8", b"404")

    # ------- POST -------
    def do_POST(self):
        ruta = self.path.split("?")[0]

        if ruta == "/api/ua/parse":
            data = self._read_json()
            ua = data.get("ua") or self.headers.get("User-Agent", "")
            return self._send_json(analizar_ua_avanzado(ua))

        if ruta == "/api/scan":
            data = self._read_json()
            target = (data.get("target") or "").strip()
            tipos = data.get("tipos") or []
            if not target or not tipos:
                return self._send_json({"error": "faltan parámetros"}, 400)
            sid = _nuevo_sid()
            with lock:
                escaneos[sid] = {
                    "id": sid, "target": target, "tipos": tipos,
                    "estado": "en curso",
                    "inicio": datetime.now().strftime("%H:%M:%S"),
                    "fin": None, "resultados": {}, "log": [],
                }
            threading.Thread(target=ejecutar_escaneo, args=(sid, target, tipos), daemon=True).start()
            return self._send_json({"id": sid})

        self._send(404, "text/plain", b"404")

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    puerto = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"Servidor en http://localhost:{puerto}")
    print(f"  · Panel UA   → http://localhost:{puerto}/")
    print(f"  · Escáner    → http://localhost:{puerto}/scan")
    print(f"  · Lab UA     → http://localhost:{puerto}/ua-lab")
    print(f"  · ua-parser  → {'OK' if UA_PARSER_OK else 'NO INSTALADO (pip install ua-parser)'}")
    try:
        ThreadingHTTPServer(("0.0.0.0", puerto), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nServidor detenido.")
