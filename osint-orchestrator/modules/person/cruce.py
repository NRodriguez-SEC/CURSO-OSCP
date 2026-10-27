"""
cruce.py - Cruza los perfiles de Sherlock y Maigret para medir la confianza.

  - confianza "alta"  -> lo encuentran las dos herramientas (fiable)
  - confianza "media" -> solo lo encuentra una (verificar a mano; posible falso positivo)

Empareja por nombre de sitio normalizado ("YouTube" == "youtube")
y, si no coincide, por dominio de la URL ("www.github.com" == "github.com").
"""
import re
from urllib.parse import urlparse
from colorama import Fore


def _norm_nombre(nombre):
    """'Xbox Gamertag' -> 'xboxgamertag'. Quita lo que va entre corchetes: 'Picuki [TikTok]' -> 'picuki'."""
    nombre = re.sub(r"\[.*?\]|\(.*?\)", "", str(nombre))
    return re.sub(r"[^a-z0-9]", "", nombre.lower())


def _norm_dominio(url):
    try:
        host = urlparse(url).netloc.lower()
    except Exception:
        return ""
    return host[4:] if host.startswith("www.") else host


def run(sherlock_data, maigret_data):
    """Recibe los dicts devueltos por social.run() y maigret.run(). Devuelve el cruce."""
    sherlock = (sherlock_data or {}).get("perfiles", []) or []
    maigret = (maigret_data or {}).get("perfiles", []) or []

    perfiles = []          # resultado final
    por_nombre = {}        # nombre normalizado -> perfil del resultado
    por_dominio = {}       # dominio de la url  -> perfil del resultado

    def registrar(p):
        por_nombre[_norm_nombre(p["red"])] = p
        for u in p["urls"]:
            d = _norm_dominio(u)
            if d:
                por_dominio[d] = p

    # 1) Todo lo de Sherlock entra como "solo Sherlock"
    for s in sherlock:
        p = {"red": s.get("red", "?"), "url": s.get("url", ""), "urls": [s.get("url", "")],
             "fuentes": ["Sherlock"], "extra": {}}
        perfiles.append(p)
        registrar(p)

    # 2) Cada perfil de Maigret: si casa con uno de Sherlock, se confirma; si no, se añade
    for m in maigret:
        nombre, url = m.get("red", "?"), m.get("url", "")
        existente = por_nombre.get(_norm_nombre(nombre)) or por_dominio.get(_norm_dominio(url))
        if existente and "Maigret" not in existente["fuentes"]:
            existente["fuentes"].append("Maigret")
            if url and url not in existente["urls"]:
                existente["urls"].append(url)
            existente["extra"] = m.get("extra", {}) or {}
        else:
            p = {"red": nombre, "url": url, "urls": [url], "fuentes": ["Maigret"],
                 "extra": m.get("extra", {}) or {}}
            perfiles.append(p)
            registrar(p)

    for p in perfiles:
        p["confianza"] = "alta" if len(p["fuentes"]) == 2 else "media"

    # Confirmados primero, luego por nombre
    perfiles.sort(key=lambda p: (p["confianza"] != "alta", p["red"].lower()))

    resumen = {
        "confirmados": sum(1 for p in perfiles if p["confianza"] == "alta"),
        "solo_sherlock": sum(1 for p in perfiles if p["fuentes"] == ["Sherlock"]),
        "solo_maigret": sum(1 for p in perfiles if p["fuentes"] == ["Maigret"]),
    }
    print(f"{Fore.GREEN}    - Cruce: {resumen['confirmados']} confirmados por ambas | "
          f"{resumen['solo_sherlock']} solo Sherlock | {resumen['solo_maigret']} solo Maigret")

    return {"perfiles": perfiles, **resumen}
