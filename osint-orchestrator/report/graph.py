import os
import re
from datetime import datetime
from pyvis.network import Network
from colorama import Fore

# Estilo por tipo de nodo (vis.js)
COLORES = {
    "target":     {"color": "#2c3e50", "shape": "star",     "size": 30},
    "dominio":    {"color": "#3498db", "shape": "box",      "size": 20},
    "subdominio": {"color": "#85c1e9", "shape": "box",      "size": 14},
    "email":      {"color": "#e67e22", "shape": "dot",      "size": 18},
    "brecha":     {"color": "#e74c3c", "shape": "triangle", "size": 16},
    "username":   {"color": "#9b59b6", "shape": "dot",      "size": 18},
    "perfil":     {"color": "#bb8fce", "shape": "box",      "size": 14},
    "puerto":     {"color": "#16a085", "shape": "hexagon",  "size": 16},
    "dns":        {"color": "#f39c12", "shape": "diamond",  "size": 16},
    "confirmado": {"color": "#27ae60", "shape": "box",      "size": 16},   # Sherlock + Maigret
    "dudoso":     {"color": "#f1c40f", "shape": "box",      "size": 14},   # solo una fuente
}


def _perfiles_cruzados(data):
    """Perfiles con confianza. Usa el cruce si existe; si no (reportes antiguos), lo calcula."""
    cruce = data.get("cruce")
    if cruce and "perfiles" in cruce:
        return cruce["perfiles"]
    from modules.person import cruce as modulo_cruce
    return modulo_cruce.run(data.get("social"), data.get("maigret"))["perfiles"]


def _nodo(net, id_nodo, label, tipo="dominio", title=None, url=None):
    """Añade un nodo. 'url' = a dónde navegar al hacer clic."""
    estilo = COLORES.get(tipo, COLORES["dominio"])
    tooltip = title or label
    if url:
        tooltip = f"{tooltip}\n🔗 {url}"
    net.add_node(
        id_nodo,
        label=label,
        color=estilo["color"],
        shape=estilo["shape"],
        size=estilo["size"],
        title=tooltip,
        url=url or "",
        font={"color": "#2c3e50", "size": 14},
    )


def _nueva_red(height="750px"):
    net = Network(
        height=height, width="100%",
        bgcolor="#f4f6f9", font_color="#2c3e50",
        directed=True, cdn_resources="in_line",  # HTML autónomo, funciona offline
    )
    return net


def _nombre_unico(prefijo, target):
    target_limpio = re.sub(r'[^a-zA-Z0-9.-]', '_', str(target))
    fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"output/{prefijo}_{target_limpio}_{fecha}.html"


def _guardar(net, filename):
    os.makedirs(os.path.dirname(filename) or ".", exist_ok=True)
    net.write_html(filename, notebook=False)
    _inyectar_click_handler(filename)


# ======================================================================
# Grafo de UN objetivo
# ======================================================================
def generate_graph(reporte, filename=None):
    """Genera un grafo INTERACTIVO (HTML). Clic en un nodo abre su URL."""
    target = reporte.get("target", "desconocido")
    tipo_target = reporte.get("type", "unknown")
    data = reporte.get("data", {})

    if filename is None:
        filename = _nombre_unico("grafo", target)

    print(f"{Fore.YELLOW}[+] Generando grafo interactivo para: {target}")

    net = _nueva_red()
    net.barnes_hut(gravity=-8000, spring_length=120)

    id_target = "target"
    _nodo(net, id_target, f"{target}", "target", title=f"Objetivo ({tipo_target})")

    # ---------------- DOMINIO ----------------
    if tipo_target == "domain":
        whois = data.get("pasivo", {}).get("whois", {})
        if whois.get("registrador"):
            _nodo(net, "whois", "WHOIS", "dns")
            net.add_edge(id_target, "whois")
            reg = str(whois.get("registrador", ""))[:40]
            _nodo(net, "registrador", reg, "subdominio")
            net.add_edge("whois", "registrador")

        dns_data = data.get("pasivo", {}).get("dns", {})
        for tipo_reg, valores in dns_data.items():
            if not valores:
                continue
            id_dns = f"dns_{tipo_reg}"
            _nodo(net, id_dns, tipo_reg, "dns")
            net.add_edge(id_target, id_dns)
            for i, valor in enumerate(valores[:3]):
                vid = f"dns_{tipo_reg}_{i}"
                _nodo(net, vid, str(valor)[:40], "subdominio")
                net.add_edge(id_dns, vid)

        harv = data.get("theharvester", {})
        if harv.get("subdominios"):
            _nodo(net, "theHarvester", f"theHarvester ({len(harv['subdominios'])})", "dns")
            net.add_edge(id_target, "theHarvester")
            for i, sub in enumerate(harv["subdominios"][:15]):
                sid = f"harv_sub_{i}"
                sub = str(sub)
                _nodo(net, sid, sub[:40], "subdominio", url=f"http://{sub}")
                net.add_edge("theHarvester", sid)
        for i, email in enumerate(harv.get("emails", [])[:5]):
            mid = f"harv_mail_{i}"
            _nodo(net, mid, str(email)[:35], "email")
            net.add_edge(id_target, mid)

        nmap = data.get("activo", {}).get("nmap", {})
        for i, p in enumerate(nmap.get("puertos_abiertos", [])[:10]):
            pid = f"puerto_{i}"
            _nodo(net, pid, f"{p['puerto']}/{p['servicio']}", "puerto",
                  title=f"Puerto {p['puerto']} - {p.get('version', '')}")
            net.add_edge(id_target, pid)

        dirs = data.get("activo", {}).get("directorios", {}).get("directorios_encontrados", [])
        base = target if str(target).startswith("http") else f"http://{target}"
        for i, d in enumerate(dirs[:8]):
            did = f"dir_{i}"
            _nodo(net, did, d["path"], "subdominio",
                  title=f"Status {d.get('status_code')}",
                  url=f"{base.rstrip('/')}{d['path']}")
            net.add_edge(id_target, did)

    # ---------------- EMAIL ----------------
    elif tipo_target == "email":
        brechas_hibp = data.get("brechas_hibp", {}).get("brechas", [])
        if brechas_hibp:
            _nodo(net, "hibp", f"HIBP ({len(brechas_hibp)})", "brecha")
            net.add_edge(id_target, "hibp")
            for i, b in enumerate(brechas_hibp[:10]):
                bid = f"hibp_{i}"
                _nodo(net, bid, str(b.get("nombre", "?"))[:30], "brecha",
                      title=f"Brecha {b.get('nombre', '?')} ({b.get('fecha', '?')})")
                net.add_edge("hibp", bid)

        brechas_xon = data.get("brechas_xposedornot", {}).get("brechas", [])
        if brechas_xon:
            _nodo(net, "xon", f"XposedOrNot ({len(brechas_xon)})", "brecha")
            net.add_edge(id_target, "xon")
            for i, b in enumerate(brechas_xon[:15]):
                bid = f"xon_{i}"
                _nodo(net, bid, str(b.get("nombre", "?"))[:30], "brecha")
                net.add_edge("xon", bid)

        sitios = data.get("holehe", {}).get("sitios", [])
        if sitios:
            _nodo(net, "holehe", f"Holehe ({len(sitios)})", "dns")
            net.add_edge(id_target, "holehe")
            for i, s in enumerate(sitios[:20]):
                sid = f"holehe_{i}"
                dominio = str(s.get("sitio", "?"))
                _nodo(net, sid, dominio[:25], "perfil",
                      title=f"Registrado en {dominio}", url=f"https://{dominio}")
                net.add_edge("holehe", sid)

    # ---------------- USERNAME ----------------
    elif tipo_target == "username":
        perfiles = _perfiles_cruzados(data)
        grupos = [
            ("alta", "conf", "✓ Confirmados", "confirmado"),
            ("media", "dud", "? Sin confirmar", "dudoso"),
        ]
        for confianza, gid, titulo, estilo in grupos:
            del_grupo = [p for p in perfiles if p["confianza"] == confianza]
            if not del_grupo:
                continue
            _nodo(net, gid, f"{titulo} ({len(del_grupo)})", estilo,
                  title="Encontrado por Sherlock y Maigret" if confianza == "alta"
                  else "Solo una fuente: verificar a mano")
            net.add_edge(id_target, gid)
            for i, p in enumerate(del_grupo[:30]):
                pid = f"{gid}_{i}"
                _nodo(net, pid, str(p["red"])[:25], estilo,
                      title=f"{p['red']} — {' + '.join(p['fuentes'])}", url=p["url"])
                net.add_edge(gid, pid)

    # ---------------- TELÉFONO ----------------
    elif tipo_target == "phone":
        tel = data.get("telefono", {})
        if tel and not tel.get("error"):
            if tel.get("pais"):
                _nodo(net, "pais", f"País: {tel['pais']}", "dns")
                net.add_edge(id_target, "pais")
            if tel.get("operador") and tel["operador"] != "Desconocido":
                _nodo(net, "operador", f"Op. original: {tel['operador']}", "subdominio",
                      title="Operador del rango original; puede variar por portabilidad")
                net.add_edge(id_target, "operador")
            if tel.get("tipo_linea"):
                _nodo(net, "tipo", f"Tipo: {tel['tipo_linea']}", "puerto")
                net.add_edge(id_target, "tipo")
            for i, zh in enumerate(tel.get("zonas_horarias", [])[:3]):
                _nodo(net, f"zh_{i}", zh, "perfil")
                net.add_edge(id_target, f"zh_{i}")
            estado = "✓ Válido" if tel.get("valido") else "✗ No válido"
            _nodo(net, "validez", estado, "dns" if tel.get("valido") else "brecha")
            net.add_edge(id_target, "validez")

    _guardar(net, filename)
    print(f"{Fore.GREEN}[*] Grafo interactivo guardado en: {filename}")
    return filename


# ======================================================================
# Clic en nodo -> abrir su URL
# ======================================================================
def _inyectar_click_handler(filename):
    """Añade un listener de clic a vis.js: al pulsar un nodo con URL, la abre."""
    js = """
    <script type="text/javascript">
      // Espera a que la red esté lista y engancha el evento de clic
      setTimeout(function () {
        if (typeof network !== "undefined") {
          network.on("click", function (params) {
            if (params.nodes.length > 0) {
              var nodo = nodes.get(params.nodes[0]);
              if (nodo && nodo.url) {
                window.open(nodo.url, "_blank");
              }
            }
          });
        }
      }, 1000);
    </script>
    """
    with open(filename, "r", encoding="utf-8") as f:
        html = f.read()
    html = html.replace("</body>", js + "\n</body>")
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)


# ======================================================================
# Grafo MAESTRO de una sesión interactiva
# ======================================================================
def generate_session_graph(reportes, historial, filename=None):
    """
    Conecta todos los objetivos de una sesión interactiva,
    mostrando cómo se pivotó de uno a otro (flechas rojas discontinuas).
    'reportes' = lista de reportes. 'historial' = lista de {target, type, origen}.
    """
    if filename is None:
        fecha = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"output/sesion_{fecha}.html"

    print(f"{Fore.YELLOW}[+] Generando grafo maestro de la sesión ({len(reportes)} objetivos)...")

    net = _nueva_red(height="800px")
    net.barnes_hut(gravity=-12000, spring_length=180, spring_strength=0.02)

    id_raiz = {}
    for idx, rep in enumerate(reportes):
        target = rep.get("target", "?")
        tipo = rep.get("type", "unknown")
        root_id = f"obj_{idx}"
        id_raiz[target] = root_id
        _nodo(net, root_id, f"{target}\n({tipo})", "target",
              title=f"Objetivo {tipo}: {target}")
        _añadir_hallazgos(net, rep, root_id, idx)

    for entrada in historial:
        target, origen = entrada["target"], entrada.get("origen")
        if origen and origen in id_raiz and target in id_raiz:
            net.add_edge(id_raiz[origen], id_raiz[target],
                         color="#e74c3c", width=3, title="pivote", dashes=True)

    _guardar(net, filename)
    print(f"{Fore.GREEN}[*] Grafo maestro guardado en: {filename}")
    return filename


def _añadir_hallazgos(net, rep, root_id, idx):
    """Cuelga los hallazgos de un reporte de su nodo raíz. El sufijo evita colisiones de IDs."""
    data = rep.get("data", {})
    tipo = rep.get("type", "unknown")
    p = f"_{idx}"

    if tipo == "email":
        for i, b in enumerate(data.get("brechas_hibp", {}).get("brechas", [])[:8]):
            nid = f"hibp{p}_{i}"
            _nodo(net, nid, str(b.get("nombre", "?"))[:25], "brecha")
            net.add_edge(root_id, nid)
        for i, b in enumerate(data.get("brechas_xposedornot", {}).get("brechas", [])[:8]):
            nid = f"xon{p}_{i}"
            _nodo(net, nid, str(b.get("nombre", "?"))[:25], "brecha")
            net.add_edge(root_id, nid)
        for i, s in enumerate(data.get("holehe", {}).get("sitios", [])[:15]):
            nid = f"hol{p}_{i}"
            dom = str(s.get("sitio", "?"))
            _nodo(net, nid, dom[:22], "perfil", url=f"https://{dom}")
            net.add_edge(root_id, nid)

    elif tipo == "username":
        for i, perf in enumerate(_perfiles_cruzados(data)[:25]):
            nid = f"usr{p}_{i}"
            estilo = "confirmado" if perf["confianza"] == "alta" else "dudoso"
            _nodo(net, nid, str(perf["red"])[:22], estilo,
                  title=f"{perf['red']} — {' + '.join(perf['fuentes'])}", url=perf["url"])
            net.add_edge(root_id, nid)

    elif tipo == "domain":
        harv = data.get("theharvester", {})
        for i, sub in enumerate(harv.get("subdominios", [])[:12]):
            nid = f"sub{p}_{i}"
            _nodo(net, nid, str(sub)[:30], "subdominio", url=f"http://{sub}")
            net.add_edge(root_id, nid)
        nmap = data.get("activo", {}).get("nmap", {})
        for i, pt in enumerate(nmap.get("puertos_abiertos", [])[:10]):
            nid = f"prt{p}_{i}"
            _nodo(net, nid, f"{pt['puerto']}/{pt['servicio']}", "puerto")
            net.add_edge(root_id, nid)

    elif tipo == "phone":
        tel = data.get("telefono", {})
        if tel.get("operador") and tel["operador"] != "Desconocido":
            nid = f"op{p}"
            _nodo(net, nid, f"Op. original: {tel['operador']}", "subdominio",
                  title="Operador del rango original; puede variar por portabilidad")
            net.add_edge(root_id, nid)
        if tel.get("pais"):
            nid = f"pais{p}"
            _nodo(net, nid, tel["pais"], "dns")
            net.add_edge(root_id, nid)
