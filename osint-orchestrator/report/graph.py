import os
from graphviz import Digraph
from colorama import Fore

# Colores por tipo de nodo (estilo pastel profesional)
COLORES = {
    "target":       {"fill": "#2c3e50", "font": "white", "shape": "doubleoctagon"},
    "dominio":      {"fill": "#3498db", "font": "white", "shape": "box"},
    "subdominio":   {"fill": "#85c1e9", "font": "black", "shape": "box"},
    "email":        {"fill": "#e67e22", "font": "white", "shape": "ellipse"},
    "brecha":       {"fill": "#e74c3c", "font": "white", "shape": "note"},
    "username":     {"fill": "#9b59b6", "font": "white", "shape": "ellipse"},
    "perfil":       {"fill": "#bb8fce", "font": "black", "shape": "box"},
    "puerto":       {"fill": "#16a085", "font": "white", "shape": "hexagon"},
    "dns":          {"fill": "#f39c12", "font": "white", "shape": "parallelogram"},
}


def _nodo(dot, id_nodo, label, tipo="dominio"):
    """Añade un nodo con estilo según su tipo."""
    estilo = COLORES.get(tipo, COLORES["dominio"])
    dot.node(
        id_nodo,
        label=label,
        style="filled,rounded",
        fillcolor=estilo["fill"],
        fontcolor=estilo["font"],
        shape=estilo["shape"],
        fontname="Helvetica"
    )


def generate_graph(reporte, filename="output/grafo"):
    """
    Genera un grafo de relaciones a partir del reporte.
    Devuelve la ruta del archivo PNG generado.
    """
    target = reporte.get("target", "desconocido")
    tipo_target = reporte.get("type", "unknown")
    data = reporte.get("data", {})

    print(f"{Fore.YELLOW}[+] Generando grafo de relaciones para: {target}")

    dot = Digraph(
        name="OSINT",
        format="png",
        graph_attr={
            "rankdir": "LR",       # Izquierda a derecha
            "bgcolor": "#f4f6f9",
            "fontname": "Helvetica",
            "splines": "true",
            "overlap": "false",
            "nodesep": "0.5",
            "ranksep": "1.0"
        },
        node_attr={"fontname": "Helvetica", "fontsize": "11"},
        edge_attr={"color": "#7f8c8d", "arrowsize": "0.7"}
    )

    # Nodo central: el target
    id_target = "target"
    _nodo(dot, id_target, f"{target}\n({tipo_target})", "target")

    # ------------------------------------------------------------------
    # CASO 1: DOMINIO
    # ------------------------------------------------------------------
    if tipo_target == "domain":
        # WHOIS
        if data.get("pasivo", {}).get("whois", {}).get("registrador"):
            id_whois = "whois"
            _nodo(dot, id_whois, "WHOIS", "dns")
            dot.edge(id_target, id_whois)
            registrador = data["pasivo"]["whois"].get("registrador", "")[:40]
            id_reg = "registrador"
            _nodo(dot, id_reg, registrador, "subdominio")
            dot.edge(id_whois, id_reg)

        # DNS
        dns_data = data.get("pasivo", {}).get("dns", {})
        for tipo_reg, valores in dns_data.items():
            if not valores:
                continue
            id_dns = f"dns_{tipo_reg}"
            _nodo(dot, id_dns, tipo_reg, "dns")
            dot.edge(id_target, id_dns)
            for i, valor in enumerate(valores[:3]):  # máximo 3 por tipo
                id_val = f"dns_{tipo_reg}_{i}"
                _nodo(dot, id_val, valor[:40], "subdominio")
                dot.edge(id_dns, id_val)

        # theHarvester
        harv = data.get("theharvester", {})
        if harv.get("subdominios"):
            id_harv = "theHarvester"
            _nodo(dot, id_harv, f"theHarvester\n({len(harv['subdominios'])} subs)", "dns")
            dot.edge(id_target, id_harv)
            for i, sub in enumerate(harv["subdominios"][:15]):  # máximo 15
                id_sub = f"harv_sub_{i}"
                _nodo(dot, id_sub, sub[:40], "subdominio")
                dot.edge(id_harv, id_sub)
        if harv.get("emails"):
            for i, email in enumerate(harv["emails"][:5]):
                id_mail = f"harv_mail_{i}"
                _nodo(dot, id_mail, email[:35], "email")
                dot.edge(id_target, id_mail)

        # Nmap - Puertos abiertos
        nmap = data.get("activo", {}).get("nmap", {})
        for i, p in enumerate(nmap.get("puertos_abiertos", [])[:10]):
            id_p = f"puerto_{i}"
            label = f"Puerto {p['puerto']}\n{p['servicio']}"
            _nodo(dot, id_p, label, "puerto")
            dot.edge(id_target, id_p)

        # Directorios encontrados
        dirs = data.get("activo", {}).get("directorios", {}).get("directorios_encontrados", [])
        for i, d in enumerate(dirs[:8]):
            id_d = f"dir_{i}"
            _nodo(dot, id_d, d["path"], "subdominio")
            dot.edge(id_target, id_d)

    # ------------------------------------------------------------------
    # CASO 2: EMAIL
    # ------------------------------------------------------------------
    elif tipo_target == "email":
        # Brechas HIBP
        brechas_hibp = data.get("brechas", {}).get("brechas", [])
        if brechas_hibp:
            id_hibp = "hibp"
            _nodo(dot, id_hibp, f"HIBP\n({len(brechas_hibp)} brechas)", "brecha")
            dot.edge(id_target, id_hibp)
            for i, b in enumerate(brechas_hibp[:10]):
                id_b = f"hibp_{i}"
                _nodo(dot, id_b, b.get("nombre", "?")[:30], "brecha")
                dot.edge(id_hibp, id_b)

        # Brechas XposedOrNot
        brechas_xon = data.get("brechas_xposedornot", {}).get("brechas", [])
        if brechas_xon:
            id_xon = "xon"
            _nodo(dot, id_xon, f"XposedOrNot\n({len(brechas_xon)} brechas)", "brecha")
            dot.edge(id_target, id_xon)
            # Solo mostramos las primeras 15 para no saturar
            for i, b in enumerate(brechas_xon[:15]):
                id_b = f"xon_{i}"
                _nodo(dot, id_b, b.get("nombre", "?")[:30], "brecha")
                dot.edge(id_xon, id_b)

    # ------------------------------------------------------------------
    # CASO 3: USERNAME
    # ------------------------------------------------------------------
    elif tipo_target == "username":
        perfiles = data.get("social", {}).get("perfiles", [])
        if perfiles:
            id_sherlock = "sherlock"
            _nodo(dot, id_sherlock, f"Sherlock\n({len(perfiles)} perfiles)", "perfil")
            dot.edge(id_target, id_sherlock)
            for i, p in enumerate(perfiles[:25]):  # máximo 25 redes
                id_p = f"perfil_{i}"
                _nodo(dot, id_p, p.get("red", "?")[:25], "perfil")
                dot.edge(id_sherlock, id_p)

    # ------------------------------------------------------------------
    # Guardar el PNG
    # ------------------------------------------------------------------
    # Aseguramos que la carpeta output existe
    os.makedirs("output", exist_ok=True)
    ruta_png = dot.render(filename=filename, cleanup=True)

    print(f"{Fore.GREEN}[*] Grafo guardado en: {ruta_png}")
    return ruta_png
