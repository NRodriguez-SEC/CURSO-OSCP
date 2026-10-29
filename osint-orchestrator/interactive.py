"""
interactive.py - Modo de investigación interactiva (man-in-the-loop).
Flujo de pivotes: cada hallazgo abre nuevos objetivos sobre los que saltar.
Ejecuta:  python3 interactive.py
"""
import argparse
import os
import re
import sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.prompt import Prompt, Confirm
from rich import box

# Reutilizamos el núcleo de main.py
from main import detect_target_type, run_investigation

console = Console()


def banner():
    console.print(Panel.fit(
        "[bold cyan]OSINT ORCHESTRATOR[/]\n[yellow]Modo Investigación Interactiva[/]\n"
        "[dim]Pivota sobre cada hallazgo — auditorías autorizadas[/]",
        border_style="cyan", box=box.DOUBLE,
    ))


def extraer_pivotes(reporte):
    """Saca de un reporte los datos sobre los que se puede pivotar.
    Devuelve lista de (tipo, valor, origen)."""
    pivotes = []
    data = reporte.get("data", {})
    tipo = reporte.get("type")

    if tipo == "domain":
        harv = data.get("theharvester", {})
        for email in harv.get("emails", []):
            pivotes.append(("email", email, "theHarvester"))
        for sub in harv.get("subdominios", [])[:10]:
            pivotes.append(("domain", sub, "theHarvester"))

    elif tipo == "email":
        # La parte antes de la @ suele reutilizarse como username
        local = reporte["target"].split("@")[0]
        pivotes.append(("username", local, "parte local del email"))
        # El dominio del email (si no es un proveedor genérico)
        dominio = reporte["target"].split("@")[-1].lower()
        genericos = {"gmail.com", "hotmail.com", "outlook.com", "yahoo.com", "icloud.com",
                     "live.com", "protonmail.com", "proton.me", "hotmail.es", "yahoo.es"}
        if dominio not in genericos:
            pivotes.append(("domain", dominio, "dominio del email"))

    return pivotes


def tabla_hallazgos(reporte):
    """Resumen visual de lo que encontró una fase."""
    data = reporte.get("data", {})
    tipo = reporte.get("type")
    t = Table(title=f"Hallazgos para [bold]{reporte['target']}[/] ({tipo})",
              box=box.ROUNDED, header_style="bold magenta")
    t.add_column("Fuente", style="cyan")
    t.add_column("Resultado", style="white")

    if tipo == "domain":
        harv = data.get("theharvester", {})
        t.add_row("theHarvester (emails)", str(len(harv.get("emails", []))))
        t.add_row("theHarvester (subdominios)", str(len(harv.get("subdominios", []))))
        nmap = data.get("activo", {}).get("nmap", {})
        t.add_row("Nmap (puertos)", str(len(nmap.get("puertos_abiertos", []))))
    elif tipo == "email":
        t.add_row("HIBP (brechas)", str(len(data.get("brechas_hibp", {}).get("brechas", []))))
        t.add_row("XposedOrNot", str(len(data.get("brechas_xposedornot", {}).get("brechas", []))))
        t.add_row("Holehe (sitios)", str(len(data.get("holehe", {}).get("sitios", []))))
    elif tipo == "username":
        t.add_row("Sherlock (perfiles)", str(len(data.get("social", {}).get("perfiles", []))))
        t.add_row("Maigret (perfiles)", str(len(data.get("maigret", {}).get("perfiles", []))))
        cr = data.get("cruce", {})
        t.add_row("[green]✓ Confirmados por ambas[/]", f"[green]{cr.get('confirmados', 0)}[/]")
        t.add_row("[yellow]? Solo una fuente (verificar)[/]",
                  f"[yellow]{cr.get('solo_sherlock', 0) + cr.get('solo_maigret', 0)}[/]")
    elif tipo == "phone":
        tel = data.get("telefono", {})
        t.add_row("País", str(tel.get("pais", "?")))
        t.add_row("Operador", str(tel.get("operador", "?")))
        t.add_row("Tipo", str(tel.get("tipo_linea", "?")))
        tw = data.get("twilio", {})
        if tw.get("disponible") and not tw.get("error"):
            t.add_row("[green]Operador actual (Twilio)[/]", f"[green]{tw.get('operador_actual', '?')}[/]")
        t.add_row("ignorant (cuentas)", str(len(data.get("ignorant", {}).get("sitios", []))))

    console.print(t)


def construir_arbol(historial):
    """Dibuja el árbol de la investigación: qué pivotó sobre qué."""
    arbol = Tree("[bold cyan]🎯 Investigación[/]")
    nodos = {}
    for entrada in historial:
        target, tipo, origen = entrada["target"], entrada["type"], entrada["origen"]
        etiqueta = f"[yellow]{target}[/] [dim]({tipo})[/]"
        padre = arbol if origen is None else nodos.get(origen, arbol)
        nodos[target] = padre.add(etiqueta)
    console.print(arbol)


def limpiar_nombre(nombre):
    """Deja el nombre apto para fichero: quita extensión, espacios y símbolos raros."""
    nombre = nombre.strip()
    nombre = re.sub(r'\.(html|json)$', '', nombre, flags=re.IGNORECASE)
    nombre = re.sub(r'[^\w.-]', '_', nombre)
    return nombre.strip('._')


def rutas_salida(nombre, n_reportes, carpeta="output"):
    """Calcula los ficheros a generar a partir del nombre elegido.
    1 objetivo  -> nombre.html / nombre.json / nombre_grafo.html
    Varios      -> nombre_1.html ... + nombre_sesion.html (grafo maestro)"""
    rutas = []
    for i in range(1, n_reportes + 1):
        base = os.path.join(carpeta, nombre if n_reportes == 1 else f"{nombre}_{i}")
        rutas.append({"html": f"{base}.html", "json": f"{base}.json", "grafo": f"{base}_grafo.html"})
    sesion = os.path.join(carpeta, f"{nombre}_sesion.html") if n_reportes > 1 else None
    return rutas, sesion


def pedir_nombre(n_reportes):
    """Pregunta el nombre de la investigación y evita sobrescribir ficheros existentes."""
    por_defecto = f"investigacion_{datetime.now().strftime('%Y%m%d_%H%M')}"
    while True:
        nombre = limpiar_nombre(Prompt.ask("[bold cyan]¿Cómo quieres llamar a esta investigación?[/]",
                                           default=por_defecto))
        if not nombre:
            console.print("[red]Nombre no válido, prueba otro.[/]")
            continue
        rutas, sesion = rutas_salida(nombre, n_reportes)
        existentes = [p for r in rutas for p in r.values() if os.path.exists(p)]
        if sesion and os.path.exists(sesion):
            existentes.append(sesion)
        if existentes and not Confirm.ask(
                f"[yellow]Ya existe '{nombre}' en output/. ¿Sobrescribir?[/]", default=False):
            continue
        return nombre, rutas, sesion


TIPOS = ["domain", "email", "username", "phone"]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Investigación OSINT interactiva con pivotes.",
        epilog="Ejemplos:  python3 interactive.py   |   python3 interactive.py -t nahia.jmnz --type username",
    )
    parser.add_argument("-t", "--target", help="Objetivo inicial (si se omite, se pregunta).")
    parser.add_argument("--type", choices=TIPOS, help="Fuerza el tipo del objetivo inicial.")
    return parser.parse_args()


def confirmar_tipo(objetivo):
    """Detecta el tipo y deja que el analista lo confirme o corrija.
    Un usuario con punto (nombre.apellido) tiene la misma forma que un dominio."""
    tipo = detect_target_type(objetivo)
    if tipo == "unknown":
        return Prompt.ask("No se detectó el tipo. Elige", choices=TIPOS)
    aviso = ""
    if tipo == "domain" and objetivo.count(".") == 1 and "/" not in objetivo:
        aviso = " [dim](si es un usuario con punto, elige username)[/]"
    console.print(f"[green]Tipo detectado:[/] [bold]{tipo}[/]{aviso}")
    return Prompt.ask("Confirma el tipo", choices=TIPOS, default=tipo)


def main():
    args = parse_args()
    banner()
    os.makedirs("output", exist_ok=True)

    objetivo = (args.target or Prompt.ask("[bold cyan]Objetivo inicial[/]")).strip()
    tipo = args.type or confirmar_tipo(objetivo)

    cola = [(objetivo, tipo, None)]   # (target, tipo, origen)
    historial = []
    reportes = []
    procesados = set()

    while cola:
        target, tipo, origen = cola.pop(0)
        if target in procesados:
            continue
        procesados.add(target)

        console.rule(f"[bold green]Investigando: {target} ({tipo})[/]")

        run_active = run_harvester = False
        if tipo == "domain":
            run_harvester = Confirm.ask("  ¿Ejecutar theHarvester?", default=True)
            run_active = Confirm.ask("  ¿Escaneo activo (nmap, hace ruido)?", default=False)

        with console.status(f"[yellow]Ejecutando módulos para {target}...[/]", spinner="dots"):
            reporte = run_investigation(target, tipo, run_active, run_harvester)

        reportes.append(reporte)
        historial.append({"target": target, "type": tipo, "origen": origen})

        tabla_hallazgos(reporte)

        pivotes = [p for p in extraer_pivotes(reporte) if p[1] not in procesados]

        if pivotes:
            console.print(f"\n[bold]Pivotes disponibles desde {target}:[/]")
            tp = Table(box=box.SIMPLE)
            tp.add_column("#", style="cyan")
            tp.add_column("Tipo", style="green")
            tp.add_column("Valor", style="white")
            tp.add_column("Origen", style="dim")
            for i, (ptipo, pvalor, porigen) in enumerate(pivotes, 1):
                tp.add_row(str(i), ptipo, pvalor, porigen)
            console.print(tp)

            sel = Prompt.ask(
                "Elige pivote(s) por número (coma para varios), [cyan]s[/] para seguir con la cola, [red]f[/] para finalizar",
                default="s")

            if sel.lower() == "f":
                break
            elif sel.lower() != "s":
                for n in sel.split(","):
                    n = n.strip()
                    if n.isdigit() and 1 <= int(n) <= len(pivotes):
                        pt, pv, _ = pivotes[int(n) - 1]
                        cola.append((pv, pt, target))
                        console.print(f"  [green]+ Añadido a la cola:[/] {pv} ({pt})")

        if not cola:
            break
        if not Confirm.ask("\n¿Continuar con la investigación?", default=True):
            break

    # --- Resumen final ---
    console.rule("[bold cyan]Resumen de la investigación[/]")
    construir_arbol(historial)
    console.print(f"\n[bold green]Total de objetivos investigados:[/] {len(reportes)}")

    if reportes and Confirm.ask("¿Generar reportes y grafos de la sesión?", default=True):
        from report import generator, graph
        nombre, rutas, sesion = pedir_nombre(len(reportes))

        for rep, r in zip(reportes, rutas):
            try:
                rep["grafo"] = graph.generate_graph(rep, filename=r["grafo"])
            except Exception as e:
                console.print(f"[red]No se pudo generar el grafo de {rep['target']}: {e}[/]")
            generator.generate_json(rep, filename=r["json"])
            generator.generate_html(rep, filename=r["html"])

        if sesion:
            graph.generate_session_graph(reportes, historial, filename=sesion)

        # Resumen de ficheros generados
        t = Table(title=f"Ficheros de '{nombre}'", box=box.ROUNDED, header_style="bold magenta")
        t.add_column("Objetivo", style="yellow")
        t.add_column("Reporte", style="white")
        t.add_column("Grafo", style="white")
        for rep, r in zip(reportes, rutas):
            t.add_row(rep["target"], os.path.basename(r["html"]), os.path.basename(r["grafo"]))
        console.print(t)
        if sesion:
            console.print(f"[bold green]✓ Grafo maestro:[/] {os.path.basename(sesion)}")
        console.print("[dim]Todo está en la carpeta output/[/]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Investigación interrumpida.[/]")
        sys.exit(0)
