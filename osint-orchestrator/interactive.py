"""
interactive.py - Modo de investigación interactiva (man-in-the-loop).
Flujo de pivotes: cada hallazgo abre nuevos objetivos sobre los que saltar.
Ejecuta:  python3 interactive.py
"""
import os
import sys
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
    elif tipo == "phone":
        tel = data.get("telefono", {})
        t.add_row("País", str(tel.get("pais", "?")))
        t.add_row("Operador", str(tel.get("operador", "?")))
        t.add_row("Tipo", str(tel.get("tipo_linea", "?")))

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


def main():
    banner()
    os.makedirs("output", exist_ok=True)

    objetivo = Prompt.ask("[bold cyan]Objetivo inicial[/]").strip()
    tipo = detect_target_type(objetivo)
    if tipo == "unknown":
        tipo = Prompt.ask("No se detectó el tipo. Elige",
                          choices=["domain", "email", "username", "phone"])

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

    if Confirm.ask("¿Generar reportes y grafo maestro de la sesión?", default=True):
        from report import generator, graph
        for rep in reportes:
            try:
                rep["grafo"] = graph.generate_graph(rep)
            except Exception as e:
                console.print(f"[red]No se pudo generar el grafo de {rep['target']}: {e}[/]")
            generator.generate_json(rep)
            generator.generate_html(rep)
        ruta = graph.generate_session_graph(reportes, historial)
        console.print(f"[bold green]✓ Grafo maestro:[/] {ruta}")
        console.print("[bold green]✓ Reportes individuales en output/[/]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red]Investigación interrumpida.[/]")
        sys.exit(0)
