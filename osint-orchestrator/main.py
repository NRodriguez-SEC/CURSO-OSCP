import argparse
import sys
import re
import os
import datetime
from colorama import init, Fore

init(autoreset=True)


def print_banner():
    banner = f"""
{Fore.CYAN}====================================================
{Fore.GREEN}   OSINT ORCHESTRATOR - Huella Digital y Web
{Fore.CYAN}====================================================
{Fore.YELLOW}   Herramienta para auditorías autorizadas
{Fore.CYAN}===================================================="""
    print(banner)


def detect_target_type(target):
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    domain_regex = r"^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$"
    phone_regex = r"^\+?[0-9\s\-\(\)]{7,15}$"

    if re.match(email_regex, target):
        return "email"
    elif re.match(phone_regex, target):
        return "phone"
    elif re.match(domain_regex, target):
        return "domain"
    elif target.isalnum() or "_" in target or "." in target:
        return "username"
    return "unknown"


def preguntar_si_no(mensaje, por_defecto=False, auto_si=False):
    """s/N. En modo no interactivo (auto_si) responde siempre que sí."""
    if auto_si:
        return True
    sufijo = "S/n" if por_defecto else "s/N"
    resp = input(f"{Fore.RED}[!] {mensaje} ({sufijo}): ").strip().lower()
    if not resp:
        return por_defecto
    return resp in ("s", "si", "sí", "y", "yes")


def run_investigation(target, target_type, run_active=False, run_harvester=False):
    """Núcleo SIN prompts: ejecuta los módulos y devuelve el reporte."""
    print(f"{Fore.BLUE}[*] Objetivo: {Fore.WHITE}{target}")
    print(f"{Fore.BLUE}[*] Tipo:     {Fore.WHITE}{target_type.upper()}")
    print(f"{Fore.CYAN}{'-' * 50}")

    reporte = {"target": target, "type": target_type, "data": {}}

    if target_type == "domain":
        print(f"{Fore.GREEN}[+] Cargando módulos de análisis WEB...")
        from modules.web import passive, active, theharvester
        reporte["data"]["pasivo"] = passive.run(target)
        if run_harvester:
            reporte["data"]["theharvester"] = theharvester.run(target)
        else:
            print(f"{Fore.YELLOW}[*] theHarvester omitido.")
        if run_active:
            reporte["data"]["activo"] = active.run(target)
        else:
            print(f"{Fore.YELLOW}[*] Escaneo activo omitido.")

    elif target_type == "email":
        print(f"{Fore.GREEN}[+] Cargando módulos de HUELLA DIGITAL...")
        from modules.person import breaches, xposedornot, holehe
        reporte["data"]["brechas_hibp"] = breaches.run(target)
        reporte["data"]["brechas_xposedornot"] = xposedornot.run(target)
        reporte["data"]["holehe"] = holehe.run(target)

    elif target_type == "username":
        print(f"{Fore.GREEN}[+] Cargando módulos de HUELLA DIGITAL...")
        from modules.person import social, maigret, cruce
        reporte["data"]["social"] = social.run(target)
        reporte["data"]["maigret"] = maigret.run(target)
        reporte["data"]["cruce"] = cruce.run(reporte["data"]["social"], reporte["data"]["maigret"])

    elif target_type == "phone":
        print(f"{Fore.GREEN}[+] Cargando módulo de ANÁLISIS DE TELÉFONO...")
        from modules.person import phone, ignorant
        reporte["data"]["telefono"] = phone.run(target)
        reporte["data"]["ignorant"] = ignorant.run(target)

    reporte["fecha"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return reporte


def generar_reportes(reporte, output_format):
    from report import generator, graph
    try:
        reporte["grafo"] = graph.generate_graph(reporte)
    except Exception as e:
        print(f"{Fore.RED}[!] No se pudo generar el grafo: {e}")
    if output_format in ("json", "all"):
        generator.generate_json(reporte)
    if output_format in ("html", "all"):
        generator.generate_html(reporte)
    print(f"\n{Fore.GREEN}[+] ¡Orquestación completada con éxito!")


# ---------- Modo interactivo simple (menú) ----------
def elegir_tipo_manual():
    opciones = {"1": "domain", "2": "email", "3": "username", "4": "phone"}
    print(f"{Fore.CYAN}  1) Dominio  2) Email  3) Usuario  4) Teléfono  0) Cancelar")
    sel = input(f"{Fore.BLUE}[?] Tipo > {Fore.WHITE}").strip()
    return None if sel == "0" else opciones.get(sel)


def elegir_formato():
    print(f"{Fore.CYAN}  Formato: 1) JSON  2) HTML  3) Ambos")
    sel = input(f"{Fore.BLUE}[?] Formato [2] > {Fore.WHITE}").strip()
    return {"1": "json", "2": "html", "3": "all"}.get(sel, "html")


def flujo_interactivo():
    while True:
        print(f"\n{Fore.CYAN}{'=' * 50}")
        print(f"{Fore.GREEN}  MENÚ PRINCIPAL  {Fore.WHITE}(dominio, email, usuario o teléfono; 'q' para salir)")
        print(f"{Fore.CYAN}{'=' * 50}")
        target = input(f"{Fore.BLUE}[?] Objetivo > {Fore.WHITE}").strip()

        if target.lower() in ("q", "salir", "exit"):
            print(f"{Fore.YELLOW}[*] Saliendo.")
            break
        if not target:
            continue

        tipo = detect_target_type(target)
        if tipo == "unknown":
            print(f"{Fore.RED}[!] No se pudo detectar el tipo.")
            tipo = elegir_tipo_manual()
        else:
            print(f"{Fore.GREEN}[+] Tipo detectado: {tipo.upper()}")
            if not preguntar_si_no("¿Es correcto?", por_defecto=True):
                tipo = elegir_tipo_manual()
        if tipo is None:
            continue

        run_active = run_harvester = False
        if tipo == "domain":
            run_harvester = preguntar_si_no("¿Ejecutar theHarvester (pasivo)?", por_defecto=True)
            run_active = preguntar_si_no("¿Escaneo ACTIVO (nmap + dirs, hace ruido)?", por_defecto=False)

        formato = elegir_formato()
        reporte = run_investigation(target, tipo, run_active, run_harvester)
        generar_reportes(reporte, formato)

        if not preguntar_si_no("\n¿Investigar otro objetivo?", por_defecto=True):
            break


def main():
    print_banner()
    parser = argparse.ArgumentParser(
        description="Orquestador OSINT para dominios, emails, usuarios y teléfonos.",
        epilog="Menú:  python3 main.py   |   Directo:  python3 main.py -t ejemplo.com -o html --active -y   |   Pivotes:  python3 interactive.py",
    )
    parser.add_argument("-t", "--target", help="Objetivo. Si se omite, abre el menú interactivo.")
    parser.add_argument("-o", "--output", choices=["json", "html", "all"], default="html")
    parser.add_argument("--type", choices=["domain", "email", "phone", "username", "auto"], default="auto")
    parser.add_argument("--active", action="store_true", help="Escaneo activo sin preguntar.")
    parser.add_argument("--harvester", action="store_true", help="theHarvester sin preguntar.")
    parser.add_argument("-y", "--yes", action="store_true", help="Sí a todo (no interactivo, para scripts).")
    args = parser.parse_args()

    os.makedirs("output", exist_ok=True)

    if not args.target:
        flujo_interactivo()
        return

    target_type = detect_target_type(args.target) if args.type == "auto" else args.type
    if target_type == "unknown":
        print(f"{Fore.RED}[!] No se pudo detectar el tipo. Usa --type.")
        sys.exit(1)

    run_active = args.active or args.yes
    run_harvester = args.harvester or args.yes
    if target_type == "domain" and not args.yes:
        if not args.harvester:
            run_harvester = preguntar_si_no("¿Ejecutar theHarvester?", por_defecto=False)
        if not args.active:
            run_active = preguntar_si_no("¿Escaneo activo?", por_defecto=False)

    reporte = run_investigation(args.target, target_type, run_active, run_harvester)
    generar_reportes(reporte, args.output)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Proceso interrumpido por el usuario.")
        sys.exit(0)
