import argparse
import sys
import re
import os
import json
from colorama import init, Fore, Style

# Inicializar colorama
init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN}====================================================
{Fore.GREEN}   OSINT ORCHESTRATOR - Huella Digital y Web
{Fore.CYAN}====================================================
{Fore.YELLOW}   Herramienta para auditorías autorizadas
{Fore.CYAN}====================================================
    """
    print(banner)

def detect_target_type(target):
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    domain_regex = r"^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)?$"
    phone_regex = r"^\+?[0-9\s\-\(\)]{7,15}$"

    if re.match(email_regex, target):
        return "email"
    elif re.match(domain_regex, target):
        return "domain"
    elif re.match(phone_regex, target):
        return "phone"
    elif target.isalnum() or "_" in target or "." in target:
        return "username"
    else:
        return "unknown"

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Orquestador OSINT: Recolecta información de dominios, emails, usuarios, etc.",
        epilog="Ejemplo de uso: python3 main.py -t ejemplo.com -o html"
    )

    parser.add_argument("-t", "--target", required=True, help="Objetivo a investigar")
    parser.add_argument("-o", "--output", choices=["json", "html", "pdf", "all"], default="json", help="Formato del reporte")
    parser.add_argument("--type", choices=["domain", "email", "phone", "username", "auto"], default="auto", help="Forzar el tipo")

    args = parser.parse_args()
    target = args.target

    if args.type == "auto":
        target_type = detect_target_type(target)
    else:
        target_type = args.type

    print(f"{Fore.BLUE}[*] Objetivo: {Fore.WHITE}{target}")
    print(f"{Fore.BLUE}[*] Tipo detectado: {Fore.WHITE}{target_type.upper()}")
    print(f"{Fore.BLUE}[*] Formato de salida: {Fore.WHITE}{args.output.upper()}")
    print(f"{Fore.CYAN}{'-' * 50}")

    if target_type == "unknown":
        print(f"{Fore.RED}[!] Error: No se pudo detectar el tipo de objetivo. Usa --type para forzarlo.")
        sys.exit(1)

    if not os.path.exists("output"):
        os.makedirs("output")

    print(f"{Fore.YELLOW}[*] Iniciando orquestación...")

    reporte_final = {
        "target": target,
        "type": target_type,
        "data": {}
    }

    if target_type == "domain":
        print(f"{Fore.GREEN}[+] Cargando módulos de análisis WEB (Pasivo y Activo)...")
        
        # Importamos el módulo pasivo
        from modules.web import passive, active, theharvester
        
        # Ejecutamos y guardamos el pasivo
        resultados_pasivos = passive.run(target)
        reporte_final["data"]["pasivo"] = resultados_pasivos

        # --- theHarvester (Análisis Pasivo Avanzado) ---
        confirm_harvester = input(f"{Fore.RED}[!] ¿Ejecutar theHarvester? (s/N): ").strip().lower()
        if confirm_harvester == 's':
            resultados_harvester = theharvester.run(target)
            reporte_final["data"]["theharvester"] = resultados_harvester
        else:
            print(f"{Fore.YELLOW}[*] theHarvester omitido por el usuario.")
            
        # --- NUEVO BLOQUE ACTIVO ---
        # Preguntamos al usuario antes de hacer ruido en la red
        confirm = input(f"{Fore.RED}[!] ¿Realizar escaneo activo? (s/N): ").strip().lower()
        if confirm == 's':
           resultados_activos = active.run(target)
           reporte_final["data"]["activo"] = resultados_activos
        else:
           print(f"{Fore.YELLOW}[*] Escaneo activo omitido por el usuario.")
            # ---------------------------

    elif target_type in ["email", "username", "phone"]:
        print(f"{Fore.GREEN}[+] Cargando módulos de HUELLA DIGITAL (Personas)...")
        
        from modules.person import breaches, social, xposedornot
        
        if target_type == "email":
            # Brechas con HIBP (modo simulado si no hay API Key)
            resultados_brechas = breaches.run(target)
            reporte_final["data"]["brechas_hibp"] = resultados_brechas
            
            # Brechas con XposedOrNot (API gratuita sin key)
            resultados_xon = xposedornot.run(target)
            reporte_final["data"]["brechas_xposedornot"] = resultados_xon
        elif target_type == "username":
            # Redes sociales para usernames
            resultados_social = social.run(target)
            reporte_final["data"]["social"] = resultados_social
        else:
            print(f"{Fore.YELLOW}    - Módulo para teléfono aún no implementado.")
    
    # --- GENERACIÓN DE REPORTES ---
    import datetime
    reporte_final["fecha"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    from report import generator
    
    if args.output in ["json", "all"]:
        generator.generate_json(reporte_final)
    if args.output in ["html", "all"]:
        generator.generate_html(reporte_final)
    
    print(f"\n{Fore.GREEN}[+] ¡Orquestación completada con éxito!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Proceso interrumpido por el usuario.")
        sys.exit(0)
