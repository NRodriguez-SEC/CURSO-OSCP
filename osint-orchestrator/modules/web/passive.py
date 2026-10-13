import whois
import dns.resolver
from colorama import Fore

def run(target):
    """
    Ejecuta el análisis pasivo sobre un dominio.
    Retorna un diccionario con los datos recolectados.
    """
    print(f"\n{Fore.MAGENTA}[*] Iniciando análisis pasivo para: {target}")
    resultados = {
        "whois": {},
        "dns": {}
    }

    # 1. Consulta WHOIS
    print(f"{Fore.YELLOW}[+] Consultando WHOIS...")
    try:
        w = whois.whois(target)
        resultados["whois"] = {
            "registrador": w.registrar,
            "fecha_creacion": str(w.creation_date),
            "fecha_expiracion": str(w.expiration_date),
            "servidores_nombre": w.name_servers
        }
        print(f"{Fore.GREEN}    - Registrador: {w.registrar}")
    except Exception as e:
        print(f"{Fore.RED}    - Error en WHOIS: {e}")
        resultados["whois"] = {"error": str(e)}

    # 2. Consulta DNS (Registros A, MX, TXT)
    print(f"{Fore.YELLOW}[+] Consultando registros DNS...")
    tipos_dns = ['A', 'MX', 'TXT', 'NS']
    for tipo in tipos_dns:
        try:
            answers = dns.resolver.resolve(target, tipo)
            registros = [rdata.to_text() for rdata in answers]
            resultados["dns"][tipo] = registros
            print(f"{Fore.GREEN}    - {tipo}: {', '.join(registros[:2])}...") # Muestra solo los 2 primeros
        except Exception as e:
            resultados["dns"][tipo] = []
            # No mostramos error si simplemente no existe el registro
            
    print(f"{Fore.MAGENTA}[*] Análisis pasivo completado.\n")
    return resultados
