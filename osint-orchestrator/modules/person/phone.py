import phonenumbers
from phonenumbers import geocoder, carrier, timezone, number_type, PhoneNumberType
from colorama import Fore

# Traducción de los tipos de línea a algo legible
TIPOS = {
    PhoneNumberType.MOBILE: "Móvil",
    PhoneNumberType.FIXED_LINE: "Fijo",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fijo o Móvil",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.TOLL_FREE: "Gratuito (900)",
    PhoneNumberType.PREMIUM_RATE: "Tarificación especial",
    PhoneNumberType.UNKNOWN: "Desconocido",
}


def run(telefono):
    """Analiza un número de teléfono (offline, sin API ni red)."""
    print(f"{Fore.YELLOW}[+] Analizando teléfono: {telefono}")

    try:
        # Si no trae prefijo internacional, asumimos España (+34)
        region = None if telefono.strip().startswith("+") else "ES"
        num = phonenumbers.parse(telefono, region)
    except phonenumbers.NumberParseException as e:
        return {"error": f"No se pudo parsear: {e}"}

    valido = phonenumbers.is_valid_number(num)
    posible = phonenumbers.is_possible_number(num)

    resultado = {
        "telefono": telefono,
        "e164": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
        "internacional": phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "valido": valido,
        "posible": posible,
        "pais": geocoder.description_for_number(num, "es") or "Desconocido",
        "codigo_pais": num.country_code,
        # OJO: es el operador al que se ASIGNÓ el rango originalmente, NO el actual.
        # La portabilidad hace que el real pueda ser otro (ej. un número de Movistar
        # portado a DIGI). Saber el operador actual requiere una consulta HLR de pago.
        "operador": carrier.name_for_number(num, "es") or "Desconocido",
        "operador_nota": "Asignación original del rango; el operador actual puede diferir por portabilidad.",
        "tipo_linea": TIPOS.get(number_type(num), "Desconocido"),
        "zonas_horarias": list(timezone.time_zones_for_number(num)),
    }

    if valido:
        print(f"{Fore.GREEN}    - Válido | {resultado['pais']} | {resultado['operador']} (orig.) | {resultado['tipo_linea']}")
    else:
        print(f"{Fore.RED}    - Número no válido.")

    return resultado
