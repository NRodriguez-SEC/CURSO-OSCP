"""Módulo ignorant: cuentas asociadas a un teléfono (Instagram, Amazon, Snapchat).

Fuente opcional (opt-in). Usa la herramienta externa `ignorant`; se omite si
no está instalada. Es pasiva respecto al objetivo: consulta plataformas de
terceros, no su infraestructura. ignorant quiere el prefijo y el número por
separado, así que se obtienen con phonenumbers a partir del número E.164.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence

import phonenumbers

from osint_tool.cli_runner import CliResult, run_cli
from osint_tool.external_errors import ToolNotFoundError
from osint_tool.models import (
    Finding,
    ModuleOutput,
    SourceCheck,
    SourceCheckStatus,
    Target,
)
from osint_tool.registry import ModuleSkipped, register

EXECUTABLE = "ignorant"
SOURCE = "ignorant"
ACCOUNT_CONFIDENCE = 0.7  # que el teléfono exista en el sitio no prueba su titularidad

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# "[+] instagram.com". El "." descarta la línea de leyenda ("[+] Phone number used, ...").
_FOUND = re.compile(r"^\[\+\]\s+(\S+)")


# Separar el parseo de la ejecución permite probarlo con salidas de ejemplo.
def _sites(stdout: str) -> list[str]:
    """Dominios de las líneas '[+]' (cuenta encontrada), sin duplicados."""
    sites: list[str] = []
    seen: set[str] = set()
    for raw in _ANSI.sub("", stdout).splitlines():
        match = _FOUND.match(raw.strip())
        if match is None:
            continue
        site = match.group(1)
        if "." in site and site not in seen:
            seen.add(site)
            sites.append(site)
    return sites


@register
class IgnorantModule:
    """Cuentas asociadas a un teléfono (Instagram, Amazon, Snapchat), según ignorant."""

    name = "ignorant"
    requires_network = True
    accepts = frozenset({"phone"})
    web_opt_in = True
    web_label = "ignorant (cuentas por teléfono)"
    web_description = (
        "Herramienta externa opcional: comprueba si un teléfono tiene cuenta en Instagram, "
        "Amazon y Snapchat. Requiere 'ignorant' instalado; si no, se omite."
    )

    # Inyectar el ejecutor permite probar el parseo sin lanzar ignorant.
    def __init__(self, runner: Callable[[Sequence[str]], CliResult] = run_cli) -> None:
        """El ejecutor de comandos se puede inyectar para las pruebas."""
        self._runner = runner

    def run(self, target: Target) -> ModuleOutput:
        if not target.phone:
            return ModuleOutput()
        # El número ya viene en E.164 (lo normaliza la validación de entrada).
        try:
            number = phonenumbers.parse(target.phone, None)
        except phonenumbers.NumberParseException as exc:
            raise ModuleSkipped(f"Teléfono no válido para ignorant: {exc}") from exc
        country_code = str(number.country_code)
        national = str(number.national_number)

        try:
            result = self._runner([EXECUTABLE, country_code, national, "--no-color"])
        except ToolNotFoundError as exc:
            raise ModuleSkipped("ignorant no está instalado") from exc

        sites = _sites(result.stdout)
        if not sites:
            return ModuleOutput(
                source_checks=[
                    SourceCheck(
                        source=SOURCE,
                        status=SourceCheckStatus.NOT_FOUND,
                        detail="Sin cuentas confirmadas",
                    )
                ]
            )
        return ModuleOutput(
            findings=[
                Finding(
                    entity_type="phone",
                    type="account",
                    value=site,
                    source=SOURCE,
                    source_url=f"https://{site}",
                    confidence=ACCOUNT_CONFIDENCE,
                    detail="registrado",
                )
                for site in sites
            ],
            source_checks=[
                SourceCheck(
                    source=SOURCE,
                    status=SourceCheckStatus.FOUND,
                    detail=f"{len(sites)} sitios",
                )
            ],
        )
