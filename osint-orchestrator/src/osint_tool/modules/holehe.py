"""Módulo Holehe: en qué sitios está registrado un email (herramienta externa).

Fuente opcional (opt-in). Consulta servicios de terceros mediante la
herramienta `holehe`; se omite si no está instalada. Es pasiva respecto al
objetivo: no contacta con su infraestructura, solo con las plataformas.
Envía el email a terceros: usar solo emails propios o ficticios.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence

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
from osint_tool.validation import ValidationError, validate_email

EXECUTABLE = "holehe"
SOURCE = "Holehe"
ACCOUNT_CONFIDENCE = 0.7  # que el email exista en el sitio no prueba su titularidad

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Línea de sitio encontrado: "[+] github.com". El "." descarta líneas de leyenda.
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
class HoleheModule:
    """Sitios donde un email está registrado, según Holehe."""

    name = "holehe"
    requires_network = True
    accepts = frozenset({"email"})
    web_opt_in = True
    web_label = "Holehe (cuentas por email)"
    web_description = (
        "Herramienta externa opcional: comprueba en qué sitios está registrado un email. "
        "Requiere 'holehe' instalado; si no, se omite."
    )

    # Inyectar el ejecutor permite probar el parseo sin lanzar Holehe.
    def __init__(self, runner: Callable[[Sequence[str]], CliResult] = run_cli) -> None:
        """El ejecutor de comandos se puede inyectar para las pruebas."""
        self._runner = runner

    def run(self, target: Target) -> ModuleOutput:
        if not target.email:
            return ModuleOutput()
        try:
            email = validate_email(target.email)
        except ValidationError as exc:
            raise ModuleSkipped(f"Email no válido: {exc}") from exc

        try:
            result = self._runner([EXECUTABLE, email, "--no-color"])
        except ToolNotFoundError as exc:
            raise ModuleSkipped("Holehe no está instalado") from exc

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
                    entity_type="email",
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
