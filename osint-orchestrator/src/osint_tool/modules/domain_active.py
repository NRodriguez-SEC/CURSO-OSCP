"""Módulo de escaneo ACTIVO de dominios: puertos abiertos con Nmap.

Es intrusivo: genera tráfico directo contra el objetivo. Úsalo SOLO sobre
sistemas propios o con autorización explícita. Fuente opcional (opt-in); se
omite si Nmap no está instalado.
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
from osint_tool.validation import ValidationError, validate_domain

EXECUTABLE = "nmap"
SOURCE = "Nmap"
PORT_CONFIDENCE = 0.9  # el puerto está abierto ahora; el servicio/versión puede variar

# Formato greppable de Nmap (-oG -): línea "Host: ... Ports: 22/open/tcp//ssh//OpenSSH//, ..."
_PORTS_LINE = re.compile(r"^Host:.*\bPorts:\s*(?P<ports>.+)$", re.MULTILINE)
# Cada puerto: puerto/estado/protocolo/owner/servicio/rpc/versión/
_PORT = re.compile(
    r"(?P<port>\d+)/open/(?P<proto>\w+)/[^/]*/(?P<service>[^/]*)/[^/]*/(?P<version>[^/]*)/"
)


# Separar el parseo del greppable mantiene la lógica de red libre de detalles de formato.
def _parse_ports(stdout: str) -> list[tuple[str, str, str, str]]:
    """Extrae (puerto, protocolo, servicio, versión) de la salida greppable de Nmap."""
    return [
        (
            match.group("port"),
            match.group("proto"),
            match.group("service").strip(),
            match.group("version").strip(),
        )
        for line in _PORTS_LINE.finditer(stdout)
        for match in _PORT.finditer(line.group("ports"))
    ]


@register
class DomainActiveModule:
    """Puertos abiertos de un dominio con Nmap (escaneo activo, intrusivo)."""

    name = "domain_active"
    requires_network = True
    active = True  # genera tráfico directo contra el objetivo (intrusivo)
    accepts = frozenset({"domain"})
    web_opt_in = True
    web_label = "Escaneo activo de puertos (Nmap)"
    web_description = (
        "Escaneo de puertos con Nmap. INTRUSIVO: úsalo solo sobre objetivos propios "
        "o autorizados. Requiere Nmap instalado; si no, se omite."
    )

    # Inyectar el ejecutor permite probar el parseo sin lanzar Nmap de verdad.
    def __init__(self, runner: Callable[[Sequence[str]], CliResult] = run_cli) -> None:
        """El ejecutor de comandos se puede inyectar para las pruebas."""
        self._runner = runner

    # Validar el dominio antes de pasarlo a Nmap evita que se interprete como una opción.
    def run(self, target: Target) -> ModuleOutput:
        if not target.domain:
            return ModuleOutput()
        try:
            domain = validate_domain(target.domain)
        except ValidationError as exc:
            raise ModuleSkipped(f"Dominio no válido para escaneo activo: {exc}") from exc

        # -F: 100 puertos más comunes; -sV: servicio y versión; -oG -: salida greppable.
        command = [EXECUTABLE, "-F", "-sV", "-oG", "-", domain]
        try:
            result = self._runner(command)
        except ToolNotFoundError as exc:
            raise ModuleSkipped("Nmap no está instalado") from exc

        ports = _parse_ports(result.stdout)
        if not ports:
            return ModuleOutput(
                source_checks=[
                    SourceCheck(
                        source=SOURCE,
                        status=SourceCheckStatus.NOT_FOUND,
                        detail="Sin puertos abiertos detectados",
                    )
                ]
            )
        findings = [
            Finding(
                entity_type="domain",
                type="open_port",
                value=f"{port}/{proto}",
                source=SOURCE,
                confidence=PORT_CONFIDENCE,
                detail=f"{service} {version}".strip() or None,
                raw={"port": port, "protocol": proto, "service": service, "version": version},
            )
            for port, proto, service, version in ports
        ]
        return ModuleOutput(
            findings=findings,
            source_checks=[
                SourceCheck(
                    source=SOURCE,
                    status=SourceCheckStatus.FOUND,
                    detail=f"{len(findings)} puertos abiertos",
                )
            ],
        )
