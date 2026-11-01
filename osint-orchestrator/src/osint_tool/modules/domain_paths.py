"""Módulo ACTIVO de rutas comunes: prueba por HTTP paths típicos de un dominio.

Es intrusivo: hace peticiones directas al servidor del objetivo. Úsalo SOLO
sobre sistemas propios o con autorización explícita. No usa herramientas
externas (solo peticiones HTTP), así que no requiere instalar nada.
"""

from __future__ import annotations

from http import HTTPStatus

import requests

from osint_tool.config import Settings, load_settings
from osint_tool.http import build_session
from osint_tool.models import (
    Finding,
    ModuleOutput,
    SourceCheck,
    SourceCheckStatus,
    Target,
)
from osint_tool.registry import ModuleSkipped, register
from osint_tool.validation import ValidationError, validate_domain

SOURCE = "Rutas comunes"
PATH_CONFIDENCE = 0.6  # que responda no implica que sea explotable

# Rutas habituales que suelen revelar paneles, config o fugas. Lista corta a propósito.
COMMON_PATHS = (
    "robots.txt",
    "sitemap.xml",
    ".git/",
    ".env",
    "admin",
    "login",
    "wp-admin/",
    "wp-login.php",
    "backup",
    "config",
    "phpinfo.php",
    "server-status",
)

# Códigos que indican que la ruta existe o está protegida (interesante en ambos casos).
INTERESTING = frozenset(
    {
        HTTPStatus.OK,
        HTTPStatus.MOVED_PERMANENTLY,
        HTTPStatus.FOUND,
        HTTPStatus.TEMPORARY_REDIRECT,
        HTTPStatus.UNAUTHORIZED,
        HTTPStatus.FORBIDDEN,
    }
)


@register
class DomainPathsModule:
    """Rutas comunes accesibles en el sitio del dominio (escaneo activo)."""

    name = "domain_paths"
    requires_network = True
    active = True  # hace peticiones directas al servidor del objetivo (intrusivo)
    accepts = frozenset({"domain"})
    web_opt_in = True
    web_label = "Rutas/directorios comunes (activo)"
    web_description = (
        "ACTIVA/INTRUSIVA: prueba por HTTP rutas comunes (admin, login, .git, .env…) "
        "en el dominio. Úsala solo sobre objetivos propios o autorizados."
    )

    # La inyección mantiene las pruebas deterministas y evita depender de la red real.
    def __init__(
        self,
        session: requests.Session | None = None,
        settings: Settings | None = None,
    ) -> None:
        """Sesión y configuración se pueden inyectar para probar sin red."""
        self._settings = load_settings() if settings is None else settings
        self._session = build_session(self._settings) if session is None else session

    # Aislar la petición evita try/except dentro del bucle y unifica el manejo de errores.
    def _status(self, url: str, *, allow_redirects: bool) -> int | None:
        """Código HTTP de la petición, o None si la conexión falla."""
        try:
            response = self._session.get(url, allow_redirects=allow_redirects)
        except requests.RequestException:
            return None
        return response.status_code

    # Probar https y luego http evita fallar en sitios que solo sirven uno de los dos.
    def _base_url(self, domain: str) -> str | None:
        """Primera base (https o http) a la que se puede conectar."""
        for scheme in ("https", "http"):
            base = f"{scheme}://{domain}"
            if self._status(base, allow_redirects=True) is not None:
                return base
        return None

    def run(self, target: Target) -> ModuleOutput:
        if not target.domain:
            return ModuleOutput()
        try:
            domain = validate_domain(target.domain)
        except ValidationError as exc:
            raise ModuleSkipped(f"Dominio no válido para rutas: {exc}") from exc

        base = self._base_url(domain)
        if base is None:
            return ModuleOutput(
                source_checks=[
                    SourceCheck(
                        source=SOURCE,
                        status=SourceCheckStatus.ERROR,
                        detail="No se pudo conectar al sitio (ni https ni http)",
                    )
                ]
            )

        findings = []
        for path in COMMON_PATHS:
            url = f"{base}/{path}"
            status = self._status(url, allow_redirects=False)
            if status in INTERESTING:
                findings.append(
                    Finding(
                        entity_type="domain",
                        type="path",
                        value=url,
                        source=SOURCE,
                        source_url=url,
                        confidence=PATH_CONFIDENCE,
                        detail=f"HTTP {status}",
                    )
                )

        status_check = (
            SourceCheckStatus.FOUND if findings else SourceCheckStatus.NOT_FOUND
        )
        return ModuleOutput(
            findings=findings,
            source_checks=[
                SourceCheck(
                    source=SOURCE,
                    status=status_check,
                    detail=f"{len(findings)} rutas de interés en {base}",
                )
            ],
        )
