"""Módulo Have I Been Pwned (HIBP): brechas de un email vía la API v3.

Fuente opcional y de pago: requiere una clave en `OSINT_HIBP_API_KEY`. Sin
clave, el módulo se omite y no se consulta nada. Envía el email a un servicio
de terceros: usar solo emails propios o ficticios.
"""

from __future__ import annotations

from http import HTTPStatus
from urllib.parse import quote

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

SOURCE = "Have I Been Pwned"
API_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"
REFERENCE_URL = "https://haveibeenpwned.com/"


# Centralizar la cobertura evita que cada rama construya el SourceCheck de forma distinta.
def _check(status: SourceCheckStatus, detail: str) -> SourceCheck:
    return SourceCheck(source=SOURCE, status=status, detail=detail)


# Validar la forma de la respuesta evita tratar un error de la API como una brecha.
def _breach_names(payload: object) -> list[str]:
    """Nombres de brecha de la respuesta (lista de objetos con 'Name')."""
    if not isinstance(payload, list):
        return []
    names: list[str] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = item.get("Name")
        if isinstance(name, str) and name.strip():
            names.append(name.strip())
    return names


@register
class HibpModule:
    """Brechas en las que aparece un email, según Have I Been Pwned."""

    name = "hibp"
    requires_network = True
    accepts = frozenset({"email"})
    web_opt_in = True
    web_label = "Have I Been Pwned"
    web_description = (
        "Brechas de un email en HIBP. Fuente externa de pago: requiere clave "
        "(OSINT_HIBP_API_KEY); sin ella se omite."
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

    # Omitir sin clave, en vez de fallar, deja claro que la fuente es opcional.
    def run(self, target: Target) -> ModuleOutput:
        if not target.email:
            return ModuleOutput()
        api_key = self._settings.hibp_api_key
        if not api_key:
            raise ModuleSkipped(
                "HIBP: define OSINT_HIBP_API_KEY para consultar esta fuente (requiere clave)"
            )

        url = API_URL.format(account=quote(target.email, safe=""))
        headers = {"hibp-api-key": api_key, "user-agent": self._settings.user_agent}
        response = self._session.get(
            url, headers=headers, params={"truncateResponse": "true"}
        )

        if response.status_code == HTTPStatus.UNAUTHORIZED:
            return ModuleOutput(
                source_checks=[_check(SourceCheckStatus.INCONCLUSIVE, "HTTP 401 (clave inválida)")]
            )
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            return ModuleOutput(
                source_checks=[_check(SourceCheckStatus.INCONCLUSIVE, "HTTP 429 (límite de uso)")]
            )
        if response.status_code == HTTPStatus.NOT_FOUND:  # sin brechas para este email
            return ModuleOutput(source_checks=[_check(SourceCheckStatus.NOT_FOUND, "HTTP 404")])
        response.raise_for_status()  # otros errores HTTP: los gestiona el servicio

        names = _breach_names(response.json())
        if not names:
            return ModuleOutput(
                source_checks=[_check(SourceCheckStatus.NOT_FOUND, "Sin brechas")]
            )
        return ModuleOutput(
            findings=[
                Finding(
                    entity_type="email",
                    type="breach",
                    value=name,
                    source=SOURCE,
                    source_url=REFERENCE_URL,
                )
                for name in names
            ],
            source_checks=[_check(SourceCheckStatus.FOUND, f"HTTP {response.status_code}")],
        )
