"""Contrato de los reporters y utilidades comunes."""

from __future__ import annotations

import re
import uuid
from pathlib import Path
from typing import Protocol

from osint_tool.models import Report

# Nombres de carpeta seguros: letras, dígitos y . _ - ; el resto se sustituye.
_SLUG_RE = re.compile(r"[^A-Za-z0-9._-]+")


# Sanear el nombre evita rutas inválidas o fuera de la carpeta de salida.
def _slugify(name: str) -> str:
    """Convierte un nombre en algo seguro como carpeta (o cadena vacía)."""
    slug = _SLUG_RE.sub("-", name.strip()).strip("-._")
    return slug[:60]

LEGAL_NOTICE = (
    "Uso responsable: solo con fines educativos, con datos propios o ficticios, "
    "y respetando los términos de servicio de cada fuente y el RGPD. "
    "Los informes pueden contener datos personales: guárdalos de forma segura y "
    "elimínalos cuando dejen de ser necesarios."
)


class Reporter(Protocol):
    """Genera uno o varios ficheros a partir de un `Report`."""

    name: str

    # El contrato común permite combinar formatos sin conocer sus implementaciones.
    def write(self, report: Report, directory: Path) -> list[Path]:
        """Escribe los ficheros en `directory` y devuelve sus rutas."""
        ...


# Un sufijo único impide que ejecuciones concurrentes sobrescriban evidencia anterior.
def create_report_dir(output_dir: Path, report: Report, name: str | None = None) -> Path:
    """Crea una carpeta nueva y única para el informe.

    Si se indica `name`, se usa como nombre de carpeta (saneado) y, si ya
    existe, se le añade un sufijo único. Sin `name`, se usa
    <output_dir>/<fecha>-<sufijo>; el sufijo aleatorio evita que dos
    ejecuciones (p. ej. en la web) escriban en la misma carpeta.
    """
    slug = _slugify(name) if name else ""
    if slug:
        directory = output_dir / slug
        if directory.exists():  # no sobrescribir un informe con el mismo nombre
            directory = output_dir / f"{slug}-{uuid.uuid4().hex[:6]}"
    else:
        stamp = report.created_at.strftime("%Y%m%dT%H%M%S")
        directory = output_dir / f"{stamp}-{uuid.uuid4().hex[:6]}"
    directory.mkdir(parents=True, exist_ok=False)
    return directory