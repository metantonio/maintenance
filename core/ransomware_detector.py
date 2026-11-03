"""
Módulo de Detección de Ransomware (detecta el cifrado EN CURSO).

No es un antivirus (no firma archivos): clasifica PATRONES de comportamiento
típicos de un cifrador activo:

  * Archivos con entropía muy alta → los datos cifrados tienen ~8 bits/byte
    (un documento txt normal está en ~4.5, una imagen en ~7, un archivo cifrado
     en ~7.7-7.99).
  * Modificación o creación MASIVA de archivos (el cifrador corre en bucle).
  * Extensiones conocidas de familias de ransomware (LockBit, Conti, Royal,
     Magma, Babel, Akira, Nox, Petya, Ransack, Shadow, Nohome, ...).
  * Tasa de creación de archivos anómala (borrada de archivos nuevos en poco
     tiempo).

Uso: RansomwareDetector().scan() devuelve un dicto estructurado con la
clasificación, severidad y recomendaciones.
"""

import math
import os
import time
from typing import Dict, Any, List, Optional


def _shannon_entropy(data: bytes) -> float:
    """Entropía de Shannon en bits por byte. 0 = muy repetido, ~8 = aleatorio."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    entropy = 0.0
    for c in freq:
        if c > 0:
            p = c / n
            entropy -= p * math.log2(p)
    return entropy


def _file_entropy(path: str, sample_bytes: int = 1_048_576) -> Optional[float]:
    """Lectura parcial del archivo (1 MB por defecto) y entropía de la muestra."""
    try:
        size = os.path.getsize(path)
        if size < 512:
            return None
        read_size = min(size, sample_bytes)
        with open(path, "rb") as f:
            data = f.read(read_size)
    except (OSError, PermissionError, FileNotFoundError):
        return None
    if not data:
        return None
    return _shannon_entropy(data)


def _format_bytes(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


# Carpetas que NO aportan señal de cifrado (dev, cache, junk). Se omiten
# al contar "modificación masiva" y "tasa de creación" para no dar ruido.
JUNK_DIRS = {
    "node_modules", ".git", "venv", ".venv", "__pycache__", ".cache",
    ".nuget", ".vscode", ".idea", ".pytest_cache", "build", "dist",
    ".tmp", "temp", "temporal", "$recycle.bin", "system volume information",
    "package cache", ".coverage", "htmlcov",
}

# Extensiones de datos "normales": un archivo con estas extensiones y entropía
# alta + cambiado recientemente es una señal fuerte de cifrado.
DATA_EXTENSIONS = {
    "txt", "pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
    "ppt", "pptx", "pot", "odt", "ods", "odp",
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "heic", "raw", "tif", "tiff",
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm",
    "mp3", "wav", "aac", "m4a", "flac", "ogg",
    "csv", "json", "xml", "sql", "db", "sqlite", "sqlite3", "bak", "dat",
    "html", "htm", "css", "js", "py", "md", "log",
}

# Extensiones conocidas de familias de ransomware (se amplía en _build).
_BASE_RANSOMWARE_EXTENSIONS = {
    # LockBit / Revil y derivados
    "lockbit", "josh", "ghos", "wrs", "wrs1", "wrs2",
    # Conti
    "crypted", "crypted1", "crypted2",
    # Royal
    "royal", "royal1", "royal2", "royal3",
    # Magma
    "magma", "magma1", "magma2", "magma3",
    # Babel
    "babel", "babel1", "babel2",
    # Akira
    "akira",
    # Nox
    "nox",
    # Petya / EternalBlue
    "petya", "ptah",
    # Ransack
    "r", "r1",
    # Shadow
    "shadow", "shadow1",
    # Nohome
    "h0me",
    # Genéricas
    "enc", "encd", "encx", "encr", "encrypted", "crypt", "crypto",
    "locked", "lock", "lck", "lckb",
    "victor", "victor2", "victor3", "victor4", "victor5",
}


def _build_ransomware_extensions() -> set:
    """Construye el set de extensiones de ransomware (LockBit 1-999, etc.)."""
    exts = set(_BASE_RANSOMWARE_EXTENSIONS)
    for n in range(0, 1000):
        exts.add(f"lockbit{n}")
    for n in range(1, 50):
        exts.add(f"crypted{n}")
        exts.add(f"royal{n}")
        exts.add(f"magma{n}")
        exts.add(f"josh{n}")
        exts.add(f"ghos{n}")
        exts.add(f"wrs{n}")
        exts.discard("encr")  # keep
    # Quitamos duplicados
    return exts


class RansomwareDetector:
    """Detección de patrones de cifrado (ransomware) en archivos del usuario."""

    ENTROPY_HIGH = 7.5      # umbral de "probablemente cifrado"
    ENTROPY_STRONG = 7.85   # umbral fuerte (casi seguro que es cifrado)
    SAMPLE_BYTES = 1_048_576   # lee 1 MB por archivo
    MIN_SIZE_BYTES = 512       # archivos muy cortos no dan señal
    MASS_THRESHOLD = 50        # archivos modificados/creados en la ventana
    CREATION_THRESHOLD = 300   # archivos creados en la ventana (tasa anómala)
    ENTROPY_MAX_SCAN = 300     # máx. archivos a muestrear para entropía

    def __init__(self):
        self._stop_requested = False
        self.RANSOMWARE_EXTENSIONS = _build_ransomware_extensions()
        self.JUNK_DIRS = JUNK_DIRS
        self.DATA_EXTENSIONS = DATA_EXTENSIONS

    def stop_scan(self):
        """Detiene el análisis activo."""
        self._stop_requested = True

    def _default_base_paths(self) -> List[str]:
        """Rutas por defecto donde mirar (carpetas de datos del usuario)."""
        profile = os.environ.get("USERPROFILE", "")
        paths = [
            os.path.join(profile, "Desktop"),
            os.path.join(profile, "Documents"),
            os.path.join(profile, "Downloads"),
            os.path.join(profile, "Pictures"),
            os.path.join(profile, "Videos"),
            os.path.join(profile, "Music"),
        ]
        return [p for p in paths if p and os.path.exists(p)]

    @staticmethod
    def _silence(err):
        """Ignora errores de acceso (carpetas bloqueadas, permisos)."""
        pass

    def _is_unknown_extension(self, ext: str) -> bool:
        """True si la extensión no es una extensión conocida de datos."""
        if not ext:
            return True
        return ext not in self.DATA_EXTENSIONS

    def scan(
        self,
        base_paths: Optional[List[str]] = None,
        window_min: int = 60,
        min_size_bytes: Optional[int] = None,
        max_entropy_files: int = None,
        progress_callback: Optional[callable] = None,
    ) -> Dict[str, Any]:
        """
        Ejecuta el análisis completo de patrones de cifrado.

        Devuelve un dict con:
          detected, severity, summary, high_entropy_files,
          ransomware_ext_files, mass_modification, file_creation_rate,
          details, recommendations
        """
        self._stop_requested = False
        min_size = min_size_bytes or self.MIN_SIZE_BYTES
        max_ent = max_entropy_files or self.ENTROPY_MAX_SCAN
        window = window_min * 60
        now = time.time()
        threshold = now - window

        base_paths = base_paths or self._default_base_paths()

        candidates: List[tuple] = []      # (path, mtime, ctime, size)
        created_count = 0
        per_folder: Dict[str, Dict[str, int]] = {}

        # ---- 1) Recolección de candidatos ----
        for base in base_paths:
            for root, dirs, files in os.walk(base, onerror=self._silence):
                if self._stop_requested:
                    break
                # Omitir carpetas junk
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in self.JUNK_DIRS and not d.startswith(".")
                ]
                for fname in files:
                    if self._stop_requested:
                        break
                    fpath = os.path.join(root, fname)
                    try:
                        st = os.lstat(fpath)
                    except (OSError, PermissionError, FileNotFoundError):
                        continue
                    mtime, ctime = st.st_mtime, st.st_ctime
                    recent_m = mtime >= threshold
                    recent_c = ctime >= threshold

                    if recent_c:
                        created_count += 1

                    per_folder.setdefault(root, {"modified": 0, "created": 0})
                    if recent_m:
                        per_folder[root]["modified"] += 1
                    if recent_c:
                        per_folder[root]["created"] += 1

                    # Candidato para entropía: mtime dentro de ventana + tamaño
                    if recent_m and st.st_size >= min_size:
                        candidates.append((fpath, mtime, ctime, st.st_size))

        if progress_callback:
            progress_callback(len(candidates), len(base_paths))

        # ---- 2) Entropía de los candidatos (los más grandes primero) ----
        candidates.sort(key=lambda x: x[3], reverse=True)
        high_entropy: List[Dict[str, Any]] = []
        rs_ext_files: List[Dict[str, Any]] = []
        scanned = 0
        for fpath, mtime, ctime, size in candidates:
            if scanned >= max_ent:
                break
            if self._stop_requested:
                break
            ext = os.path.splitext(fpath)[1].lower().lstrip(".")
            ent = _file_entropy(fpath)
            scanned += 1

            is_rs_ext = bool(ext) and ext.lower() in self.RANSOMWARE_EXTENSIONS
            is_data = ext in self.DATA_EXTENSIONS
            is_unknown = self._is_unknown_extension(ext)

            entry = {
                "path": fpath,
                "name": os.path.basename(fpath),
                "folder": os.path.dirname(fpath),
                "size_bytes": size,
                "size_formatted": _format_bytes(size),
                "extension": ext,
                "entropy": ent,
                "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime)),
                "ctime": time.strftime("%Y-%m-%d %H:%M", time.localtime(ctime)),
                "is_data_ext": is_data,
                "is_unknown_ext": is_unknown,
                "is_ransomware_ext": is_rs_ext,
                "risk": "",
                "reason": "",
            }

            if ent is not None and ent >= self.ENTROPY_HIGH:
                if is_rs_ext:
                    entry["risk"] = "CRÍTICO"
                    entry["reason"] = (
                        f"Extensión conocida de ransomware ('{ext}') + entropía "
                        f"{ent:.2f} bits/byte"
                    )
                    rs_ext_files.append(entry)
                elif ent >= self.ENTROPY_STRONG:
                    entry["risk"] = "CRÍTICO"
                    entry["reason"] = (
                        f"Entropía {ent:.2f} bits/byte (casi cifrado) + "
                        f"{'extensión de datos' if is_data else 'extensión desconocida'}"
                    )
                    high_entropy.append(entry)
                elif (ent >= self.ENTROPY_HIGH and (is_data or is_unknown)):
                    entry["risk"] = "ADVERTENCIA"
                    entry["reason"] = (
                        f"Entropía alta ({ent:.2f}) en archivo con extensión de datos "
                        f"'{ext}' — posible cifrado"
                    )
                    high_entropy.append(entry)
            elif is_rs_ext:
                # Extensión de ransomware aunque la entropía no se haya calculado
                entry["risk"] = "CRÍTICO"
                entry["reason"] = f"Extensión de ransomware: '{ext}'"
                rs_ext_files.append(entry)

        # ---- 3) Modificación masiva por carpeta ----
        mass_modification: List[Dict[str, int]] = []
        for folder, d in per_folder.items():
            total = d["modified"] + d["created"]
            if total >= self.MASS_THRESHOLD:
                mass_modification.append({
                    "folder": folder,
                    "modified": d["modified"],
                    "created": d["created"],
                    "total": total,
                })
        mass_modification.sort(key=lambda x: x["total"], reverse=True)

        # ---- 4) Tasa de creación ----
        creation_rate = {
            "files_created_in_window": created_count,
            "window_min": window_min,
            "per_min": round(created_count / max(window_min, 1), 1),
            "suspicious": created_count >= self.CREATION_THRESHOLD,
            "threshold": self.CREATION_THRESHOLD,
        }

        # ---- 5) Severidad y resumen ----
        high_critical = any(e["entropy"] >= self.ENTROPY_STRONG for e in high_entropy)
        critical = bool(rs_ext_files) or high_critical or (mass_modification and mass_modification[0]["total"] >= self.MASS_THRESHOLD * 3)
        adverse = bool(rs_ext_files) or bool(high_entropy) or bool(mass_modification) or creation_rate["suspicious"]

        details: List[str] = []
        recommendations: List[str] = []

        if rs_ext_files:
            details.append(
                f"{len(rs_ext_files)} archivo(s) con extensión conocida de "
                "ransomware detectado(s) en los últimos {0} min.".format(window_min)
            )
            recommendations.append("Archivos con extensión de ransomware activos: "
                                   "posible cifrado en curso.")
        if high_entropy:
            details.append(
                f"{len(high_entropy)} archivo(s) con entropía alta ({self.ENTROPY_HIGH}-8) "
                "en los últimos {0} min.".format(window_min)
            )
        if mass_modification:
            top = mass_modification[0]
            details.append(
                "Modificación masiva: {0} archivo(s) tocado(s) en {1} min en: "
                "{2}".format(top["total"], window_min, top["folder"])
            )
        if creation_rate["suspicious"]:
            details.append(
                "Tasa de creación anómala: {0} archivo(s) creado(s) en {1} min "
                "(umbral {2})".format(created_count, window_min, creation_rate["threshold"])
            )

        if critical:
            severity = "CRÍTICO"
            summary = (
                "POSIBLE CIFRADO ACTIVO: patrones de ransomware detectados "
                "(entropía alta, extensión de cifrador y/o modificación masiva). "
                "Actúa con cuidado: no borres, no reemplaces."
            )
            recommendations += [
                "No apagues ni reinicies el equipo si hay datos importantes en riesgo.",
                "Aísla el equipo de la red (desconecta Wi-Fi/Ethernet) para evitar "
                "que suba tus datos a un servidor externo.",
                "Si puedes, copia los metadatos (nombres, rutas, fechas) antes de "
                "hacer nada para documentar el ataque.",
                "Cambia tus contraseñas desde otro dispositivo de confianza.",
            ]
        elif adverse:
            severity = "ADVERTENCIA"
            summary = (
                "Patrones suaves de cifrado: verifica manualmente los archivos "
                "señalados (entropía, extensión, modificación masiva)."
            )
            recommendations += [
                "Revisa los archivos señalados: si están ilegibles o con extensión "
                "rara, es posible que estén cifrados.",
                "Repite el análisis en 10-30 minutos para ver si crece el número.",
            ]
        else:
            severity = "NORMAL"
            summary = (
                "Sin indicios de cifrado activo. {0} archivo(s) analizado(s) "
                "por entropía, {1} carpeta(s) vigiladas.".format(scanned, len(base_paths))
            )
            recommendations += [
                "Todo normal. Mantén la monitorización activa.",
            ]

        # Limpiamos el orden por severidad
        high_entropy.sort(key=lambda e: e.get("entropy", 0), reverse=True)
        rs_ext_files.sort(key=lambda e: e["entropy"] if e.get("entropy") else 0, reverse=True)

        return {
            "detected": bool(rs_ext_files) or bool(high_entropy) or bool(mass_modification) or creation_rate["suspicious"],
            "severity": severity,
            "window_min": window_min,
            "summary": summary,
            "high_entropy_files": high_entropy,
            "ransomware_ext_files": rs_ext_files,
            "mass_modification": mass_modification,
            "file_creation_rate": creation_rate,
            "files_scanned": len(candidates),
            "entropy_scanned": scanned,
            "details": details,
            "recommendations": recommendations,
        }

    def quick_creation_rate(self, base_paths: Optional[List[str]] = None,
                            window_min: int = 5) -> Dict[str, Any]:
        """
        Análisis RÁPIDO: solo cuenta archivos creados/modificados en la ventana.
        No calcula entropía. Para monitorización en segundo plano.
        """
        self._stop_requested = False
        window = window_min * 60
        now = time.time()
        threshold = now - window
        base_paths = base_paths or self._default_base_paths()

        created = 0
        modified = 0
        per_folder = {}
        for base in base_paths:
            for root, dirs, files in os.walk(base, onerror=self._silence):
                if self._stop_requested:
                    break
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in self.JUNK_DIRS and not d.startswith(".")
                ]
                for fname in files:
                    if self._stop_requested:
                        break
                    fpath = os.path.join(root, fname)
                    try:
                        st = os.lstat(fpath)
                    except (OSError, PermissionError, FileNotFoundError):
                        continue
                    if st.st_ctime >= threshold:
                        created += 1
                    if st.st_mtime >= threshold:
                        modified += 1
                    per_folder.setdefault(root, {"modified": 0, "created": 0})
                    if st.st_mtime >= threshold:
                        per_folder[root]["modified"] += 1
                    if st.st_ctime >= threshold:
                        per_folder[root]["created"] += 1

        suspicious_folders = [
            {"folder": f, **d, "total": d["modified"] + d["created"]}
            for f, d in per_folder.items()
            if d["modified"] + d["created"] >= self.MASS_THRESHOLD
        ]
        suspicious_folders.sort(key=lambda x: x["total"], reverse=True)

        return {
            "window_min": window_min,
            "created": created,
            "modified": modified,
            "per_min_created": round(created / max(window_min, 1), 1),
            "suspicious_folders": suspicious_folders,
            "suspicious": suspicious_folders,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }


if __name__ == "__main__":
    import sys
    dd = RansomwareDetector()
    res = dd.scan(window_min=15)
    print("Severidad:", res["severity"])
    print("Resumen:", res["summary"])
    for d in res["details"]:
        print("  -", d)
