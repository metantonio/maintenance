"""
Monitoreo de Integridad de Archivos (FIM) — el corazón anti-ransomware.

Genera una baseline de hashes SHA-256 de las carpetas vigiladas y las
compara en verificaciones posteriores. La detección de cambios (modificados,
nuevos, eliminados) es la defensa central contra ransomware: un cifrador
deja huella (los hashes de tus documentos cambian) y esto lo detecta.

La baseline se guarda en:
  %APPDATA%\\NetShield\\Integrity\\baseline.json

Uso:
    monitor = IntegrityMonitor()
    monitor.create_default_config()
    monitor.generate_baseline()
    res = monitor.verify_baseline()
"""

import json
import os
import time
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Generator

APP_NAME = "NetShield"

# Carpetas que NO se vigilan (dev, cache, junk) dentro de las rutas vigiladas.
SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", ".cache",
    ".nuget", ".vscode", ".idea", "build", "dist", "tmp", "temp",
    ".pytest_cache", ".coverage", "$recycle.bin", "system volume information",
    "package cache",
}

WATCHED_DEFAULTS = ("Desktop", "Documents", "Downloads", "Pictures", "Videos", "Music")


def _app_dir() -> str:
    base = os.environ.get("APPDATA")
    if not base:
        base = os.path.join(os.environ.get("USERPROFILE", "C:\\Users\\Default"), "AppData")
    return os.path.join(base, APP_NAME)


def _sha256_file(path: str) -> Optional[str]:
    """SHA-256 de un archivo (lectura por bloques de 1 MB)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except (OSError, PermissionError, FileNotFoundError):
        return None
    return h.hexdigest()


def _is_watched_dir(path: str) -> bool:
    """Evita vigilar la propia carpeta de baseline (evitar recursión)."""
    return path.lower().endswith(os.sep + os.path.basename(_app_dir()).lower()) or \
           os.path.basename(path).lower().endswith("integrity")


class IntegrityMonitor:
    """Gestión de baseline de hashes (SHA-256) y verificación de integridad."""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or os.path.join(_app_dir(), "Integrity")
        self.baseline_file = os.path.join(self.base_dir, "baseline.json")
        self.config_file = os.path.join(self.base_dir, "config.json")

    # ---------------- configuración ----------------

    def default_config(self) -> Dict[str, Any]:
        profile = os.environ.get("USERPROFILE") or "C:\\Users\\Default"
        watched = [os.path.join(profile, d) for d in WATCHED_DEFAULTS]
        return {
            "watched_paths": [p for p in watched if os.path.isdir(p)],
            "include_extensions": [],  # vacía = vigilar todas las extensiones
            "max_file_size_bytes": 2 * 1024 ** 3,  # no hashar archivos > 2 GB
            "created": datetime.now(timezone.utc).isoformat(),
        }

    def load_config(self) -> Optional[Dict[str, Any]]:
        try:
            if not os.path.exists(self.config_file):
                return None
            with open(self.config_file, "r", encoding="utf-8", errors="ignore") as f:
                return json.load(f)
        except Exception:
            return None

    def save_config(self, config: Dict[str, Any]) -> bool:
        try:
            os.makedirs(self.base_dir, exist_ok=True)
            tmp = self.config_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.config_file)
            return True
        except Exception:
            return False

    def create_default_config(self, overwrite: bool = False) -> bool:
        if os.path.exists(self.config_file) and not overwrite:
            return True  # ya existe, no se toca
        cfg = self.default_config()
        # Añadir la carpeta propia de la app si existe
        app_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if os.path.exists(app_root) and os.path.isdir(app_root) and app_root not in cfg["watched_paths"]:
            cfg["watched_paths"].append(app_root)
        return self.save_config(cfg)

    def config_summary(self) -> Dict[str, Any]:
        cfg = self.load_config() or self.default_config()
        return {
            "exists": bool(self.load_config()),
            "watched_paths": cfg.get("watched_paths", []),
            "max_file_size": cfg.get("max_file_size_bytes"),
            "created": cfg.get("created", ""),
        }

    # ---------------- helpers de recorrido ----------------

    def _walk_files(
        self,
        paths: List[str],
        max_size: int,
        include_ext: Optional[set],
        on_error,
    ) -> Generator[tuple, None, None]:
        """Yield (abs_path, size). Omitiendo carpeta de baseline y junk."""
        for root in paths:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root, onerror=on_error):
                # Omitir la carpeta de la propia integridad
                dirnames[:] = [
                    d for d in dirnames
                    if d.lower() not in SKIP_DIRS
                    and not _is_watched_dir(dirpath)
                ]
                for name in filenames:
                    fpath = os.path.join(dirpath, name)
                    if os.path.abspath(fpath).lower().startswith(self.baseline_file.lower()):
                        continue
                    ext = os.path.splitext(name)[1].lower().lstrip(".")
                    if include_ext and ext not in include_ext:
                        continue
                    try:
                        st = os.lstat(fpath)
                    except OSError:
                        continue
                    if not os.path.isfile(fpath) or os.path.islink(fpath):
                        continue
                    if st.st_size <= 0 or st.st_size > max_size:
                        continue
                    yield os.path.normpath(fpath), st.st_size

    def _write_json(self, path: str, data: Any) -> bool:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
            return True
        except Exception:
            return False

    # ---------------- baseline ----------------

    def generate_baseline(
        self,
        watched_paths: Optional[List[str]] = None,
        progress_callback=None,
    ) -> Dict[str, Any]:
        """
        Genera la baseline de hashes.

        Devuelve:
          {success, files_hashed, skipped_size, errors, elapsed_s,
           baseline_file, message}
        """
        config = self.load_config()
        base = config or self.default_config()

        paths = [p for p in (watched_paths or base["watched_paths"]) if os.path.isdir(p)]
        # Persiste las rutas efectivamente usadas en la config para que la
        # verificación utilice exactamente el mismo conjunto de rutas.
        if not config:
            config = self.default_config()
        config["watched_paths"] = paths
        self.save_config(config)
        max_size = base.get("max_file_size_bytes", 2 * 1024 ** 3)
        inc = base.get("include_extensions")
        include_ext = set(inc) if inc else None  # None = todas

        files: Dict[str, str] = {}
        counters = {"files": 0, "skipped_size": 0, "errors": 0}
        start = time.time()

        def on_error(err):
            counters["errors"] += 1

        for path, size in self._walk_files(paths, max_size, include_ext, on_error):
            if path in files:
                continue
            digest = _sha256_file(path)
            if digest is None:
                counters["errors"] += 1
                continue
            files[path] = digest
            counters["files"] += 1
            if progress_callback and counters["files"] % 25 == 0:
                progress_callback(counters["files"])

        baseline = {
            "created": datetime.now(timezone.utc).isoformat(),
            "counters": counters,
            "files": files,
        }
        self._write_json(self.baseline_file, baseline)
        baseline["elapsed_s"] = round(time.time() - start, 2)

        return {
            "success": True,
            "files_hashed": counters["files"],
            "skipped_size": counters["skipped_size"],
            "errors": counters["errors"],
            "elapsed_s": baseline["elapsed_s"],
            "baseline_file": self.baseline_file,
            "message": f"Baseline generada: {counters['files']} archivo(s) hashados.",
        }

    # ---------------- verificación ----------------

    def verify_baseline(self) -> Dict[str, Any]:
        """
        Compara la baseline actual con la generada.

        Devuelve:
          {success, changed, deleted, new_files, checked_files,
           current_files, severity, summary}
        """
        if not os.path.exists(self.baseline_file):
            return {
                "success": False,
                "error": "No existe una baseline previa. Genera una primero.",
                "severity": "",
                "summary": "Sin baseline.",
            }

        try:
            with open(self.baseline_file, "r", encoding="utf-8", errors="ignore") as f:
                baseline = json.load(f)
        except Exception as e:
            return {
                "success": False,
                "error": f"No se puede leer la baseline: {e}",
                "severity": "",
                "summary": "Error de lectura.",
            }

        config = self.load_config()
        base = config or self.default_config()

        paths = [p for p in base["watched_paths"] if os.path.isdir(p)]
        max_size = base.get("max_file_size_bytes", 2 * 1024 ** 3)
        inc = base.get("include_extensions")
        include_ext = set(inc) if inc else None

        current: Dict[str, str] = {}
        counters = {"errors": 0}

        def on_error(err):
            counters["errors"] += 1

        for path, size in self._walk_files(paths, max_size, include_ext, on_error):
            if path in current:
                continue
            digest = _sha256_file(path)
            if digest is None:
                counters["errors"] += 1
                continue
            current[path] = digest

        changed: List[Dict[str, Any]] = []
        deleted: List[Dict[str, Any]] = []
        new_files: List[Dict[str, Any]] = []

        for path, old_hash in baseline.get("files", {}).items():
            if path not in current:
                deleted.append({"path": path, "old_hash": old_hash})
            else:
                if current[path] != old_hash:
                    changed.append({"path": path, "old_hash": old_hash,
                                    "new_hash": current[path]})
        for path, new_hash in current.items():
            if path not in baseline.get("files", {}):
                new_files.append({"path": path, "new_hash": new_hash})

        changed.sort(key=lambda x: x["path"])
        deleted.sort(key=lambda x: x["path"])
        new_files.sort(key=lambda x: x["path"])

        if changed or deleted:
            severity = "CRÍTICO"
            summary = (
                f"Integridad COMPROMETA: {len(changed)} archivo(s) MODIFICADO(S) y "
                f"{len(deleted)} ELIMINADO(S). Posible cifrado/alteración de tus datos."
            )
        elif new_files:
            severity = "ADVERTENCIA" if len(new_files) > 20 else "NORMAL"
            summary = (
                f"Integridad conservada: {len(new_files)} archivo(s) nuevo(s) en "
                "carpetas vigiladas."
            )
        else:
            severity = "NORMAL"
            summary = (
                f"Integridad conservada: sin cambios desde la baseline "
                f"({baseline.get('created', 'sin fecha')})."
            )

        return {
            "success": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "baseline_created": baseline.get("created"),
            "changed": changed,
            "deleted": deleted,
            "new_files": new_files,
            "checked_files": len(baseline.get("files", {})),
            "current_files": len(current),
            "errors": counters["errors"],
            "severity": severity,
            "summary": summary,
        }

    # ---------------- exportación ----------------

    def export_report(
        self,
        dest_dir: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Guarda el reporte en JSON bajo %APPDATA%/NetShield/Reports."""
        base = dest_dir or os.path.join(_app_dir(), "Reports")
        path = os.path.join(base, f"integrity-{datetime.now():%Y%m%d-%H%M%S}.json")
        if payload is None:
            payload = {"type": "integrity", "timestamp": datetime.now().isoformat()}
        self._write_json(path, payload)
        return path
