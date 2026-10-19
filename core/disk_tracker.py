"""
Módulo de Rastreo de Archivos Creados y Modificados Recientemente.
Permite descubrir qué archivos y carpetas están devorando el espacio en disco
en los últimos 7 días (u otro período configurable), utilizando escaneo acelerado
con os.scandir y filtrado inteligente de carpetas del sistema.
"""

import os
import sys
import time
import subprocess
from typing import List, Dict, Any, Callable, Optional


def format_bytes(size: int) -> str:
    """Convierte un tamaño en bytes a formato legible (KB, MB, GB)."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


class DiskTracker:
    """Rastreador de archivos y consumo de espacio en disco."""

    # Carpetas de desarrollo y sistema que generan millones de archivos pequeños irrelevantes
    SKIP_FOLDER_NAMES = {
        ".git", "node_modules", "venv", ".venv", "__pycache__", ".cache",
        "winsxs", "$recycle.bin", "system volume information", "package cache",
        ".vscode", ".idea", ".nuget"
    }

    def __init__(self):
        self._stop_requested = False

    def stop_scan(self):
        """Detiene el rastreo de archivos en curso."""
        self._stop_requested = True

    def open_in_explorer(self, file_path: str) -> bool:
        """Abre el Explorador de Windows resaltando el archivo indicado."""
        try:
            norm_path = os.path.normpath(file_path)
            if os.path.exists(norm_path):
                subprocess.Popen(f'explorer.exe /select,"{norm_path}"')
                return True
        except Exception:
            pass
        return False

    def _fast_walk(
        self,
        root_dir: str,
        time_threshold: float,
        min_size_bytes: int,
        matching_files: List[Dict[str, Any]],
        folder_growth: Dict[str, int],
        extension_growth: Dict[str, int],
        state: Dict[str, int],
        progress_callback: Optional[Callable[[int, str], None]] = None
    ):
        """Recorrido recursivo ultra-rápido utilizando os.scandir."""
        if self._stop_requested:
            return

        subdirs = []
        try:
            with os.scandir(root_dir) as it:
                for entry in it:
                    if self._stop_requested:
                        return

                    try:
                        # Si es subdirectorio, verificar si se omite
                        if entry.is_dir(follow_symlinks=False):
                            name_lower = entry.name.lower()
                            if name_lower not in self.SKIP_FOLDER_NAMES and not name_lower.startswith("."):
                                subdirs.append(entry.path)
                            continue

                        # Si es archivo
                        if entry.is_file(follow_symlinks=False):
                            state["total_scanned"] += 1
                            if progress_callback and state["total_scanned"] % 250 == 0:
                                progress_callback(state["total_scanned"], root_dir)

                            stat = entry.stat(follow_symlinks=False)
                            sz = stat.st_size

                            # En Windows: st_ctime = fecha creación, st_mtime = fecha modificación
                            ctime = stat.st_ctime
                            mtime = stat.st_mtime
                            is_recent = (ctime >= time_threshold) or (mtime >= time_threshold)

                            if is_recent:
                                state["total_recent_bytes"] += sz

                                if sz >= min_size_bytes:
                                    ext = os.path.splitext(entry.name)[1].lower() or "Sin Extensión"
                                    extension_growth[ext] = extension_growth.get(ext, 0) + sz
                                    folder_growth[root_dir] = folder_growth.get(root_dir, 0) + sz

                                    recent_date = max(ctime, mtime)
                                    date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(recent_date))

                                    matching_files.append({
                                        "name": entry.name,
                                        "path": entry.path,
                                        "folder": root_dir,
                                        "size_bytes": sz,
                                        "size_formatted": format_bytes(sz),
                                        "extension": ext,
                                        "date_timestamp": recent_date,
                                        "date_formatted": date_str
                                    })
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
        except (PermissionError, FileNotFoundError, OSError):
            return

        # Recorrer subdirectorios
        for sdir in subdirs:
            if self._stop_requested:
                break
            self._fast_walk(
                sdir, time_threshold, min_size_bytes, matching_files,
                folder_growth, extension_growth, state, progress_callback
            )

    def scan_recent_files(
        self,
        base_paths: Optional[List[str]] = None,
        days: int = 7,
        min_size_mb: float = 1.0,
        limit_results: int = 100,
        progress_callback: Optional[Callable[[int, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Escanea carpetas clave buscando archivos creados o modificados en los últimos N días.
        """
        self._stop_requested = False

        if not base_paths:
            user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
            base_paths = [
                os.path.join(user_profile, "Downloads"),
                os.path.join(user_profile, "Documents"),
                os.path.join(user_profile, "Videos"),
                os.path.join(user_profile, "Desktop"),
                os.path.join(user_profile, "AppData", "Local", "Temp"),
                os.path.join(user_profile, "AppData", "Local", "CrashDumps"),
                os.path.join(user_profile, "AppData", "Roaming")
            ]

        time_threshold = time.time() - (days * 86400)
        min_size_bytes = int(min_size_mb * 1024 * 1024)

        matching_files: List[Dict[str, Any]] = []
        folder_growth: Dict[str, int] = {}
        extension_growth: Dict[str, int] = {}
        state = {"total_scanned": 0, "total_recent_bytes": 0}

        for path in base_paths:
            if self._stop_requested:
                break
            if os.path.exists(path):
                self._fast_walk(
                    path, time_threshold, min_size_bytes, matching_files,
                    folder_growth, extension_growth, state, progress_callback
                )

        # Ordenar por tamaño descendente
        matching_files.sort(key=lambda x: x["size_bytes"], reverse=True)
        top_files = matching_files[:limit_results]

        # Top carpetas con mayor peso reciente
        sorted_folders = sorted(folder_growth.items(), key=lambda x: x[1], reverse=True)[:6]
        top_folders = [
            {"folder": f, "size_bytes": sz, "size_formatted": format_bytes(sz)}
            for f, sz in sorted_folders
        ]

        # Top extensiones recientes
        sorted_exts = sorted(extension_growth.items(), key=lambda x: x[1], reverse=True)[:8]
        top_extensions = [
            {"extension": ext, "size_bytes": sz, "size_formatted": format_bytes(sz)}
            for ext, sz in sorted_exts
        ]

        return {
            "days": days,
            "min_size_mb": min_size_mb,
            "total_files_scanned": state["total_scanned"],
            "matching_files_count": len(matching_files),
            "total_recent_space_bytes": state["total_recent_bytes"],
            "total_recent_space_formatted": format_bytes(state["total_recent_bytes"]),
            "top_files": top_files,
            "top_folders": top_folders,
            "top_extensions": top_extensions
        }
