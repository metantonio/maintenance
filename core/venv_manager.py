"""
Módulo de Detección, Análisis y Eliminación de Entornos Virtuales de Python.
Permite descubrir entornos venv, conda y poetry en el disco, calcular su tamaño
y eliminarlos de forma segura individualmente o en lote para recuperar espacio.
"""

import os
import sys
import stat
import shutil
import time
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


def _remove_readonly(func, path, excinfo):
    """Manejador para eliminar archivos con atributo de solo lectura en Windows."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


class VenvManager:
    """Administrador de Entornos Virtuales de Python."""

    # Carpetas a omitir para no perder tiempo recursando
    SKIP_DIRS = {
        ".git", "node_modules", "build", "dist", "__pycache__",
        "appdata", "$recycle.bin", "system volume information", "windows"
    }

    def __init__(self):
        self._stop_requested = False
        # Identificar la ruta del entorno virtual de la aplicación actual
        self.current_app_venv = os.path.normpath(sys.prefix).lower()

    def stop_scan(self):
        """Detiene el escaneo activo."""
        self._stop_requested = True

    def calculate_dir_size(self, dir_path: str) -> int:
        """Calcula el tamaño total en bytes de un directorio usando os.scandir."""
        total = 0
        try:
            with os.scandir(dir_path) as it:
                for entry in it:
                    try:
                        if entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                        elif entry.is_dir(follow_symlinks=False):
                            total += self.calculate_dir_size(entry.path)
                    except (PermissionError, FileNotFoundError, OSError):
                        pass
        except (PermissionError, FileNotFoundError, OSError):
            pass
        return total

    def _extract_venv_metadata(self, venv_path: str) -> Dict[str, Any]:
        """Lee 'pyvenv.cfg' si existe para extraer la versión de Python."""
        meta = {
            "version": "Desconocida",
            "base_python": "Desconocido",
            "prompt": ""
        }
        cfg_path = os.path.join(venv_path, "pyvenv.cfg")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if "=" in line:
                            k, v = line.split("=", 1)
                            k = k.strip().lower()
                            v = v.strip()
                            if k == "version":
                                meta["version"] = v
                            elif k in ("home", "base-executable", "base-prefix"):
                                meta["base_python"] = v
                            elif k == "prompt":
                                meta["prompt"] = v
            except Exception:
                pass
        return meta

    def scan_virtual_environments(
        self,
        search_paths: Optional[List[str]] = None,
        max_depth: int = 5,
        progress_callback: Optional[Callable[[str, int], None]] = None
    ) -> List[Dict[str, Any]]:
        """
        Escanea rutas clave en busca de entornos virtuales de Python.
        Devuelve una lista de diccionarios con información detallada de cada venv.
        """
        self._stop_requested = False

        if not search_paths:
            # Rutas típicas donde los desarrolladores tienen sus entornos virtuales
            user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
            candidates = [
                "C:\\Repositorios",
                os.path.join(user_profile, "Projects"),
                os.path.join(user_profile, "source", "repos"),
                os.path.join(user_profile, "PycharmProjects"),
                os.path.join(user_profile, "Desktop"),
                os.path.join(user_profile, "Documents"),
                os.path.join(user_profile, ".virtualenvs")
            ]
            search_paths = [p for p in candidates if os.path.exists(p)]

            # Si no hay ninguna de las carpetas anteriores, escanear user_profile
            if not search_paths:
                search_paths = [user_profile]

        found_paths = set()
        venv_entries = []

        for root in search_paths:
            if self._stop_requested:
                break
            if not os.path.exists(root):
                continue

            root_abs = os.path.abspath(root)

            for dirpath, dirnames, filenames in os.walk(root_abs):
                if self._stop_requested:
                    break

                rel = os.path.relpath(dirpath, root_abs)
                depth = len(rel.split(os.sep)) if rel != "." else 0
                if depth > max_depth:
                    dirnames.clear()
                    continue

                # Filtrar directorios que no deben explorarse
                dirnames[:] = [
                    d for d in dirnames
                    if d.lower() not in self.SKIP_DIRS and not d.startswith(".")
                ]

                # Comprobar si este directorio es un entorno virtual de Python
                is_venv = (
                    "pyvenv.cfg" in filenames
                    or os.path.exists(os.path.join(dirpath, "Scripts", "activate"))
                    or os.path.exists(os.path.join(dirpath, "bin", "activate"))
                    or os.path.exists(os.path.join(dirpath, "conda-meta"))
                )

                if is_venv:
                    norm_path = os.path.normpath(dirpath)
                    if norm_path not in found_paths:
                        found_paths.add(norm_path)

                        if progress_callback:
                            progress_callback(norm_path, len(found_paths))

                        meta = self._extract_venv_metadata(norm_path)
                        sz = self.calculate_dir_size(norm_path)

                        # Saber si es el venv actual de esta misma aplicación
                        is_current = (norm_path.lower() == self.current_app_venv)

                        # Nombre legible del proyecto / entorno
                        parent_name = os.path.basename(os.path.dirname(norm_path))
                        folder_name = os.path.basename(norm_path)
                        display_name = f"{parent_name}/{folder_name}" if parent_name else folder_name

                        # Fecha de última modificación
                        try:
                            mtime = os.path.getmtime(norm_path)
                            date_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime))
                        except Exception:
                            date_str = "Desconocida"

                        entry = {
                            "path": norm_path,
                            "display_name": display_name,
                            "folder_name": folder_name,
                            "parent_folder": os.path.dirname(norm_path),
                            "size_bytes": sz,
                            "size_formatted": format_bytes(sz),
                            "python_version": meta["version"],
                            "last_modified": date_str,
                            "is_current": is_current,
                            "is_conda": os.path.exists(os.path.join(norm_path, "conda-meta"))
                        }
                        venv_entries.append(entry)

                    # Muy importante: No descender dentro del venv buscando más venvs
                    dirnames.clear()

        # Ordenar por tamaño descendente (los que más espacio ocupan primero)
        venv_entries.sort(key=lambda x: x["size_bytes"], reverse=True)
        return venv_entries

    def delete_virtual_environment(self, venv_path: str) -> Dict[str, Any]:
        """
        Elimina un entorno virtual seleccionado por completo.
        Protege el entorno virtual en uso por esta aplicación.
        """
        norm_path = os.path.normpath(venv_path)

        if norm_path.lower() == self.current_app_venv:
            return {
                "success": False,
                "error": "No puedes eliminar el entorno virtual que está ejecutando esta aplicación."
            }

        if not os.path.exists(norm_path):
            return {
                "success": False,
                "error": "La ruta especificada no existe."
            }

        # Calcular tamaño antes de borrar para reportarlo
        sz = self.calculate_dir_size(norm_path)

        try:
            shutil.rmtree(norm_path, onerror=_remove_readonly)
            return {
                "success": True,
                "freed_bytes": sz,
                "freed_formatted": format_bytes(sz),
                "path": norm_path
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "path": norm_path
            }
