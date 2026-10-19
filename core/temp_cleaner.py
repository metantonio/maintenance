"""
Módulo de Diagnóstico y Limpieza Segura de Archivos Temporales.
Permite analizar el espacio recuperable y limpiar de forma segura archivos temporales,
volcados de fallos (Crash Dumps), informes de error (WER) y cachés obsoletas de Windows.
"""

import os
import shutil
import ctypes
from typing import Dict, Any, List, Callable, Optional


def format_bytes(size: int) -> str:
    """Convierte un tamaño en bytes a formato legible."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    elif size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.2f} MB"
    else:
        return f"{size / (1024 * 1024 * 1024):.2f} GB"


class TempCleaner:
    """Limpiador seguro de archivos temporales y datos residuales del sistema."""

    def __init__(self):
        self._stop_requested = False

    def stop_operation(self):
        """Detiene la operación en curso."""
        self._stop_requested = True

    def get_cleanup_targets(self) -> List[Dict[str, Any]]:
        """Devuelve las categorías y rutas de limpieza estándar en Windows."""
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        program_data = os.environ.get("PROGRAMDATA", "")
        windir = os.environ.get("WINDIR", "C:\\Windows")
        user_temp = os.environ.get("TEMP", "")

        targets = [
            {
                "id": "user_temp",
                "name": "Archivos Temporales de Usuario",
                "description": "Caché y temporales de aplicaciones en ejecución",
                "path": user_temp,
                "is_directory": True
            },
            {
                "id": "system_temp",
                "name": "Archivos Temporales del Sistema",
                "description": "Temporales creados por servicios y el instalador de Windows",
                "path": os.path.join(windir, "Temp"),
                "is_directory": True
            },
            {
                "id": "crash_dumps",
                "name": "Volcados de Fallo (Crash Dumps)",
                "description": "Archivos .dmp pesados generados cuando un programa falla",
                "path": os.path.join(local_app_data, "CrashDumps"),
                "is_directory": True
            },
            {
                "id": "wer_reports",
                "name": "Informes de Errores de Windows (WER)",
                "description": "Registros de diagnóstico y telemetría de fallos",
                "path": os.path.join(local_app_data, "Microsoft", "Windows", "WER"),
                "is_directory": True
            },
            {
                "id": "update_cache",
                "name": "Caché de Descargas de Windows Update",
                "description": "Instaladores residuales de parches de Windows ya aplicados",
                "path": os.path.join(windir, "SoftwareDistribution", "Download"),
                "is_directory": True
            },
            {
                "id": "shader_cache",
                "name": "Caché de Sombras DirectX (D3DSCache)",
                "description": "Caché temporal de compilación de shaders gráficos",
                "path": os.path.join(local_app_data, "D3DSCache"),
                "is_directory": True
            }
        ]

        # Filtrar solo las que existen en este sistema
        valid_targets = [t for t in targets if t["path"] and os.path.exists(t["path"])]
        return valid_targets

    def scan_temp_space(
        self,
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> Dict[str, Any]:
        """
        Escanea las carpetas temporales sin eliminar nada para calcular el espacio recuperable.
        """
        self._stop_requested = False
        targets = self.get_cleanup_targets()

        results_by_category = []
        grand_total_bytes = 0
        grand_total_files = 0

        for target in targets:
            if self._stop_requested:
                break

            cat_bytes = 0
            cat_files = 0
            t_path = target["path"]

            try:
                for dirpath, _, filenames in os.walk(t_path):
                    if self._stop_requested:
                        break

                    for fname in filenames:
                        fpath = os.path.join(dirpath, fname)
                        try:
                            sz = os.path.getsize(fpath)
                            cat_bytes += sz
                            cat_files += 1
                        except (PermissionError, FileNotFoundError, OSError):
                            pass

                    if progress_callback:
                        progress_callback(target["name"], cat_files, cat_bytes)

            except Exception:
                pass

            grand_total_bytes += cat_bytes
            grand_total_files += cat_files

            results_by_category.append({
                "id": target["id"],
                "name": target["name"],
                "description": target["description"],
                "path": t_path,
                "file_count": cat_files,
                "size_bytes": cat_bytes,
                "size_formatted": format_bytes(cat_bytes)
            })

        return {
            "total_bytes": grand_total_bytes,
            "total_formatted": format_bytes(grand_total_bytes),
            "total_files": grand_total_files,
            "categories": results_by_category
        }

    def clean_temp_space(
        self,
        selected_category_ids: Optional[List[str]] = None,
        empty_recycle_bin: bool = False,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ) -> Dict[str, Any]:
        """
        Limpia de forma segura los archivos temporales seleccionados.
        Los archivos en uso por Windows u otras aplicaciones abiertas se omiten automáticamente sin error.
        """
        self._stop_requested = False
        targets = self.get_cleanup_targets()

        if selected_category_ids:
            targets = [t for t in targets if t["id"] in selected_category_ids]

        deleted_files_count = 0
        freed_bytes = 0
        skipped_files_count = 0

        for target in targets:
            if self._stop_requested:
                break

            t_path = target["path"]
            if not os.path.exists(t_path):
                continue

            # Recorrer archivos dentro del directorio
            for root, dirs, files in os.walk(t_path, topdown=False):
                if self._stop_requested:
                    break

                for fname in files:
                    if self._stop_requested:
                        break

                    file_path = os.path.join(root, fname)
                    try:
                        sz = os.path.getsize(file_path)
                        os.unlink(file_path)
                        deleted_files_count += 1
                        freed_bytes += sz
                    except (PermissionError, OSError):
                        # Archivo en uso o bloqueado por el sistema
                        skipped_files_count += 1

                    if progress_callback and (deleted_files_count + skipped_files_count) % 50 == 0:
                        progress_callback(deleted_files_count, freed_bytes, fname)

                # Intentar eliminar subdirectorios que hayan quedado vacíos
                for dname in dirs:
                    dir_full_path = os.path.join(root, dname)
                    try:
                        os.rmdir(dir_full_path)
                    except (PermissionError, OSError):
                        pass

        # Vaciar Papelera de Reciclaje si se solicitó explícitamente
        recycle_bin_freed = False
        if empty_recycle_bin and not self._stop_requested:
            try:
                # Flags: SHERB_NOCONFIRMATION (0x00000001) | SHERB_NOPROGRESSUI (0x00000002) | SHERB_NOSOUND (0x00000004)
                ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 7)
                recycle_bin_freed = True
            except Exception:
                pass

        return {
            "deleted_files_count": deleted_files_count,
            "skipped_files_count": skipped_files_count,
            "freed_bytes": freed_bytes,
            "freed_formatted": format_bytes(freed_bytes),
            "recycle_bin_emptied": recycle_bin_freed
        }
