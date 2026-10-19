"""
Punto de Entrada Principal (Main Entry Point)
NetShield & DiskCleaner Pro
"""

import sys
import os

# Asegurar que el directorio raíz del proyecto esté en el path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)


def main():
    try:
        import customtkinter
        import psutil
    except ImportError as e:
        print(f"Error: Falta instalar dependencias ({e}).")
        print("Por favor ejecuta: pip install -r requirements.txt")
        sys.exit(1)

    from gui.app import launch
    launch()


if __name__ == "__main__":
    main()
