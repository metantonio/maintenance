"""
Interfaz Gráfica Principal (GUI) con CustomTkinter.
Herramienta de Auditoría Wi-Fi, Seguridad de Red y Mantenimiento de Disco.
"""

import os
import sys
import json
import time
import threading
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
import customtkinter as ctk
from typing import Dict, Any, List, Optional

from core.wifi_analyzer import WiFiAnalyzer
from core.network_scanner import NetworkScanner
from core.security_auditor import SecurityAuditor
from core.disk_tracker import DiskTracker, format_bytes
from core.temp_cleaner import TempCleaner
from core.venv_manager import VenvManager
from core.process_auditor import ProcessAuditor
from core.data_leak_detector import DataLeakDetector
from core.ransomware_detector import RansomwareDetector
from core.integrity_monitor import IntegrityMonitor
from core.system_harden import SystemHardener


class ModernApp(ctk.CTk):
    """Ventana principal de la suite de ciberseguridad y mantenimiento."""

    def __init__(self):
        super().__init__()

        # Configuración de apariencia
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title("NetShield & DiskCleaner Pro - Auditoría Wi-Fi y Mantenimiento")
        self.geometry("1120x720")
        self.minsize(980, 640)

        # Módulos del sistema
        self.wifi_analyzer = WiFiAnalyzer()
        self.network_scanner = NetworkScanner()
        self.security_auditor = SecurityAuditor()
        self.data_leak_detector = DataLeakDetector()
        self.disk_tracker = DiskTracker()
        self.temp_cleaner = TempCleaner()
        self.venv_manager = VenvManager()
        self.process_auditor = ProcessAuditor()

        # Seguridad proactiva
        self.ransomware_detector = RansomwareDetector()
        self.integrity_monitor = IntegrityMonitor()
        self.system_hardener = SystemHardener()

        # Estados de datos en memoria
        self.cached_wifi_data = None
        self.cached_devices = []
        self.cached_security_data = None
        self.cached_leak_data = None
        self.cached_disk_data = None
        self.cached_temp_scan = None
        self.cached_venvs = []
        self.cached_processes = []
        self.cached_ransomware = None
        self.cached_integrity = None
        self.cached_hardening = None
        self.leak_filter_var = None
        self.venv_checkboxes = {}

        # Monitorización continua
        self.monitor_stop = threading.Event()
        self.monitor_thread = None
        self.monitor_events: List[str] = []

        # Control de hilos
        self.active_scan_thread = None

        # Construcción de la interfaz
        self._build_layout()

        # Iniciar en la pestaña de Wi-Fi y cargar datos iniciales
        self.show_view("wifi")
        self.after(300, self.refresh_wifi_data)

    def _build_layout(self):
        """Crea la barra de navegación lateral y el contenedor principal."""
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ---------------- BARRA LATERAL (SIDEBAR) ----------------
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#13171f")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")

        # Logo / Título
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="🛡️ NETSHIELD\n& DISK PRO",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#38bdf8"
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(18, 12))

        # Botones de navegación
        self.nav_buttons = {}

        views = [
            ("wifi", "📶  Wi-Fi & Red"),
            ("network", "💻  Dispositivos LAN"),
            ("security", "🛡️  Seguridad & Riesgos"),
            ("leak_detector", "📡  Fuga de Datos / Espía"),
            ("disk", "📈  Disco (7 Días)"),
            ("cleaner", "🧹  Limpiar Temporales"),
            ("venvs", "🐍  Entornos Virtuales"),
            ("processes", "⚠️  Procesos Activos"),
            ("ransomware", "🔒  Ransomware & Archivos"),
            ("hardening", "🛡️  Hidratación & Sistema"),
            ("help", "❓  Centro de Ayuda"),
        ]

        for idx, (view_id, text) in enumerate(views, start=1):
            btn = ctk.CTkButton(
                self.sidebar_frame,
                text=text,
                anchor="w",
                font=ctk.CTkFont(size=12, weight="bold"),
                height=34,
                corner_radius=8,
                fg_color="transparent",
                text_color="#94a3b8",
                hover_color="#1e293b",
                command=lambda v=view_id: self.show_view(v)
            )
            btn.grid(row=idx, column=0, padx=12, pady=2, sticky="ew")
            self.nav_buttons[view_id] = btn

        self.sidebar_frame.grid_rowconfigure(len(views) + 1, weight=1)

        # Versión e información inferior
        self.version_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="v2.0.0 • Python 3.14\nProtección Local Activa",
            font=ctk.CTkFont(size=11),
            text_color="#64748b"
        )
        self.version_label.grid(row=len(views) + 2, column=0, padx=20, pady=14)

        # ---------------- CONTENEDOR PRINCIPAL (PÁGINAS) ----------------
        self.content_container = ctk.CTkFrame(self, corner_radius=0, fg_color="#0a0d14")
        self.content_container.grid(row=0, column=1, sticky="nsew")
        self.content_container.grid_rowconfigure(0, weight=1)
        self.content_container.grid_columnconfigure(0, weight=1)

        # Inicializar vistas
        self.views = {
            "wifi": self._create_wifi_view(),
            "network": self._create_network_view(),
            "security": self._create_security_view(),
            "leak_detector": self._create_leak_view(),
            "disk": self._create_disk_view(),
            "cleaner": self._create_cleaner_view(),
            "venvs": self._create_venvs_view(),
            "processes": self._create_processes_view(),
            "ransomware": self._create_ransomware_view(),
            "hardening": self._create_hardening_view(),
            "help": self._create_help_view(),
        }

    def show_view(self, view_id: str):
        """Cambia la vista activa en el panel principal."""
        for name, frame in self.views.items():
            if name == view_id:
                frame.grid(row=0, column=0, sticky="nsew", padx=20, pady=20)
                self.nav_buttons[name].configure(
                    fg_color="#0284c7",
                    text_color="#ffffff"
                )
            else:
                frame.grid_forget()
                self.nav_buttons[name].configure(
                    fg_color="transparent",
                    text_color="#94a3b8"
                )

    # =========================================================================
    # VISTA 1: WI-FI & CONEXIÓN
    # =========================================================================
    def _create_wifi_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure((0, 1), weight=1)

        # Encabezado
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 16))

        title = ctk.CTkLabel(
            header_box,
            text="Análisis de Red Wi-Fi y Conexión Activa",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(side="left")

        btn_refresh = ctk.CTkButton(
            header_box,
            text="🔄 Actualizar Análisis",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            width=150,
            command=self.refresh_wifi_data
        )
        btn_refresh.pack(side="right")

        # Tarjeta 1: Información de Wi-Fi
        self.wifi_card = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=12, border_width=1, border_color="#1e293b")
        self.wifi_card.grid(row=1, column=0, sticky="nsew", padx=(0, 10), pady=10)

        wifi_title = ctk.CTkLabel(self.wifi_card, text="Punto de Acceso Wi-Fi", font=ctk.CTkFont(size=15, weight="bold"), text_color="#38bdf8")
        wifi_title.pack(anchor="w", padx=16, pady=(16, 10))

        self.wifi_details_label = ctk.CTkLabel(
            self.wifi_card,
            text="Cargando información del Wi-Fi...",
            font=ctk.CTkFont(size=13),
            justify="left",
            anchor="w",
            text_color="#cbd5e1"
        )
        self.wifi_details_label.pack(anchor="w", padx=16, pady=8, fill="x")

        # Tarjeta 2: Red, Gateway y DNS
        self.net_card = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=12, border_width=1, border_color="#1e293b")
        self.net_card.grid(row=1, column=1, sticky="nsew", padx=(10, 0), pady=10)

        net_title = ctk.CTkLabel(self.net_card, text="Configuración de Red Local", font=ctk.CTkFont(size=15, weight="bold"), text_color="#38bdf8")
        net_title.pack(anchor="w", padx=16, pady=(16, 10))

        self.net_details_label = ctk.CTkLabel(
            self.net_card,
            text="Cargando configuración de red...",
            font=ctk.CTkFont(size=13),
            justify="left",
            anchor="w",
            text_color="#cbd5e1"
        )
        self.net_details_label.pack(anchor="w", padx=16, pady=8, fill="x")

        # Tarjeta 3: Estado de Seguridad del Cifrado
        self.sec_badge_card = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=12, border_width=1, border_color="#1e293b")
        self.sec_badge_card.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(15, 0))

        sec_title = ctk.CTkLabel(self.sec_badge_card, text="Evaluación de Seguridad del Enlace Wi-Fi", font=ctk.CTkFont(size=15, weight="bold"), text_color="#f8fafc")
        sec_title.pack(anchor="w", padx=16, pady=(14, 6))

        self.wifi_sec_status_label = ctk.CTkLabel(
            self.sec_badge_card,
            text="Analizando protocolo...",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#38bdf8"
        )
        self.wifi_sec_status_label.pack(anchor="w", padx=16, pady=2)

        self.wifi_sec_notes_label = ctk.CTkLabel(
            self.sec_badge_card,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8",
            wraplength=800,
            justify="left"
        )
        self.wifi_sec_notes_label.pack(anchor="w", padx=16, pady=(2, 14))

        return frame

    def refresh_wifi_data(self):
        """Actualiza los datos de Wi-Fi en segundo plano."""
        def worker():
            data = self.wifi_analyzer.get_full_analysis()
            self.cached_wifi_data = data
            self.after(0, lambda: self._update_wifi_ui(data))

        threading.Thread(target=worker, daemon=True).start()

    def _update_wifi_ui(self, data: Dict[str, Any]):
        wifi = data["wifi"]
        net = data["network"]

        if wifi["connected"]:
            wifi_text = (
                f"• Nombre de Red (SSID):  {wifi['ssid']}\n"
                f"• MAC Punto de Acceso (BSSID):  {wifi['bssid']}\n"
                f"• Fabricante del Router/AP:  {wifi['ap_vendor']}\n"
                f"• Frecuencia / Banda:  {wifi['band']} (Canal {wifi['channel']})\n"
                f"• Tipo de Radio:  {wifi['radio_type']}\n"
                f"• Nivel de Señal:  {wifi['signal_percent']}% ({wifi['rssi_dbm']})\n"
                f"• Velocidad de Enlace:  ↓ {wifi['receive_rate_mbps']} Mbps  /  ↑ {wifi['transmit_rate_mbps']} Mbps\n"
                f"• Autenticación:  {wifi['authentication']}\n"
                f"• Cifrado de Paquetes:  {wifi['cipher']}"
            )
        else:
            wifi_text = "❌ No hay ninguna red Wi-Fi conectada actualmente."

        self.wifi_details_label.configure(text=wifi_text)

        dns_lines = []
        for d in net.get("dns_providers", []):
            dns_lines.append(f"    - {d['ip']}  ({d['provider']})")
        dns_str = "\n".join(dns_lines) if dns_lines else "    - No detectados"

        net_text = (
            f"• Dirección IP Local (Tu PC):  {net['local_ip']}\n"
            f"• Puerta de Enlace (Router):  {net['gateway_ip']}\n"
            f"• MAC de la Puerta de Enlace:  {net['gateway_mac']}\n"
            f"• Fabricante del Router:  {net['gateway_vendor']}\n"
            f"• Máscara de Subred:  {net['subnet_mask']}\n"
            f"• Servidores DNS Configurados:\n{dns_str}"
        )
        self.net_details_label.configure(text=net_text)

        # Actualizar evaluación de seguridad
        self.wifi_sec_status_label.configure(
            text=f"Estado: {wifi['security_level']}",
            text_color=wifi['security_color']
        )
        notes = "\n".join(wifi['security_notes']) if wifi['security_notes'] else "Conexión Wi-Fi segura con cifrado activo."
        self.wifi_sec_notes_label.configure(text=notes)

    # =========================================================================
    # VISTA 2: DISPOSITIVOS EN LA RED (LAN SCANNER)
    # =========================================================================
    def _create_network_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        # Encabezado
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        title = ctk.CTkLabel(
            header_box,
            text="Explorador de Dispositivos Conectados a la Red",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(side="left")

        self.btn_scan_network = ctk.CTkButton(
            header_box,
            text="🔍 Escanear Red Local",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            width=170,
            command=self.start_network_scan
        )
        self.btn_scan_network.pack(side="right")

        # Barra de progreso y estado
        self.scan_progress_box = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=10)
        self.scan_progress_box.grid(row=1, column=0, sticky="ew", pady=(0, 10), padx=2)

        self.scan_status_label = ctk.CTkLabel(
            self.scan_progress_box,
            text="Presiona 'Escanear Red Local' para descubrir todos los dispositivos activos en tu Wi-Fi.",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8"
        )
        self.scan_status_label.pack(anchor="w", padx=14, pady=(8, 4))

        self.scan_progress_bar = ctk.CTkProgressBar(self.scan_progress_box, height=8, corner_radius=4)
        self.scan_progress_bar.pack(fill="x", padx=14, pady=(0, 10))
        self.scan_progress_bar.set(0)

        # Tabla / Lista Scrollable de Dispositivos
        self.devices_scroll_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color="#13171f",
            corner_radius=12,
            border_width=1,
            border_color="#1e293b"
        )
        self.devices_scroll_frame.grid(row=2, column=0, sticky="nsew")

        # Fila de Cabecera de la Tabla
        self._create_device_table_header()

        return frame

    def _create_device_table_header(self):
        header = ctk.CTkFrame(self.devices_scroll_frame, fg_color="#1e293b", corner_radius=6, height=36)
        header.pack(fill="x", pady=(2, 8), padx=4)

        cols = [
            ("IP", 130),
            ("Dirección MAC", 150),
            ("Fabricante / Marca", 250),
            ("Nombre de Host", 180),
            ("Rol / Tipo", 140),
            ("Puertos Abiertos", 100)
        ]
        for title, width in cols:
            lbl = ctk.CTkLabel(header, text=title, font=ctk.CTkFont(size=12, weight="bold"), width=width, anchor="w", text_color="#38bdf8")
            lbl.pack(side="left", padx=6)

    def start_network_scan(self):
        """Inicia el escaneo multihilo de dispositivos LAN."""
        self.btn_scan_network.configure(state="disabled", text="⏳ Escaneando...")
        self.scan_progress_bar.set(0)
        self.scan_status_label.configure(text="Iniciando escáner ARP y sockets de alta velocidad...")

        # Limpiar filas anteriores de la tabla
        for widget in self.devices_scroll_frame.winfo_children()[1:]:
            widget.destroy()

        def worker():
            def progress(scanned, total, last_found):
                pct = scanned / total
                self.after(0, lambda: self._update_scan_progress(scanned, total, pct, last_found))

            devices = self.network_scanner.scan_network(progress_callback=progress)
            self.cached_devices = devices
            self.after(0, lambda: self._on_scan_finished(devices))

        threading.Thread(target=worker, daemon=True).start()

    def _update_scan_progress(self, scanned: int, total: int, pct: float, last_found: Optional[Dict[str, Any]]):
        self.scan_progress_bar.set(pct)
        if last_found:
            self.scan_status_label.configure(
                text=f"Escaneando... ({scanned}/{total}) | ¡Dispositivo encontrado!: {last_found['ip']} - {last_found['vendor']}"
            )
            self._add_device_row(last_found)
        else:
            self.scan_status_label.configure(text=f"Escaneando subred local... ({scanned}/{total} IPs comprobadas)")

    def _add_device_row(self, dev: Dict[str, Any]):
        row = ctk.CTkFrame(self.devices_scroll_frame, fg_color="#0f172a", corner_radius=6, height=38)
        row.pack(fill="x", pady=2, padx=4)

        # Distintivo de color según rol
        ip_color = "#38bdf8" if dev.get("is_local") else ("#a855f7" if dev.get("is_gateway") else "#f8fafc")

        lbl_ip = ctk.CTkLabel(row, text=dev["ip"], font=ctk.CTkFont(size=12, weight="bold"), width=130, anchor="w", text_color=ip_color)
        lbl_ip.pack(side="left", padx=6)

        lbl_mac = ctk.CTkLabel(row, text=dev["mac"], font=ctk.CTkFont(size=12), width=150, anchor="w", text_color="#94a3b8")
        lbl_mac.pack(side="left", padx=6)

        lbl_vendor = ctk.CTkLabel(row, text=dev["vendor"][:36], font=ctk.CTkFont(size=12), width=250, anchor="w", text_color="#cbd5e1")
        lbl_vendor.pack(side="left", padx=6)

        lbl_host = ctk.CTkLabel(row, text=dev["hostname"][:24], font=ctk.CTkFont(size=12), width=180, anchor="w", text_color="#94a3b8")
        lbl_host.pack(side="left", padx=6)

        lbl_role = ctk.CTkLabel(row, text=dev["role"], font=ctk.CTkFont(size=11, weight="bold"), width=140, anchor="w", text_color=ip_color)
        lbl_role.pack(side="left", padx=6)

        ports_str = ", ".join(map(str, dev.get("ports", []))) if dev.get("ports") else "Ninguno"
        lbl_ports = ctk.CTkLabel(row, text=ports_str, font=ctk.CTkFont(size=11), width=100, anchor="w", text_color="#38bdf8" if dev.get("ports") else "#64748b")
        lbl_ports.pack(side="left", padx=6)

    def _on_scan_finished(self, devices: List[Dict[str, Any]]):
        self.btn_scan_network.configure(state="normal", text="🔍 Escanear Red Local")
        self.scan_progress_bar.set(1.0)
        self.scan_status_label.configure(
            text=f"✅ Escaneo completado. Se encontraron {len(devices)} dispositivos activos en tu red local."
        )

    # =========================================================================
    # VISTA 3: SEGURIDAD & RIESGOS (ANTI-HACKING AUDIT)
    # =========================================================================
    def _create_security_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        # Encabezado
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        title = ctk.CTkLabel(
            header_box,
            text="Auditoría de Ciberseguridad & Detección de Amenazas",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(side="left")

        btn_run_audit = ctk.CTkButton(
            header_box,
            text="🛡️ Ejecutar Auditoría",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            width=170,
            command=self.run_security_audit
        )
        btn_run_audit.pack(side="right")

        # Tarjeta de Puntuación Global (Score Banner)
        self.score_banner = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=12, border_width=1, border_color="#1e293b")
        self.score_banner.grid(row=1, column=0, sticky="ew", pady=(0, 12))

        self.score_label = ctk.CTkLabel(
            self.score_banner,
            text="Puntuación de Seguridad: -- / 100",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#38bdf8"
        )
        self.score_label.pack(anchor="w", padx=16, pady=(12, 4))

        self.score_desc_label = ctk.CTkLabel(
            self.score_banner,
            text="Presiona 'Ejecutar Auditoría' para evaluar ARP spoofing, secuestro DNS y servicios expuestos.",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8"
        )
        self.score_desc_label.pack(anchor="w", padx=16, pady=(0, 12))

        # Cuadrícula Scrollable de Informes de Amenazas
        self.sec_scroll_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color="#13171f",
            corner_radius=12,
            border_width=1,
            border_color="#1e293b"
        )
        self.sec_scroll_frame.grid(row=2, column=0, sticky="nsew")

        return frame

    def run_security_audit(self):
        """Ejecuta la suite completa de ciberseguridad en segundo plano."""
        self.score_label.configure(text="Ejecutando pruebas de ciberseguridad...", text_color="#38bdf8")
        self.score_desc_label.configure(text="Comprobando ARP poisoning, resolución DNS y sockets a la escucha...")

        def worker():
            audit_result = self.security_auditor.run_full_security_audit(self.cached_devices)
            self.cached_security_data = audit_result
            self.after(0, lambda: self._update_security_ui(audit_result))

        threading.Thread(target=worker, daemon=True).start()

    def _update_security_ui(self, audit: Dict[str, Any]):
        score = audit["score"]
        status = audit["overall_status"]
        color = audit["status_color"]
        desc = audit["status_description"]

        self.score_label.configure(
            text=f"Puntuación de Seguridad: {score} / 100  [{status}]",
            text_color=color
        )
        self.score_desc_label.configure(text=desc)

        # Limpiar contenedor de tarjetas de seguridad
        for widget in self.sec_scroll_frame.winfo_children():
            widget.destroy()

        # 1. Tarjeta ARP Spoofing / MitM
        arp = audit["arp_check"]
        self._add_security_card(
            title="1. Detección de Envenenamiento ARP (Man-In-The-Middle)",
            status_text="PELIGRO DETECTADO" if arp["detected"] else "SEGURO (Sin Envenenamiento)",
            status_color="#ff4444" if arp["detected"] else "#00C851",
            details=arp["details"]
        )

        # 2. Tarjeta DNS Hijacking
        dns = audit["dns_check"]
        self._add_security_card(
            title="2. Integridad de Servidores y Respuestas DNS",
            status_text="POSIBLE SECUESTRO" if dns["detected"] else "SEGURO (Sin Manipulación)",
            status_color="#ff4444" if dns["detected"] else "#00C851",
            details=dns["details"]
        )

        # 3. Tarjeta Wi-Fi
        wifi = audit["wifi_check"]
        self._add_security_card(
            title="3. Seguridad del Cifrado Wi-Fi",
            status_text="VULNERABLE" if wifi["detected"] else "PROTEGIDO",
            status_color="#ff4444" if wifi["detected"] else "#00C851",
            details=wifi["details"]
        )

        # 4. Tarjeta Puertos en Escucha Expuestos
        ports = audit["ports_check"]
        exposed_count = len(ports["exposed_services"])
        suspicious_count = len(ports["suspicious_processes"])

        port_details = []
        if suspicious_count > 0:
            port_details.extend(ports["suspicious_processes"])

        if exposed_count > 0:
            port_details.append(
                f"Hay {exposed_count} servicios de tu equipo escuchando en '0.0.0.0' o '::' (accesibles para otros dispositivos de tu red Wi-Fi):"
            )
            for s in ports["exposed_services"][:12]:
                port_details.append(f"  • Puerto {s['port']} ({s['ip']}) -> Proceso: {s['process']} (PID: {s['pid']})")
        else:
            port_details.append("No se detectaron puertos abiertos globalmente hacia la red Wi-Fi.")

        self._add_security_card(
            title="4. Servicios y Puertos en Escucha Local (Listeners)",
            status_text="RIESGO" if suspicious_count > 0 else (f"{exposed_count} Servicios Expuestos" if exposed_count > 0 else "SEGURO"),
            status_color="#ff4444" if suspicious_count > 0 else ("#ffbb33" if exposed_count > 0 else "#00C851"),
            details=port_details
        )

        # 5. Recomendaciones de acción
        if audit["recommendations"]:
            rec_card = ctk.CTkFrame(self.sec_scroll_frame, fg_color="#1e293b", corner_radius=10)
            rec_card.pack(fill="x", pady=6, padx=4)

            lbl_rec_title = ctk.CTkLabel(rec_card, text="💡 Recomendaciones de Protección Inmediata", font=ctk.CTkFont(size=14, weight="bold"), text_color="#38bdf8")
            lbl_rec_title.pack(anchor="w", padx=14, pady=(10, 4))

            for r in audit["recommendations"]:
                lbl = ctk.CTkLabel(rec_card, text=f"• {r}", font=ctk.CTkFont(size=12), text_color="#f8fafc", justify="left")
                lbl.pack(anchor="w", padx=14, pady=2)

    def _add_security_card(self, title: str, status_text: str, status_color: str, details: List[str]):
        card = ctk.CTkFrame(self.sec_scroll_frame, fg_color="#0f172a", corner_radius=10)
        card.pack(fill="x", pady=5, padx=4)

        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=14, pady=(10, 4))

        t_lbl = ctk.CTkLabel(header, text=title, font=ctk.CTkFont(size=14, weight="bold"), text_color="#f8fafc")
        t_lbl.pack(side="left")

        s_lbl = ctk.CTkLabel(header, text=f" {status_text} ", font=ctk.CTkFont(size=12, weight="bold"), text_color=status_color)
        s_lbl.pack(side="right")

        for d in details:
            d_lbl = ctk.CTkLabel(card, text=d, font=ctk.CTkFont(size=12), text_color="#cbd5e1", wraplength=780, justify="left")
            d_lbl.pack(anchor="w", padx=14, pady=2)

        ctk.CTkLabel(card, text="", height=4).pack()

    # =========================================================================
    # VISTA: DETECCIÓN DE FUGA DE DATOS & TRÁFICO ESPÍA
    # =========================================================================
    def _create_leak_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        # Encabezado
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        title = ctk.CTkLabel(
            header_box,
            text="Detección de Fuga de Datos & Tráfico Espía",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(side="left")

        btn_box = ctk.CTkFrame(header_box, fg_color="transparent")
        btn_box.pack(side="right")

        self.leak_filter_var = tk.BooleanVar(value=True)
        chk_filter = ctk.CTkCheckBox(
            btn_box,
            text="Solo Tráfico Sospechoso / Peligro",
            font=ctk.CTkFont(size=12),
            variable=self.leak_filter_var,
            command=self._render_leak_list
        )
        chk_filter.pack(side="left", padx=(0, 14))

        self.btn_scan_leak = ctk.CTkButton(
            btn_box,
            text="📡 Analizar Transmisiones",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            width=180,
            command=self.start_leak_scan
        )
        self.btn_scan_leak.pack(side="left")

        # Banner de Estado Global
        self.leak_banner = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=12, border_width=1, border_color="#1e293b")
        self.leak_banner.grid(row=1, column=0, sticky="ew", pady=(0, 12))

        self.leak_status_label = ctk.CTkLabel(
            self.leak_banner,
            text="Estado de Exfiltración: Pendiente de Análisis",
            font=ctk.CTkFont(size=17, weight="bold"),
            text_color="#38bdf8"
        )
        self.leak_status_label.pack(anchor="w", padx=16, pady=(12, 4))

        self.leak_desc_label = ctk.CTkLabel(
            self.leak_banner,
            text="Pulsa 'Analizar Transmisiones' para auditar conexiones hacia internet, canales C2 (Telegram/Discord) y procesos espía.",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8"
        )
        self.leak_desc_label.pack(anchor="w", padx=16, pady=(0, 10))

        # Cuadrícula de Contadores
        self.leak_stats_frame = ctk.CTkFrame(self.leak_banner, fg_color="transparent")
        self.leak_stats_frame.pack(fill="x", padx=16, pady=(0, 12))

        self.stat_leak_total = self._create_leak_stat_badge(self.leak_stats_frame, "Transmisiones Salientes", "0", "#38bdf8")
        self.stat_leak_total.pack(side="left", padx=(0, 12))

        self.stat_leak_crit = self._create_leak_stat_badge(self.leak_stats_frame, "Exfiltración Crítica", "0", "#ef4444")
        self.stat_leak_crit.pack(side="left", padx=(0, 12))

        self.stat_leak_warn = self._create_leak_stat_badge(self.leak_stats_frame, "Tráfico Sospechoso", "0", "#f59e0b")
        self.stat_leak_warn.pack(side="left", padx=(0, 12))

        self.stat_leak_safe = self._create_leak_stat_badge(self.leak_stats_frame, "Conexiones Normales", "0", "#00C851")
        self.stat_leak_safe.pack(side="left", padx=(0, 12))

        # Frame Scrollable de Transmisiones
        self.leak_scroll_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color="#13171f",
            corner_radius=12,
            border_width=1,
            border_color="#1e293b"
        )
        self.leak_scroll_frame.grid(row=2, column=0, sticky="nsew")

        return frame

    def _create_leak_stat_badge(self, parent, label_text: str, val_text: str, color: str) -> ctk.CTkFrame:
        card = ctk.CTkFrame(parent, fg_color="#1e293b", corner_radius=8, width=170, height=48)
        card.pack_propagate(False)

        lbl = ctk.CTkLabel(card, text=label_text, font=ctk.CTkFont(size=10, weight="bold"), text_color="#94a3b8")
        lbl.pack(anchor="w", padx=10, pady=(4, 0))

        val = ctk.CTkLabel(card, text=val_text, font=ctk.CTkFont(size=15, weight="bold"), text_color=color)
        val.pack(anchor="w", padx=10, pady=(0, 4))
        card.val_label = val
        return card

    def start_leak_scan(self):
        """Inicia la auditoría de conexiones salientes y exfiltración de datos."""
        self.btn_scan_leak.configure(state="disabled", text="⏳ Analizando Salida...")
        self.leak_status_label.configure(text="Inspeccionando sockets de internet, procesos emisores y destinos...", text_color="#38bdf8")

        def worker():
            result = self.data_leak_detector.audit_outbound_transmissions()
            self.cached_leak_data = result
            self.after(0, lambda: self._on_leak_scan_finished(result))

        threading.Thread(target=worker, daemon=True).start()

    def _on_leak_scan_finished(self, result: Dict[str, Any]):
        self.btn_scan_leak.configure(state="normal", text="📡 Analizar Transmisiones")

        self.leak_status_label.configure(text=result["status_text"], text_color=result["status_color"])
        self.leak_desc_label.configure(text=result["summary_desc"])

        self.stat_leak_total.val_label.configure(text=str(result["total_transmissions"]))
        self.stat_leak_crit.val_label.configure(text=str(result["critical_count"]))
        self.stat_leak_warn.val_label.configure(text=str(result["warning_count"]))
        self.stat_leak_safe.val_label.configure(text=str(result["normal_count"]))

        self._render_leak_list()

    def _render_leak_list(self):
        for widget in self.leak_scroll_frame.winfo_children():
            widget.destroy()

        if not self.cached_leak_data:
            lbl = ctk.CTkLabel(
                self.leak_scroll_frame,
                text="Pulsa 'Analizar Transmisiones' para iniciar la detección de fuga de datos.",
                font=ctk.CTkFont(size=14),
                text_color="#94a3b8"
            )
            lbl.pack(pady=40)
            return

        items = self.cached_leak_data.get("transmissions", [])
        only_suspicious = self.leak_filter_var.get() if self.leak_filter_var else False

        if only_suspicious:
            items = [t for t in items if t["is_suspicious"]]

        # Mostrar recomendaciones si hay alertas
        recs = self.cached_leak_data.get("recommendations", [])
        if recs:
            rec_card = ctk.CTkFrame(self.leak_scroll_frame, fg_color="#1e293b", corner_radius=10)
            rec_card.pack(fill="x", pady=(2, 10), padx=4)

            lbl_rec_title = ctk.CTkLabel(
                rec_card,
                text="💡 Recomendaciones Inmediatas de Contención",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#38bdf8"
            )
            lbl_rec_title.pack(anchor="w", padx=14, pady=(8, 3))

            for r in recs:
                lbl = ctk.CTkLabel(rec_card, text=f"• {r}", font=ctk.CTkFont(size=12), text_color="#f8fafc", justify="left")
                lbl.pack(anchor="w", padx=14, pady=2)
            ctk.CTkLabel(rec_card, text="", height=4).pack()

        if not items:
            msg = "No se detectaron transmisiones sospechosas o de riesgo en este momento." if only_suspicious else "No hay transmisiones activas."
            lbl = ctk.CTkLabel(
                self.leak_scroll_frame,
                text=msg,
                font=ctk.CTkFont(size=14),
                text_color="#94a3b8"
            )
            lbl.pack(pady=40)
            return

        for t in items:
            self._add_leak_card(t)

    def _add_leak_card(self, t: Dict[str, Any]):
        card = ctk.CTkFrame(self.leak_scroll_frame, fg_color="#0f172a", corner_radius=8)
        card.pack(fill="x", pady=4, padx=4)

        # Fila superior
        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x", padx=12, pady=(8, 4))

        # Badge de riesgo
        badge_risk = ctk.CTkLabel(
            top_row,
            text=f" {t['risk_level']} ",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=t["risk_color"]
        )
        badge_risk.pack(side="left", padx=(0, 8))

        lbl_proc = ctk.CTkLabel(
            top_row,
            text=f"{t['process_name']} (PID: {t['pid']})",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#f8fafc"
        )
        lbl_proc.pack(side="left")

        # Flecha y destino
        arrow_lbl = ctk.CTkLabel(
            top_row,
            text=" ➔ ",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#38bdf8"
        )
        arrow_lbl.pack(side="left", padx=4)

        remote_desc = f"{t['remote_ip']}:{t['remote_port']}"
        if t["remote_host"] and t["remote_host"] != t["remote_ip"]:
            remote_desc += f"  ({t['remote_host'][:38]})"

        lbl_remote = ctk.CTkLabel(
            top_row,
            text=remote_desc,
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1"
        )
        lbl_remote.pack(side="left")

        # Botones de acción a la derecha
        btn_box = ctk.CTkFrame(top_row, fg_color="transparent")
        btn_box.pack(side="right")

        if t["exe"]:
            btn_open = ctk.CTkButton(
                btn_box,
                text="📂 Carpeta",
                width=70,
                height=26,
                font=ctk.CTkFont(size=11),
                fg_color="#1e293b",
                hover_color="#334155",
                command=lambda e=t["exe"]: self.data_leak_detector.open_process_folder(e)
            )
            btn_open.pack(side="left", padx=(0, 6))

        btn_kill = ctk.CTkButton(
            btn_box,
            text="🛑 Cortar Conexión",
            width=115,
            height=26,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#dc2626",
            hover_color="#b91c1c",
            command=lambda pid=t["pid"], n=t["process_name"]: self._confirm_kill_leak_process(pid, n)
        )
        btn_kill.pack(side="left")

        # Motivos si está alertado
        if t["reasons"]:
            for r in t["reasons"]:
                lbl_r = ctk.CTkLabel(
                    card,
                    text=f"⚠️ {r}",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=t["risk_color"],
                    anchor="w",
                    justify="left"
                )
                lbl_r.pack(fill="x", padx=12, pady=1)

        # Ruta del ejecutable
        exe_text = t["exe"] if t["exe"] else "(Sin archivo ejecutable directo en disco)"
        lbl_path = ctk.CTkLabel(
            card,
            text=f"Ruta: {exe_text}   |   RAM: {t['memory_mb']} MB   |   Estado: {t['connection_state']}",
            font=ctk.CTkFont(size=11),
            text_color="#64748b",
            anchor="w"
        )
        lbl_path.pack(fill="x", padx=12, pady=(0, 8))

    def _confirm_kill_leak_process(self, pid: int, name: str):
        confirm = messagebox.askyesno(
            "Confirmar Cortar Conexión / Terminar Proceso",
            f"¿Deseas terminar forzosamente el proceso para detener la transmisión?\n\n"
            f"• Proceso: {name}\n"
            f"• PID: {pid}\n\n"
            f"Esto cerrará inmediatamente el socket de red y detendrá cualquier subida o descarga de datos."
        )
        if not confirm:
            return

        res = self.data_leak_detector.kill_process(pid)
        if res["success"]:
            messagebox.showinfo("Transmisión Detenida", res["message"])
            self.start_leak_scan()
        else:
            messagebox.showerror("Error al Finalizar", res["message"])

    # =========================================================================
    # VISTA 4: RASTREADOR DE DISCO (ÚLTIMOS 7 DÍAS)
    # =========================================================================
    def _create_disk_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        # Encabezado con controles de filtro
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        title = ctk.CTkLabel(
            header_box,
            text="Rastreador de Archivos Recientes (Crecimiento de Disco)",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(side="left")

        # Controles a la derecha
        controls_frame = ctk.CTkFrame(header_box, fg_color="transparent")
        controls_frame.pack(side="right")

        ctk.CTkLabel(controls_frame, text="Período:", font=ctk.CTkFont(size=12), text_color="#94a3b8").pack(side="left", padx=(0, 4))
        self.days_combo = ctk.CTkOptionMenu(
            controls_frame,
            values=["3 Días", "7 Días", "14 Días", "30 Días"],
            width=100,
            fg_color="#1e293b",
            button_color="#0284c7"
        )
        self.days_combo.set("7 Días")
        self.days_combo.pack(side="left", padx=(0, 10))

        ctk.CTkLabel(controls_frame, text="Mín:", font=ctk.CTkFont(size=12), text_color="#94a3b8").pack(side="left", padx=(0, 4))
        self.size_combo = ctk.CTkOptionMenu(
            controls_frame,
            values=["> 5 MB", "> 10 MB", "> 25 MB", "> 50 MB", "> 100 MB"],
            width=100,
            fg_color="#1e293b",
            button_color="#0284c7"
        )
        self.size_combo.set("> 10 MB")
        self.size_combo.pack(side="left", padx=(0, 10))

        self.btn_scan_disk = ctk.CTkButton(
            controls_frame,
            text="🚀 Rastrear Archivos",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            width=150,
            command=self.start_disk_scan
        )
        self.btn_scan_disk.pack(side="left")

        # Banner de resumen de espacio
        self.disk_summary_banner = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=10)
        self.disk_summary_banner.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        self.disk_summary_label = ctk.CTkLabel(
            self.disk_summary_banner,
            text="Haz clic en 'Rastrear Archivos' para identificar qué archivos gigantes han consumido tu espacio en disco.",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8"
        )
        self.disk_summary_label.pack(anchor="w", padx=16, pady=10)

        # Tabla de Archivos Recientes
        self.disk_scroll_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color="#13171f",
            corner_radius=12,
            border_width=1,
            border_color="#1e293b"
        )
        self.disk_scroll_frame.grid(row=2, column=0, sticky="nsew")

        self._create_disk_table_header()

        return frame

    def _create_disk_table_header(self):
        header = ctk.CTkFrame(self.disk_scroll_frame, fg_color="#1e293b", corner_radius=6, height=36)
        header.pack(fill="x", pady=(2, 6), padx=4)

        cols = [
            ("Tamaño", 95),
            ("Nombre de Archivo", 260),
            ("Fecha Creado / Modificado", 170),
            ("Carpeta Contenedora", 280),
            ("Acción", 80)
        ]
        for title, width in cols:
            lbl = ctk.CTkLabel(header, text=title, font=ctk.CTkFont(size=12, weight="bold"), width=width, anchor="w", text_color="#38bdf8")
            lbl.pack(side="left", padx=6)

    def start_disk_scan(self):
        """Inicia el rastreo de archivos recientes en segundo plano."""
        days_map = {"3 Días": 3, "7 Días": 7, "14 Días": 14, "30 Días": 30}
        size_map = {"> 5 MB": 5.0, "> 10 MB": 10.0, "> 25 MB": 25.0, "> 50 MB": 50.0, "> 100 MB": 100.0}

        days = days_map.get(self.days_combo.get(), 7)
        min_mb = size_map.get(self.size_combo.get(), 10.0)

        self.btn_scan_disk.configure(state="disabled", text="⏳ Rastreando...")
        self.disk_summary_label.configure(text=f"Escaneando carpetas de usuario en busca de archivos creados en los últimos {days} días...")

        # Limpiar filas anteriores
        for widget in self.disk_scroll_frame.winfo_children()[1:]:
            widget.destroy()

        def worker():
            def progress(count, path):
                self.after(0, lambda: self.disk_summary_label.configure(
                    text=f"Escaneando... ({count} archivos analizados) | {path[:65]}..."
                ))

            res = self.disk_tracker.scan_recent_files(
                days=days,
                min_size_mb=min_mb,
                limit_results=100,
                progress_callback=progress
            )
            self.cached_disk_data = res
            self.after(0, lambda: self._on_disk_scan_finished(res))

        threading.Thread(target=worker, daemon=True).start()

    def _on_disk_scan_finished(self, res: Dict[str, Any]):
        self.btn_scan_disk.configure(state="normal", text="🚀 Rastrear Archivos")

        summary_text = (
            f"📊 Resultado: {res['total_recent_space_formatted']} generados en los últimos {res['days']} días "
            f"({res['matching_files_count']} archivos pesados de más de {res['min_size_mb']} MB encontrados)."
        )
        self.disk_summary_label.configure(text=summary_text)

        # Poblar tabla de archivos
        for item in res["top_files"]:
            self._add_file_row(item)

    def _add_file_row(self, item: Dict[str, Any]):
        row = ctk.CTkFrame(self.disk_scroll_frame, fg_color="#0f172a", corner_radius=6, height=38)
        row.pack(fill="x", pady=2, padx=4)

        # Tamaño
        sz_color = "#f43f5e" if item["size_bytes"] > 200 * 1024 * 1024 else ("#fbbf24" if item["size_bytes"] > 50 * 1024 * 1024 else "#38bdf8")
        lbl_size = ctk.CTkLabel(row, text=item["size_formatted"], font=ctk.CTkFont(size=12, weight="bold"), width=95, anchor="w", text_color=sz_color)
        lbl_size.pack(side="left", padx=6)

        # Nombre
        lbl_name = ctk.CTkLabel(row, text=item["name"][:32], font=ctk.CTkFont(size=12), width=260, anchor="w", text_color="#f8fafc")
        lbl_name.pack(side="left", padx=6)

        # Fecha
        lbl_date = ctk.CTkLabel(row, text=item["date_formatted"], font=ctk.CTkFont(size=12), width=170, anchor="w", text_color="#94a3b8")
        lbl_date.pack(side="left", padx=6)

        # Carpeta
        lbl_folder = ctk.CTkLabel(row, text=item["folder"][:38], font=ctk.CTkFont(size=11), width=280, anchor="w", text_color="#64748b")
        lbl_folder.pack(side="left", padx=6)

        # Botón para abrir en Explorador
        btn_open = ctk.CTkButton(
            row,
            text="📂 Abrir",
            width=70,
            height=26,
            font=ctk.CTkFont(size=11),
            fg_color="#1e293b",
            hover_color="#334155",
            command=lambda p=item["path"]: self.disk_tracker.open_in_explorer(p)
        )
        btn_open.pack(side="left", padx=6)

    # =========================================================================
    # VISTA 5: LIMPIADOR DE TEMPORALES (TEMP CLEANER)
    # =========================================================================
    def _create_cleaner_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        # Encabezado
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        title = ctk.CTkLabel(
            header_box,
            text="Limpiador Seguro de Archivos Temporales y Caché",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(side="left")

        actions_box = ctk.CTkFrame(header_box, fg_color="transparent")
        actions_box.pack(side="right")

        self.btn_scan_temp = ctk.CTkButton(
            actions_box,
            text="🔍 Analizar Basura",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#1e293b",
            hover_color="#334155",
            width=140,
            command=self.start_temp_scan
        )
        self.btn_scan_temp.pack(side="left", padx=(0, 10))

        self.btn_clean_temp = ctk.CTkButton(
            actions_box,
            text="🧹 Limpiar Ahora",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            width=140,
            command=self.confirm_and_clean_temp
        )
        self.btn_clean_temp.pack(side="left")

        # Banner de resumen de limpieza
        self.cleaner_banner = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=10)
        self.cleaner_banner.grid(row=1, column=0, sticky="ew", pady=(0, 12))

        self.cleaner_banner_label = ctk.CTkLabel(
            self.cleaner_banner,
            text="Analiza el espacio residual para ver cuántos Gigabytes puedes recuperar de forma 100% segura.",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8"
        )
        self.cleaner_banner_label.pack(anchor="w", padx=16, pady=12)

        # Contenedor de Categorías de Limpieza
        self.cleaner_scroll_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color="#13171f",
            corner_radius=12,
            border_width=1,
            border_color="#1e293b"
        )
        self.cleaner_scroll_frame.grid(row=2, column=0, sticky="nsew")

        # Casilla opcional para Papelera de reciclaje
        self.recycle_bin_var = tk.BooleanVar(value=False)
        self.recycle_bin_cb = ctk.CTkCheckBox(
            frame,
            text="Vaciar también la Papelera de Reciclaje al limpiar",
            variable=self.recycle_bin_var,
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1"
        )
        self.recycle_bin_cb.grid(row=3, column=0, sticky="w", pady=(10, 0))

        # Cargar categorías iniciales
        self._populate_cleaner_categories()

        return frame

    def _populate_cleaner_categories(self):
        targets = self.temp_cleaner.get_cleanup_targets()
        self.category_checkboxes = {}

        for t in targets:
            card = ctk.CTkFrame(self.cleaner_scroll_frame, fg_color="#0f172a", corner_radius=8)
            card.pack(fill="x", pady=4, padx=4)

            var = tk.BooleanVar(value=True)
            self.category_checkboxes[t["id"]] = var

            cb = ctk.CTkCheckBox(
                card,
                text=t["name"],
                variable=var,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#f8fafc"
            )
            cb.pack(side="left", padx=14, pady=10)

            lbl_desc = ctk.CTkLabel(
                card,
                text=f"{t['description']}  ({t['path']})",
                font=ctk.CTkFont(size=11),
                text_color="#64748b"
            )
            lbl_desc.pack(side="left", padx=10)

    def start_temp_scan(self):
        """Analiza el espacio ocupado por archivos temporales."""
        self.btn_scan_temp.configure(state="disabled", text="⏳ Analizando...")
        self.cleaner_banner_label.configure(text="Calculando tamaño de archivos temporales...")

        def worker():
            res = self.temp_cleaner.scan_temp_space()
            self.cached_temp_scan = res
            self.after(0, lambda: self._on_temp_scan_finished(res))

        threading.Thread(target=worker, daemon=True).start()

    def _on_temp_scan_finished(self, res: Dict[str, Any]):
        self.btn_scan_temp.configure(state="normal", text="🔍 Analizar Basura")

        summary = (
            f"🧹 Espacio recuperable detectado: {res['total_formatted']} en {res['total_files']} archivos temporales."
        )
        self.cleaner_banner_label.configure(text=summary, text_color="#38bdf8")

    def confirm_and_clean_temp(self):
        """Confirma y ejecuta la limpieza segura."""
        selected_cats = [cid for cid, var in self.category_checkboxes.items() if var.get()]

        if not selected_cats and not self.recycle_bin_var.get():
            messagebox.showwarning("Atención", "Selecciona al menos una categoría de archivos a limpiar.")
            return

        confirm = messagebox.askyesno(
            "Confirmar Limpieza",
            "¿Deseas proceder con la eliminación de los archivos temporales seleccionados?\n\n"
            "• La operación es segura: cualquier archivo que esté en uso por un programa abierto será omitido automáticamente."
        )
        if not confirm:
            return

        self.btn_clean_temp.configure(state="disabled", text="⏳ Limpiando...")
        self.cleaner_banner_label.configure(text="Eliminando archivos temporales de forma segura...")

        empty_recycle = self.recycle_bin_var.get()

        def worker():
            res = self.temp_cleaner.clean_temp_space(
                selected_category_ids=selected_cats,
                empty_recycle_bin=empty_recycle
            )
            self.after(0, lambda: self._on_temp_clean_finished(res))

        threading.Thread(target=worker, daemon=True).start()

    def _on_temp_clean_finished(self, res: Dict[str, Any]):
        self.btn_clean_temp.configure(state="normal", text="🧹 Limpiar Ahora")

        msg = (
            f"🎉 ¡Limpieza completada con éxito!\n\n"
            f"• Espacio liberado: {res['freed_formatted']}\n"
            f"• Archivos eliminados: {res['deleted_files_count']}\n"
            f"• Archivos omitidos (en uso por el sistema/apps): {res['skipped_files_count']}"
        )
        if res.get("recycle_bin_emptied"):
            msg += "\n• Papelera de reciclaje vaciada."

        self.cleaner_banner_label.configure(
            text=f"✅ {res['freed_formatted']} liberados con éxito ({res['deleted_files_count']} archivos eliminados).",
            text_color="#00C851"
        )
        messagebox.showinfo("Limpieza Exitosa", msg)

    # =========================================================================
    # VISTA 6: GESTOR DE ENTORNOS VIRTUALES (VENVS MANAGER)
    # =========================================================================
    def _create_venvs_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        # Encabezado con acciones
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        title = ctk.CTkLabel(
            header_box,
            text="Gestor de Entornos Virtuales de Python",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(side="left")

        actions_box = ctk.CTkFrame(header_box, fg_color="transparent")
        actions_box.pack(side="right")

        self.btn_scan_venvs = ctk.CTkButton(
            actions_box,
            text="🔍 Buscar Entornos",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            width=140,
            command=self.start_venvs_scan
        )
        self.btn_scan_venvs.pack(side="left", padx=(0, 10))

        self.btn_delete_selected_venvs = ctk.CTkButton(
            actions_box,
            text="🗑️ Eliminar Seleccionados",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#dc2626",
            hover_color="#b91c1c",
            width=170,
            command=self._confirm_delete_selected_venvs
        )
        self.btn_delete_selected_venvs.pack(side="left")

        # Banner de resumen
        self.venvs_banner = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=10)
        self.venvs_banner.grid(row=1, column=0, sticky="ew", pady=(0, 12))

        self.venvs_banner_label = ctk.CTkLabel(
            self.venvs_banner,
            text="Haz clic en 'Buscar Entornos' para detectar entornos venv en tus proyectos y recuperar gigabytes de disco.",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8"
        )
        self.venvs_banner_label.pack(anchor="w", padx=16, pady=12)

        # Contenedor scrollable de entornos
        self.venvs_scroll_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color="#13171f",
            corner_radius=12,
            border_width=1,
            border_color="#1e293b"
        )
        self.venvs_scroll_frame.grid(row=2, column=0, sticky="nsew")

        return frame

    def start_venvs_scan(self):
        """Inicia la búsqueda de entornos virtuales en segundo plano."""
        self.btn_scan_venvs.configure(state="disabled", text="⏳ Buscando...")
        self.venvs_banner_label.configure(text="Buscando entornos virtuales en C:\\Repositorios y carpetas de proyectos...")

        # Limpiar contenedor anterior
        for widget in self.venvs_scroll_frame.winfo_children():
            widget.destroy()

        def worker():
            def progress(path, count):
                self.after(0, lambda: self.venvs_banner_label.configure(
                    text=f"Buscando... ({count} entornos encontrados hasta ahora) | {path[:60]}..."
                ))

            venvs = self.venv_manager.scan_virtual_environments(progress_callback=progress)
            self.cached_venvs = venvs
            self.after(0, lambda: self._on_venvs_scan_finished(venvs))

        threading.Thread(target=worker, daemon=True).start()

    def _on_venvs_scan_finished(self, venvs: List[Dict[str, Any]]):
        self.btn_scan_venvs.configure(state="normal", text="🔍 Buscar Entornos")

        total_bytes = sum(v["size_bytes"] for v in venvs)
        total_formatted = format_bytes(total_bytes)

        self.venvs_banner_label.configure(
            text=f"📦 Se encontraron {len(venvs)} entornos virtuales ocupando un total de {total_formatted} en disco.",
            text_color="#38bdf8"
        )

        self.venv_checkboxes.clear()

        if not venvs:
            lbl = ctk.CTkLabel(
                self.venvs_scroll_frame,
                text="No se encontraron entornos virtuales en las carpetas exploradas.",
                font=ctk.CTkFont(size=14),
                text_color="#94a3b8"
            )
            lbl.pack(pady=40)
            return

        for item in venvs:
            self._add_venv_card(item)

    def _add_venv_card(self, venv_data: Dict[str, Any]):
        card = ctk.CTkFrame(self.venvs_scroll_frame, fg_color="#0f172a", corner_radius=8)
        card.pack(fill="x", pady=4, padx=4)

        # Fila superior de la tarjeta
        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x", padx=12, pady=(8, 4))

        var = tk.BooleanVar(value=False)
        self.venv_checkboxes[venv_data["path"]] = (var, venv_data)

        if venv_data["is_current"]:
            # Entorno protegido
            lock_label = ctk.CTkLabel(
                top_row,
                text="🔒 [APP ACTUAL]",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color="#10b981"
            )
            lock_label.pack(side="left", padx=(0, 8))
        else:
            cb = ctk.CTkCheckBox(top_row, text="", variable=var, width=24)
            cb.pack(side="left", padx=(0, 8))

        lbl_title = ctk.CTkLabel(
            top_row,
            text=venv_data["display_name"],
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#f8fafc"
        )
        lbl_title.pack(side="left")

        # Insignia de tamaño
        sz_color = "#f43f5e" if venv_data["size_bytes"] > 1024 * 1024 * 1024 else "#38bdf8"
        badge_sz = ctk.CTkLabel(
            top_row,
            text=f" {venv_data['size_formatted']} ",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=sz_color
        )
        badge_sz.pack(side="left", padx=12)

        # Insignia de Python
        lbl_py = ctk.CTkLabel(
            top_row,
            text=f"Python {venv_data['python_version']}",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        )
        lbl_py.pack(side="left", padx=6)

        # Botones a la derecha
        btn_box = ctk.CTkFrame(top_row, fg_color="transparent")
        btn_box.pack(side="right")

        btn_open = ctk.CTkButton(
            btn_box,
            text="📂 Abrir",
            width=65,
            height=26,
            font=ctk.CTkFont(size=11),
            fg_color="#1e293b",
            hover_color="#334155",
            command=lambda p=venv_data["path"]: self.disk_tracker.open_in_explorer(p)
        )
        btn_open.pack(side="left", padx=(0, 6))

        if not venv_data["is_current"]:
            btn_del = ctk.CTkButton(
                btn_box,
                text="🗑️ Eliminar",
                width=75,
                height=26,
                font=ctk.CTkFont(size=11, weight="bold"),
                fg_color="#dc2626",
                hover_color="#b91c1c",
                command=lambda p=venv_data["path"], n=venv_data["display_name"]: self._confirm_delete_single_venv(p, n)
            )
            btn_del.pack(side="left")

        # Fila inferior con la ruta completa
        lbl_path = ctk.CTkLabel(
            card,
            text=f"Ruta: {venv_data['path']}   |   Modificado: {venv_data['last_modified']}",
            font=ctk.CTkFont(size=11),
            text_color="#64748b",
            anchor="w"
        )
        lbl_path.pack(fill="x", padx=12, pady=(0, 8))

    def _confirm_delete_single_venv(self, venv_path: str, display_name: str):
        confirm = messagebox.askyesno(
            "Confirmar Eliminación",
            f"¿Estás seguro de que deseas eliminar permanentemente el entorno virtual:\n\n"
            f"• {display_name}\n"
            f"• Ruta: {venv_path}\n\n"
            f"Esta acción no se puede deshacer."
        )
        if not confirm:
            return

        res = self.venv_manager.delete_virtual_environment(venv_path)
        if res["success"]:
            messagebox.showinfo(
                "Entorno Eliminado",
                f"✅ Entorno virtual eliminado con éxito.\nSe han liberado {res['freed_formatted']} de espacio."
            )
            self.start_venvs_scan()
        else:
            messagebox.showerror("Error al Eliminar", f"No se pudo eliminar el entorno:\n{res.get('error')}")

    def _confirm_delete_selected_venvs(self):
        selected = []
        for path, (var, data) in self.venv_checkboxes.items():
            if var.get() and not data["is_current"]:
                selected.append(data)

        if not selected:
            messagebox.showwarning("Atención", "No has seleccionado ningún entorno virtual para eliminar.")
            return

        total_bytes = sum(item["size_bytes"] for item in selected)
        total_formatted = format_bytes(total_bytes)

        confirm = messagebox.askyesno(
            "Confirmar Eliminación Múltiple",
            f"¿Deseas eliminar permanentemente los {len(selected)} entornos virtuales seleccionados?\n\n"
            f"• Espacio total que se liberará: {total_formatted}\n\n"
            f"Esta acción eliminará las carpetas completas del disco."
        )
        if not confirm:
            return

        deleted_count = 0
        freed_bytes = 0
        errors = []

        for item in selected:
            res = self.venv_manager.delete_virtual_environment(item["path"])
            if res["success"]:
                deleted_count += 1
                freed_bytes += res["freed_bytes"]
            else:
                errors.append(f"{item['display_name']}: {res.get('error')}")

        msg = f"🎉 Se eliminaron {deleted_count} entornos virtuales.\nEspacio liberado: {format_bytes(freed_bytes)}."
        if errors:
            msg += f"\n\nHubo {len(errors)} errores al eliminar algunos entornos."

        messagebox.showinfo("Limpieza Completada", msg)
        self.start_venvs_scan()

    # =========================================================================
    # VISTA 7: MONITOR DE PROCESOS ACTIVOS & PELIGROSOS
    # =========================================================================
    def _create_processes_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        # Encabezado
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        title = ctk.CTkLabel(
            header_box,
            text="Monitor de Procesos Activos & Detección de Amenazas",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(side="left")

        actions_box = ctk.CTkFrame(header_box, fg_color="transparent")
        actions_box.pack(side="right")

        self.proc_filter_var = tk.BooleanVar(value=True)
        self.cb_only_suspicious = ctk.CTkCheckBox(
            actions_box,
            text="Solo Sospechosos / Peligrosos",
            variable=self.proc_filter_var,
            font=ctk.CTkFont(size=12),
            text_color="#cbd5e1",
            command=self._render_processes_list
        )
        self.cb_only_suspicious.pack(side="left", padx=(0, 14))

        self.btn_refresh_procs = ctk.CTkButton(
            actions_box,
            text="🔄 Analizar Procesos",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7",
            hover_color="#0369a1",
            width=150,
            command=self.start_processes_scan
        )
        self.btn_refresh_procs.pack(side="left")

        # Banner de estado de procesos
        self.procs_banner = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=10)
        self.procs_banner.grid(row=1, column=0, sticky="ew", pady=(0, 12))

        self.procs_banner_label = ctk.CTkLabel(
            self.procs_banner,
            text="Haz clic en 'Analizar Procesos' para escanear todos los procesos en busca de mineros, suplantaciones o ejecutables en Temp.",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8"
        )
        self.procs_banner_label.pack(anchor="w", padx=16, pady=12)

        # Contenedor scrollable de procesos
        self.procs_scroll_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color="#13171f",
            corner_radius=12,
            border_width=1,
            border_color="#1e293b"
        )
        self.procs_scroll_frame.grid(row=2, column=0, sticky="nsew")

        return frame

    def start_processes_scan(self):
        """Escanea todos los procesos activos en segundo plano."""
        self.btn_refresh_procs.configure(state="disabled", text="⏳ Analizando...")
        self.procs_banner_label.configure(text="Inspeccionando procesos en ejecución, rutas y firmas...")

        def worker():
            procs = self.process_auditor.scan_running_processes()
            self.cached_processes = procs
            self.after(0, lambda: self._on_processes_scan_finished(procs))

        threading.Thread(target=worker, daemon=True).start()

    def _on_processes_scan_finished(self, procs: List[Dict[str, Any]]):
        self.btn_refresh_procs.configure(state="normal", text="🔄 Analizar Procesos")

        danger_count = sum(1 for p in procs if p["risk_level"] == "PELIGRO")
        susp_count = sum(1 for p in procs if p["risk_level"] == "SOSPECHOSO")

        if danger_count > 0:
            msg = f"🚨 ¡ALERTA! Se han detectado {danger_count} proceso(s) de ALTO PELIGRO y {susp_count} sospechoso(s)."
            color = "#ef4444"
        elif susp_count > 0:
            msg = f"⚠️ Atención: Se han detectado {susp_count} proceso(s) sospechoso(s) entre {len(procs)} procesos activos."
            color = "#f59e0b"
        else:
            msg = f"✅ Sistema limpio: {len(procs)} procesos analizados sin indicios de mineros, suplantaciones ni troyanos activos."
            color = "#00C851"

        self.procs_banner_label.configure(text=msg, text_color=color)
        self._render_processes_list()

    def _render_processes_list(self):
        """Renderiza los procesos en el frame según el filtro activo."""
        for widget in self.procs_scroll_frame.winfo_children():
            widget.destroy()

        only_suspicious = self.proc_filter_var.get()
        items = self.cached_processes

        if only_suspicious:
            items = [p for p in items if p["is_suspicious"]]

        if not items:
            lbl = ctk.CTkLabel(
                self.procs_scroll_frame,
                text="No hay procesos sospechosos o peligrosos activos en este momento." if only_suspicious else "No hay procesos para mostrar.",
                font=ctk.CTkFont(size=14),
                text_color="#94a3b8"
            )
            lbl.pack(pady=40)
            return

        for p in items:
            self._add_process_card(p)

    def _add_process_card(self, p: Dict[str, Any]):
        card = ctk.CTkFrame(self.procs_scroll_frame, fg_color="#0f172a", corner_radius=8)
        card.pack(fill="x", pady=4, padx=4)

        # Fila superior
        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x", padx=12, pady=(8, 4))

        # Badge de riesgo
        badge_risk = ctk.CTkLabel(
            top_row,
            text=f" {p['risk_level']} ",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=p["risk_color"]
        )
        badge_risk.pack(side="left", padx=(0, 8))

        lbl_name = ctk.CTkLabel(
            top_row,
            text=f"{p['name']} (PID: {p['pid']})",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#f8fafc"
        )
        lbl_name.pack(side="left")

        lbl_usage = ctk.CTkLabel(
            top_row,
            text=f"RAM: {p['memory_mb']} MB   |   CPU: {p['cpu_percent']}%",
            font=ctk.CTkFont(size=11),
            text_color="#94a3b8"
        )
        lbl_usage.pack(side="left", padx=12)

        # Botones
        btn_box = ctk.CTkFrame(top_row, fg_color="transparent")
        btn_box.pack(side="right")

        if p["exe"]:
            btn_open = ctk.CTkButton(
                btn_box,
                text="📂 Carpeta",
                width=70,
                height=26,
                font=ctk.CTkFont(size=11),
                fg_color="#1e293b",
                hover_color="#334155",
                command=lambda e=p["exe"]: self.process_auditor.open_process_folder(e)
            )
            btn_open.pack(side="left", padx=(0, 6))

        btn_kill = ctk.CTkButton(
            btn_box,
            text="🛑 Finalizar",
            width=75,
            height=26,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#dc2626",
            hover_color="#b91c1c",
            command=lambda pid=p["pid"], n=p["name"]: self._confirm_kill_process(pid, n)
        )
        btn_kill.pack(side="left")

        # Motivos si es sospechoso
        if p["reasons"]:
            for r in p["reasons"]:
                lbl_r = ctk.CTkLabel(
                    card,
                    text=f"⚠️ {r}",
                    font=ctk.CTkFont(size=11, weight="bold"),
                    text_color=p["risk_color"],
                    anchor="w"
                )
                lbl_r.pack(fill="x", padx=12, pady=1)

        # Ruta
        exe_text = p["exe"] if p["exe"] else "(Sin archivo ejecutable en disco)"
        lbl_path = ctk.CTkLabel(
            card,
            text=f"Ruta: {exe_text}",
            font=ctk.CTkFont(size=11),
            text_color="#64748b",
            anchor="w"
        )
        lbl_path.pack(fill="x", padx=12, pady=(0, 8))

    def _confirm_kill_process(self, pid: int, name: str):
        confirm = messagebox.askyesno(
            "Confirmar Cierre de Proceso",
            f"¿Estás seguro de que deseas forzar el cierre del proceso?\n\n"
            f"• Nombre: {name}\n"
            f"• PID: {pid}\n\n"
            f"Si es un proceso crítico de Windows o de una app con datos no guardados, podría cerrarse inesperadamente."
        )
        if not confirm:
            return

        res = self.process_auditor.kill_process(pid)
        if res["success"]:
            messagebox.showinfo("Proceso Finalizado", res["message"])
            self.start_processes_scan()
        else:
            messagebox.showerror("Error al Finalizar", res["message"])

    def _severity_color(self, sev: str) -> str:
        return {"CRÍTICO": "#ef4444", "ADVERTENCIA": "#f59e0b", "NORMAL": "#00c851"}.get(sev, "#f8fafc")

    # =========================================================================
    # VISTA: RANSOMWARE & ARCHIVOS
    # =========================================================================
    def _create_ransomware_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)
        frame.grid_rowconfigure(4, weight=1)

        # Encabezado
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        title = ctk.CTkLabel(
            header_box,
            text="🔒 Ransomware & Protección de Archivos",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(side="left")

        btn_export = ctk.CTkButton(
            header_box,
            text="📤 Exportar reporte",
            font=ctk.CTkFont(size=12),
            fg_color="#1e293b",
            hover_color="#334155",
            width=170,
            command=self._export_report
        )
        btn_export.pack(side="right")

        # Banner global
        self.ransom_banner_label = ctk.CTkLabel(
            frame,
            text="Analiza archivos recientes en busca de patrones de cifrado (entropía, extensión, modificación masiva) y protege tus datos con una baseline de integridad.",
            font=ctk.CTkFont(size=13),
            justify="left",
            anchor="w",
            text_color="#94a3b8",
            wraplength=900
        )
        self.ransom_banner_label.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 10))

        # Fila de controles
        controls = ctk.CTkFrame(frame, fg_color="#1e293b", corner_radius=8)
        controls.grid(row=2, column=0, sticky="ew", pady=(0, 6))

        # Escaneo de cripto
        ctk.CTkLabel(controls, text="Ventana:", font=ctk.CTkFont(size=12), text_color="#94a3b8").pack(side="left", padx=(12, 2), pady=8)
        self.ransom_window_menu = ctk.CTkOptionMenu(
            controls, values=["5 min", "15 min", "30 min", "60 min", "120 min"],
            width=80, fg_color="#1e293b", button_color="#0284c7"
        )
        self.ransom_window_menu.set("60 min")
        self.ransom_window_menu.pack(side="left", padx=(0, 10))

        self.ransom_scan_btn = ctk.CTkButton(
            controls, text="🔍 Analizar patrón de cifrado",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7", hover_color="#0369a1", width=210,
            command=self.start_ransomware_scan
        )
        self.ransom_scan_btn.pack(side="left", padx=(0, 14))

        ctk.CTkLabel(controls, text="Integridad:", font=ctk.CTkFont(size=12), text_color="#94a3b8").pack(side="left", padx=(0, 2))
        btn_base = ctk.CTkButton(
            controls, text="📌 Generar baseline",
            font=ctk.CTkFont(size=12),
            fg_color="#1e293b", hover_color="#334155", width=155,
            command=self._generate_baseline
        )
        btn_base.pack(side="left", padx=(0, 8))
        btn_verify = ctk.CTkButton(
            controls, text="✅ Verificar",
            font=ctk.CTkFont(size=12),
            fg_color="#1e293b", hover_color="#334155", width=110,
            command=self._verify_baseline
        )
        btn_verify.pack(side="left")

        # Scroll de resultados de escaneo de cripto
        self.ransom_scroll = ctk.CTkScrollableFrame(
            frame, fg_color="#13171f", corner_radius=12, border_width=1, border_color="#1e293b",
            label_text="🔍 Resultados: patrón de cifrado (entropía, extensión, masiva)"
        )
        self.ransom_scroll.grid(row=3, column=0, sticky="nsew", padx=6, pady=2)

        # Scroll de resultados de integridad
        self.integrity_scroll = ctk.CTkScrollableFrame(
            frame, fg_color="#13171f", corner_radius=12, border_width=1, border_color="#1e293b",
            label_text="📌 Resultados: integridad (baseline)"
        )
        self.integrity_scroll.grid(row=4, column=0, sticky="nsew", padx=6, pady=2)

        # Monitorización continua
        mon_box = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=8, border_width=1, border_color="#1e293b")
        mon_box.grid(row=5, column=0, sticky="ew", pady=(6, 0))
        mon_box.grid_columnconfigure(0, weight=1)

        mon_top = ctk.CTkFrame(mon_box, fg_color="transparent")
        mon_top.grid(row=0, column=0, sticky="ew", padx=12, pady=(8, 4))

        self.monitor_btn = ctk.CTkButton(
            mon_top, text="👁️ Iniciar monitorización",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7", hover_color="#0369a1", width=210,
            command=self._toggle_monitor
        )
        self.monitor_btn.pack(side="left")

        ctk.CTkLabel(mon_top, text="Intervalo:", font=ctk.CTkFont(size=12), text_color="#94a3b8").pack(side="left", padx=(10, 4))
        self.monitor_interval_menu = ctk.CTkOptionMenu(
            mon_top, values=["5", "10", "15", "30"], width=50,
            fg_color="#1e293b", button_color="#0284c7"
        )
        self.monitor_interval_menu.set("5")
        self.monitor_interval_menu.pack(side="left", padx=(0, 10))

        self.monitor_status_label = ctk.CTkLabel(
            mon_top, text="Monitorización: apagada",
            font=ctk.CTkFont(size=12), text_color="#64748b"
        )
        self.monitor_status_label.pack(side="left")

        self.monitor_log = ctk.CTkTextbox(
            mon_box, width=55, height=4,
            fg_color="#0f172a", corner_radius=6,
            font=ctk.CTkFont(size=10),
            bg_color="#0a0d14"
        )
        self.monitor_log.insert("1.0", "Registro de eventos del monitor de integridad.\n")
        self.monitor_log.configure(state="disabled")
        self.monitor_log.grid(row=1, column=0, sticky="ew", padx=12, pady=(4, 8))

        return frame

    def start_ransomware_scan(self):
        """Inicia el análisis de patrón de cifrado en segundo plano."""
        window_map = {"5 min": 5, "15 min": 15, "30 min": 30, "60 min": 60, "120 min": 120}
        window_min = window_map.get(self.ransom_window_menu.get(), 60)
        self.ransom_scan_btn.configure(state="disabled", text="⏳ Analizando...")

        def worker():
            result = self.ransomware_detector.scan(window_min=window_min)
            self.cached_ransomware = result
            self.after(0, lambda: self._render_ransomware_results(result))

        threading.Thread(target=worker, daemon=True).start()

    def _render_ransomware_results(self, result: Dict[str, Any]):
        for widget in self.ransom_scroll.winfo_children():
            widget.destroy()

        color = self._severity_color(result["severity"])
        ctk.CTkLabel(
            self.ransom_scroll, text=result["summary"], font=ctk.CTkFont(size=12, weight="bold"),
            text_color=color, wraplength=800, justify="left"
        ).pack(fill="x", padx=12, pady=(8, 4))

        for d in result.get("details", []):
            ctk.CTkLabel(self.ransom_scroll, text=f"• {d}", font=ctk.CTkFont(size=11),
                         text_color="#cbd5e1", wraplength=800, justify="left").pack(anchor="w", padx=14, pady=1)

        if result.get("ransomware_ext_files"):
            ctk.CTkLabel(self.ransom_scroll, text=f"🔴 Extensiones de ransomware ({len(result['ransomware_ext_files'])})",
                         font=ctk.CTkFont(size=12, weight="bold"), text_color="#ef4444").pack(anchor="w", padx=14, pady=(8, 2))
            for f in result["ransomware_ext_files"][:50]:
                self._add_file_card(self.ransom_scroll, f, "#ef4444")

        if result.get("high_entropy_files"):
            ctk.CTkLabel(self.ransom_scroll, text=f"🟠 Entropía alta ({len(result['high_entropy_files'])})",
                         font=ctk.CTkFont(size=12, weight="bold"), text_color="#f59e0b").pack(anchor="w", padx=14, pady=(6, 2))
            for f in result["high_entropy_files"][:50]:
                color = "#ef4444" if (f.get("entropy") or 0) >= 7.85 else "#f59e0b"
                self._add_file_card(self.ransom_scroll, f, color)

        if result.get("mass_modification"):
            ctk.CTkLabel(self.ransom_scroll, text=f"🟡 Modificación masiva ({len(result['mass_modification'])} carpeta(s))",
                         font=ctk.CTkFont(size=12, weight="bold"), text_color="#f59e0b").pack(anchor="w", padx=14, pady=(8, 2))
            for m in result["mass_modification"][:20]:
                ctk.CTkLabel(self.ransom_scroll,
                             text=f"{m['folder']} — {m['total']} archivo(s) en {result['window_min']} min",
                             font=ctk.CTkFont(size=11), text_color="#f59e0b", wraplength=800, justify="left"
                             ).pack(anchor="w", padx=14, pady=1)

    def _add_file_card(self, parent, item, risk_color="#ef4444"):
        card = ctk.CTkFrame(parent, fg_color="#0f172a", corner_radius=6)
        card.pack(fill="x", pady=2, padx=8)
        ctk.CTkLabel(
            card, text=f"• {item.get('name', '')}  [{item.get('extension', '')}]",
            font=ctk.CTkFont(size=11), text_color=risk_color, anchor="w"
        ).pack(side="left", padx=10, pady=4)
        ctk.CTkLabel(
            card, text=item.get("size_formatted", ""),
            font=ctk.CTkFont(size=11), text_color="#f8fafc", anchor="w"
        ).pack(side="left", padx=4, pady=4)
        if item.get("entropy") is not None:
            ctk.CTkLabel(card, text=f"entropía {item['entropy']:.2f}", font=ctk.CTkFont(size=10),
                         text_color="#cbd5e1", anchor="w").pack(side="left", padx=(4, 0), pady=4)
        btn = ctk.CTkButton(card, text="📂", width=40, height=24, font=ctk.CTkFont(size=11),
                            fg_color="#1e293b", hover_color="#334155",
                            command=lambda p=item.get("path"): self.disk_tracker.open_in_explorer(p))
        btn.pack(side="right", padx=10, pady=4)

    def _generate_baseline(self):
        self.ransom_banner_label.configure(text="Generando baseline de hashes... (puede tardar un rato)",
                                           text_color="#38bdf8")
        def worker():
            res = self.integrity_monitor.generate_baseline()
            self.after(0, lambda: self._show_baseline_result(res, is_gen=True))
        threading.Thread(target=worker, daemon=True).start()

    def _verify_baseline(self):
        self.ransom_banner_label.configure(text="Verificando integridad...", text_color="#38bdf8")
        def worker():
            res = self.integrity_monitor.verify_baseline()
            self.after(0, lambda: self._show_baseline_result(res, is_gen=False))
        threading.Thread(target=worker, daemon=True).start()

    def _show_baseline_result(self, res: Dict[str, Any], is_gen: bool):
        color = "#00c851" if res.get("success") else "#ef4444"
        self.ransom_banner_label.configure(text=res.get("summary", res.get("message", "Hecho")),
                                           text_color=color)
        self._render_integrity_results(res)

    def _render_integrity_results(self, res: Dict[str, Any]):
        for widget in self.integrity_scroll.winfo_children():
            widget.destroy()
        if not res.get("success"):
            ctk.CTkLabel(self.integrity_scroll, text=res.get("error", "Error"),
                         font=ctk.CTkFont(size=12), text_color="#ef4444").pack(pady=30)
            return
        if "changed" not in res and "deleted" not in res:
            ctk.CTkLabel(self.integrity_scroll, text=f"✅ {res.get('message', 'Baseline generada')}",
                         font=ctk.CTkFont(size=12, weight="bold"), text_color="#00c851").pack(fill="x", padx=14)
            return
        ctk.CTkLabel(
            self.integrity_scroll, text=res.get("summary", ""),
            font=ctk.CTkFont(size=12, weight="bold"), text_color=self._severity_color(res.get("severity", "NORMAL")),
            wraplength=800, justify="left"
        ).pack(anchor="w", padx=14, pady=8)
        for label, color, items in [
            ("🔴 MODIFICADOS", "#ef4444", res.get("changed", [])),
            ("🔴 ELIMINADOS", "#ef4444", res.get("deleted", [])),
            ("🟠 NUEVOS", "#f59e0b", res.get("new_files", [])),
        ]:
            if items:
                ctk.CTkLabel(self.integrity_scroll, text=f"{label} ({len(items)})",
                             font=ctk.CTkFont(size=12, weight="bold"), text_color=color).pack(anchor="w", padx=14, pady=(4, 2))
                for f in items[:50]:
                    self._add_integrity_file_card(self.integrity_scroll, f, color)

    def _add_integrity_file_card(self, parent, item, color):
        ctk.CTkLabel(
            parent, text=item.get("path", "")[:80], font=ctk.CTkFont(size=11),
            text_color=color, anchor="w"
        ).pack(anchor="w", padx=14, pady=2)

    # =========================================================================
    # MONITORIZACIÓN CONTINUA
    # =========================================================================
    def _toggle_monitor(self):
        if self.monitor_thread is not None and self.monitor_thread.is_alive():
            self.monitor_stop.set()
            self.monitor_btn.configure(text="👁️ Iniciar monitorización", fg_color="#0284c7")
            self.monitor_status_label.configure(text="Monitorización: apagada", text_color="#64748b")
        else:
            self.monitor_stop.clear()
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            self.monitor_btn.configure(text="🛑 Detener monitorización", fg_color="#dc2626")
            self.monitor_status_label.configure(text="Monitorización: activa", text_color="#00c851")

    def _monitor_loop(self):
        while not self.monitor_stop.is_set():
            try:
                interval_min = int(self.monitor_interval_menu.get())
            except Exception:
                interval_min = 5
            try:
                rate = self.ransomware_detector.quick_creation_rate(window_min=interval_min)
                defender = self.system_hardener.check_defender()
            except Exception:
                rate, defender = {"created": 0, "modified": 0, "suspicious": False}, {"status": "ERROR"}
            alert = bool(rate.get("suspicious")) or defender["status"] == "CRÍTICO"
            msg = (
                f"[{time.strftime('%H:%M:%S')}] "
                + ("⚠️ ALERTA: " if alert else "✅ OK: ")
                + f"creaciones={rate.get('created')}, modificados={rate.get('modified')}, "
                + f"defender={defender['status']}"
            )
            self.monitor_events.append(msg)
            self.after(0, lambda m=msg: self._monitor_log_append(m))
            self.after(0, lambda a=alert: self.monitor_status_label.configure(
                text="Monitorización: activa" + (" (alerta)" if a else ""),
                text_color="#f59e0b" if a else "#00c851"))
            time.sleep(interval_min * 60)
        self.after(0, lambda: self.monitor_btn.configure(text="👁️ Iniciar monitorización", fg_color="#0284c7"))
        self.after(0, lambda: self.monitor_status_label.configure(text="Monitorización: apagada", text_color="#64748b"))

    def _monitor_log_append(self, msg):
        self.monitor_log.configure(state="normal")
        self.monitor_log.insert("end", msg + "\n")
        self.monitor_log.see("end")
        self.monitor_log.configure(state="disabled")

    # =========================================================================
    # VISTA: HIDRATAción & SISTEMA
    # =========================================================================
    def _create_hardening_view(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.grid(row=0, column=0, sticky="ew", pady=(0, 12))

        title = ctk.CTkLabel(
            header_box,
            text="🛡️ Hidratación & Sistema (Defensas + Persistencia)",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(side="left")

        self.harden_btn = ctk.CTkButton(
            header_box, text="🛡️ Analizar sistema", font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#0284c7", hover_color="#0369a1", width=170,
            command=self.start_harden_scan
        )
        self.harden_btn.pack(side="right")

        btn_export = ctk.CTkButton(
            header_box, text="📤 Exportar reporte", font=ctk.CTkFont(size=12),
            fg_color="#1e293b", hover_color="#334155", width=170,
            command=self._export_report
        )
        btn_export.pack(side="right", padx=(6, 0))

        self.harden_banner_label = ctk.CTkLabel(
            frame, text="Audita el estado de las defensas de Windows (Defender, parches) y los mecanismos de persistencia (arrancado, servicios, tareas, WMI) que usan los atacantes.",
            font=ctk.CTkFont(size=13), justify="left", anchor="w", text_color="#94a3b8", wraplength=900
        )
        self.harden_banner_label.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 10))

        self.harden_scroll = ctk.CTkScrollableFrame(
            frame, fg_color="#13171f", corner_radius=12, border_width=1, border_color="#1e293b"
        )
        self.harden_scroll.grid(row=2, column=0, sticky="nsew", padx=6, pady=2)

        return frame

    def start_harden_scan(self):
        self.harden_btn.configure(state="disabled", text="⏳ Analizando...")

        def worker():
            res = self.system_hardener.run_all()
            self.cached_hardening = res
            self.after(0, lambda: self._render_harden_results(res))

        threading.Thread(target=worker, daemon=True).start()

    def _render_harden_results(self, res: Dict[str, Any]):
        for widget in self.harden_scroll.winfo_children():
            widget.destroy()

        color = self._severity_color(res.get("global_status", "NORMAL"))
        ctk.CTkLabel(self.harden_scroll, text=f"🛡️ ESTADO GLOBAL: {res['global_status']}",
                     font=ctk.CTkFont(size=14, weight="bold"), text_color=color).pack(pady=10)

        def card(title, status, message):
            self._add_harden_card(self.harden_scroll, title, status, message)

        card("🔒 Defender (Antivirus)", res["defender"]["status"], res["defender"]["message"])
        wu = res["windows_update"]
        wu_msg = res["windows_update"]["message"]
        if wu.get("pending"):
            wu_msg = f"Parches pendientes: {wu['pending']}. {wu_msg}"
        card("📦 Windows Update", wu["status"], wu_msg)
        smb = res["smb"]
        card("🌐 SMB (puerto 445)", smb["status"], smb["message"])
        p = res["persistence"]
        p_summary = (
            f"{len(p.get('issues', []))} Run keys · "
            f"{len(p.get('startup_folder_files', []))} Startup · "
            f"{len(p.get('services', []))} servicios no-Windows · "
            f"{len(p.get('wmi', {}).get('consumers', []))} WMI consumers"
        )
        card("🔁 Persistencia", p["status"], p_summary)
        self._render_harden_details(res)

    def _add_harden_card(self, parent, title, status, message):
        color = self._severity_color(status)
        card = ctk.CTkFrame(parent, fg_color="#0f172a", corner_radius=8)
        card.pack(fill="x", pady=4, padx=8)
        ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#38bdf8", anchor="w").pack(side="left", padx=14, pady=6)
        ctk.CTkLabel(card, text=f" {status} ", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=color, anchor="w").pack(side="right", padx=14)
        ctk.CTkLabel(card, text=message, font=ctk.CTkFont(size=11), text_color="#cbd5e1",
                     wraplength=800, justify="left", anchor="w").pack(anchor="w", padx=14, pady=(0, 8))

    def _render_harden_details(self, res):
        p = res["persistence"]

        def add_section(title, items):
            if not items:
                return
            ctk.CTkLabel(self.harden_scroll, text=title, font=ctk.CTkFont(size=13, weight="bold"),
                         text_color="#38bdf8").pack(anchor="w", padx=14, pady=(6, 2))
            for it in items[:25]:
                ctk.CTkLabel(self.harden_scroll, text=it, font=ctk.CTkFont(size=11),
                             wraplength=800).pack(anchor="w", padx=16, pady=1)

        add_section("⚠️ Persistencia detectada (Run keys)",
                    [f"{e['hive']}\\{e['key']}: {e['name']} -> {e['value'][:60]}" for e in p.get("startup_entries", [])
                     if "c:\\windows" not in e.get("value", "").lower()])
        add_section("📁 Carpeta Startup (archivos)", p.get("startup_folder_files", []))
        add_section("⚙️ Servicios no-Windows en ejecución",
                    [f"{s['name']}  →  {s['path'][:60]}" for s in p.get("services", [])])
        add_section("⏰ Tareas programadas",
                    [f"{t['name']} ({t['user']}) -> {t['command'][:50]}" for t in p.get("scheduled_tasks", [])])
        wmi_consumers = p.get("wmi", {}).get("consumers", [])
        add_section("📡 WMI event consumers",
                    [f"{c['id']} -> {c['command_line'][:50]}" for c in wmi_consumers])
        if not (p.get("startup_entries") or p.get("startup_folder_files") or p.get("services")
                or p.get("scheduled_tasks") or wmi_consumers):
            ctk.CTkLabel(self.harden_scroll, text="Nada de interés detectado en persistencia.",
                         font=ctk.CTkFont(size=12), text_color="#00c851").pack(pady=20)

    # =========================================================================
    # EXPORTACIÓN DE REPORTES
    # =========================================================================
    def _export_report(self):
        report_dir = os.path.join(
            os.environ.get("APPDATA", os.path.join(os.environ.get("USERPROFILE", ""), "AppData")),
            "NetShield", "Reports"
        )
        try:
            os.makedirs(report_dir, exist_ok=True)
            payload = {
                "type": "netshield-report",
                "timestamp": datetime.now().isoformat(),
                "ransomware": self.cached_ransomware,
                "integrity": self.cached_integrity,
                "hardening": self.cached_hardening,
                "monitor_log": self.monitor_events[-50:],
            }
            path = os.path.join(report_dir, f"report-{datetime.now():%Y%m%d-%H%M%S}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("Reporte Exportado", f"Reporte guardado en:\n\n{path}")
        except Exception as e:
            messagebox.showerror("Error exportando reporte", str(e))

    # =========================================================================
    # VISTA 11: CENTRO DE AYUDA Y GUÍA DEL USUARIO
    # =========================================================================
    def _create_help_view(self) -> ctk.CTkFrame:
        """Crea la vista interactiva del Centro de Ayuda y Documentación de Módulos."""
        frame = ctk.CTkFrame(self.content_container, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        # Encabezado
        header_box = ctk.CTkFrame(frame, fg_color="transparent")
        header_box.grid(row=0, column=0, sticky="ew", pady=(0, 10))

        title_box = ctk.CTkFrame(header_box, fg_color="transparent")
        title_box.pack(side="left")

        title = ctk.CTkLabel(
            title_box,
            text="📖 Centro de Ayuda & Guía del Usuario",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#f8fafc"
        )
        title.pack(anchor="w")

        subtitle = ctk.CTkLabel(
            title_box,
            text="Explicación detallada, funcionamiento técnico y guía paso a paso de cada módulo de la aplicación.",
            font=ctk.CTkFont(size=12),
            text_color="#94a3b8"
        )
        subtitle.pack(anchor="w")

        # Buscador interactivo
        search_box = ctk.CTkFrame(header_box, fg_color="transparent")
        search_box.pack(side="right")

        self.help_search_var = tk.StringVar()
        self.help_search_entry = ctk.CTkEntry(
            search_box,
            placeholder_text="🔍 Buscar tema o sección...",
            textvariable=self.help_search_var,
            width=260,
            font=ctk.CTkFont(size=12)
        )
        self.help_search_entry.pack(side="left", padx=(0, 6))

        btn_clear_search = ctk.CTkButton(
            search_box,
            text="✕",
            width=28,
            height=28,
            fg_color="#1e293b",
            hover_color="#334155",
            font=ctk.CTkFont(size=12, weight="bold"),
            command=lambda: self.help_search_var.set("")
        )
        btn_clear_search.pack(side="left")

        # Barra de Filtros por Categoría
        filter_frame = ctk.CTkFrame(frame, fg_color="#13171f", corner_radius=10, border_width=1, border_color="#1e293b")
        filter_frame.grid(row=1, column=0, sticky="ew", pady=(0, 10))

        lbl_filter = ctk.CTkLabel(
            filter_frame,
            text="Filtrar por Área:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#cbd5e1"
        )
        lbl_filter.pack(side="left", padx=(14, 10), pady=8)

        self.help_category_var = tk.StringVar(value="Todas")
        self.help_cat_seg = ctk.CTkSegmentedButton(
            filter_frame,
            values=["Todas", "Redes & Wi-Fi", "Seguridad & Amenazas", "Disco & Sistema", "Guía Rápida"],
            variable=self.help_category_var,
            command=lambda _: self._filter_help_cards(),
            font=ctk.CTkFont(size=12)
        )
        self.help_cat_seg.pack(side="left", padx=(0, 14), pady=6)

        # Contenedor desplazable de tarjetas de ayuda
        self.help_scroll_frame = ctk.CTkScrollableFrame(
            frame,
            fg_color="#13171f",
            corner_radius=12,
            border_width=1,
            border_color="#1e293b"
        )
        self.help_scroll_frame.grid(row=2, column=0, sticky="nsew", padx=2, pady=2)

        # Etiqueta de búsqueda sin resultados
        self.help_empty_label = ctk.CTkLabel(
            self.help_scroll_frame,
            text="🔍 No se encontraron módulos ni temas que coincidan con la búsqueda.\nPrueba con otros términos (ej. wifi, dns, ransomware, temporales, puertos).",
            font=ctk.CTkFont(size=13),
            text_color="#94a3b8",
            justify="center"
        )

        # Vinculación del evento de búsqueda en tiempo real
        self.help_search_var.trace_add("write", lambda *_: self._filter_help_cards())

        # Construcción inicial de las tarjetas
        self.help_card_widgets = []
        self._build_help_cards()

        return frame

    def _build_help_cards(self):
        """Genera el catálogo explicativo para todas las secciones de la aplicación."""
        sections = [
            {
                "id": "wifi",
                "title": "1. 📶 Wi-Fi & Red Activa",
                "category": "Redes & Wi-Fi",
                "badge": "CONECTIVIDAD & CIFRADO",
                "badge_color": "#0284c7",
                "target_view": "wifi",
                "keywords": "wifi wlan red ssid bssid ap router mac canal frecuencia banda ghz wpa wpa2 wpa3 wep tkip senal rssi dbm mbps dns gateway",
                "purpose": "Auditar en detalle la conexión inalámbrica activa, la intensidad de la señal, la robustez del cifrado y la configuración del router y servidores DNS.",
                "how_it_works": [
                    "• Consulta nativa a la interfaz WLAN de Windows ('netsh wlan show interfaces') para extraer el SSID, BSSID (MAC física del Punto de Acceso), canal actual (1-165), bandas de frecuencia (2.4 GHz, 5 GHz o 6 GHz) y estándar de radio (802.11ax/ac/n/g).",
                    "• Medición precisa de la calidad de señal en porcentaje y potencia real de recepción en dBm (RSSI), además de velocidades teóricas de enlace en Mbps de subida y bajada.",
                    "• Análisis del protocolo de seguridad y cifrado de paquetes: WPA3-SAE, WPA2-CCMP (AES), WPA-TKIP o redes abiertas sin contraseña.",
                    "• Identificación de la puerta de enlace predeterminada (Gateway), resolución del fabricante del router mediante su prefijo OUI y listado de servidores DNS configurados (Google, Cloudflare, Quad9, ISP, etc.)."
                ],
                "how_to_use": [
                    "1. Accede a la pestaña '📶 Wi-Fi & Red' en la barra lateral.",
                    "2. Pulsa el botón '🔄 Actualizar Análisis' en la esquina superior derecha.",
                    "3. Revisa la tarjeta izquierda para datos de señal y radio, la tarjeta derecha para DNS y Gateway, y la tarjeta inferior para la evaluación de seguridad del cifrado."
                ],
                "alerts": [
                    "🟢 WPA3-SAE / WPA2-CCMP (AES): Cifrado moderno y robusto contra interceptación y ataques de fuerza bruta.",
                    "🟡 WPA-TKIP: Protocolo desactualizado y vulnerable a descifrado parcial de paquetes.",
                    "🔴 Red Abierta o WEP: Riesgo crítico; cualquier usuario en el radio de alcance puede capturar tu tráfico no cifrado."
                ],
                "recommendation": "Nunca introduzcas contraseñas ni accedas a cuentas bancarias en redes abiertas sin usar VPN. En tu router personal, asegúrate de activar WPA2-AES o WPA3 y desactivar WPS."
            },
            {
                "id": "network",
                "title": "2. 💻 Dispositivos LAN (Escáner de Red Local)",
                "category": "Redes & Wi-Fi",
                "badge": "ESCANEO ARP MULTIHILO",
                "badge_color": "#0ea5e9",
                "target_view": "network",
                "keywords": "lan red local arp sendarp ip mac oui fabricante dispositivos host hostname puertos vecinos intrusos subred",
                "purpose": "Descubrir, clasificar y auditar todos los equipos, smartphones, consolas, dispositivos IoT e intrusos conectados a tu red local.",
                "how_it_works": [
                    "• Ejecuta un barrido paralelo ultrarrápido (2 a 4 segundos) mediante la API nativa de Windows 'SendARP' ('iphlpapi.dll') sobre las 254 IPs de tu subred (/24).",
                    "• Resuelve direcciones MAC físicas y consulta una base de datos local OUI con más de 300 fabricantes (Apple, Samsung, Xiaomi, Huawei, Intel, Raspberry Pi, etc.).",
                    "• Detección de Privacidad: Identifica si un dispositivo utiliza una dirección MAC aleatoria/privada (común en smartphones iOS y Android modernos).",
                    "• Resolución inversa de nombres DNS (hostname) y escaneo selectivo de puertos clave (80 HTTP, 443 HTTPS, 22 SSH, 445 SMB, 8080)."
                ],
                "how_to_use": [
                    "1. Ve a la pestaña '💻 Dispositivos LAN'.",
                    "2. Pulsa el botón '🔍 Iniciar Escaneo de Red'.",
                    "3. Observa el listado completo con la IP, nombre de equipo, fabricante identificado, dirección MAC y puertos expuestos de cada dispositivo."
                ],
                "alerts": [
                    "🟢 Fabricante Conocido: Equipos de tu hogar u oficina (PC, Smart TV, móvil).",
                    "🟡 MAC Aleatoria / Privada: Teléfono o tablet con funciones de anonimato Wi-Fi activadas.",
                    "🔴 Dispositivo Desconocido con Puertos Abiertos (ej. 22 SSH o 445 SMB): Posible intruso conectado a tu Wi-Fi o equipo no autorizado."
                ],
                "recommendation": "Si detectas dispositivos que no reconoces, cambia la contraseña de tu red Wi-Fi en el router y activa el aislamiento de clientes o filtrado por MAC."
            },
            {
                "id": "security",
                "title": "3. 🛡️ Seguridad & Riesgos (Auditoría Anti-Hacking)",
                "category": "Seguridad & Amenazas",
                "badge": "AUDITORÍA MITM & DNS",
                "badge_color": "#f59e0b",
                "target_view": "security",
                "keywords": "mitm man in the middle arp spoofing envenenamiento dns hijacking secuestro listeners puertos escuchando score puntuacion firewall",
                "purpose": "Evaluar la seguridad de tu entorno de red frente a ataques Man-In-The-Middle (MitM), manipulación de DNS y servicios locales expuestos sin protección.",
                "how_it_works": [
                    "• Detección de Envenenamiento ARP (ARP Spoofing): Audita la tabla ARP de Windows para detectar direcciones MAC duplicadas o suplantación del router, técnica típica para interceptar tráfico de red.",
                    "• Integridad de DNS (Anti-Hijacking): Resuelve dominios de control contra tus servidores configurados y contra resolvers seguros globales para descubrir desvíos hacia IPs maliciosas.",
                    "• Auditoría de Puertos en Escucha (Listeners): Identifica qué aplicaciones o procesos locales están escuchando en '0.0.0.0' o '::', dejando puertas abiertas hacia otros equipos de la red.",
                    "• Puntuación de Seguridad (Score 0-100): Genera un índice con diagnóstico por semáforo y recomendaciones automáticas de mitigación."
                ],
                "how_to_use": [
                    "1. Dirígete a '🛡️ Seguridad & Riesgos'.",
                    "2. Pulsa '🛡️ Ejecutar Auditoría'.",
                    "3. Revisa la puntuación global en el encabezado y desglosa las tarjetas de ARP, DNS, Cifrado Wi-Fi y Puertos Expuestos."
                ],
                "alerts": [
                    "🟢 Puntuación 90-100 (Seguro): Sin envenenamiento ARP, DNS legítimo y servicios protegidos.",
                    "🟡 Puntuación 60-89 (Advertencia): Puertos en escucha globales o cifrado Wi-Fi mejorable.",
                    "🔴 Puntuación < 60 (Riesgo Crítico): Envenenamiento ARP detectado o manipulación DNS activa."
                ],
                "recommendation": "Si detectas ARP Spoofing en una red pública, desconéctate de inmediato o activa una VPN con cifrado completo para tunelizar todo tu tráfico."
            },
            {
                "id": "leak_detector",
                "title": "4. 📡 Fuga de Datos / Espía (Anti-Exfiltración)",
                "category": "Seguridad & Amenazas",
                "badge": "ANTI-EXFILTRACIÓN & C2",
                "badge_color": "#ef4444",
                "target_view": "leak_detector",
                "keywords": "exfiltracion fuga datos espia spyware infostealer c2 command control lolbins powershell certutil rundll32 bot telegram discord webhook dga dns udp 53 smb 445 rat backdoor troyano cortar conexion",
                "purpose": "Monitorear en tiempo real las conexiones salientes hacia internet para neutralizar programas espía, infostealers, troyanos y fugas silenciosas de datos confidenciales.",
                "how_it_works": [
                    "• Audita sockets TCP y UDP activos en el sistema, vinculando cada conexión con su ejecutable exacto (.exe), PID, memoria consumida y ruta en disco.",
                    "• Abuso de Binarios del Sistema (LOLBins): Alerta de inmediato si procesos como 'powershell.exe', 'cmd.exe', 'certutil.exe' o 'rundll32.exe' establecen comunicaciones hacia IPs públicas externas.",
                    "• Exfiltración encubierta por DNS: Detecta consultas anómalas por UDP 53 a servidores desconocidos y nombres de dominio generados por algoritmos aleatorios (DGA).",
                    "• Canales C2 y Webhooks: Detecta conexiones hacia servidores de comando y control o webhooks de Discord y bots de Telegram frecuentemente abusados por ladrones de datos (RedLine, Lumma, AgentTesla).",
                    "• Puertos de Malware y RATs: Alerta sobre tráfico hacia puertos típicos de troyanos de acceso remoto (1337, 4444, 5555, 6667, 8888) y SMB saliente (puerto 445)."
                ],
                "how_to_use": [
                    "1. Abre '📡 Fuga de Datos / Espía'.",
                    "2. Pulsa '📡 Analizar Transmisiones'. Puedes activar la casilla 'Solo Tráfico Sospechoso / Peligro' para enfocar la revisión.",
                    "3. Si identificas una conexión sospechosa o no autorizada, haz clic en el botón rojo '🛑 Cortar Conexión' para terminar el proceso emisor en el acto."
                ],
                "alerts": [
                    "🔴 Exfiltración Crítica: Proceso LOLBin o troyano enviando datos hacia un servidor externo o webhook sospechoso.",
                    "🟡 Tráfico Sospechoso: Conexiones a puertos no estándar o servidores DNS públicos desconocidos.",
                    "🟢 Conexiones Normales: Navegadores y servicios legítimos comunicándose vía HTTPS (puerto 443)."
                ],
                "recommendation": "Ante una alerta crítica en un ejecutable desconocido, pulsa '🛑 Cortar Conexión', desconecta el equipo de la red y realiza un análisis exhaustivo con tu antivirus."
            },
            {
                "id": "disk",
                "title": "5. 📈 Consumo de Disco (Últimos 7 Días)",
                "category": "Disco & Sistema",
                "badge": "RASTREADOR DE ESPACIO",
                "badge_color": "#8b5cf6",
                "target_view": "disk",
                "keywords": "disco gigas espacio gb mb archivos recientes creados 7 dias descargas dmp volcados scandir",
                "purpose": "Localizar qué archivos creados o modificados recientemente están consumiendo tu almacenamiento y provocando caídas inesperadas de espacio libre.",
                "how_it_works": [
                    "• Escaneo optimizado a bajo nivel mediante 'os.scandir' para inspeccionar directorios sin sobrecargar el procesador ni congelar la interfaz.",
                    "• Filtra archivos creados o modificados en la ventana de tiempo seleccionada (3, 7, 14 o 30 días).",
                    "• Ordena los resultados de mayor a menor tamaño para revelar con rapidez los archivos más pesados.",
                    "• Detecta con especial atención volcados de fallo del sistema (.dmp), imágenes ISO, instaladores gigantes, vídeos y archivos temporales pesados."
                ],
                "how_to_use": [
                    "1. Ve a '📈 Disco (7 Días)'.",
                    "2. Selecciona la unidad o carpeta a analizar y el rango de días (ej. 7 días).",
                    "3. Pulsa '🔍 Rastrear Archivos'.",
                    "4. En la lista resultante, pulsa el botón '📂 Abrir' en cualquier archivo para abrir el Explorador de Windows en su ubicación exacta."
                ],
                "alerts": [
                    "📦 Archivos > 1 GB: Instaladores pesados, vídeos o volcados de error (.dmp) que suelen poder eliminarse o archivarse."
                ],
                "recommendation": "Revisa frecuentemente la carpeta Descargas y elimina instaladores '.iso' o '.zip' tras instalarlos para mantener el SSD desahogado."
            },
            {
                "id": "cleaner",
                "title": "6. 🧹 Limpiar Temporales (Mantenimiento Inteligente)",
                "category": "Disco & Sistema",
                "badge": "LIMPIEZA SEGURA",
                "badge_color": "#10b981",
                "target_view": "cleaner",
                "keywords": "limpiar temporales basura temp crashdumps wer cache directx d3dscache papelera reciclaje windows update liberar espacio gigas",
                "purpose": "Recuperar gigabytes de espacio en disco de forma segura eliminando archivos temporales, informes de error y cachés residuales que Windows no borra por sí mismo.",
                "how_it_works": [
                    "• Limpia selectivamente 7 categorías seguras: Temporales de Usuario (%TEMP%), Temporales del Sistema (C:\\Windows\\Temp), Volcados de Error de Apps (CrashDumps), Informes de Error de Windows (WER), Caché de Descargas de Windows Update, Caché de Sombreadores DirectX (D3DSCache) y Papelera de Reciclaje.",
                    "• Protección Antifallos: Omite silenciosamente archivos bloqueados o en uso por aplicaciones abiertas sin congelar la app ni dañar procesos activos.",
                    "• Modo Análisis Previo: Calcula con exactitud la cantidad de archivos y el tamaño exacto en MB/GB que se recuperará antes de proceder al borrado."
                ],
                "how_to_use": [
                    "1. Accede a '🧹 Limpiar Temporales'.",
                    "2. Pulsa '🔍 Analizar Archivos Temporales' para ver el diagnóstico de espacio recuperable.",
                    "3. Marca o desmarca las casillas según tus preferencias (ej. Papelera de reciclaje).",
                    "4. Haz clic en '🧹 Limpiar Archivos Seleccionados' y confirma la operación para liberar espacio."
                ],
                "alerts": [
                    "🟢 Limpieza Completada: Muestra el espacio exacto recuperado y el total de archivos eliminados."
                ],
                "recommendation": "Ejecuta esta limpieza semanalmente o tras actualizaciones mayores de Windows para evitar la degradación del rendimiento de tu disco SSD."
            },
            {
                "id": "venvs",
                "title": "7. 🐍 Entornos Virtuales (Gestor Python)",
                "category": "Disco & Sistema",
                "badge": "DESARROLLO & PYTHON",
                "badge_color": "#f59e0b",
                "target_view": "venvs",
                "keywords": "entornos virtuales venv .venv conda python pip paquetes librerias repositorios desarrollador espacio eliminar lote",
                "purpose": "Localizar, medir y depurar entornos virtuales de Python olvidados o duplicados en tus carpetas de proyectos y repositorios de código.",
                "how_it_works": [
                    "• Rastreo recursivo inteligente en 'C:\\Repositorios', carpetas de usuario y proyectos buscando estructuras 'venv', '.venv' y entornos Conda.",
                    "• Cálculo del tamaño real en disco en tiempo real (un entorno con PyTorch o TensorFlow puede superar los 5 GB de espacio).",
                    "• Detección de la versión exacta de Python del entorno y fecha de última modificación.",
                    "• Protección del Entorno Activo: Detecta e impide borrar el entorno virtual en el que se ejecuta NetShield para evitar la autodestrucción involuntaria."
                ],
                "how_to_use": [
                    "1. Ve a '🐍 Entornos Virtuales'.",
                    "2. Pulsa '🔍 Escanear Entornos Virtuales'.",
                    "3. Usa las casillas de verificación para marcar entornos antiguos o haz clic en '🗑️ Eliminar' en un entorno específico.",
                    "4. Si seleccionaste varios, pulsa '🗑️ Eliminar Seleccionados' para borrarlos todos de golpe."
                ],
                "alerts": [
                    "🛡️ [PROTEGIDO - EN USO]: Entorno virtual propio de la aplicación NetShield (bloqueado para evitar borrado accidental)."
                ],
                "recommendation": "Elimina entornos virtuales de proyectos que ya no utilices; siempre podrás recrearlos en minutos ejecutando 'python -m venv venv' y 'pip install -r requirements.txt'."
            },
            {
                "id": "processes",
                "title": "8. ⚠️ Procesos Activos (Auditoría de Malware y Mineros)",
                "category": "Seguridad & Amenazas",
                "badge": "MONITOR DE PROCESOS",
                "badge_color": "#ef4444",
                "target_view": "processes",
                "keywords": "procesos activos malware troyanos mineros xmrig minerd masquerading suplantacion svchost temp ofuscado base64 powershell finalizar proceso matar",
                "purpose": "Supervisar todos los procesos en memoria para cazar malware, herramientas de suplantación de sistema (Masquerading), mineros de criptomonedas y comandos ofuscados.",
                "how_it_works": [
                    "• Detección de Suplantación (Masquerading): Detecta procesos con nombres críticos del sistema ('svchost.exe', 'csrss.exe', 'lsass.exe', 'explorer.exe') corriendo fuera de 'C:\\Windows\\System32'.",
                    "• Detección de Rutas de Alto Riesgo: Alerta sobre programas lanzados directamente desde carpetas temporales (%TEMP% o AppData\\Local\\Temp), técnica habitual de instaladores troyanizados.",
                    "• Comandos Ofuscados: Identifica llamadas a PowerShell codificadas en Base64 (-enc / -encodedcommand) o descargas web desde la consola.",
                    "• Mineros de Criptomonedas: Comprueba patrones y binarios de minería ('xmrig', 'minerd', 'ethminer', etc.) y consumos excesivos no justificados."
                ],
                "how_to_use": [
                    "1. Abre '⚠️ Procesos Activos'.",
                    "2. Pulsa '🔍 Auditar Procesos'.",
                    "3. Examina la lista clasificada por nivel de riesgo.",
                    "4. Pulsa '📂 Abrir Carpeta' para revisar el archivo en el Explorador o '🛑 Finalizar Proceso' para cerrarlo forzosamente."
                ],
                "alerts": [
                    "🔴 Crítico (Masquerading o Minero): Proceso haciéndose pasar por Windows o minero de criptomonedas activo.",
                    "🟡 Sospechoso: Ejecutable en carpeta temporal o script PowerShell codificado.",
                    "🟢 Normal: Procesos legítimos verificados del sistema operativo y aplicaciones estándar."
                ],
                "recommendation": "Si observas un proceso sospechoso que no reconoces, finalízalo de inmediato y revisa la carpeta donde reside antes de reiniciar el equipo."
            },
            {
                "id": "ransomware",
                "title": "9. 🔒 Ransomware & Archivos (Detección Activa & FIM)",
                "category": "Seguridad & Amenazas",
                "badge": "ENTROPÍA & INTEGRIDAD FIM",
                "badge_color": "#dc2626",
                "target_view": "ransomware",
                "keywords": "ransomware entropia shannon cifrado masivo lockbit conti blackcat extensiones baseline fim integridad sha256 hashes modificaciones",
                "purpose": "Detección temprana de ataques de cifrado masivo (Ransomware) y supervisión continua de la integridad de tus archivos personales (File Integrity Monitoring).",
                "how_it_works": [
                    "• Entropía de Shannon: Mide matemáticamente la aleatoriedad de los bytes (0 a 8 bits/byte). Los archivos normales rondan ~4.5 bits/byte, mientras que los archivos cifrados por ransomware superan ~7.70 - 7.99 bits/byte.",
                    "• Detección de Extensiones de Ransomware: Identifica más de 40 extensiones asociadas a familias célebres de ransomware (LockBit, Conti, BlackCat, Akira, Royal, Petya, Crypt, etc.).",
                    "• Modificación Masiva y Ráfagas: Detecta si en una ventana de pocos minutos se han alterado o creado cientos de archivos a gran velocidad.",
                    "• Monitor de Integridad (FIM): Genera una 'Línea Base' de hashes criptográficos SHA-256 de tus carpetas personales (Documentos, Escritorio, Descargas). Al verificarla, delata qué archivos han sido MODIFICADOS, ELIMINADOS o CREADOS."
                ],
                "how_to_use": [
                    "1. Para Integridad de Archivos: Pulsa '📌 Generar Línea Base' cuando tu equipo esté limpio. En cualquier momento posterior, pulsa '🔍 Verificar Integridad' para descubrir modificaciones no autorizadas.",
                    "2. Para Detección de Ransomware: Ajusta la ventana de minutos (ej. 15 min) y pulsa '🔍 Analizar Cifrado Sospechoso'."
                ],
                "alerts": [
                    "🔴 Crítico: Se detectaron archivos con entropía extrema (> 7.7) o extensiones de ransomware en tus carpetas.",
                    "🟢 Seguro: No se detectan anomalías de cifrado y la línea base de archivos coincide exactamente."
                ],
                "recommendation": "Genera una línea base de integridad de tus carpetas de trabajo con frecuencia y mantén copias de seguridad desconectadas (offline) de tus datos más valiosos."
            },
            {
                "id": "hardening",
                "title": "10. 🛡️ Hidratación & Persistencia del Sistema",
                "category": "Seguridad & Amenazas",
                "badge": "BLINDAJE DE WINDOWS",
                "badge_color": "#059669",
                "target_view": "hardening",
                "keywords": "hidratacion hardening persistencia defender antivirus windows update parches smb 445 relay pass the hash run keys startup servicios wmi exportar reporte",
                "purpose": "Auditar la postura global de seguridad de Windows y descubrir mecanismos ocultos de persistencia que los atacantes instalan para sobrevivir al reinicio del equipo.",
                "how_it_works": [
                    "• Estado de Microsoft Defender: Comprueba si el antivirus está activo, si la protección en tiempo real está habilitada o si fue desactivada mediante políticas o modificaciones en el Registro.",
                    "• Parches de Windows Update: Verifica el estado del servicio de actualizaciones y la presencia de parches de seguridad críticos pendientes.",
                    "• Puerto SMB (445) y Firmado: Audita si el servicio de compartición de archivos SMB está expuesto y si requiere firma de paquetes para impedir ataques locales de retransmisión (SMB Relay / Pass-the-Hash).",
                    "• Auditoría de Persistencia Oculta: Rastrea los 5 mecanismos favoritos de persistencia del malware: Claves Run del Registro (HKCU y HKLM en 32 y 64 bits), accesos directos en la carpeta de Inicio (Startup), Servicios no-Windows en ejecución, Tareas Programadas y Consumidores de Eventos WMI (WMI Event Consumers).",
                    "• Exportación de Reportes Forenses: Permite guardar un reporte consolidado en JSON con fecha y hora en '%APPDATA%\\NetShield\\Reports\\'."
                ],
                "how_to_use": [
                    "1. Haz clic en '🛡️ Hidratación & Sistema'.",
                    "2. Pulsa '🔍 Analizar Seguridad del Sistema'.",
                    "3. Examina el Estado Global (Seguro, Advertencia o Crítico) y las tarjetas individuales de Defender, Windows Update, SMB y Persistencia.",
                    "4. Pulsa '📤 Exportar reporte' si deseas guardar un archivo JSON con la evidencia completa del análisis."
                ],
                "alerts": [
                    "🔴 Crítico: Microsoft Defender desactivado o presencia de consumidores de eventos WMI sospechosos.",
                    "🟡 Advertencia: Puerto SMB escuchando sin firma obligatoria o parches de seguridad pendientes.",
                    "🟢 Normal: Antivirus activo, sistema al día y mecanismos de persistencia dentro de la normalidad."
                ],
                "recommendation": "Mantén siempre Microsoft Defender activado y actualizado. Si detectas una entrada en el Registro o Tarea Programada que apunta a un archivo desconocido, investiga su procedencia de inmediato."
            },
            {
                "id": "quick_guide",
                "title": "11. 💡 Rutina Recomendada & Preguntas Frecuentes (FAQ)",
                "category": "Guía Rápida",
                "badge": "BUENAS PRÁCTICAS",
                "badge_color": "#6366f1",
                "target_view": None,
                "keywords": "faq preguntas frecuentes rutina semanal que hacer infeccion virus admin permisos consejos mantenimiento",
                "purpose": "Buenas prácticas y recomendaciones esenciales para mantener tu ordenador limpio, rápido y blindado contra amenazas digitales.",
                "how_it_works": [
                    "• Rutina Semanal en 3 Minutos: 1) Ejecuta 'Limpiar Temporales' para recuperar varios gigabytes de espacio. 2) Revisa 'Dispositivos LAN' para cerciorarte de que no hay intrusos en tu Wi-Fi. 3) Ejecuta 'Seguridad & Riesgos' e 'Hidratación' para verificar el estado de tus defensas.",
                    "• ¿Qué hacer si NetShield detecta una amenaza crítica?: 1) Pulsa '🛑 Cortar Conexión' o 'Finalizar Proceso'. 2) Desconecta el cable de red o apaga el Wi-Fi para cortar el canal de comunicación del atacante. 3) Realiza un escaneo completo con Microsoft Defender o tu antivirus de cabecera.",
                    "• ¿Por qué algunas funciones requieren permisos de Administrador?: Ciertas llamadas a la API de Windows (como inspeccionar el estado de servicios protegidos, examinar ciertos procesos del sistema o leer claves del registro en HKLM) requieren privilegios elevados para entregar información 100% precisa."
                ],
                "how_to_use": [
                    "Consulta esta sección siempre que tengas dudas sobre el flujo de trabajo recomendado o cómo proceder ante un incidente de seguridad."
                ],
                "alerts": [
                    "💡 Compromiso de Seguridad: NetShield Pro no modifica archivos de tu sistema operativo ni altera tus configuraciones sin tu confirmación explícita."
                ],
                "recommendation": "La prevención es la mejor defensa: mantén Windows actualizado, no abras adjuntos de correos sospechosos y audita tu red regularmente con esta herramienta."
            }
        ]

        for data in sections:
            card = ctk.CTkFrame(self.help_scroll_frame, fg_color="#0f172a", corner_radius=10, border_width=1, border_color="#1e293b")
            card.pack(fill="x", pady=6, padx=6)

            # Barra superior de la tarjeta
            top_bar = ctk.CTkFrame(card, fg_color="transparent")
            top_bar.pack(fill="x", padx=14, pady=(12, 6))

            # Lado izquierdo: Badge + Título
            title_box = ctk.CTkFrame(top_bar, fg_color="transparent")
            title_box.pack(side="left", fill="x", expand=True)

            badge_frame = ctk.CTkFrame(title_box, fg_color="transparent")
            badge_frame.pack(anchor="w", pady=(0, 2))

            lbl_badge = ctk.CTkLabel(
                badge_frame,
                text=f" {data['badge']} ",
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color="#ffffff",
                fg_color=data["badge_color"],
                corner_radius=4
            )
            lbl_badge.pack(side="left", padx=(0, 8))

            lbl_cat = ctk.CTkLabel(
                badge_frame,
                text=f"Categoría: {data['category']}",
                font=ctk.CTkFont(size=11),
                text_color="#64748b"
            )
            lbl_cat.pack(side="left")

            lbl_title = ctk.CTkLabel(
                title_box,
                text=data["title"],
                font=ctk.CTkFont(size=15, weight="bold"),
                text_color="#f8fafc"
            )
            lbl_title.pack(anchor="w")

            # Lado derecho: Botón de acceso directo a la sección
            if data.get("target_view"):
                btn_nav = ctk.CTkButton(
                    top_bar,
                    text="🚀 Abrir Sección",
                    font=ctk.CTkFont(size=12, weight="bold"),
                    fg_color="#0284c7",
                    hover_color="#0369a1",
                    width=135,
                    height=30,
                    corner_radius=6,
                    command=lambda v=data["target_view"]: self.show_view(v)
                )
                btn_nav.pack(side="right", padx=(10, 0))

            # Cuerpo de la tarjeta
            body = ctk.CTkFrame(card, fg_color="transparent")
            body.pack(fill="x", padx=14, pady=(4, 12))

            # 1. Propósito
            p_box = ctk.CTkFrame(body, fg_color="#13171f", corner_radius=6)
            p_box.pack(fill="x", pady=3)
            ctk.CTkLabel(p_box, text="🎯 Objetivo:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=10, pady=(6, 2))
            ctk.CTkLabel(p_box, text=data["purpose"], font=ctk.CTkFont(size=12), text_color="#e2e8f0", wraplength=780, justify="left").pack(anchor="w", padx=10, pady=(0, 6))

            # 2. Cómo funciona
            ctk.CTkLabel(body, text="⚙️ Cómo funciona internamente y qué analiza:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#94a3b8").pack(anchor="w", pady=(8, 2))
            for line in data["how_it_works"]:
                ctk.CTkLabel(body, text=line, font=ctk.CTkFont(size=11), text_color="#cbd5e1", wraplength=780, justify="left").pack(anchor="w", padx=8, pady=1)

            # 3. Modo de uso
            ctk.CTkLabel(body, text="📋 Modo de uso paso a paso:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#94a3b8").pack(anchor="w", pady=(8, 2))
            for step in data["how_to_use"]:
                ctk.CTkLabel(body, text=step, font=ctk.CTkFont(size=11), text_color="#cbd5e1", wraplength=780, justify="left").pack(anchor="w", padx=8, pady=1)

            # 4. Interpretación de estados y alertas
            ctk.CTkLabel(body, text="🚦 Interpretación de estados y semáforos:", font=ctk.CTkFont(size=12, weight="bold"), text_color="#94a3b8").pack(anchor="w", pady=(8, 2))
            for alert in data["alerts"]:
                ctk.CTkLabel(body, text=alert, font=ctk.CTkFont(size=11), text_color="#cbd5e1", wraplength=780, justify="left").pack(anchor="w", padx=8, pady=1)

            # 5. Recomendación
            rec_box = ctk.CTkFrame(body, fg_color="#1e293b", corner_radius=6)
            rec_box.pack(fill="x", pady=(8, 2))
            ctk.CTkLabel(rec_box, text="💡 Recomendación de seguridad / mantenimiento:", font=ctk.CTkFont(size=11, weight="bold"), text_color="#38bdf8").pack(anchor="w", padx=10, pady=(6, 2))
            ctk.CTkLabel(rec_box, text=data["recommendation"], font=ctk.CTkFont(size=11), text_color="#f1f5f9", wraplength=780, justify="left").pack(anchor="w", padx=10, pady=(0, 6))

            # Guardar referencia para filtrado interactivo
            self.help_card_widgets.append({
                "widget": card,
                "data": data
            })

    def _filter_help_cards(self):
        """Filtra las tarjetas de ayuda en tiempo real según el texto de búsqueda y la categoría seleccionada."""
        query = self.help_search_var.get().strip().lower()
        selected_cat = self.help_category_var.get()

        visible_count = 0
        for item in self.help_card_widgets:
            card_widget = item["widget"]
            card_data = item["data"]

            # Comprobación de categoría
            cat_match = (selected_cat == "Todas" or card_data["category"] == selected_cat)

            # Comprobación de texto de búsqueda
            text_to_search = " ".join([
                card_data["title"],
                card_data["category"],
                card_data["purpose"],
                " ".join(card_data["how_it_works"]),
                " ".join(card_data["how_to_use"]),
                " ".join(card_data["alerts"]),
                card_data["recommendation"],
                card_data.get("keywords", "")
            ]).lower()

            search_match = (not query) or (query in text_to_search)

            if cat_match and search_match:
                card_widget.pack(fill="x", pady=6, padx=6)
                visible_count += 1
            else:
                card_widget.pack_forget()

        if visible_count == 0:
            self.help_empty_label.pack(pady=40)
        else:
            self.help_empty_label.pack_forget()


def launch():
    """Función de entrada para arrancar la aplicación."""
    app = ModernApp()
    app.mainloop()



if __name__ == "__main__":
    launch()
