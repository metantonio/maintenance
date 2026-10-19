"""
Interfaz Gráfica Principal (GUI) con CustomTkinter.
Herramienta de Auditoría Wi-Fi, Seguridad de Red y Mantenimiento de Disco.
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import messagebox
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

        # Estados de datos en memoria
        self.cached_wifi_data = None
        self.cached_devices = []
        self.cached_security_data = None
        self.cached_leak_data = None
        self.cached_disk_data = None
        self.cached_temp_scan = None
        self.cached_venvs = []
        self.cached_processes = []
        self.leak_filter_var = None
        self.venv_checkboxes = {}

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
        self.sidebar_frame.grid_rowconfigure(10, weight=1)

        # Logo / Título
        self.logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="🛡️ NETSHIELD\n& DISK PRO",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#38bdf8"
        )
        self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 16))

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
        ]

        for idx, (view_id, text) in enumerate(views, start=1):
            btn = ctk.CTkButton(
                self.sidebar_frame,
                text=text,
                anchor="w",
                font=ctk.CTkFont(size=13, weight="bold"),
                height=38,
                corner_radius=8,
                fg_color="transparent",
                text_color="#94a3b8",
                hover_color="#1e293b",
                command=lambda v=view_id: self.show_view(v)
            )
            btn.grid(row=idx, column=0, padx=14, pady=3, sticky="ew")
            self.nav_buttons[view_id] = btn

        # Versión e información inferior
        self.version_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="v1.1.0 • Python 3.14\nProtección Local Activa",
            font=ctk.CTkFont(size=11),
            text_color="#64748b"
        )
        self.version_label.grid(row=11, column=0, padx=20, pady=16)

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
            "processes": self._create_processes_view()
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


def launch():
    """Función de entrada para arrancar la aplicación."""
    app = ModernApp()
    app.mainloop()



if __name__ == "__main__":
    launch()
