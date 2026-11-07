import tkinter as tk
from tkinter import ttk
import subprocess
import threading
import time
import socket
import re
import csv
import os
import ctypes
import statistics
from datetime import datetime
from collections import deque

# Activar nitidez High-DPI en Windows para fuentes y gráficos definidos
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

CREATE_NO_WINDOW = 0x08000000
ARCHIVO_LOG = "registro_incidentes_red.csv"

# Paleta de colores estilo Cyberpunk / Datadog Dark
THEME = {
    "bg_main": "#070b14",
    "bg_panel": "#0d1322",
    "bg_card": "#11192c",
    "bg_input": "#17223b",
    "border": "#1e2d4a",
    "text_main": "#f8fafc",
    "text_muted": "#8b9bb4",
    "accent_blue": "#0ea5e9",
    "accent_hover": "#0284c7",
    "accent_purple": "#a855f7",
    "ok": "#10b981",
    "warn": "#f59e0b",
    "crit": "#ef4444",
}

PRESETS = {
    "Gaming & Redes LATAM": [
        {"nombre": "Router Local (LAN)", "host": "AUTO", "modo": "ICMP", "puerto": 0, "fijo": True},
        {"nombre": "Salida ISP Nacional", "host": "1.1.1.1", "modo": "ICMP", "puerto": 0, "fijo": True},
        {"nombre": "AWS São Paulo (BR)", "host": "dynamodb.sa-east-1.amazonaws.com", "modo": "TCP", "puerto": 443, "fijo": False},
        {"nombre": "Valve / Steam Chile", "host": "scl.valve.net", "modo": "ICMP", "puerto": 0, "fijo": False},
        {"nombre": "Riot Games LATAM/BR", "host": "104.160.152.3", "modo": "ICMP", "puerto": 0, "fijo": False},
        {"nombre": "Discord Gateway", "host": "gateway.discord.gg", "modo": "TCP", "puerto": 443, "fijo": False},
    ],
    "Cloud & DevOps": [
        {"nombre": "Router Local (LAN)", "host": "AUTO", "modo": "ICMP", "puerto": 0, "fijo": True},
        {"nombre": "Cloudflare Anycast", "host": "1.1.1.1", "modo": "ICMP", "puerto": 0, "fijo": True},
        {"nombre": "AWS sa-east-1 (BR)", "host": "dynamodb.sa-east-1.amazonaws.com", "modo": "TCP", "puerto": 443, "fijo": False},
        {"nombre": "Google Cloud Santiago", "host": "34.176.0.1", "modo": "ICMP", "puerto": 0, "fijo": False},
        {"nombre": "GitHub API Edge", "host": "api.github.com", "modo": "TCP", "puerto": 443, "fijo": False},
        {"nombre": "Google Public DNS", "host": "8.8.8.8", "modo": "ICMP", "puerto": 0, "fijo": False},
    ],
    "Streaming & Creadores": [
        {"nombre": "Router Local (LAN)", "host": "AUTO", "modo": "ICMP", "puerto": 0, "fijo": True},
        {"nombre": "Salida ISP Nacional", "host": "1.1.1.1", "modo": "ICMP", "puerto": 0, "fijo": True},
        {"nombre": "Twitch Ingest Server", "host": "live.twitch.tv", "modo": "TCP", "puerto": 443, "fijo": False},
        {"nombre": "TikTok LIVE Studio", "host": "webcast.tiktok.com", "modo": "TCP", "puerto": 443, "fijo": False},
        {"nombre": "YouTube Live RTMP", "host": "upload.youtube.com", "modo": "TCP", "puerto": 443, "fijo": False},
        {"nombre": "Discord Voice Edge", "host": "gateway.discord.gg", "modo": "TCP", "puerto": 443, "fijo": False},
    ]
}


def obtener_gateway_local():
    """Detecta automáticamente la puerta de enlace predeterminada en Windows."""
    try:
        salida = subprocess.check_output("ipconfig", creationflags=CREATE_NO_WINDOW).decode("latin-1", errors="ignore")
        lineas = salida.splitlines()
        for i, linea in enumerate(lineas):
            if "Puerta de enlace" in linea or "Default Gateway" in linea:
                texto = linea + " " + (lineas[i + 1] if i + 1 < len(lineas) else "")
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", texto)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return "192.168.1.1"


def medir_icmp(ip):
    """Mide latencia por paquete ICMP Echo."""
    try:
        cmd = ["ping", "-n", "1", "-w", "900", ip]
        res = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW, text=True, encoding="latin-1"
        )
        m = re.search(r"(?:tiempo|time)[=<](\d+)\s*ms", res.stdout, re.IGNORECASE)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def medir_tcp_socket(host, puerto=443, timeout=0.9):
    """Mide latencia abriendo un socket TCP."""
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, int(puerto)), timeout=timeout):
            t1 = time.perf_counter()
            return int((t1 - t0) * 1000)
    except Exception:
        return None


def leer_estadisticas_interfaz():
    """Obtiene bytes, paquetes y descartes de la tarjeta de red vía netstat -e."""
    try:
        salida = subprocess.check_output("netstat -e", creationflags=CREATE_NO_WINDOW).decode("latin-1", errors="ignore")
        datos = {}
        for l in salida.strip().splitlines():
            p = l.split()
            if len(p) >= 3:
                k = p[0].lower()
                if k in ["bytes", "bytes:"]:
                    datos["b_rx"], datos["b_tx"] = int(p[1]), int(p[2])
                elif "unicast" in k:
                    datos["p_rx"], datos["p_tx"] = int(p[-2]), int(p[-1])
                elif "discards" in k or "descartes" in k:
                    datos["disc"] = int(p[1]) + int(p[2])
                elif "errors" in k or "errores" in k:
                    datos["err"] = int(p[1]) + int(p[2])
        if "b_rx" in datos:
            return datos.get("b_rx", 0), datos.get("b_tx", 0), datos.get("p_rx", 0), datos.get("p_tx", 0), datos.get("disc", 0), datos.get("err", 0)
    except Exception:
        pass
    return None


def listar_conexiones_activas():
    """Escanea todos los procesos con conexiones remotas activas sin bloquear la UI."""
    resultados = []
    try:
        tasks_out = subprocess.check_output("tasklist /FO CSV /NH", creationflags=CREATE_NO_WINDOW).decode("latin-1", errors="ignore")
        mapa_pids = {}
        for linea in tasks_out.splitlines():
            partes = [p.strip('"') for p in linea.split('","')]
            if len(partes) >= 2:
                mapa_pids[partes[1]] = partes[0]

        net_out = subprocess.check_output("netstat -ano", creationflags=CREATE_NO_WINDOW).decode("latin-1", errors="ignore")
        vistos = set()
        ignorar = ("svchost.exe", "system", "msedgewebview2.exe", "searchhost.exe")

        for l in net_out.splitlines():
            cols = l.split()
            if len(cols) >= 4:
                pid = cols[-1]
                nombre_proc = mapa_pids.get(pid, "")
                if not nombre_proc or nombre_proc.lower() in ignorar:
                    continue
                proto = cols[0].upper()
                remoto = cols[2]
                m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$", remoto)
                if m:
                    ip, port = m.group(1), int(m.group(2))
                    if not ip.startswith(("127.", "0.", "192.168.", "10.", "172.16.", "169.254.")):
                        clave = (nombre_proc, ip)
                        if clave not in vistos:
                            vistos.add(clave)
                            nombre_limpio = nombre_proc.replace(".exe", "")
                            etiqueta = f"{nombre_limpio} ({ip}:{port} {proto})"
                            resultados.append((etiqueta, nombre_limpio, ip, port, proto))
    except Exception:
        pass
    resultados.sort(key=lambda x: x[0].lower())
    return resultados


class NodoTelemetria:
    """Clase compatible tanto con la interfaz gráfica como con exporter.py."""
    def __init__(self, nombre, host, modo="ICMP", puerto_tcp=443, fijo=False, ventana=60):
        self.nombre = nombre
        self.host = host
        self.modo = modo
        self.puerto_tcp = int(puerto_tcp) if puerto_tcp else 443
        self.fijo = fijo
        self.historial = deque(maxlen=ventana)
        self.ultimo_ping = None

    def sondear(self):
        if self.modo == "TCP":
            ms = medir_tcp_socket(self.host, self.puerto_tcp)
        else:
            ms = medir_icmp(self.host)
        self.ultimo_ping = ms
        self.historial.append(ms)
        return ms

    def estadisticas(self):
        if not self.historial:
            return 0, 0.0, 0.0
        validos = [x for x in self.historial if x is not None]
        perdidos = sum(1 for x in self.historial if x is None)
        loss_pct = (perdidos / len(self.historial)) * 100.0
        ping_act = self.ultimo_ping if self.ultimo_ping is not None else -1
        jitter = statistics.stdev(validos) if len(validos) > 1 else 0.0
        return ping_act, jitter, loss_pct

    def reiniciar(self):
        self.historial.clear()
        self.ultimo_ping = None


class BotonPlano(tk.Label):
    """Botón estilizado moderno con efecto hover suave sin bordes clásicos de Windows."""
    def __init__(self, parent, text, command, bg=THEME["accent_blue"], fg="white", hover_bg=THEME["accent_hover"], font=("Segoe UI", 9, "bold"), padx=12, pady=5):
        super().__init__(parent, text=text, bg=bg, fg=fg, font=font, padx=padx, pady=pady, cursor="hand2")
        self.bg_normal = bg
        self.bg_hover = hover_bg
        self.command = command
        self.bind("<Enter>", lambda e: self.config(bg=self.bg_hover))
        self.bind("<Leave>", lambda e: self.config(bg=self.bg_normal))
        self.bind("<Button-1>", lambda e: self.command() if self.command else None)


class NetScopeStudioApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetScope Studio v4.0 | Real-Time Network & SLA Telemetry")
        self.root.geometry("1220x760")
        self.root.minsize(1050, 660)
        self.root.configure(bg=THEME["bg_main"])

        self.gateway = obtener_gateway_local()
        self.targets = []
        self.card_widgets = {}
        self.procesos_detectados = {}
        self.ejecutando = True
        self.pausado = False
        self.siempre_visible = False

        # Variables de tráfico
        self.prev_traffic = None
        self.prev_time = None
        self.bw_down = "0.0 KB/s"
        self.bw_up = "0.0 KB/s"
        self.pps_down = "0 pps"
        self.pps_up = "0 pps"
        self.discards_info = "Descartes: 0 | Errores: 0"

        self._configurar_estilos_ttk()
        self._inicializar_csv()
        self._cargar_preset("Gaming & Redes LATAM")
        self._construir_interfaz()

        # Lanzar escaneo inicial de procesos activos y bucles de monitoreo
        self._escanear_apps_async()
        threading.Thread(target=self._bucle_sondeo, daemon=True).start()
        threading.Thread(target=self._bucle_trafico, daemon=True).start()

    def _configurar_estilos_ttk(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Dark.TCombobox",
            fieldbackground=THEME["bg_input"],
            background=THEME["bg_panel"],
            foreground=THEME["text_main"],
            arrowcolor=THEME["accent_blue"],
            bordercolor=THEME["border"],
            lightcolor=THEME["border"],
            darkcolor=THEME["border"]
        )
        style.map(
            "Dark.TCombobox",
            fieldbackground=[("readonly", THEME["bg_input"])],
            selectbackground=[("readonly", THEME["bg_input"])],
            selectforeground=[("readonly", THEME["text_main"])]
        )
        style.configure(
            "Dark.Vertical.TScrollbar",
            gripcount=0,
            background=THEME["bg_input"],
            darkcolor=THEME["bg_panel"],
            lightcolor=THEME["bg_panel"],
            troughcolor=THEME["bg_main"],
            bordercolor=THEME["bg_main"],
            arrowcolor=THEME["text_muted"]
        )

    def _inicializar_csv(self):
        if not os.path.exists(ARCHIVO_LOG):
            with open(ARCHIVO_LOG, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Servicio", "Host", "Protocolo", "Ping_ms", "Jitter_ms", "Loss_Pct", "Evento"])

    def _registrar_csv(self, t, ping, jitter, loss, evento):
        try:
            with open(ARCHIVO_LOG, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    t.nombre, t.host, f"{t.modo}:{t.puerto_tcp}",
                    ping, f"{jitter:.2f}", f"{loss:.1f}", evento
                ])
        except Exception:
            pass

    def _cargar_preset(self, nombre_preset):
        self.targets.clear()
        for item in PRESETS.get(nombre_preset, PRESETS["Gaming & Redes LATAM"]):
            host = self.gateway if item["host"] == "AUTO" else item["host"]
            self.targets.append(NodoTelemetria(item["nombre"], host, item["modo"], item["puerto"], item["fijo"]))

    def _construir_interfaz(self):
        # 1. BARRA SUPERIOR (HEADER + FLUJO DE PAQUETES EN TIEMPO REAL)
        top_bar = tk.Frame(self.root, bg=THEME["bg_panel"], padx=20, pady=12, highlightbackground=THEME["border"], highlightthickness=1)
        top_bar.pack(fill="x")

        brand = tk.Frame(top_bar, bg=THEME["bg_panel"])
        brand.pack(side="left")
        tk.Label(brand, text="NETSCOPE", font=("Segoe UI", 15, "bold"), fg=THEME["accent_blue"], bg=THEME["bg_panel"]).pack(side="left")
        tk.Label(brand, text="STUDIO v4.0", font=("Segoe UI", 9, "bold"), fg=THEME["text_main"], bg="#1e293b", padx=7, pady=2).pack(side="left", padx=8)

        # Indicadores de Tráfico de Red en Vivo
        net_ribbon = tk.Frame(top_bar, bg=THEME["bg_panel"])
        net_ribbon.pack(side="left", padx=30)

        self.lbl_down = tk.Label(net_ribbon, text="▼ BAJADA: 0.0 KB/s (0 pps)", font=("Consolas", 10, "bold"), fg="#38bdf8", bg="#111c33", padx=10, pady=4)
        self.lbl_down.pack(side="left", padx=5)

        self.lbl_up = tk.Label(net_ribbon, text="▲ SUBIDA: 0.0 KB/s (0 pps)", font=("Consolas", 10, "bold"), fg="#c084fc", bg="#1e1533", padx=10, pady=4)
        self.lbl_up.pack(side="left", padx=5)

        self.lbl_discards = tk.Label(net_ribbon, text="Descartes: 0 | Errores: 0", font=("Consolas", 9), fg=THEME["text_muted"], bg=THEME["bg_panel"], padx=8)
        self.lbl_discards.pack(side="left")

        # Botones de Acción Rápida a la Derecha
        quick_actions = tk.Frame(top_bar, bg=THEME["bg_panel"])
        quick_actions.pack(side="right")

        self.btn_pin = BotonPlano(quick_actions, "📌 Fijar Ventana", self._toggle_pin, bg="#1e293b", hover_bg="#334155")
        self.btn_pin.pack(side="left", padx=4)

        self.btn_pause = BotonPlano(quick_actions, "⏸ Pausar", self._toggle_pausa, bg="#1e293b", hover_bg="#334155")
        self.btn_pause.pack(side="left", padx=4)

        BotonPlano(quick_actions, "🧹 Limpiar", self._reiniciar_todo, bg="#1e293b", hover_bg="#334155").pack(side="left", padx=4)
        BotonPlano(quick_actions, "📂 Abrir CSV", self._abrir_csv, bg="#0f766e", hover_bg="#115e59").pack(side="left", padx=4)

        # 2. CUERPO CENTRAL (SIDEBAR + DASHBOARD DE TARJETAS)
        body = tk.Frame(self.root, bg=THEME["bg_main"])
        body.pack(fill="both", expand=True)

        # --- PANEL LATERAL IZQUIERDO (CONTROL INTEGRADO SIN VENTANAS EMERGENTES) ---
        sidebar = tk.Frame(body, bg=THEME["bg_panel"], width=290, padx=16, pady=14, highlightbackground=THEME["border"], highlightthickness=1)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        # Sección 1: Búsqueda y Perfiles
        tk.Label(sidebar, text="FILTRO Y PERFILES", font=("Segoe UI", 8, "bold"), fg=THEME["accent_blue"], bg=THEME["bg_panel"]).pack(anchor="w", pady=(0, 6))

        tk.Label(sidebar, text="Buscar en pantalla:", font=("Segoe UI", 8), fg=THEME["text_muted"], bg=THEME["bg_panel"]).pack(anchor="w")
        self.entry_filtro = tk.Entry(sidebar, font=("Segoe UI", 9), bg=THEME["bg_input"], fg="white", insertbackground="white", bd=0)
        self.entry_filtro.pack(fill="x", ipady=5, pady=(2, 10))
        self.entry_filtro.bind("<KeyRelease>", lambda e: self._reconstruir_cuadricula())

        tk.Label(sidebar, text="Perfil predefinido:", font=("Segoe UI", 8), fg=THEME["text_muted"], bg=THEME["bg_panel"]).pack(anchor="w")
        self.combo_preset = ttk.Combobox(sidebar, values=list(PRESETS.keys()), state="readonly", style="Dark.TCombobox", font=("Segoe UI", 9))
        self.combo_preset.current(0)
        self.combo_preset.pack(fill="x", pady=(2, 14))
        self.combo_preset.bind("<<ComboboxSelected>>", self._cambiar_preset)

        tk.Frame(sidebar, bg=THEME["border"], height=1).pack(fill="x", pady=8)

        # Sección 2: Escáner Inteligente de Juegos y Aplicaciones
        tk.Label(sidebar, text="DETECTOR DE JUEGOS Y APPS", font=("Segoe UI", 8, "bold"), fg=THEME["accent_blue"], bg=THEME["bg_panel"]).pack(anchor="w", pady=(4, 6))
        tk.Label(sidebar, text="Selecciona una app activa en red:", font=("Segoe UI", 8), fg=THEME["text_muted"], bg=THEME["bg_panel"]).pack(anchor="w")

        self.combo_apps = ttk.Combobox(sidebar, values=["Escaneando red..."], state="readonly", style="Dark.TCombobox", font=("Consolas", 8))
        self.combo_apps.current(0)
        self.combo_apps.pack(fill="x", pady=(2, 8))

        row_scan = tk.Frame(sidebar, bg=THEME["bg_panel"])
        row_scan.pack(fill="x", pady=(0, 14))
        BotonPlano(row_scan, "🔄 Refrescar Apps", self._escanear_apps_async, bg="#1e293b", hover_bg="#334155", padx=8, pady=4).pack(side="left", fill="x", expand=True, padx=(0, 4))
        BotonPlano(row_scan, "＋ Monitorear", self._agregar_app_seleccionada, bg=THEME["accent_blue"], hover_bg=THEME["accent_hover"], padx=8, pady=4).pack(side="right", fill="x", expand=True, padx=(4, 0))

        tk.Frame(sidebar, bg=THEME["border"], height=1).pack(fill="x", pady=8)

        # Sección 3: Agregar Servidor Manualmente (Integrado)
        tk.Label(sidebar, text="AGREGAR SERVIDOR MANUAL", font=("Segoe UI", 8, "bold"), fg=THEME["accent_blue"], bg=THEME["bg_panel"]).pack(anchor="w", pady=(4, 6))

        tk.Label(sidebar, text="Nombre del servicio:", font=("Segoe UI", 8), fg=THEME["text_muted"], bg=THEME["bg_panel"]).pack(anchor="w")
        self.ent_add_name = tk.Entry(sidebar, font=("Segoe UI", 9), bg=THEME["bg_input"], fg="white", insertbackground="white", bd=0)
        self.ent_add_name.pack(fill="x", ipady=4, pady=(2, 8))

        tk.Label(sidebar, text="IP o Dominio:", font=("Segoe UI", 8), fg=THEME["text_muted"], bg=THEME["bg_panel"]).pack(anchor="w")
        self.ent_add_host = tk.Entry(sidebar, font=("Consolas", 9), bg=THEME["bg_input"], fg="#38bdf8", insertbackground="white", bd=0)
        self.ent_add_host.pack(fill="x", ipady=4, pady=(2, 8))

        row_proto = tk.Frame(sidebar, bg=THEME["bg_panel"])
        row_proto.pack(fill="x", pady=(0, 10))

        col_m = tk.Frame(row_proto, bg=THEME["bg_panel"])
        col_m.pack(side="left", fill="x", expand=True, padx=(0, 4))
        tk.Label(col_m, text="Modo:", font=("Segoe UI", 8), fg=THEME["text_muted"], bg=THEME["bg_panel"]).pack(anchor="w")
        self.combo_add_modo = ttk.Combobox(col_m, values=["ICMP", "TCP"], state="readonly", style="Dark.TCombobox", width=8)
        self.combo_add_modo.current(0)
        self.combo_add_modo.pack(fill="x", pady=2)

        col_p = tk.Frame(row_proto, bg=THEME["bg_panel"])
        col_p.pack(side="right", fill="x", expand=True, padx=(4, 0))
        tk.Label(col_p, text="Puerto TCP:", font=("Segoe UI", 8), fg=THEME["text_muted"], bg=THEME["bg_panel"]).pack(anchor="w")
        self.ent_add_port = tk.Entry(col_p, font=("Consolas", 9), bg=THEME["bg_input"], fg="white", insertbackground="white", bd=0, width=8)
        self.ent_add_port.insert(0, "443")
        self.ent_add_port.pack(fill="x", ipady=3, pady=2)

        BotonPlano(sidebar, "＋ Agregar al Panel", self._agregar_manual, bg=THEME["ok"], hover_bg="#059669", pady=6).pack(fill="x", pady=(4, 10))

        # Notificación integrada (Toast sin ventanas emergentes)
        self.lbl_toast = tk.Label(sidebar, text="Sistema listo y monitoreando.", font=("Segoe UI", 8), fg=THEME["text_muted"], bg=THEME["bg_panel"], wraplength=250, justify="left")
        self.lbl_toast.pack(side="bottom", anchor="w", pady=4)

        # --- ZONA DERECHA: CUADRÍCULA DE TARJETAS CON GRÁFICOS ---
        right_area = tk.Frame(body, bg=THEME["bg_main"], padx=14, pady=12)
        right_area.pack(side="left", fill="both", expand=True)

        self.canvas = tk.Canvas(right_area, bg=THEME["bg_main"], bd=0, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(right_area, orient="vertical", command=self.canvas.yview, style="Dark.Vertical.TScrollbar")
        self.grid_frame = tk.Frame(self.canvas, bg=THEME["bg_main"])

        self.grid_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas_win = self.canvas.create_window((0, 0), window=self.grid_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.canvas_win, width=e.width))
        self.canvas.bind_all("<MouseWheel>", lambda e: self.canvas.yview_scroll(int(-1 * (e.delta / 120)), "units"))

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # 3. BARRA INFERIOR DE DIAGNÓSTICO AUTOMÁTICO
        footer = tk.Frame(self.root, bg=THEME["bg_panel"], padx=20, pady=10, highlightbackground=THEME["border"], highlightthickness=1)
        footer.pack(fill="x", side="bottom")

        self.lbl_veredicto = tk.Label(footer, text="Analizando capas de red en vivo...", font=("Segoe UI", 10, "bold"), fg=THEME["accent_blue"], bg=THEME["bg_panel"])
        self.lbl_veredicto.pack(side="left")

        self.lbl_reloj = tk.Label(footer, text="--:--:--", font=("Consolas", 9), fg=THEME["text_muted"], bg=THEME["bg_panel"])
        self.lbl_reloj.pack(side="right")

        self._reconstruir_cuadricula()

    def _notificar(self, texto, color=THEME["accent_blue"]):
        """Muestra avisos suaves en la barra lateral sin interrumpir al usuario."""
        self.lbl_toast.config(text=f"● {texto}", fg=color)

    def _reconstruir_cuadricula(self):
        for w in self.grid_frame.winfo_children():
            w.destroy()
        self.card_widgets.clear()

        filtro = self.entry_filtro.get().strip().lower()
        columnas = 3
        r, c = 0, 0

        for t in self.targets:
            if filtro and (filtro not in t.nombre.lower() and filtro not in t.host.lower()):
                continue

            card = tk.Frame(self.grid_frame, bg=THEME["bg_card"], padx=14, pady=12, highlightbackground=THEME["border"], highlightthickness=1)
            card.grid(row=r, column=c, padx=7, pady=7, sticky="nsew")
            self.grid_frame.grid_columnconfigure(c, weight=1)

            # Cabecera de la tarjeta
            header_c = tk.Frame(card, bg=THEME["bg_card"])
            header_c.pack(fill="x")

            tk.Label(header_c, text=t.nombre, font=("Segoe UI", 10, "bold"), fg=THEME["text_main"], bg=THEME["bg_card"], anchor="w").pack(side="left")

            if not t.fijo:
                btn_close = tk.Label(header_c, text="✕", font=("Segoe UI", 9, "bold"), fg=THEME["text_muted"], bg=THEME["bg_card"], cursor="hand2", padx=4)
                btn_close.pack(side="right")
                btn_close.bind("<Enter>", lambda e, b=btn_close: b.config(fg=THEME["crit"]))
                btn_close.bind("<Leave>", lambda e, b=btn_close: b.config(fg=THEME["text_muted"]))
                btn_close.bind("<Button-1>", lambda e, item=t: self._eliminar_servicio(item))

            # Subtítulo con IP clicable para copiar
            modo_txt = f"{t.modo}:{t.puerto_tcp}" if t.modo == "TCP" else "ICMP"
            lbl_host = tk.Label(card, text=f"{t.host} [{modo_txt}] 📋", font=("Consolas", 8), fg=THEME["text_muted"], bg=THEME["bg_card"], anchor="w", cursor="hand2")
            lbl_host.pack(fill="x", pady=(2, 8))
            lbl_host.bind("<Button-1>", lambda e, ip=t.host: self._copiar_ip(ip))

            # Fila Central: Ping Grande + Métricas de Loss/Jitter
            mid_c = tk.Frame(card, bg=THEME["bg_card"])
            mid_c.pack(fill="x", pady=2)

            lbl_ping = tk.Label(mid_c, text="-- ms", font=("Segoe UI", 22, "bold"), fg=THEME["ok"], bg=THEME["bg_card"])
            lbl_ping.pack(side="left")

            stats_c = tk.Frame(mid_c, bg=THEME["bg_card"])
            stats_c.pack(side="right")
            lbl_loss = tk.Label(stats_c, text="Loss: 0.0%", font=("Segoe UI", 9, "bold"), fg=THEME["text_main"], bg=THEME["bg_card"], anchor="e")
            lbl_loss.pack(anchor="e")
            lbl_jitter = tk.Label(stats_c, text="Jitter: 0.0 ms", font=("Segoe UI", 8), fg=THEME["text_muted"], bg=THEME["bg_card"], anchor="e")
            lbl_jitter.pack(anchor="e")

            # Gráfico Sparkline en tiempo real (60 muestras + barras rojas de Packet Loss)
            spark = tk.Canvas(card, bg="#090d16", height=42, bd=0, highlightthickness=1, highlightbackground="#1a263e")
            spark.pack(fill="x", pady=(8, 6))

            # Badge de estado SLA
            lbl_badge = tk.Label(card, text="SONDEANDO...", font=("Segoe UI", 8, "bold"), fg="white", bg="#1e293b", pady=3)
            lbl_badge.pack(fill="x")

            self.card_widgets[t] = {
                "card": card, "ping": lbl_ping, "loss": lbl_loss,
                "jitter": lbl_jitter, "spark": spark, "badge": lbl_badge
            }

            c += 1
            if c >= columnas:
                c = 0
                r += 1

        self._actualizar_ui()

    def _dibujar_sparkline(self, canvas, historial):
        """Dibuja la curva de latencia en vivo y marca con líneas rojas los paquetes perdidos."""
        canvas.delete("all")
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w <= 10:
            w = 240
        if h <= 10:
            h = 42

        # Línea guía intermedia sutil
        canvas.create_line(0, h // 2, w, h // 2, fill="#141e30", dash=(2, 2))

        muestras = list(historial)
        if not muestras:
            return

        max_ventana = 60
        paso_x = w / max(1, max_ventana - 1)
        validos = [x for x in muestras if x is not None]
        techo_ms = max(validos + [100]) * 1.15

        puntos_linea = []
        for idx, valor in enumerate(muestras):
            x = idx * paso_x
            if valor is None:
                # Barra vertical roja idéntica al indicador de Packet Loss de juegos competitivos
                canvas.create_line(x, 0, x, h, fill=THEME["crit"], width=2)
            else:
                y = h - int((valor / techo_ms) * (h - 8)) - 4
                y = max(3, min(h - 3, y))
                puntos_linea.extend([x, y])

        if len(puntos_linea) >= 4:
            color_curva = THEME["ok"] if (validos and validos[-1] < 80) else THEME["warn"]
            canvas.create_line(*puntos_linea, fill=color_curva, width=1.5, smooth=True)

    def _copiar_ip(self, ip):
        self.root.clipboard_clear()
        self.root.clipboard_append(ip)
        self._notificar(f"IP '{ip}' copiada al portapapeles.", THEME["ok"])

    def _eliminar_servicio(self, target):
        if target in self.targets:
            self.targets.remove(target)
            self._reconstruir_cuadricula()
            self._notificar(f"Servicio '{target.nombre}' eliminado.", THEME["text_muted"])

    def _cambiar_preset(self, event=None):
        nombre = self.combo_preset.get()
        self._cargar_preset(nombre)
        self._reconstruir_cuadricula()
        self._notificar(f"Perfil '{nombre}' cargado.", THEME["accent_blue"])

    def _escanear_apps_async(self):
        self._notificar("Buscando juegos y aplicaciones con red activa...", THEME["accent_blue"])

        def tarea():
            lista = listar_conexiones_activas()
            self.root.after(0, lambda: self._actualizar_combo_apps(lista))

        threading.Thread(target=tarea, daemon=True).start()

    def _actualizar_combo_apps(self, lista):
        self.procesos_detectados.clear()
        if not lista:
            self.combo_apps["values"] = ["Sin conexiones externas activas"]
            self.combo_apps.current(0)
            self._notificar("No se detectaron procesos externos activos.", THEME["warn"])
            return

        etiquetas = []
        for etiqueta, nombre_proc, ip, port, proto in lista:
            etiquetas.append(etiqueta)
            self.procesos_detectados[etiqueta] = (nombre_proc, ip, port, proto)

        self.combo_apps["values"] = etiquetas
        self.combo_apps.current(0)
        self._notificar(f"{len(etiquetas)} conexiones activas encontradas.", THEME["ok"])

    def _agregar_app_seleccionada(self):
        sel = self.combo_apps.get()
        if sel not in self.procesos_detectados:
            self._notificar("Primero selecciona una aplicación válida de la lista.", THEME["warn"])
            return

        nombre_proc, ip, port, proto = self.procesos_detectados[sel]
        modo = "TCP" if proto == "TCP" else "ICMP"
        nuevo = NodoTelemetria(f"App: {nombre_proc}", ip, modo, port, fijo=False)
        self.targets.append(nuevo)
        self._reconstruir_cuadricula()
        self._notificar(f"Monitoreando {nombre_proc} ({ip}).", THEME["ok"])

    def _agregar_manual(self):
        host = self.ent_add_host.get().strip()
        if not host:
            self._notificar("Ingresa una IP o dominio válido.", THEME["warn"])
            return
        nombre = self.ent_add_name.get().strip() or host
        modo = self.combo_add_modo.get()
        port_str = self.ent_add_port.get().strip()
        puerto = int(port_str) if port_str.isdigit() else 443

        self.targets.append(NodoTelemetria(nombre, host, modo, puerto, fijo=False))
        self.ent_add_name.delete(0, tk.END)
        self.ent_add_host.delete(0, tk.END)
        self._reconstruir_cuadricula()
        self._notificar(f"'{nombre}' agregado al panel.", THEME["ok"])

    def _toggle_pin(self):
        self.siempre_visible = not self.siempre_visible
        self.root.attributes("-topmost", self.siempre_visible)
        if self.siempre_visible:
            self.btn_pin.config(text="📌 Fijado (Activo)", bg=THEME["accent_blue"])
            self.btn_pin.bg_normal = THEME["accent_blue"]
            self._notificar("Ventana fijada sobre los demás programas.", THEME["accent_blue"])
        else:
            self.btn_pin.config(text="📌 Fijar Ventana", bg="#1e293b")
            self.btn_pin.bg_normal = "#1e293b"
            self._notificar("Modo siempre visible desactivado.", THEME["text_muted"])

    def _toggle_pausa(self):
        self.pausado = not self.pausado
        if self.pausado:
            self.btn_pause.config(text="▶ Reanudar", bg=THEME["warn"])
            self.btn_pause.bg_normal = THEME["warn"]
            self._notificar("Sondeo en pausa.", THEME["warn"])
        else:
            self.btn_pause.config(text="⏸ Pausar", bg="#1e293b")
            self.btn_pause.bg_normal = "#1e293b"
            self._notificar("Sondeo reanudado.", THEME["ok"])

    def _reiniciar_todo(self):
        for t in self.targets:
            t.reiniciar()
        self._actualizar_ui()
        self._notificar("Historial y gráficas reiniciados.", THEME["accent_blue"])

    def _abrir_csv(self):
        try:
            os.startfile(ARCHIVO_LOG)
            self._notificar("Abriendo registro CSV...", THEME["ok"])
        except Exception:
            self._notificar("El archivo CSV se encuentra en la carpeta del programa.", THEME["text_muted"])

    def _bucle_trafico(self):
        while self.ejecutando:
            actual = leer_estadisticas_interfaz()
            ahora = time.time()
            if actual and self.prev_traffic and self.prev_time:
                dt = ahora - self.prev_time
                if dt > 0:
                    rx_kbs = max(0, actual[0] - self.prev_traffic[0]) / dt / 1024.0
                    tx_kbs = max(0, actual[1] - self.prev_traffic[1]) / dt / 1024.0
                    rx_pps = int(max(0, actual[2] - self.prev_traffic[2]) / dt)
                    tx_pps = int(max(0, actual[3] - self.prev_traffic[3]) / dt)

                    self.bw_down = f"{rx_kbs / 1024.0:.2f} MB/s" if rx_kbs >= 1024 else f"{rx_kbs:.1f} KB/s"
                    self.bw_up = f"{tx_kbs / 1024.0:.2f} MB/s" if tx_kbs >= 1024 else f"{tx_kbs:.1f} KB/s"
                    self.pps_down = f"{rx_pps} pkts/s"
                    self.pps_up = f"{tx_pps} pkts/s"
                    self.discards_info = f"Descartes NIC: {actual[4]} | Errores: {actual[5]}"

            if actual:
                self.prev_traffic = actual
                self.prev_time = ahora
            time.sleep(1)

    def _bucle_sondeo(self):
        while self.ejecutando:
            if not self.pausado:
                copia = list(self.targets)
                hilos = [threading.Thread(target=t.sondear) for t in copia]
                for h in hilos:
                    h.start()
                for h in hilos:
                    h.join()
                self.root.after(0, self._actualizar_ui)
            time.sleep(1)

    def _actualizar_ui(self):
        self.lbl_reloj.config(text=datetime.now().strftime("%H:%M:%S"))
        self.lbl_down.config(text=f"▼ BAJADA: {self.bw_down} ({self.pps_down})")
        self.lbl_up.config(text=f"▲ SUBIDA: {self.bw_up} ({self.pps_up})")
        self.lbl_discards.config(text=self.discards_info)

        loss_lan = 0.0
        loss_isp = 0.0
        peor_externo = None
        peor_loss_ext = 0.0

        for t, w in list(self.card_widgets.items()):
            ping, jitter, loss = t.estadisticas()

            if "Router" in t.nombre or "LAN" in t.nombre:
                loss_lan = loss
            elif "ISP" in t.nombre or "Cloudflare" in t.nombre:
                loss_isp = loss
            else:
                if loss > peor_loss_ext:
                    peor_loss_ext = loss
                    peor_externo = t

            if ping == -1:
                w["ping"].config(text="TIMEOUT", fg=THEME["crit"])
                self._registrar_csv(t, -1, jitter, loss, "PACKET_DROP")
            else:
                col_p = THEME["ok"] if ping < 65 else (THEME["warn"] if ping < 135 else THEME["crit"])
                w["ping"].config(text=f"{ping} ms", fg=col_p)

            w["loss"].config(text=f"Loss: {loss:.1f}%", fg=THEME["crit"] if loss > 0 else THEME["text_main"])
            w["jitter"].config(text=f"Jitter: {jitter:.1f} ms")

            self._dibujar_sparkline(w["spark"], t.historial)

            if loss >= 2.0:
                w["badge"].config(text="PÉRDIDA DE PAQUETES DETECTADA", bg="#991b1b")
                w["card"].config(highlightbackground=THEME["crit"])
            elif jitter > 15.0:
                w["badge"].config(text="JITTER / LATENCIA INESTABLE", bg="#b45309")
                w["card"].config(highlightbackground=THEME["warn"])
            elif ping == -1:
                w["badge"].config(text="SIN RESPUESTA (FIREWALL / CAÍDO)", bg="#7f1d1d")
                w["card"].config(highlightbackground=THEME["crit"])
            else:
                w["badge"].config(text="CONEXIÓN ESTABLE (SLA OK)", bg="#065f46")
                w["card"].config(highlightbackground=THEME["border"])

        # Diagnóstico global inteligente correlacionando capas
        if loss_lan > 0 and loss_isp == 0 and peor_loss_ext == 0:
            self.lbl_veredicto.config(
                text="ℹ️ INFO: Tu router descartó pings locales por priorización CPU (ICMP Rate Limit), pero tu salida a Internet va al 100%.",
                fg=THEME["accent_blue"]
            )
        elif loss_lan >= 2.0 and loss_isp >= 2.0:
            self.lbl_veredicto.config(
                text="⚠️ ALERTA DE RED LOCAL: Pérdida entre tu PC y el router que está afectando tu salida a Internet.",
                fg=THEME["crit"]
            )
        elif loss_isp >= 2.0 and loss_lan == 0:
            self.lbl_veredicto.config(
                text="🚨 INCIDENTE DEL PROVEEDOR (ISP): Tu router responde al 100%, pero la salida nacional pierde paquetes.",
                fg=THEME["warn"]
            )
        elif peor_externo and peor_loss_ext >= 2.0 and loss_isp == 0:
            self.lbl_veredicto.config(
                text=f"🎯 PROBLEMA DE SERVIDOR / RUTA EXTERNA: Tu casa e ISP tienen 0% pérdida. Fallo aislado en '{peor_externo.nombre}' ({peor_loss_ext:.1f}% Loss).",
                fg=THEME["accent_blue"]
            )
        else:
            self.lbl_veredicto.config(
                text="✅ TELEMETRÍA ÓPTIMA: 0% pérdida de paquetes real y flujo estable en todas las capas.",
                fg=THEME["ok"]
            )


if __name__ == "__main__":
    root = tk.Tk()
    app = NetScopeStudioApp(root)
    root.mainloop()