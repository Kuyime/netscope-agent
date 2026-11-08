import subprocess
import threading
import time
import socket
import re
import csv
import os
import sys
import json
import statistics
import webbrowser
from datetime import datetime
from collections import deque
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

CREATE_NO_WINDOW = 0x08000000
ARCHIVO_LOG = "registro_incidentes_red.csv"
PUERTO_WEB = 8765


# =====================================================================
# FUNCIONES DE RED Y DESCUBRIMIENTO DE BAJO NIVEL
# =====================================================================

def obtener_gateway_local():
    """Detecta automáticamente la IP del router (Puerta de enlace) en Windows."""
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


def obtener_ips_locales():
    """Devuelve todas las direcciones IPv4 locales de las interfaces de la PC."""
    ips = []
    try:
        salida = subprocess.check_output("ipconfig", creationflags=CREATE_NO_WINDOW).decode("latin-1", errors="ignore")
        for linea in salida.splitlines():
            if "IPv4" in linea or "Direcci" in linea:
                m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", linea)
                if m and not m.group(1).startswith("127."):
                    ips.append(m.group(1))
    except Exception:
        pass
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ips.append(s.getsockname()[0])
            s.close()
        except Exception:
            ips.append("127.0.0.1")
    return list(dict.fromkeys(ips))


def resolver_ip_remota(host):
    """Resuelve un dominio a su IPv4 real para mostrar hacia dónde van los paquetes."""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return host


def medir_icmp(host, timeout_ms=900, packet_size=32, source_ip="AUTO"):
    """Mide latencia por ICMP Echo con tamaño de paquete e IP de origen configurables."""
    try:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout_ms)), "-l", str(int(packet_size))]
        if source_ip and source_ip != "AUTO":
            cmd.extend(["-S", source_ip])
        cmd.append(host)

        res = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW, text=True, encoding="latin-1"
        )
        m = re.search(r"(?:tiempo|time)[=<](\d+)\s*ms", res.stdout, re.IGNORECASE)
        return (int(m.group(1)), 0) if m else (None, 0)
    except Exception:
        return None, 0


def medir_tcp_socket(host, puerto=443, timeout_ms=900, source_ip="AUTO"):
    """Mide latencia por TCP Handshake y obtiene el puerto efímero local real."""
    try:
        timeout_sec = max(0.2, float(timeout_ms) / 1000.0)
        source_addr = (source_ip, 0) if (source_ip and source_ip != "AUTO") else None
        t0 = time.perf_counter()
        with socket.create_connection((host, int(puerto)), timeout=timeout_sec, source_address=source_addr) as sock:
            t1 = time.perf_counter()
            local_port = sock.getsockname()[1]
            return int((t1 - t0) * 1000), local_port
    except Exception:
        return None, 0


def medir_udp_socket(host, puerto=53, timeout_ms=900, packet_size=32, source_ip="AUTO"):
    """Envía un datagrama UDP y verifica si el socket local canaliza sin error ICMP Unreachable."""
    try:
        timeout_sec = max(0.2, float(timeout_ms) / 1000.0)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_sec)
        if source_ip and source_ip != "AUTO":
            sock.bind((source_ip, 0))
        t0 = time.perf_counter()
        sock.connect((host, int(puerto)))
        local_port = sock.getsockname()[1]
        payload = b"X" * max(4, min(1472, int(packet_size)))
        sock.send(payload)
        t1 = time.perf_counter()
        sock.close()
        return max(1, int((t1 - t0) * 1000)), local_port
    except Exception:
        return None, 0


def leer_estadisticas_interfaz():
    """Lee el flujo total de bytes, paquetes y descartes de la tarjeta de red."""
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


def escanear_tabla_sockets():
    """Devuelve todas las conexiones activas con IP Origen, Puerto Origen, IP Destino, Puerto Destino, Protocolo y Proceso."""
    conexiones = []
    try:
        tasks_out = subprocess.check_output("tasklist /FO CSV /NH", creationflags=CREATE_NO_WINDOW).decode("latin-1", errors="ignore")
        mapa_pids = {}
        for linea in tasks_out.splitlines():
            partes = [p.strip('"') for p in linea.split('","')]
            if len(partes) >= 2:
                mapa_pids[partes[1]] = partes[0]

        net_out = subprocess.check_output("netstat -ano", creationflags=CREATE_NO_WINDOW).decode("latin-1", errors="ignore")
        ignorar = ("svchost.exe", "system", "searchhost.exe")

        for l in net_out.splitlines():
            cols = l.split()
            if len(cols) >= 4:
                proto = cols[0].upper()
                if proto not in ("TCP", "UDP"):
                    continue
                local_str = cols[1]
                remoto_str = cols[2]
                pid = cols[-1]
                estado = cols[3] if (proto == "TCP" and len(cols) >= 5) else "ACTIVO"

                proc = mapa_pids.get(pid, f"PID-{pid}")
                if proc.lower() in ignorar:
                    continue

                m_loc = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$", local_str)
                m_rem = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$", remoto_str)
                if m_loc and m_rem:
                    src_ip, src_port = m_loc.group(1), int(m_loc.group(2))
                    dst_ip, dst_port = m_rem.group(1), int(m_rem.group(2))
                    if not dst_ip.startswith(("127.", "0.", "192.168.", "10.", "169.254.")):
                        conexiones.append({
                            "proceso": proc.replace(".exe", ""),
                            "pid": pid,
                            "proto": proto,
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "estado": estado
                        })
    except Exception:
        pass
    return conexiones


# =====================================================================
# CLASE DE TELEMETRÍA (COMPATIBLE CON EXPORTER.PY Y WEB ENGINE)
# =====================================================================

class NodoTelemetria:
    _id_counter = 1

    def __init__(self, nombre, host, modo="ICMP", puerto_tcp=443, fijo=False, ventana=60,
                 source_ip="AUTO", packet_size=32, timeout_ms=900):
        self.id = NodoTelemetria._id_counter
        NodoTelemetria._id_counter += 1
        self.nombre = nombre
        self.host = host
        self.ip_resuelta = resolver_ip_remota(host)
        self.modo = modo.upper()
        self.puerto_tcp = int(puerto_tcp) if puerto_tcp else (443 if self.modo == "TCP" else 0)
        self.fijo = fijo
        self.source_ip = source_ip
        self.local_port = 0
        self.packet_size = int(packet_size)
        self.timeout_ms = int(timeout_ms)
        self.historial = deque(maxlen=ventana)
        self.ultimo_ping = None

    def sondear(self):
        if self.ip_resuelta == self.host and not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", self.host):
            self.ip_resuelta = resolver_ip_remota(self.host)

        if self.modo == "TCP":
            ms, lport = medir_tcp_socket(self.host, self.puerto_tcp, self.timeout_ms, self.source_ip)
        elif self.modo == "UDP":
            ms, lport = medir_udp_socket(self.host, self.puerto_tcp or 53, self.timeout_ms, self.packet_size, self.source_ip)
        else:
            ms, lport = medir_icmp(self.host, self.timeout_ms, self.packet_size, self.source_ip)

        self.ultimo_ping = ms
        self.local_port = lport
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

    def to_dict(self, default_local_ip):
        ping, jitter, loss = self.estadisticas()
        src_efectiva = default_local_ip if self.source_ip == "AUTO" else self.source_ip
        return {
            "id": self.id,
            "nombre": self.nombre,
            "host": self.host,
            "dst_ip": self.ip_resuelta,
            "dst_port": self.puerto_tcp,
            "src_ip": src_efectiva,
            "src_port": self.local_port,
            "modo": self.modo,
            "packet_size": self.packet_size,
            "timeout_ms": self.timeout_ms,
            "fijo": self.fijo,
            "ping": ping,
            "jitter": round(jitter, 1),
            "loss": round(loss, 1),
            "historial": [x if x is not None else -1 for x in self.historial]
        }


# =====================================================================
# ESTADO GLOBAL DEL SERVIDOR LOCAL
# =====================================================================

class EstadoMotor:
    def __init__(self):
        self.lock = threading.Lock()
        self.gateway = obtener_gateway_local()
        self.ips_locales = obtener_ips_locales()
        self.ip_primaria = self.ips_locales[0] if self.ips_locales else "192.168.1.10"
        self.pausado = False
        self.ejecutando = True
        self.targets = []
        self.trafico = {
            "down_str": "0.0 KB/s", "up_str": "0.0 KB/s",
            "pps_down": 0, "pps_up": 0,
            "discards": 0, "errors": 0
        }
        self._prev_net = None
        self._prev_time = None
        self._inicializar_csv()
        self.cargar_preset("Gaming & Redes LATAM")

    def _inicializar_csv(self):
        if not os.path.exists(ARCHIVO_LOG):
            with open(ARCHIVO_LOG, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Servicio", "IP_Origen", "IP_Destino", "Protocolo", "Ping_ms", "Jitter_ms", "Loss_Pct"])

    def registrar_incidente(self, t, ping, jitter, loss):
        try:
            with open(ARCHIVO_LOG, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                src = self.ip_primaria if t.source_ip == "AUTO" else t.source_ip
                writer.writerow([
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    t.nombre, f"{src}:{t.local_port}", f"{t.ip_resuelta}:{t.puerto_tcp}",
                    f"{t.modo} ({t.packet_size}B)", ping, f"{jitter:.1f}", f"{loss:.1f}"
                ])
        except Exception:
            pass

    def cargar_preset(self, preset):
        perfiles = {
            "Gaming & Redes LATAM": [
                ("Router Local (Gateway)", self.gateway, "ICMP", 0, True, 32),
                ("Salida ISP (Cloudflare)", "1.1.1.1", "ICMP", 0, True, 32),
                ("AWS São Paulo (BR)", "dynamodb.sa-east-1.amazonaws.com", "TCP", 443, False, 64),
                ("Valve / Steam Santiago", "scl.valve.net", "ICMP", 0, False, 64),
                ("Riot Games LATAM/BR", "104.160.152.3", "ICMP", 0, False, 64),
                ("Discord Gateway", "gateway.discord.gg", "TCP", 443, False, 64),
            ],
            "Cloud & DevOps": [
                ("Router Local (Gateway)", self.gateway, "ICMP", 0, True, 32),
                ("Cloudflare Edge", "1.1.1.1", "ICMP", 0, True, 32),
                ("AWS sa-east-1 (BR)", "dynamodb.sa-east-1.amazonaws.com", "TCP", 443, False, 64),
                ("Google Cloud Santiago", "34.176.0.1", "ICMP", 0, False, 64),
                ("GitHub Enterprise API", "api.github.com", "TCP", 443, False, 64),
                ("Google DNS Anycast", "8.8.8.8", "UDP", 53, False, 64),
            ],
            "Streaming & Creadores": [
                ("Router Local (Gateway)", self.gateway, "ICMP", 0, True, 32),
                ("Salida ISP Nacional", "1.1.1.1", "ICMP", 0, True, 32),
                ("Twitch Ingest Server", "live.twitch.tv", "TCP", 443, False, 128),
                ("TikTok LIVE Studio", "webcast.tiktok.com", "TCP", 443, False, 128),
                ("YouTube Live RTMP", "upload.youtube.com", "TCP", 443, False, 128),
            ]
        }
        lista = perfiles.get(preset, perfiles["Gaming & Redes LATAM"])
        with self.lock:
            self.targets = [
                NodoTelemetria(n, h, m, p, f, packet_size=sz)
                for (n, h, m, p, f, sz) in lista
            ]


MOTOR = EstadoMotor()


def bucle_monitoreo_fondo():
    while MOTOR.ejecutando:
        # 1. Actualizar ancho de banda de la interfaz
        est = leer_estadisticas_interfaz()
        ahora = time.time()
        if est and MOTOR._prev_net and MOTOR._prev_time:
            dt = ahora - MOTOR._prev_time
            if dt > 0:
                rx_kbs = max(0, est[0] - MOTOR._prev_net[0]) / dt / 1024.0
                tx_kbs = max(0, est[1] - MOTOR._prev_net[1]) / dt / 1024.0
                MOTOR.trafico["down_str"] = f"{rx_kbs / 1024.0:.2f} MB/s" if rx_kbs >= 1024 else f"{rx_kbs:.1f} KB/s"
                MOTOR.trafico["up_str"] = f"{tx_kbs / 1024.0:.2f} MB/s" if tx_kbs >= 1024 else f"{tx_kbs:.1f} KB/s"
                MOTOR.trafico["pps_down"] = int(max(0, est[2] - MOTOR._prev_net[2]) / dt)
                MOTOR.trafico["pps_up"] = int(max(0, est[3] - MOTOR._prev_net[3]) / dt)
                MOTOR.trafico["discards"] = est[4]
                MOTOR.trafico["errors"] = est[5]
        if est:
            MOTOR._prev_net = est
            MOTOR._prev_time = ahora

        # 2. Sondear todos los destinos en paralelo
        if not MOTOR.pausado:
            with MOTOR.lock:
                copia = list(MOTOR.targets)
            hilos = [threading.Thread(target=t.sondear) for t in copia]
            for h in hilos:
                h.start()
            for h in hilos:
                h.join()

            for t in copia:
                ping, jitter, loss = t.estadisticas()
                if ping == -1:
                    MOTOR.registrar_incidente(t, -1, jitter, loss)

        time.sleep(1)


# =====================================================================
# INTERFAZ WEB SPA EMBEBIDA (HTML5 + CSS GLASSMORPHISM + JS EN VIVO)
# =====================================================================

HTML_SPA = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetScope Web-Studio v5.0 | Local Network & Flow Telemetry</title>
<style>
  :root {
    --bg-base: #050811;
    --bg-surface: #0b1120;
    --bg-card: rgba(17, 25, 44, 0.85);
    --bg-input: #15203b;
    --border: #1e2d4a;
    --text-main: #f8fafc;
    --text-muted: #8b9bb4;
    --cyan: #0ea5e9;
    --purple: #a855f7;
    --emerald: #10b981;
    --amber: #f59e0b;
    --rose: #ef4444;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; user-select: none; }
  body { background: radial-gradient(circle at top right, #0f172a, var(--bg-base) 65%); color: var(--text-main); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }
  
  /* HEADER */
  .topbar { background: rgba(11, 17, 32, 0.9); backdrop-filter: blur(12px); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; z-index: 10; }
  .brand { display: flex; align-items: center; gap: 12px; }
  .logo-dot { width: 12px; height: 12px; border-radius: 50%; background: var(--cyan); box-shadow: 0 0 12px var(--cyan); animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(1.15); } }
  .brand-title { font-size: 18px; font-weight: 800; letter-spacing: 0.5px; background: linear-gradient(90deg, #38bdf8, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .badge-ver { background: #1e293b; color: #38bdf8; font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 6px; border: 1px solid #334155; }

  /* KPI RIBBON */
  .kpi-ribbon { display: flex; gap: 14px; align-items: center; }
  .kpi-pill { background: #111a2e; border: 1px solid var(--border); padding: 6px 14px; border-radius: 8px; display: flex; align-items: center; gap: 10px; font-family: 'Consolas', monospace; font-size: 12px; }
  .kpi-down { color: #38bdf8; font-weight: 700; }
  .kpi-up { color: #c084fc; font-weight: 700; }

  /* ACTIONS */
  .actions { display: flex; gap: 8px; }
  .btn { background: #1e293b; color: var(--text-main); border: 1px solid #334155; padding: 7px 14px; border-radius: 7px; font-size: 12px; font-weight: 600; cursor: pointer; transition: all 0.15s; display: inline-flex; align-items: center; gap: 6px; }
  .btn:hover { background: #334155; border-color: #475569; transform: translateY(-1px); }
  .btn-primary { background: linear-gradient(135deg, #0284c7, #2563eb); border: none; }
  .btn-primary:hover { background: linear-gradient(135deg, #0369a1, #1d4ed8); }
  .btn-emerald { background: linear-gradient(135deg, #059669, #10b981); border: none; }
  .btn-danger { background: rgba(239, 68, 68, 0.15); color: #f87171; border-color: rgba(239, 68, 68, 0.3); }
  .btn-danger:hover { background: rgba(239, 68, 68, 0.3); }

  /* MAIN LAYOUT */
  .layout { display: flex; flex: 1; overflow: hidden; }
  
  /* SIDEBAR */
  .sidebar { width: 290px; background: var(--bg-surface); border-right: 1px solid var(--border); padding: 18px; display: flex; flex-direction: column; gap: 18px; overflow-y: auto; }
  .nav-tabs { display: flex; flex-direction: column; gap: 6px; }
  .nav-btn { padding: 10px 14px; border-radius: 8px; font-size: 13px; font-weight: 600; color: var(--text-muted); background: transparent; border: 1px solid transparent; text-align: left; cursor: pointer; transition: 0.15s; display: flex; align-items: center; justify-content: space-between; }
  .nav-btn:hover { background: #131d33; color: white; }
  .nav-btn.active { background: rgba(14, 165, 233, 0.12); color: #38bdf8; border-color: rgba(14, 165, 233, 0.35); }

  .panel-box { background: #0f172a; border: 1px solid var(--border); border-radius: 10px; padding: 14px; display: flex; flex-direction: column; gap: 10px; }
  .panel-title { font-size: 11px; font-weight: 800; text-transform: uppercase; color: var(--cyan); letter-spacing: 0.8px; }
  .form-group { display: flex; flex-direction: column; gap: 4px; }
  .form-group label { font-size: 11px; color: var(--text-muted); font-weight: 600; }
  .input, .select { background: var(--bg-input); border: 1px solid #263859; color: white; padding: 7px 10px; border-radius: 6px; font-size: 12px; outline: none; width: 100%; }
  .input:focus, .select:focus { border-color: var(--cyan); }
  .row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }

  /* CONTENT AREA */
  .content { flex: 1; padding: 20px; overflow-y: auto; display: flex; flex-direction: column; gap: 16px; }
  .tab-view { display: none; flex-direction: column; gap: 16px; }
  .tab-view.active { display: flex; }

  /* CARDS GRID */
  .cards-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(330px, 1fr)); gap: 16px; }
  .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 16px; display: flex; flex-direction: column; gap: 10px; position: relative; transition: border-color 0.2s, box-shadow 0.2s; }
  .card.status-crit { border-color: var(--rose); box-shadow: 0 0 20px rgba(239, 68, 68, 0.12); }
  .card.status-warn { border-color: var(--amber); }
  .card-head { display: flex; justify-content: space-between; align-items: center; }
  .card-title { font-size: 14px; font-weight: 700; color: white; }
  .card-close { background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 14px; padding: 2px 6px; border-radius: 4px; }
  .card-close:hover { color: var(--rose); background: rgba(239,68,68,0.1); }

  /* ROUTE FLOW PILL (ORIGEN -> DESTINO) */
  .route-box { background: #090e1a; border: 1px solid #19253f; border-radius: 8px; padding: 8px 10px; display: flex; flex-direction: column; gap: 5px; font-family: 'Consolas', monospace; font-size: 11px; }
  .route-line { display: flex; align-items: center; justify-content: space-between; gap: 6px; }
  .ip-tag { color: #cbd5e1; background: #152238; padding: 2px 6px; border-radius: 4px; }
  .ip-dst { color: #38bdf8; font-weight: 700; }
  .proto-badge { padding: 2px 7px; border-radius: 4px; font-size: 10px; font-weight: 800; letter-spacing: 0.4px; }
  .proto-ICMP { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.3); }
  .proto-TCP { background: rgba(14, 165, 233, 0.15); color: #38bdf8; border: 1px solid rgba(14,165,233,0.3); }
  .proto-UDP { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168,85,247,0.3); }

  /* METRICS ROW */
  .metrics-row { display: flex; justify-content: space-between; align-items: flex-end; margin-top: 2px; }
  .ping-big { font-size: 28px; font-weight: 800; font-family: 'Segoe UI', sans-serif; line-height: 1; }
  .sub-metrics { text-align: right; font-size: 12px; display: flex; flex-direction: column; gap: 2px; }

  /* SPARKLINE SVG */
  .spark-container { background: #070b14; border: 1px solid #17223b; border-radius: 6px; height: 48px; width: 100%; overflow: hidden; position: relative; }
  .sla-bar { font-size: 11px; font-weight: 700; text-align: center; padding: 5px; border-radius: 6px; letter-spacing: 0.5px; }
  .sla-ok { background: rgba(16, 185, 129, 0.15); color: #34d399; }
  .sla-warn { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
  .sla-crit { background: rgba(239, 68, 68, 0.25); color: #f87171; }

  /* SOCKET TABLE */
  .table-wrap { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; text-align: left; }
  th { background: #111a2e; color: var(--text-muted); font-weight: 700; text-transform: uppercase; font-size: 11px; padding: 12px 16px; border-bottom: 1px solid var(--border); }
  td { padding: 10px 16px; border-bottom: 1px solid #152038; font-family: 'Consolas', monospace; }
  tr:hover td { background: rgba(14, 165, 233, 0.05); }

  /* FOOTER */
  .footer { background: var(--bg-surface); border-top: 1px solid var(--border); padding: 10px 24px; display: flex; justify-content: space-between; align-items: center; font-size: 13px; font-weight: 600; }
</style>
</head>
<body>

  <!-- BARRA SUPERIOR -->
  <div class="topbar">
    <div class="brand">
      <div class="logo-dot"></div>
      <span class="brand-title">NETSCOPE WEB-STUDIO</span>
      <span class="badge-ver">v5.0 LOCAL ENGINE</span>
    </div>

    <div class="kpi-ribbon">
      <div class="kpi-pill">
        <span>▼ BAJADA:</span>
        <span class="kpi-down" id="kpi-down">0.0 KB/s (0 pps)</span>
      </div>
      <div class="kpi-pill">
        <span>▲ SUBIDA:</span>
        <span class="kpi-up" id="kpi-up">0.0 KB/s (0 pps)</span>
      </div>
      <div class="kpi-pill" style="color: var(--text-muted);" id="kpi-err">
        Descartes: 0 | Errores: 0
      </div>
    </div>

    <div class="actions">
      <button class="btn" id="btn-pause" onclick="togglePause()">⏸ Pausar</button>
      <button class="btn" onclick="resetStats()">🧹 Limpiar Historial</button>
      <button class="btn" onclick="openCsv()">📂 Abrir CSV</button>
      <button class="btn btn-danger" onclick="shutdownApp()">⏻ Cerrar App</button>
    </div>
  </div>

  <!-- CUERPO PRINCIPAL -->
  <div class="layout">
    <!-- BARRA LATERAL -->
    <div class="sidebar">
      <div class="nav-tabs">
        <button class="nav-btn active" id="tabbtn-dash" onclick="switchTab('dash')">
          <span>📊 Panel de Telemetría</span>
          <span id="count-targets" class="badge-ver">6</span>
        </button>
        <button class="nav-btn" id="tabbtn-sockets" onclick="switchTab('sockets'); loadSockets();">
          <span>🔀 Inspector Origen ➔ Destino</span>
          <span class="badge-ver">LIVE</span>
        </button>
      </div>

      <!-- FILTRO Y PERFILES -->
      <div class="panel-box">
        <div class="panel-title">Filtro y Escenarios</div>
        <div class="form-group">
          <label>Filtrar por Nombre, IP o Protocolo:</label>
          <input type="text" id="filter-input" class="input" placeholder="Ej. AWS, UDP, 1.1.1.1..." oninput="renderCards()">
        </div>
        <div class="form-group">
          <label>Cargar Perfil Predefinido:</label>
          <select id="preset-select" class="select" onchange="changePreset()">
            <option value="Gaming & Redes LATAM">Gaming & Redes LATAM</option>
            <option value="Cloud & DevOps">Cloud & DevOps</option>
            <option value="Streaming & Creadores">Streaming & Creadores</option>
          </select>
        </div>
      </div>

      <!-- AGREGAR NODO CON AJUSTES DETALLADOS DE PROTOCOLO Y FLUJO -->
      <div class="panel-box">
        <div class="panel-title">Nuevo Sondeo Avanzado</div>
        <div class="form-group">
          <label>Nombre Identificador:</label>
          <input type="text" id="add-name" class="input" placeholder="Ej. Servidor Partida BR">
        </div>
        <div class="form-group">
          <label>IP / Interfaz Local de Salida (Origen):</label>
          <select id="add-src-ip" class="select">
            <option value="AUTO">Automática (Interfaz Principal)</option>
          </select>
        </div>
        <div class="form-group">
          <label>IP o Dominio Remoto (Destino):</label>
          <input type="text" id="add-host" class="input" placeholder="Ej. 18.228.10.5 o dominio.com">
        </div>
        <div class="row-2">
          <div class="form-group">
            <label>Protocolo:</label>
            <select id="add-proto" class="select">
              <option value="ICMP">ICMP (Ping)</option>
              <option value="TCP">TCP (Socket)</option>
              <option value="UDP">UDP (Datagram)</option>
            </select>
          </div>
          <div class="form-group">
            <label>Puerto Destino:</label>
            <input type="number" id="add-port" class="input" value="443">
          </div>
        </div>
        <div class="row-2">
          <div class="form-group">
            <label>Payload (Bytes):</label>
            <input type="number" id="add-size" class="input" value="64" min="8" max="1472">
          </div>
          <div class="form-group">
            <label>Timeout (ms):</label>
            <input type="number" id="add-timeout" class="input" value="900" min="200" max="5000">
          </div>
        </div>
        <button class="btn btn-emerald" style="width:100%; justify-content:center; margin-top:4px;" onclick="addCustomTarget()">
          ＋ Inyectar al Monitor en Vivo
        </button>
      </div>
    </div>

    <!-- ÁREA DE CONTENIDO -->
    <div class="content">
      <!-- VISTA 1: TARJETAS DE MONITOREO -->
      <div class="tab-view active" id="view-dash">
        <div class="cards-grid" id="cards-container"></div>
      </div>

      <!-- VISTA 2: INSPECTOR DE CONEXIONES (IP ORIGEN -> IP DESTINO) -->
      <div class="tab-view" id="view-sockets">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <h2 style="font-size:18px; font-weight:800;">Inspector de Flujo de Red (Origen ➔ Destino)</h2>
            <p style="font-size:12px; color:var(--text-muted);">Visualiza de qué IP y puerto local salen tus paquetes, qué protocolo usan y a qué servidor remoto llegan.</p>
          </div>
          <div style="display:flex; gap:10px;">
            <input type="text" id="sock-filter" class="input" style="width:220px;" placeholder="Filtrar proceso, IP o UDP/TCP..." oninput="renderSocketTable()">
            <button class="btn btn-primary" onclick="loadSockets()">🔄 Escanear Sockets Ahora</button>
          </div>
        </div>

        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Aplicación / Proceso</th>
                <th>Protocolo</th>
                <th>IP Origen (Tu Máquina)</th>
                <th>Dirección</th>
                <th>IP Destino (Servidor Remoto)</th>
                <th>Estado</th>
                <th>Acción</th>
              </tr>
            </thead>
            <tbody id="socket-tbody">
              <tr><td colspan="7" style="text-align:center; padding:24px; color:var(--text-muted);">Haz clic en "Escanear Sockets Ahora" para listar las conexiones activas.</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- FOOTER CON VEREDICTO INTELIGENTE -->
  <div class="footer">
    <div id="verdict-text" style="color: var(--cyan);">Analizando telemetría de red multicapa...</div>
    <div id="clock-text" style="color: var(--text-muted); font-family: 'Consolas', monospace;">--:--:--</div>
  </div>

<script>
  let stateData = { targets: [], trafico: {}, ips_locales: [], pausado: false };
  let socketsCache = [];
  let initializedIps = false;

  function switchTab(tab) {
    document.querySelectorAll('.tab-view').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
    document.getElementById('view-' + tab).classList.add('active');
    document.getElementById('tabbtn-' + tab).classList.add('active');
  }

  function buildSparklineSvg(historial) {
    const w = 300, h = 46;
    if (!historial || historial.length === 0) return `<svg width="100%" height="100%"></svg>`;
    const validos = historial.filter(v => v >= 0);
    const maxVal = Math.max(...validos, 100) * 1.15;
    const stepX = w / Math.max(1, 59);

    let pts = [];
    let lossBars = '';
    historial.forEach((val, idx) => {
      const x = (idx * stepX).toFixed(1);
      if (val < 0) {
        lossBars += `<line x1="${x}" y1="0" x2="${x}" y2="${h}" stroke="#ef4444" stroke-width="2.5" />`;
      } else {
        const y = Math.max(4, Math.min(h - 4, h - ((val / maxVal) * (h - 8)) - 4)).toFixed(1);
        pts.push(`${x},${y}`);
      }
    });

    const lastVal = validos.length ? validos[validos.length - 1] : 0;
    const strokeCol = lastVal < 70 ? '#10b981' : (lastVal < 140 ? '#f59e0b' : '#ef4444');
    const polyline = pts.length >= 2 ? `<polyline fill="none" stroke="${strokeCol}" stroke-width="2" points="${pts.join(' ')}" />` : '';

    return `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" width="100%" height="100%">
      <line x1="0" y1="${h/2}" x2="${w}" y2="${h/2}" stroke="#152238" stroke-dasharray="3,3" stroke-width="1" />
      ${polyline}
      ${lossBars}
    </svg>`;
  }

  function renderCards() {
    const container = document.getElementById('cards-container');
    const filter = (document.getElementById('filter-input').value || '').toLowerCase();
    document.getElementById('count-targets').innerText = stateData.targets.length;

    let html = '';
    stateData.targets.forEach(t => {
      const matchText = `${t.nombre} ${t.host} ${t.dst_ip} ${t.src_ip} ${t.modo}`.toLowerCase();
      if (filter && !matchText.includes(filter)) return;

      let statusClass = '';
      let slaClass = 'sla-ok';
      let slaText = 'FLUJO ESTABLE (SLA 100%)';
      let pingColor = '#10b981';

      if (t.ping === -1) {
        statusClass = 'status-crit';
        slaClass = 'sla-crit';
        slaText = 'TIMEOUT / PAQUETE PERDIDO';
        pingColor = '#ef4444';
      } else {
        if (t.ping >= 140) pingColor = '#ef4444';
        else if (t.ping >= 70) pingColor = '#f59e0b';

        if (t.loss >= 2.0) {
          statusClass = 'status-crit';
          slaClass = 'sla-crit';
          slaText = `PÉRDIDA DE PAQUETES (${t.loss}%)`;
        } else if (t.jitter > 15.0) {
          statusClass = 'status-warn';
          slaClass = 'sla-warn';
          slaText = `JITTER INESTABLE (${t.jitter} ms)`;
        }
      }

      const srcPortStr = t.src_port ? `:${t.src_port}` : '';
      const dstPortStr = t.dst_port ? `:${t.dst_port}` : '';
      const closeBtn = !t.fijo ? `<button class="card-close" onclick="deleteTarget(${t.id})" title="Eliminar">✕</button>` : '';

      html += `
      <div class="card ${statusClass}">
        <div class="card-head">
          <span class="card-title">${t.nombre}</span>
          <div style="display:flex; gap:6px; align-items:center;">
            <span class="proto-badge proto-${t.modo}">${t.modo} • ${t.packet_size}B</span>
            ${closeBtn}
          </div>
        </div>

        <div class="route-box">
          <div class="route-line">
            <span style="color:var(--text-muted);">DESDE (ORIGEN):</span>
            <span class="ip-tag">${t.src_ip}${srcPortStr}</span>
          </div>
          <div class="route-line">
            <span style="color:var(--text-muted);">HACIA (DESTINO):</span>
            <span class="ip-tag ip-dst" title="${t.host}">${t.dst_ip}${dstPortStr}</span>
          </div>
        </div>

        <div class="metrics-row">
          <div class="ping-big" style="color:${pingColor};">
            ${t.ping === -1 ? 'DROP' : t.ping + ' ms'}
          </div>
          <div class="sub-metrics">
            <span style="color:${t.loss > 0 ? '#ef4444' : '#e2e8f0'}; font-weight:700;">Loss (60s): ${t.loss}%</span>
            <span style="color:var(--text-muted);">Jitter: ${t.jitter} ms | T-Out: ${t.timeout_ms}ms</span>
          </div>
        </div>

        <div class="spark-container">
          ${buildSparklineSvg(t.historial)}
        </div>

        <div class="sla-bar ${slaClass}">${slaText}</div>
      </div>`;
    });

    container.innerHTML = html;
  }

  function updateVerdict() {
    let lossLan = 0, lossIsp = 0, worstExt = null, worstLoss = 0;
    stateData.targets.forEach(t => {
      if (t.nombre.includes('Router') || t.nombre.includes('Gateway')) lossLan = t.loss;
      else if (t.nombre.includes('ISP') || t.host === '1.1.1.1') lossIsp = t.loss;
      else if (t.loss > worstLoss) { worstLoss = t.loss; worstExt = t; }
    });

    const el = document.getElementById('verdict-text');
    if (lossLan > 0 && lossIsp === 0 && worstLoss === 0) {
      el.style.color = '#38bdf8';
      el.innerText = 'ℹ️ INFO: Tu router descartó pings locales por priorización CPU (ICMP Rate Limit), pero tu salida a Internet tiene 0% pérdida.';
    } else if (lossLan >= 2 && lossIsp >= 2) {
      el.style.color = '#ef4444';
      el.innerText = '⚠️ FALLO EN RED LOCAL: Pérdida entre tu PC y el router local que está cortando tu tráfico hacia Internet.';
    } else if (lossIsp >= 2 && lossLan === 0) {
      el.style.color = '#f59e0b';
      el.innerText = '🚨 INCIDENTE DEL ISP: Tu red local responde al 100%, pero el proveedor pierde paquetes en la salida nacional.';
    } else if (worstExt && worstLoss >= 2 && lossIsp === 0) {
      el.style.color = '#38bdf8';
      el.innerText = `🎯 RUTA / SERVIDOR EXTERNO: Tu casa e ISP están al 100% (0% loss). El problema ocurre en '${worstExt.nombre}' (${worstExt.dst_ip} - ${worstLoss}% Loss).`;
    } else {
      el.style.color = '#10b981';
      el.innerText = '✅ TELEMETRÍA GLOBAL ÓPTIMA: 0% pérdida de paquetes real entre tu IP local, tu ISP y los servidores remotos.';
    }
  }

  async function pollState() {
    try {
      const res = await fetch('/api/state');
      stateData = await res.json();

      document.getElementById('kpi-down').innerText = `${stateData.trafico.down_str} (${stateData.trafico.pps_down} pkts/s)`;
      document.getElementById('kpi-up').innerText = `${stateData.trafico.up_str} (${stateData.trafico.pps_up} pkts/s)`;
      document.getElementById('kpi-err').innerText = `Descartes: ${stateData.trafico.discards} | Errores: ${stateData.trafico.errors}`;
      document.getElementById('clock-text').innerText = stateData.hora;

      if (!initializedIps && stateData.ips_locales) {
        const sel = document.getElementById('add-src-ip');
        stateData.ips_locales.forEach(ip => {
          const opt = document.createElement('option');
          opt.value = ip;
          opt.innerText = `Interfaz Local (${ip})`;
          sel.appendChild(opt);
        });
        initializedIps = true;
      }

      renderCards();
      updateVerdict();
    } catch (e) {}
  }

  async function loadSockets() {
    const tbody = document.getElementById('socket-tbody');
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:#38bdf8;">Escaneando tabla de sockets de Windows...</td></tr>`;
    try {
      const res = await fetch('/api/sockets');
      socketsCache = await res.json();
      renderSocketTable();
    } catch (e) {}
  }

  function renderSocketTable() {
    const tbody = document.getElementById('socket-tbody');
    const q = (document.getElementById('sock-filter').value || '').toLowerCase();
    const filtrados = socketsCache.filter(s => `${s.proceso} ${s.proto} ${s.src_ip} ${s.dst_ip} ${s.dst_port}`.toLowerCase().includes(q));

    if (!filtrados.length) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:20px; color:var(--text-muted);">No se encontraron conexiones externas con ese filtro.</td></tr>`;
      return;
    }

    tbody.innerHTML = filtrados.map(s => `
      <tr>
        <td style="font-weight:700; color:white;">${s.proceso} <span style="color:var(--text-muted); font-weight:400;">(PID ${s.pid})</span></td>
        <td><span class="proto-badge proto-${s.proto}">${s.proto}</span></td>
        <td><span class="ip-tag">${s.src_ip}:${s.src_port}</span></td>
        <td style="color:var(--cyan); font-weight:800;">───►</td>
        <td><span class="ip-tag ip-dst">${s.dst_ip}:${s.dst_port}</span></td>
        <td style="color:var(--text-muted);">${s.estado}</td>
        <td>
          <button class="btn btn-primary" style="padding:4px 10px; font-size:11px;"
            onclick="monitorSocket('${s.proceso}', '${s.src_ip}', '${s.dst_ip}', ${s.dst_port}, '${s.proto}')">
            ＋ Monitorear Ruta
          </button>
        </td>
      </tr>
    `).join('');
  }

  async function monitorSocket(proc, srcIp, dstIp, dstPort, proto) {
    await fetch('/api/action', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        action: 'add',
        nombre: `${proc} (${proto})`,
        host: dstIp,
        modo: proto,
        puerto: dstPort,
        source_ip: srcIp,
        packet_size: 64,
        timeout_ms: 900
      })
    });
    switchTab('dash');
    pollState();
  }

  async function addCustomTarget() {
    const host = document.getElementById('add-host').value.trim();
    if (!host) return;
    const nombre = document.getElementById('add-name').value.trim() || host;
    const modo = document.getElementById('add-proto').value;
    const puerto = parseInt(document.getElementById('add-port').value) || 443;
    const size = parseInt(document.getElementById('add-size').value) || 64;
    const timeout = parseInt(document.getElementById('add-timeout').value) || 900;
    const srcIp = document.getElementById('add-src-ip').value;

    await fetch('/api/action', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        action: 'add', nombre, host, modo, puerto,
        source_ip: srcIp, packet_size: size, timeout_ms: timeout
      })
    });
    document.getElementById('add-name').value = '';
    document.getElementById('add-host').value = '';
    switchTab('dash');
    pollState();
  }

  async function deleteTarget(id) {
    await fetch('/api/action', { method: 'POST', body: JSON.stringify({ action: 'delete', id }) });
    pollState();
  }

  async function changePreset() {
    const preset = document.getElementById('preset-select').value;
    await fetch('/api/action', { method: 'POST', body: JSON.stringify({ action: 'preset', preset }) });
    pollState();
  }

  async function togglePause() {
    const res = await fetch('/api/action', { method: 'POST', body: JSON.stringify({ action: 'pause' }) });
    const d = await res.json();
    document.getElementById('btn-pause').innerText = d.pausado ? '▶ Reanudar' : '⏸ Pausar';
  }

  async function resetStats() {
    await fetch('/api/action', { method: 'POST', body: JSON.stringify({ action: 'reset' }) });
    pollState();
  }

  async function openCsv() {
    await fetch('/api/action', { method: 'POST', body: JSON.stringify({ action: 'csv' }) });
  }

  async function shutdownApp() {
    await fetch('/api/action', { method: 'POST', body: JSON.stringify({ action: 'shutdown' }) });
    window.close();
  }

  setInterval(pollState, 1000);
  pollState();
</script>
</body>
</html>
"""


# =====================================================================
# CONTROLADOR HTTP LOCAL (API + SPA + PROMETHEUS METRICS)
# =====================================================================

class NetScopeWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        ruta = urlparse(self.path).path

        if ruta == "/":
            cuerpo = HTML_SPA.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(cuerpo)))
            self.end_headers()
            self.wfile.write(cuerpo)

        elif ruta == "/api/state":
            with MOTOR.lock:
                lista_targets = [t.to_dict(MOTOR.ip_primaria) for t in MOTOR.targets]
            respuesta = {
                "hora": datetime.now().strftime("%H:%M:%S"),
                "pausado": MOTOR.pausado,
                "ips_locales": MOTOR.ips_locales,
                "trafico": MOTOR.trafico,
                "targets": lista_targets
            }
            cuerpo = json.dumps(respuesta).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(cuerpo)

        elif ruta == "/api/sockets":
            conexiones = escanear_tabla_sockets()
            cuerpo = json.dumps(conexiones).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(cuerpo)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        longitud = int(self.headers.get("Content-Length", 0))
        datos = json.loads(self.rfile.read(longitud).decode("utf-8")) if longitud > 0 else {}
        accion = datos.get("action")
        resp = {"ok": True}

        if accion == "add":
            nuevo = NodoTelemetria(
                nombre=datos.get("nombre", "Custom"),
                host=datos.get("host", "1.1.1.1"),
                modo=datos.get("modo", "ICMP"),
                puerto_tcp=datos.get("puerto", 443),
                fijo=False,
                source_ip=datos.get("source_ip", "AUTO"),
                packet_size=datos.get("packet_size", 64),
                timeout_ms=datos.get("timeout_ms", 900)
            )
            with MOTOR.lock:
                MOTOR.targets.append(nuevo)

        elif accion == "delete":
            id_borrar = datos.get("id")
            with MOTOR.lock:
                MOTOR.targets = [t for t in MOTOR.targets if t.id != id_borrar or t.fijo]

        elif accion == "preset":
            MOTOR.cargar_preset(datos.get("preset", "Gaming & Redes LATAM"))

        elif accion == "pause":
            MOTOR.pausado = not MOTOR.pausado
            resp["pausado"] = MOTOR.pausado

        elif accion == "reset":
            with MOTOR.lock:
                for t in MOTOR.targets:
                    t.reiniciar()

        elif accion == "csv":
            try:
                os.startfile(ARCHIVO_LOG)
            except Exception:
                pass

        elif accion == "shutdown":
            MOTOR.ejecutando = False
            threading.Thread(target=lambda: (time.sleep(0.4), os._exit(0)), daemon=True).start()

        cuerpo = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(cuerpo)

    def log_message(self, format, *args):
        return  # Silenciar logs de consola


def abrir_ventana_web_nativa(url):
    """Abre el dashboard local como una ventana de aplicación nativa sin barra de direcciones."""
    rutas_navegadores = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    for exe in rutas_navegadores:
        if os.path.exists(exe):
            try:
                subprocess.Popen([exe, f"--app={url}", "--window-size=1280,800"])
                return
            except Exception:
                pass
    webbrowser.open(url)


if __name__ == "__main__":
    hilo_mon = threading.Thread(target=bucle_monitoreo_fondo, daemon=True)
    hilo_mon.start()

    servidor = HTTPServer(("127.0.0.1", PUERTO_WEB), NetScopeWebHandler)
    url_local = f"http://127.0.0.1:{PUERTO_WEB}"
    abrir_ventana_web_nativa(url_local)

    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        os._exit(0)