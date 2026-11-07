import tkinter as tk
from tkinter import ttk
import subprocess
import threading
import time
import socket
import re
import csv
import os
import statistics
from datetime import datetime
from collections import deque

CREATE_NO_WINDOW = 0x08000000
ARCHIVO_LOG = "registro_incidentes_red.csv"


def obtener_gateway_local():
    """Detecta automáticamente la IP del router local en Windows."""
    try:
        salida = subprocess.check_output("ipconfig", creationflags=CREATE_NO_WINDOW).decode("latin-1", errors="ignore")
        lineas = salida.splitlines()
        for i, linea in enumerate(lineas):
            if "Puerta de enlace" in linea or "Default Gateway" in linea:
                texto = linea + " " + (lineas[i + 1] if i + 1 < len(lineas) else "")
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", texto)
                if match:
                    return match.group(1)
    except Exception:
        pass
    return "192.168.1.1"


def detectar_ip_por_proceso(nombre_parcial):
    """Extrae la IP remota activa de un proceso en ejecución usando tasklist y netstat."""
    try:
        salida_tasks = subprocess.check_output(
            "tasklist /FO CSV /NH", creationflags=CREATE_NO_WINDOW
        ).decode("latin-1", errors="ignore")

        pids = set()
        for linea in salida_tasks.splitlines():
            partes = [p.strip('"') for p in linea.split('","')]
            if len(partes) >= 2 and nombre_parcial.lower() in partes[0].lower():
                pids.add(partes[1])

        if not pids:
            return None, f"Proceso '{nombre_parcial}' no encontrado."

        salida_net = subprocess.check_output(
            "netstat -ano", creationflags=CREATE_NO_WINDOW
        ).decode("latin-1", errors="ignore")

        ips_remotas = []
        for linea in salida_net.splitlines():
            columnas = linea.split()
            if len(columnas) >= 4 and columnas[-1] in pids:
                proto = columnas[0].upper()
                remoto = columnas[2]
                match_ip = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$", remoto)
                if match_ip:
                    ip, puerto = match_ip.group(1), int(match_ip.group(2))
                    if not ip.startswith(("127.", "0.", "192.168.", "10.", "172.16.")):
                        ips_remotas.append((ip, puerto, proto))

        if not ips_remotas:
            return None, "Proceso sin conexiones remotas activas."

        ips_remotas.sort(key=lambda x: x[1], reverse=True)
        ip_elegida, puerto_elegido, proto_elegido = ips_remotas[0]
        return ip_elegida, f"Conectado: {ip_elegida}:{puerto_elegido} ({proto_elegido})"
    except Exception as e:
        return None, f"Error: {e}"


def medir_icmp(ip):
    """Mide latencia mediante paquete ICMP Echo."""
    try:
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
        res = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW, text=True, encoding="latin-1"
        )
        match = re.search(r"(?:tiempo|time)[=<](\d+)\s*ms", res.stdout, re.IGNORECASE)
        return int(match.group(1)) if match else None
    except Exception:
        return None


def medir_tcp_socket(host, puerto=443, timeout=1.0):
    """Mide latencia mediante TCP Handshake (evita bloqueos de Firewall ICMP)."""
    try:
        inicio = time.perf_counter()
        with socket.create_connection((host, puerto), timeout=timeout):
            fin = time.perf_counter()
            return int((fin - inicio) * 1000)
    except Exception:
        return None


class NodoTelemetria:
    def __init__(self, nombre, host, modo="ICMP", puerto_tcp=443, ventana=60):
        self.nombre = nombre
        self.host = host
        self.modo = modo
        self.puerto_tcp = puerto_tcp
        self.historial = deque(maxlen=ventana)
        self.ultimo_ping = None

    def sondear(self):
        ms = medir_tcp_socket(self.host, self.puerto_tcp) if self.modo == "TCP" else medir_icmp(self.host)
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


class NetScopeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetScope Agent v2.0 | Multi-Layer Network & SLA Telemetry")
        self.root.geometry("820x560")
        self.root.configure(bg="#0f172a")
        self.root.resizable(False, False)

        gateway = obtener_gateway_local()
        self.nodos = {
            "router": NodoTelemetria("1. Gateway Local (LAN)", gateway, "ICMP"),
            "isp": NodoTelemetria("2. Salida ISP (Cloudflare)", "1.1.1.1", "ICMP"),
            "target": NodoTelemetria("3. Servidor Destino / Cloud", "dynamodb.sa-east-1.amazonaws.com", "TCP", 443)
        }

        self.widgets = {}
        self.ejecutando = True
        self._inicializar_csv()
        self._construir_ui()

        threading.Thread(target=self._loop_telemetria, daemon=True).start()

    def _inicializar_csv(self):
        if not os.path.exists(ARCHIVO_LOG):
            with open(ARCHIVO_LOG, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Nodo", "Host", "Modo", "Ping_ms", "Jitter_ms", "Packet_Loss_Pct", "Evento"])

    def _registrar_incidente_csv(self, nodo, ping, jitter, loss, evento):
        try:
            with open(ARCHIVO_LOG, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    nodo.nombre, nodo.host, nodo.modo,
                    ping, f"{jitter:.2f}", f"{loss:.1f}", evento
                ])
        except Exception:
            pass

    def _construir_ui(self):
        tk.Label(
            self.root, text="NETSCOPE // AGENTE DE TELEMETRÍA Y AUDITORÍA DE RED",
            font=("Segoe UI", 13, "bold"), bg="#0f172a", fg="#f8fafc"
        ).pack(pady=(14, 4))

        frame_proc = tk.Frame(self.root, bg="#1e293b", padx=12, pady=8)
        frame_proc.pack(fill="x", padx=20, pady=4)

        tk.Label(frame_proc, text="Auto-Detectar Proceso:", font=("Segoe UI", 9, "bold"), bg="#1e293b", fg="#94a3b8").pack(side="left")
        self.entry_proceso = tk.Entry(frame_proc, font=("Consolas", 10), bg="#0f172a", fg="#38bdf8", insertbackground="white", width=18)
        self.entry_proceso.insert(0, "FortniteClient")
        self.entry_proceso.pack(side="left", padx=8)

        tk.Button(
            frame_proc, text="Escanear Socket Activo", font=("Segoe UI", 9, "bold"),
            bg="#0284c7", fg="white", relief="flat", command=self._accion_escanear_proceso
        ).pack(side="left", padx=4)

        self.lbl_status_scan = tk.Label(frame_proc, text="Listo para escanear", font=("Segoe UI", 8), bg="#1e293b", fg="#cbd5e1")
        self.lbl_status_scan.pack(side="left", padx=10)

        frame_target = tk.Frame(self.root, bg="#1e293b", padx=12, pady=8)
        frame_target.pack(fill="x", padx=20, pady=4)

        tk.Label(frame_target, text="Host / IP Destino:", font=("Segoe UI", 9, "bold"), bg="#1e293b", fg="#94a3b8").pack(side="left")
        self.entry_host = tk.Entry(frame_target, font=("Consolas", 10), bg="#0f172a", fg="#10b981", insertbackground="white", width=30)
        self.entry_host.insert(0, self.nodos["target"].host)
        self.entry_host.pack(side="left", padx=8)

        tk.Label(frame_target, text="Modo:", font=("Segoe UI", 9, "bold"), bg="#1e293b", fg="#94a3b8").pack(side="left")
        self.combo_modo = ttk.Combobox(frame_target, values=["TCP (Puerto 443)", "ICMP (Ping)"], state="readonly", width=15)
        self.combo_modo.current(0)
        self.combo_modo.pack(side="left", padx=6)

        tk.Button(
            frame_target, text="Aplicar y Reiniciar", font=("Segoe UI", 9, "bold"),
            bg="#4f46e5", fg="white", relief="flat", command=self._actualizar_destino
        ).pack(side="left", padx=6)

        frame_cards = tk.Frame(self.root, bg="#0f172a")
        frame_cards.pack(fill="both", expand=True, padx=20, pady=10)

        for idx, (clave, nodo) in enumerate(self.nodos.items()):
            card = tk.Frame(frame_cards, bg="#1e293b", bd=1, relief="solid", padx=14, pady=12)
            card.grid(row=0, column=idx, padx=8, sticky="nsew")
            frame_cards.grid_columnconfigure(idx, weight=1)

            tk.Label(card, text=nodo.nombre, font=("Segoe UI", 10, "bold"), bg="#1e293b", fg="#f8fafc").pack(anchor="w")
            lbl_host = tk.Label(card, text=f"{nodo.host} [{nodo.modo}]", font=("Consolas", 8), bg="#1e293b", fg="#94a3b8")
            lbl_host.pack(anchor="w", pady=(2, 10))

            lbl_ping = tk.Label(card, text="-- ms", font=("Segoe UI", 24, "bold"), bg="#1e293b", fg="#10b981")
            lbl_ping.pack(pady=4)

            lbl_loss = tk.Label(card, text="Packet Loss (60s): 0.0%", font=("Segoe UI", 10, "bold"), bg="#1e293b", fg="#e2e8f0")
            lbl_loss.pack(pady=2)

            lbl_jitter = tk.Label(card, text="Jitter: 0.0 ms", font=("Segoe UI", 9), bg="#1e293b", fg="#94a3b8")
            lbl_jitter.pack(pady=2)

            lbl_estado = tk.Label(card, text="SONDEANDO...", font=("Segoe UI", 9, "bold"), bg="#334155", fg="white", pady=5)
            lbl_estado.pack(fill="x", pady=(12, 0))

            self.widgets[clave] = {
                "host": lbl_host, "ping": lbl_ping,
                "loss": lbl_loss, "jitter": lbl_jitter, "estado": lbl_estado
            }

        self.lbl_veredicto = tk.Label(
            self.root, text="Analizando telemetría de capas...",
            font=("Segoe UI", 10, "bold"), bg="#0f172a", fg="#38bdf8", pady=8
        )
        self.lbl_veredicto.pack(fill="x", padx=20)

        tk.Label(
            self.root, text=f"Auditoría activa: Incidentes guardados automáticamente en '{ARCHIVO_LOG}'",
            font=("Segoe UI", 8), bg="#0f172a", fg="#64748b"
        ).pack(pady=(0, 10))

    def _accion_escanear_proceso(self):
        proc = self.entry_proceso.get().strip()
        if not proc:
            return
        ip, msg = detectar_ip_por_proceso(proc)
        self.lbl_status_scan.config(text=msg, fg="#38bdf8" if ip else "#f87171")
        if ip:
            self.entry_host.delete(0, tk.END)
            self.entry_host.insert(0, ip)
            self.combo_modo.current(1)
            self._actualizar_destino()

    def _actualizar_destino(self):
        nuevo_host = self.entry_host.get().strip()
        modo_sel = "TCP" if "TCP" in self.combo_modo.get() else "ICMP"
        if nuevo_host:
            self.nodos["target"].host = nuevo_host
            self.nodos["target"].modo = modo_sel
            for n in self.nodos.values():
                n.reiniciar()
            self.widgets["target"]["host"].config(text=f"{nuevo_host} [{modo_sel}]")

    def _loop_telemetria(self):
        while self.ejecutando:
            hilos = [threading.Thread(target=nodo.sondear) for nodo in self.nodos.values()]
            for t in hilos:
                t.start()
            for t in hilos:
                t.join()
            self.root.after(0, self._refrescar_ui)
            time.sleep(1)

    def _refrescar_ui(self):
        stats = {}
        for clave, nodo in self.nodos.items():
            ping, jitter, loss = nodo.estadisticas()
            stats[clave] = (ping, jitter, loss)
            w = self.widgets[clave]

            if ping == -1:
                w["ping"].config(text="TIMEOUT", fg="#ef4444")
                self._registrar_incidente_csv(nodo, -1, jitter, loss, "PACKET_TIMEOUT")
            else:
                color = "#10b981" if ping < 75 else ("#f59e0b" if ping < 140 else "#ef4444")
                w["ping"].config(text=f"{ping} ms", fg=color)

            w["loss"].config(text=f"Packet Loss (60s): {loss:.1f}%", fg="#ef4444" if loss > 0 else "#e2e8f0")
            w["jitter"].config(text=f"Jitter: {jitter:.1f} ms")

            if loss >= 2.0:
                w["estado"].config(text="PÉRDIDA DETECTADA", bg="#991b1b", fg="white")
            elif jitter > 15.0:
                w["estado"].config(text="JITTER ALTO", bg="#b45309", fg="white")
            else:
                w["estado"].config(text="ESTABLE (SLA OK)", bg="#065f46", fg="white")

        loss_lan, loss_isp, loss_target = stats["router"][2], stats["isp"][2], stats["target"][2]

        if loss_lan > 0 and loss_isp == 0 and loss_target == 0:
            txt = "INFO: El router descartó pings locales por priorización CPU (ICMP Rate Limit), pero Internet va al 100%."
            col = "#38bdf8"
        elif loss_lan > 1.0 and loss_isp > 1.0:
            txt = "FALLO DE RED LOCAL: Pérdida real entre tu PC y el router que afecta tu salida a Internet."
            col = "#ef4444"
        elif loss_isp > 1.0 and loss_lan == 0:
            txt = "INCIDENTE DEL PROVEEDOR (ISP): Red doméstica al 100%, pero el nodo nacional pierde paquetes."
            col = "#f59e0b"
        elif loss_target == 100.0 and loss_isp == 0:
            txt = "FIREWALL / TIMEOUT REMOTO: El destino bloquea ICMP o cayó la ruta. Cambia al modo TCP."
            col = "#a855f7"
        elif loss_target > 1.0 and loss_isp == 0:
            txt = "DEGRADACIÓN EN SERVIDOR / RUTA INTERNACIONAL: Casa e ISP en 0% loss. Problema exclusivo del destino."
            col = "#38bdf8"
        else:
            txt = "SLA 100% CUMPLIDO: 0% pérdida de paquetes y latencia estable en todas las capas."
            col = "#10b981"

        self.lbl_veredicto.config(text=txt, fg=col)


if __name__ == "__main__":
    root = tk.Tk()
    app = NetScopeApp(root)
    root.mainloop()