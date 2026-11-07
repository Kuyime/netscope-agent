import argparse
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from netscope_agent import obtener_gateway_local, NodoTelemetria

ESTADO_METRICAS = {}
LOCK = threading.Lock()


def bucle_sondeo_headless(nodos, intervalo):
    """Ejecuta el monitoreo continuo en segundo plano y actualiza las métricas."""
    while True:
        hilos = [threading.Thread(target=n.sondear) for n in nodos.values()]
        for t in hilos:
            t.start()
        for t in hilos:
            t.join()

        with LOCK:
            for clave, nodo in nodos.items():
                ping, jitter, loss = nodo.estadisticas()
                ESTADO_METRICAS[clave] = {
                    "host": nodo.host,
                    "modo": nodo.modo,
                    "ping": ping if ping != -1 else 0,
                    "up": 0 if ping == -1 else 1,
                    "jitter": round(jitter, 2),
                    "loss": round(loss, 2)
                }
        time.sleep(intervalo)


class PrometheusMetricsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/metrics":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found. Use /metrics\n")
            return

        lineas = [
            "# HELP netscope_up Estado de alcanzabilidad del nodo (1 = Online, 0 = Timeout)",
            "# TYPE netscope_up gauge",
            "# HELP netscope_latency_ms Latencia actual en milisegundos",
            "# TYPE netscope_latency_ms gauge",
            "# HELP netscope_jitter_ms Variacion de latencia (desviacion estandar 60s)",
            "# TYPE netscope_jitter_ms gauge",
            "# HELP netscope_packet_loss_percent Porcentaje de perdida de paquetes (ventana 60s)",
            "# TYPE netscope_packet_loss_percent gauge"
        ]

        with LOCK:
            for capa, datos in ESTADO_METRICAS.items():
                labels = f'layer="{capa}",target="{datos["host"]}",protocol="{datos["modo"]}"'
                lineas.append(f"netscope_up{{{labels}}} {datos['up']}")
                lineas.append(f"netscope_latency_ms{{{labels}}} {datos['ping']}")
                lineas.append(f"netscope_jitter_ms{{{labels}}} {datos['jitter']}")
                lineas.append(f"netscope_packet_loss_percent{{{labels}}} {datos['loss']}")

        cuerpo = ("\n".join(lineas) + "\n").encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def log_message(self, format, *args):
        return  # Silenciar logs HTTP en consola


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetScope Prometheus Exporter (Headless Agent)")
    parser.add_argument("--port", type=int, default=9100, help="Puerto HTTP para /metrics (default: 9100)")
    parser.add_argument("--target", type=str, default="dynamodb.sa-east-1.amazonaws.com", help="Host o IP de Capa 3")
    parser.add_argument("--mode", type=str, choices=["ICMP", "TCP"], default="TCP", help="Protocolo para Capa 3")
    parser.add_argument("--interval", type=int, default=1, help="Intervalo de sondeo en segundos")
    args = parser.parse_args()

    gateway = obtener_gateway_local()
    nodos_monitoreo = {
        "lan_gateway": NodoTelemetria("Gateway Local", gateway, "ICMP"),
        "isp_egress": NodoTelemetria("Salida ISP", "1.1.1.1", "ICMP"),
        "cloud_target": NodoTelemetria("Destino Cloud", args.target, args.mode, 443)
    }

    t = threading.Thread(target=bucle_sondeo_headless, args=(nodos_monitoreo, args.interval), daemon=True)
    t.start()

    servidor = HTTPServer(("0.0.0.0", args.port), PrometheusMetricsHandler)
    print(f"[*] NetScope Prometheus Exporter activo en http://localhost:{args.port}/metrics")
    print(f"[*] Monitoreando -> LAN: {gateway} | ISP: 1.1.1.1 | Target: {args.target} ({args.mode})")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Deteniendo agente...")
        servidor.server_close()