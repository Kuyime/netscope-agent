# 🌐 NetScope Agent | Multi-Layer Network & SLA Telemetry

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-Exporter%20Ready-E6522C?logo=prometheus&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

**NetScope Agent** es una suite Open Source de observabilidad de red en tiempo real y auditoría de SLA (Service Level Agreement). Diseñada con un enfoque dual: provee una **interfaz gráfica de diagnóstico en vivo** para usuarios avanzados/gamers y un **exportador nativo de métricas para Prometheus** orientado a infraestructura empresarial (NOC/DevOps).

---

## 🚨 El Problema que Resuelve

Las pruebas de velocidad convencionales miden el ancho de banda máximo por protocolo TCP contra servidores locales del mismo proveedor (ISP), ocultando pérdidas de paquetes en enlaces internacionales o descartes silenciosos en equipos domésticos.

Un enlace puede registrar **500 Mbps simétricos y 4 ms de latencia local**, pero sufrir un **11% de pérdida de paquetes en el flujo de subida (Upload Packet Loss)** hacia servidores de aplicaciones o partidas en tiempo real alojados en otra región (como AWS `sa-east-1` en São Paulo). **NetScope** sondea simultáneamente las tres capas de red cada segundo para aislar el punto exacto de falla:

```text
+-------------------+        +------------------------+        +-----------------------+        +----------------------------+
|   Tu PC / Host    | ─────► |  Capa 1: LAN Gateway   | ─────► |  Capa 2: ISP Egress   | ─────► | Capa 3: Cloud / App Server |
| (NetScope Agent)  |  ICMP  |   Router (192.168.x.x) |  ICMP  |  Nacional (1.1.1.1)   |  TCP/  |  AWS / Socket de Partida   |
+-------------------+        +------------------------+        +-----------------------+  ICMP  +----------------------------+
```

---

## 🧠 Matriz de Correlación Automática

| Capa 1 (LAN) | Capa 2 (ISP) | Capa 3 (Destino) | Diagnóstico Automático de NetScope |
| :---: | :---: | :---: | :--- |
| `0% Loss` | `0% Loss` | `0% Loss` | **SLA 100% Cumplido:** Red estable en todos los tramos. |
| `>1% Loss` | `0% Loss` | `0% Loss` | **ICMP Rate Limiting (Falso Positivo):** La CPU del router descarta pings directos por priorización, pero el reenvío a Internet está limpio al 100%. |
| `>1% Loss` | `>1% Loss` | `>1% Loss` | **Fallo Físico / Red Local:** Problemas en Wi-Fi, cable Ethernet o saturación local del router. |
| `0% Loss` | `>1% Loss` | `>1% Loss` | **Incidente del Proveedor (ISP):** La red local opera sin errores, pero se pierden paquetes en la salida del operador. |
| `0% Loss` | `0% Loss` | `>1% Loss` | **Degradación de Ruta Internacional / Servidor:** Tu conexión e ISP funcionan correctamente; el problema reside en el peering internacional o en el servidor final. |

---

## ✨ Características Principales

* **Auto-Descubrimiento de Sockets por Proceso:** Escanea dinámicamente los procesos activos del sistema (`tasklist` + `netstat`) para extraer la IP y el puerto remoto exacto de cualquier aplicación o juego en curso sin configuración manual.
* **Sondeo Híbrido (ICMP + TCP Handshake):** Mide la latencia mediante sockets TCP (puerto 443) cuando los servidores de destino o balanceadores Cloud bloquean paquetes ICMP por políticas de Firewall.
* **Auditoría Automática en CSV:** Registra automáticamente cada corte o pérdida de paquetes (`Timestamp`, `Nodo`, `Host`, `Ping`, `Jitter`, `Packet Loss`) en `registro_incidentes_red.csv` como evidencia técnica ante proveedores.
* **Prometheus Exporter Nativo (`exporter.py`):** Modo silencioso (`--headless`) que expone métricas en `http://localhost:9100/metrics` listas para ser recolectadas por **Prometheus** y visualizadas en **Grafana**.
* **Cero Dependencias Externas:** Construido al 100% con la librería estándar de Python.

---

## 🚀 Uso Rápido

### 1. Modo Escritorio (GUI)
Descarga `NetScope_Agent_v2.exe` desde la sección **Releases** o ejecútalo con Python:
```bash
python netscope_agent.py
```

### 2. Modo Servidor / Empresa (Prometheus Exporter)
Ejecuta el agente silencioso indicando el servidor de destino y el protocolo:
```bash
python exporter.py --port 9100 --target dynamodb.sa-east-1.amazonaws.com --mode TCP
```

Ejemplo de salida expuesta en `http://localhost:9100/metrics`:
```text
# HELP netscope_up Estado de alcanzabilidad del nodo (1 = Online, 0 = Timeout)
# TYPE netscope_up gauge
netscope_up{layer="lan_gateway",target="192.168.100.1",protocol="ICMP"} 1
netscope_up{layer="isp_egress",target="1.1.1.1",protocol="ICMP"} 1
netscope_up{layer="cloud_target",target="dynamodb.sa-east-1.amazonaws.com",protocol="TCP"} 1
# HELP netscope_latency_ms Latencia actual en milisegundos
# TYPE netscope_latency_ms gauge
netscope_latency_ms{layer="lan_gateway",target="192.168.100.1",protocol="ICMP"} 1
netscope_latency_ms{layer="isp_egress",target="1.1.1.1",protocol="ICMP"} 5
netscope_latency_ms{layer="cloud_target",target="dynamodb.sa-east-1.amazonaws.com",protocol="TCP"} 54
# HELP netscope_packet_loss_percent Porcentaje de perdida de paquetes (ventana 60s)
# TYPE netscope_packet_loss_percent gauge
netscope_packet_loss_percent{layer="lan_gateway",target="192.168.100.1",protocol="ICMP"} 0.0
netscope_packet_loss_percent{layer="isp_egress",target="1.1.1.1",protocol="ICMP"} 0.0
netscope_packet_loss_percent{layer="cloud_target",target="dynamodb.sa-east-1.amazonaws.com",protocol="TCP"} 0.0
```

---

## 🛠️ Compilar el Ejecutable (`.exe`)

```bash
pip install pyinstaller
pyinstaller --noconsole --onefile --clean --name "NetScope_Agent_v2" netscope_agent.py
```
El ejecutable final se generará en `dist/NetScope_Agent_v2.exe`.

---

## 📄 Licencia
Distribuido bajo la licencia **MIT**.