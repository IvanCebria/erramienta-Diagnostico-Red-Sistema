# Importamos todas las librerías necesarias
import streamlit as st 


import numpy as np
import pandas as pd
import plotly.express as px
import plotly.io as pio
import plotly.graph_objects as go
import time
from pythonping import ping
import psutil
import datetime
import subprocess
import re
import platform
import socket
import ipaddress
import hashlib
import requests
import zeroconf 
import logging 
import json
from concurrent.futures import ThreadPoolExecutor
try:
    from zoneinfo import ZoneInfo
except ImportError: ZoneInfo = None

# --- Configuración de Página ---
st.set_page_config(
    layout="wide", page_title="Diagnóstico Red Pro", page_icon="🌐", initial_sidebar_state="expanded"
)

# --- Función para Cargar CSS desde archivo ---
def load_css_from_file(file_path):
    try:
        with open(file_path) as f: st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError: st.error(f"Error: Archivo CSS '{file_path}' no encontrado.")

load_css_from_file("style.css") 

# --- Configuración App (Constantes) ---
USUARIOS_VALIDOS = { "Ivan123": "Ivan123", "Marcos123": "Marcos123" }
LATENCIA_RAPIDA_MS = 80; LATENCIA_ACEPTABLE_MS = 200; PERDIDA_PAQUETES_MAX_PERMITIDA = 0.5
PING_TIMEOUT_SCAN = 0.2; VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/"
PUERTOS_COMUNES_TCP = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5900, 8080, 8443]
PORT_SCAN_TIMEOUT = 0.5; MAX_WORKERS_PORT_SCAN = 20
TASA_ALTA_BPS = 1 * 1024 * 1024; TASA_MUY_ALTA_BPS = 10 * 1024 * 1024; TASA_BAJA_BPS = 5 * 1024
GB = 1024**3 

# --- Diccionario de Descripciones de Puertos ---
try: 
    from diccionario import PORT_DATA
except ImportError: PORT_DATA = { 
        21: "FTP", 22: "SSH/SFTP", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
        139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB/CIFS", 993: "IMAPS", 995: "POP3S", 1433: "MS SQL",
        1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP Alt", 8443: "HTTPS Alt"
    }

# --- Funciones ---

# --- Función Auxiliar: Obtener Información Local ---
def obtener_info_local_simple():
    local_ips = set() # Conjunto para guardar IPs (evita duplicados)
    local_macs = set() # Conjunto para guardar MACs
    try:
        interfaces = psutil.net_if_addrs()
        for name, snics in interfaces.items():
            for snic in snics:
                if snic.family == socket.AF_INET:
                    local_ips.add(snic.address)
                elif snic.family == psutil.AF_LINK:
                    mac = snic.address.upper().replace('-',':')
                    if mac and mac != "00:00:00:00:00:00":
                         local_macs.add(mac)
    except Exception as e:
        st.warning(f"No se pudo obtener toda la info local: {e}", icon="⚠️")
    return local_ips, local_macs

# --- Función Auxiliar: Resolver Hostname vía mDNS/Zeroconf ---
def resolver_hostname_mdns(ip_address, timeout=1):
    hostname = None 
    zc = None 
    try:
        zc = zeroconf.Zeroconf(unicast=True)
        reverse_name = ipaddress.ip_address(ip_address).reverse_pointer + "."
        q = zeroconf.DNSQuestion(reverse_name, zeroconf.DNSQuestionType.PTR, zeroconf.DNSQuestionClass.IN)
        record = zc.get_record(q.name, q.type, timeout=timeout*1000)
        zc.close()
        zc = None 
        if record and isinstance(record, zeroconf.DNSPointer):
             hostname_local = str(record.alias).rstrip('.')
             if hostname_local.lower().endswith(".local"):
                  hostname = hostname_local[:-6]
             else:
                  hostname = hostname_local 
    except ImportError:
        if 'zeroconf_warning_shown' not in st.session_state:
            st.warning("Librería 'zeroconf' no instalada. No se puede usar mDNS.", icon="⚠️")
            st.session_state.zeroconf_warning_shown = True
        return None
    except NameError:
         if 'zeroconf_warning_shown' not in st.session_state:
             st.warning("Librería 'zeroconf' no disponible. No se puede usar mDNS.", icon="⚠️")
             st.session_state.zeroconf_warning_shown = True
         return None
    except Exception as e:
        hostname = None
    finally:
        if zc:
            try:
                zc.close()
            except: 
                pass
    return hostname


# --- Función Auxiliar: Generar Sugerencias de Tráfico ---
def sugerir_solucion_tasa(tasa_bps):
    causa = "" 
    accion = "**Estado:** Considerado **Normal** para actividad ligera o moderada."
    if not isinstance(tasa_bps, (int, float)) or not np.isfinite(tasa_bps):
        return {'causa': "Valor de tasa inválido.", 'accion': "Verificar datos de origen."}
    tasa_mbps = tasa_bps / (1024*1024)
    tasa_kbps = tasa_bps / 1024
    if tasa_bps > TASA_MUY_ALTA_BPS: 
        causa = (f"**Actividad MUY INTENSA** ({tasa_mbps:.1f} MB/s).\n"
                 f"* Común durante: Descargas/subidas P2P, backups cloud masivos, streaming 4K/8K (múltiple), servidor local activo (Plex, etc.), transferencias grandes, actualizaciones de juegos/SO.\n"
                 f"* Posible proceso inesperado/malicioso.")
        accion = ("**Pasos de Diagnóstico:**\n"
                  f"* **Identificar Proceso:** Abra el Administrador de Tareas (Ctrl+Shift+Esc) o Monitor de Actividad (Mac) y ordene por columna 'Red' para ver qué aplicación consume más.\n"
                  f"* **¿Esperado?:** Si es una descarga, backup, etc., considere pausarlo si interfiere con otras tareas o déjelo terminar.\n"
                  f"* **¿Desconocido?:** Busque el nombre del proceso en internet. Si sospecha de malware, use la pestaña 'Analizar Archivo (VT)' si puede localizar el ejecutable, o realice un escaneo completo con su antivirus.\n"
                  f"* **Otros Dispositivos:** Verifique si otros dispositivos en la red están realizando tareas de alto consumo (puede requerir acceso al router).\n"
                  f"* **Persistencia:** Si la tasa alta es constante e inexplicable, podría indicar un problema de hardware o configuración; considere consultar a soporte técnico/ISP.")
    elif tasa_bps > TASA_ALTA_BPS:
        causa = (f"**Actividad CONSIDERABLE** ({tasa_mbps:.1f} MB/s).\n"
                 f"* Común durante: Navegación web activa (vídeos, muchas pestañas), streaming de video HD, videollamadas, juegos online, sincronización cloud (OneDrive, Drive, etc.), actualizaciones en segundo plano.")
        accion = ("**Evaluación:**\n"
                  f"* **Normal durante uso activo.**\n"
                  f"* **Si ocurre en reposo:** Verifique actualizaciones silenciosas (Windows Update, etc.), sincronización cloud activa, o escaneos de antivirus en segundo plano.")
    elif tasa_bps < TASA_BAJA_BPS and tasa_bps >= 0: 
        causa = (f"**Actividad MUY BAJA o NULA** ({tasa_kbps:.1f} KB/s).")
        accion = ("**Evaluación:**\n"
                  f"* **Normal si el equipo está inactivo** o sin tareas de red.\n"
                  f"* **Si esperaba tráfico** (ej. descarga lenta, web no carga) y la tasa es persistentemente muy baja, podría indicar:\n"
                  f"    1.  **Problema Conectividad General:** Use la pestaña 'Ping' para probar con 8.8.8.8. Si falla, reinicie router/módem, revise cables/WiFi, contacte ISP.\n"
                  f"    2.  **Problema Conectividad Local:** Use 'Ping' hacia su router (gateway). Si falla, revise conexión PC-Router.\n"
                  f"    3.  **Limitación de Velocidad:** ¿ISP aplica límites? ¿La app usada tiene límite?\n"
                  f"    4.  **Problema App/Servidor Remoto:** ¿El servicio/web funciona lento? ¿Fuente lenta?\n"
                  f"    5.  **Firewall/Antivirus:** ¿Podrían estar interfiriendo?")
    else: 
        causa = f"Tasa Total: {tasa_bps:,.0f} B/s (aprox. {tasa_mbps:.2f} MB/s)."
    return {'causa': causa, 'accion': accion}



# --- Función Auxiliar: Crear Gráfico Monitor Tráfico ---
def crear_grafico_plotly_tasa(datos_monitor):
    if not datos_monitor: return None
    try:
        df = pd.DataFrame(datos_monitor)
        required_cols = ['segundo', 'tasa_sent_bps', 'tasa_recv_bps', 'tasa_total_bps', 'estado_umbral']
        if not all(col in df.columns for col in required_cols):
             st.error("Datos incompletos para generar gráfico."); return None 
        for col in ['tasa_sent_bps', 'tasa_recv_bps', 'tasa_total_bps']:
             df[col] = pd.to_numeric(df[col], errors='coerce')
        df.fillna(0, inplace=True)
        df.rename(columns={'segundo': 'Segundo'}, inplace=True) 
        df['Sugerencia_Dict'] = df['tasa_total_bps'].apply(sugerir_solucion_tasa)
        df['Sugerencia_Hover'] = df['Sugerencia_Dict'].apply(
             lambda x: x.get('causa','').replace('\n','<br>') + "<br><hr>" + x.get('accion','').replace('\n','<br>')
        )
        color_map_estado = {
            "Normal": "#2ecc71", # Verde
            "ALTA": "#f1c40f",   # Amarillo
            "MUY ALTA": "#e74c3c", # Rojo
            "MUY BAJA": "#3498db", # Azul
            "Indeterminado": "#95a5a6", # Gris
            "Normal (o Baja)": "#2ecc71", # Verde
            "Baja/Normal (Sin Delta)": "#2ecc71" # Verde
        }
        df['marker_color'] = df['estado_umbral'].map(color_map_estado).fillna('#95a5a6') 
        # Crear la figura base de Plotly Graph Objects
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df['Segundo'], y=df['tasa_sent_bps'], mode='lines', name='Enviado',
            line=dict(color='#0d6efd', width=2), 
            hoverinfo='none' 
        ))
        fig.add_trace(go.Scatter(
            x=df['Segundo'], y=df['tasa_recv_bps'], mode='lines', name='Recibido',
            line=dict(color='#198754', width=2), 
            hoverinfo='none'
        ))
        fig.add_trace(go.Scatter(
            x=df['Segundo'], y=df['tasa_total_bps'], mode='lines', name='Total (Ref.)',
            line=dict(color='#adb5bd', width=1, dash='dot'), 
            hoverinfo='none'
        ))
        fig.add_trace(go.Scatter(
            x=df['Segundo'], y=df['tasa_total_bps'],
            mode='markers', 
            marker=dict(
                color=df['marker_color'], 
                size=7,                   
                line=dict(width=1, color='rgba(128,128,128,0.6)') 
            ),
            name='Estado/Detalle', 
            customdata=df[['tasa_sent_bps', 'tasa_recv_bps', 'tasa_total_bps', 'estado_umbral', 'Sugerencia_Hover']],
            hovertemplate=(
                "<b>Seg: %{x} | Estado: %{customdata[3]}</b><br>"
                "--------------------<br>"
                "Total: %{customdata[2]:,.0f} B/s<br>"
                "Enviado: %{customdata[0]:,.0f} B/s<br>"
                "Recibido: %{customdata[1]:,.0f} B/s<br><hr>"
                "<b>Info:</b><br>%{customdata[4]}"
                "<extra></extra>"
            )
        ))
        fig.add_hline(y=TASA_ALTA_BPS, line_dash="dash", line_color="orange", annotation_text="Umbral Alto")
        fig.add_hline(y=TASA_MUY_ALTA_BPS, line_dash="dash", line_color="red", annotation_text="Umbral Muy Alto")
        fig.update_layout(
            title='Actividad de Red Local',
            xaxis_title="Tiempo (s)",
            yaxis_title="Tasa (Bytes/s)",
            hovermode='closest', 
            title_x=0.5, 
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
        )
        max_total = df['tasa_total_bps'].max()
        max_val_data = max_total if pd.notna(max_total) else 0
        max_for_scale = max(max_val_data, TASA_MUY_ALTA_BPS) 
        if max_for_scale > 0:
            escala = 'log' if max_for_scale > 100000 else 'linear'
            fig.update_yaxes(type=escala, title_text=f"Tasa (B/s) - Escala {escala.capitalize()}")
            if escala == 'log':
                 min_val_log = df[df['tasa_total_bps'] > 0]['tasa_total_bps'].min()
                 range_min = max(min_val_log * 0.5, 100) if pd.notna(min_val_log) else 100 
                 range_max = max(max_val_data * 1.5, TASA_MUY_ALTA_BPS * 1.5)
                 if pd.notna(range_min) and pd.notna(range_max) and range_min > 0 and range_max > range_min:
                       try: fig.update_yaxes(range=[np.log10(range_min), np.log10(range_max)])
                       except ValueError: pass 
        return fig 
    except Exception as e:
        st.error(f"Error al generar gráfico: {e}")
        return None


# --- Función Auxiliar: Ejecutar Ping ---
def realizar_ping(host, count=1, timeout=PING_TIMEOUT_SCAN):
    try:
        return ping(host, count=count, timeout=timeout, verbose=False)
    except PermissionError:
        return None
    except Exception as e:
        return None


# --- Función Auxiliar: Obtener Red Local ---
def obtener_red_local():
    try:
        interfaces = psutil.net_if_addrs(); stats = psutil.net_if_stats()
        for name, snics in interfaces.items():
            if stats[name].isup and not name.lower().startswith('lo'):
                for snic in snics:
                    if snic.family == socket.AF_INET:
                        ip = snic.address
                        netmask = snic.netmask
                        if ip and netmask and not ip.startswith("169.254"):
                            try: network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False);
                            except ValueError: continue 
                            if network.is_private:
                                return network 
        st.warning("No se pudo determinar la red local automáticamente.")
        return None
    except Exception as e:
        st.error(f"Error obteniendo info de red: {e}") 
        return None

# --- Función Auxiliar: Escanear Red Local con ARP ---
def escanear_red_local_arp(active_scan=False):
    dispositivos = [] 
    comando = ['arp', '-a'] 
    sistema_operativo = platform.system().lower()
    red_local = None 
    if active_scan:
        status_ping_placeholder = st.empty()
        prog_bar_ping = st.progress(0)
        red_local = obtener_red_local()
        if red_local:
            status_ping_placeholder.info(f"Realizando ping sweep en {red_local} (puede tardar)...")
            ips_a_pingear = list(red_local.hosts()) 
            total_a_pingear = len(ips_a_pingear); hosts_vivos = 0
            if total_a_pingear == 0: total_a_pingear = 1 
            for i, host_ip_obj in enumerate(ips_a_pingear):
                if (i + 1) % 20 == 0: status_ping_placeholder.info(f"Pingeando {i+1}/{total_a_pingear}...")
                ping_res = realizar_ping(str(host_ip_obj), count=1, timeout=PING_TIMEOUT_SCAN) 
                if ping_res and ping_res.success: hosts_vivos += 1
                prog_bar_ping.progress((i + 1) / total_a_pingear)
            status_ping_placeholder.success(f"Ping sweep finalizado. {hosts_vivos} hosts respondieron (leyendo ARP).")
            prog_bar_ping.empty(); time.sleep(1.5); status_ping_placeholder.empty()
        else:
             st.warning("No se pudo determinar la red local para el escaneo activo.")
    try:
        encoding_usar = 'utf-8' if sistema_operativo != "windows" else 'cp850'
        proceso = subprocess.run(comando, capture_output=True, text=True, check=False, encoding=encoding_usar, errors='ignore', timeout=10) 
        if proceso.returncode != 0 and sistema_operativo == "windows":
             encoding_usar = 'cp1252'; proceso = subprocess.run(comando, capture_output=True, text=True, check=False, encoding=encoding_usar, errors='ignore', timeout=10)
        if proceso.returncode != 0: st.error(f"Error al ejecutar 'arp -a'. Código: {proceso.returncode}. Stderr: {proceso.stderr}"); return []
        salida = proceso.stdout 
        regex_linux_mac = r'(?:(?:\w+|\?)\s+\()(\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:-]+)'
        regex_windows = r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+'
        if sistema_operativo == "windows":
            bloques = re.split(r'Interface:.*', salida)
            for bloque in bloques:
                 for linea in bloque.strip().split('\n'):
                     match = re.match(regex_windows, linea.strip())
                     if match:
                         ip = match.group(1); mac = match.group(2).upper().replace('-',':')
                         if not ip.endswith('.255') and not ip.startswith('224.'):
                            try:
                                ip_addr = ipaddress.ip_address(ip) 
                                if red_local is None or ip_addr in red_local:
                                    dispositivos.append({"IP": ip, "MAC": mac, "Tipo": "N/A"})
                            except ValueError: continue 
        else: 
            for match in re.finditer(regex_linux_mac, salida):
                ip = match.group(1); mac = match.group(2).upper()
                if not ip.endswith('.255') and not ip.startswith('224.'):
                    try:
                        ip_addr = ipaddress.ip_address(ip) 
                        if red_local is None or ip_addr in red_local:
                            dispositivos.append({"IP": ip, "MAC": mac, "Tipo": "ether"})
                    except ValueError: continue 
        vistos = set(); dispositivos_unicos = []
        for d in dispositivos:
            if d['MAC'] not in vistos and d['MAC'] != 'FF:FF:FF:FF:FF:FF':
                dispositivos_unicos.append(d); vistos.add(d['MAC'])
        return dispositivos_unicos
    except subprocess.TimeoutExpired: st.error("'arp -a' tardó demasiado en responder."); return []
    except FileNotFoundError: st.error("Error: Comando 'arp' no encontrado."); return []
    except Exception as e: st.error(f"Error inesperado escaneando ARP: {e}"); return []


# --- Función Auxiliar: Obtener Fabricante por MAC ---
def obtener_fabricante_mac(mac_address):
    if not isinstance(mac_address, str) or len(mac_address) < 17:
        return "MAC Inválida" 
    try:
        time.sleep(0.6)
        mac_clean = mac_address.upper().replace(':','')
        url = f"https://api.maclookup.app/v2/macs/{mac_clean}"
        headers = {'Accept': 'application/json'}
        response = requests.get(url, timeout=5, headers=headers)
        if response.status_code == 200: 
            data = response.json() 
            return data.get("vendor", "No encontrado") if data.get("found") else "No Encontrado"
        elif response.status_code == 404: 
            return "No encontrado"
        elif response.status_code == 429: 
            return "Límite API"
        else: 
            return f"Error API ({response.status_code})"
    except requests.exceptions.Timeout:
        return "Timeout API"
    except Exception:
        return "Error Consulta"


# --- Función Auxiliar: Crear Tarjeta HTML para Métricas ---
def create_metric_card(title, value, key_suffix=""):
    display_value = "N/A" 
    if value is not None:
        if isinstance(value, float) and not np.isfinite(value):
            display_value = "∞"
        elif isinstance(value, (float, int)) and np.isfinite(value):
            if isinstance(value, float):
                if "Perdidos" in title:
                    display_value = f"{value:.1%}"
                elif "Mbps" in title:
                    display_value = f"{value:.2f}<span style='font-size: 0.6em;'> Mbps</span>"
                elif "ms" in title:
                    display_value = f"{value:.2f}<span style='font-size: 0.6em;'> ms</span>"
                else:
                    display_value = f"{value:,.2f}"
            elif isinstance(value, int):
                display_value = f"{value:,}"
            else:
                display_value = str(value)
    card_html = f"""
    <div class="metric-card" key="card-{key_suffix}">
        <h3>{title}</h3>
        <div class="value">{display_value}</div>
    </div>"""
    return card_html

# --- Función Auxiliar: Consultar VirusTotal API ---
def consultar_virustotal(file_hash, api_key):
    if not api_key:
        st.error("Introduce tu API Key de VirusTotal.")
        return None
    if not file_hash:
        st.error("No se pudo calcular hash.")
        return None
    headers = { "accept": "application/json", "x-apikey": api_key }
    url = f"{VIRUSTOTAL_API_URL}{file_hash}"
    try:
        response = requests.get(url, headers=headers, timeout=15, verify=False)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        st.error("Timeout conectando con VirusTotal.")
        return None
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 404:
            return {"error": {"code": "NotFoundError", "message": "Hash no encontrado."}}
        elif response.status_code == 401:
            st.error("Error 401: API Key inválida.")
            return None
        elif response.status_code == 429:
            st.error("Error 429: Límite API Key excedido.")
            return None
        else:
            st.error(f"Error HTTP: {http_err}")
            return None
    except requests.exceptions.RequestException as req_err:
        st.error(f"Error de conexión: {req_err}")
        return None
    except json.JSONDecodeError:
        st.error("Error: Respuesta VirusTotal no es JSON.")
        return None
    except Exception as e:
        st.error(f"Error inesperado: {e}")
        return None


# --- Función Auxiliar: Escanear un Puerto TCP Único ---
def escanear_puerto(ip_puerto_timeout):
    ip, puerto, timeout = ip_puerto_timeout
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout); resultado = sock.connect_ex((ip, puerto))
            if resultado == 0:
                return puerto 
    except socket.gaierror:
        return None
    except socket.error:
        return None
    return None

# --- Función Auxiliar: Escanear Lista de Puertos en Paralelo ---
def escanear_puertos_lista(ip, lista_puertos, timeout=PORT_SCAN_TIMEOUT, workers=MAX_WORKERS_PORT_SCAN):
    puertos_abiertos = [] 
    args_list = [(ip, puerto, timeout) for puerto in lista_puertos]
    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            resultados = executor.map(escanear_puerto, args_list)
            for puerto_abierto in resultados:
                if puerto_abierto is not None:
                    puertos_abiertos.append(puerto_abierto)
    except Exception as e:
        st.error(f"Error escaneo paralelo: {e}")
    return sorted(puertos_abiertos)

# --- Función Auxiliar: Resolver Hostname vía mDNS/Zeroconf ---
def resolver_hostname_mdns(ip_address, timeout=1):
    if not zeroconf: 
        return None
    hostname = None 
    zc = None 
    try:
        zc = zeroconf.Zeroconf(unicast=True)
        reverse_name = ipaddress.ip_address(ip_address).reverse_pointer + "."
        q = zeroconf.DNSQuestion(reverse_name, zeroconf.DNSQuestionType.PTR, zeroconf.DNSQuestionClass.IN)
        record = zc.get_record(q.name, q.type, timeout=timeout*1000) 
        if record and isinstance(record, zeroconf.DNSPointer):
             hostname_local = str(record.alias).rstrip('.')
             hostname = hostname_local[:-6] if hostname_local.lower().endswith(".local") else hostname_local
    except ImportError:
        if 'zeroconf_warning_shown' not in st.session_state:
            st.warning("Librería 'zeroconf' no instalada. No se puede usar mDNS.", icon="⚠️")
            st.session_state.zeroconf_warning_shown = True
        return None 
    except NameError:
         if 'zeroconf_warning_shown' not in st.session_state:
             st.warning("Librería 'zeroconf' no disponible. No se puede usar mDNS.", icon="⚠️")
             st.session_state.zeroconf_warning_shown = True
         return None
    except Exception as e:
        hostname = None
    finally:
        if zc: 
            try:
                zc.close()
            except: 
                pass
    return hostname

# --- Función Auxiliar: Crear Gráfico RTT para Ping ---
def crear_grafico_ping_rtt(ping_results):
    rtts = getattr(ping_results, 'rtts', [])
    if not rtts:
        return None
    paquetes = list(range(1, len(rtts) + 1))
    try:
        avg_rtt = getattr(ping_results, 'rtt_avg_ms', None)
        titulo_graf = "Latencia por Paquete Ping (RTT)"
        if avg_rtt is not None and np.isfinite(avg_rtt):
             titulo_graf += f" - Media: {avg_rtt:.2f} ms"
        fig = px.line(x=paquetes, y=rtts, markers=True, 
                      title=titulo_graf,
                      labels={'x': 'Nº Paquete', 'y': 'Latencia (ms)'}) 
        fig.update_layout(
            title_x=0.5, 
            yaxis_title="Latencia (ms)",
            xaxis_title="Nº Paquete",
            xaxis=dict(tickmode='linear', dtick=1, showgrid=False), 
            yaxis=dict(gridcolor='rgba(128,128,128,0.2)') 
        )
        fig.update_traces(
            line=dict(color='royalblue', width=2), 
            marker=dict(color='salmon', size=8, line=dict(width=1, color='DarkSlateGrey')), 
            hovertemplate="Paquete %{x}: %{y:.2f} ms<extra></extra>" 
        )
        if avg_rtt is not None and np.isfinite(avg_rtt):
            fig.add_hline(y=avg_rtt, line_dash="dash", line_color="grey", opacity=0.8,
                          annotation_text=f"Media: {avg_rtt:.2f} ms",
                          annotation_position="bottom right") 
        if rtts: 
            min_rtt = min(rtts); max_rtt = max(rtts)
            padding = (max_rtt - min_rtt) * 0.15 if max_rtt > min_rtt else 10
            range_y_min = max(0, min_rtt - padding) 
            range_y_max = max_rtt + padding
            fig.update_yaxes(range=[range_y_min, range_y_max])
        return fig
    except Exception as e:
        st.error(f"Error al generar gráfico RTT: {e}")
        return None


# --- Función Auxiliar: Mostrar Página Simulada del Solucionador ---
def mostrar_pagina_solucionador():
    st.title("🔧 Solucionador de Problemas (Simulación)")
    st.markdown("---")
    details = st.session_state.get('problem_details', {})
    if not details:
        st.warning("No se han pasado detalles del problema.")
        if st.button("<< Volver"):
            st.session_state.show_problem_solver = False; st.rerun()
        return 
    seg = details.get('segundo', '?')
    estado = details.get('estado_umbral', 'N/A')
    t_total_raw = pd.to_numeric(details.get('tasa_total_bps'), errors='coerce')
    t_total = t_total_raw if pd.notna(t_total_raw) else 0.0
    t_sent_raw = pd.to_numeric(details.get('tasa_sent_bps'), errors='coerce')
    t_sent = t_sent_raw if pd.notna(t_sent_raw) else 0.0
    t_recv_raw = pd.to_numeric(details.get('tasa_recv_bps'), errors='coerce')
    t_recv = t_recv_raw if pd.notna(t_recv_raw) else 0.0
    sugerencia_dict = sugerir_solucion_tasa(t_total)
    causa_posible = sugerencia_dict.get('causa', 'N/A').replace('<br>', '\n')
    accion_sugerida = sugerencia_dict.get('accion', 'N/A').replace('<br>', '\n')
    st.subheader(f"Problema Detectado en Segundo {seg}")
    st.write(f"**Estado Registrado:** {estado}")
    st.write(f"**Tasa Total Registrada:** {t_total:,.0f} B/s")
    st.write(f"(Enviado: {t_sent:,.0f} B/s | Recibido: {t_recv:,.0f} B/s)")
    st.markdown("---")
    st.subheader("Análisis Detallado (Simulado)")
    st.write("Simulación: Analizando contexto y posibles causas...")
    time.sleep(0.5)
    st.markdown(f"**Causa Más Probable (según tasa):**\n {causa_posible}")
    time.sleep(0.5)
    st.write("Simulación: Ejecutando diagnósticos adicionales...")
    time.sleep(1)
    st.markdown("---")
    st.subheader("Posibles Soluciones (Simulado)")
    st.markdown(f"**Acciones Recomendadas:**\n {accion_sugerida}")
    st.write("") 
    col_sol1, col_sol2 = st.columns(2)
    with col_sol1:
        if st.button("Ejecutar Diagnóstico Avanzado (Sim.)", key="sol_diag"):
            st.success("Simulación: Diagnóstico avanzado ejecutado.")
    with col_sol2:
        if st.button("Optimizar Configuración (Sim.)", key="sol_opt", disabled=True):
            pass
    st.markdown("---")
    if st.button("<< Volver al Monitor de Tráfico"):
        st.session_state.show_problem_solver = False
        st.rerun()

def obtener_info_so():
    """Obtiene información básica del Sistema Operativo usando platform."""
    try:
        return {
            "Sistema": f"{platform.system()} {platform.release()}", 
            "Versión": platform.version(), 
            "Arquitectura": f"{platform.machine()} ({platform.architecture()[0]})",
            "Procesador": platform.processor() 
        }
    except Exception as e:
        return {"Error": f"No se pudo obtener info SO: {e}"}
    

def obtener_info_hardware():
    """Obtiene información básica de CPU, RAM y Disco usando psutil."""
    info = {} 
    try:
        info["CPU Uso"] = psutil.cpu_percent(interval=0.5)
        info["CPU Núcleos Lógicos"] = psutil.cpu_count(logical=True)
        info["CPU Núcleos Físicos"] = psutil.cpu_count(logical=False)
    except Exception as e: info["CPU Error"] = str(e) 
    try:
        mem = psutil.virtual_memory()
        info["RAM Total (GB)"] = f"{mem.total / GB:.2f}" 
        info["RAM Usada (GB)"] = f"{mem.used / GB:.2f}"
        info["RAM Porcentaje Uso"] = mem.percent
    except Exception as e: info["RAM Error"] = str(e) 
    try:
        disk_path = 'C:\\' if platform.system() == "Windows" else '/'
        disk = psutil.disk_usage(disk_path)
        info["Disco Principal Total (GB)"] = f"{disk.total / GB:.2f}"
        info["Disco Principal Usado (GB)"] = f"{disk.used / GB:.2f}"
        info["Disco Principal Porcentaje Uso"] = disk.percent
    except Exception as e: info["Disco Error"] = str(e) 
    return info  



# --- Inicializar estados ---
if 'logged_in' not in st.session_state: st.session_state.logged_in = False
if 'username' not in st.session_state: st.session_state.username = ""
if 'ping_results' not in st.session_state: st.session_state.ping_results = None
if 'monitor_results' not in st.session_state: st.session_state.monitor_results = None
if 'arp_results' not in st.session_state: st.session_state.arp_results = None
if 'arp_hostnames' not in st.session_state: st.session_state.arp_hostnames = None
if 'vt_results' not in st.session_state: st.session_state.vt_results = None
if 'vt_file_hash' not in st.session_state: st.session_state.vt_file_hash = None
if 'port_scan_results' not in st.session_state: st.session_state.port_scan_results = {}
if 'selected_option' not in st.session_state: st.session_state.selected_option = "Monitor Tráfico Local"
if 'show_problem_solver' not in st.session_state: st.session_state.show_problem_solver = False
if 'problem_details' not in st.session_state: st.session_state.problem_details = None
if 'local_port_scan_results' not in st.session_state: st.session_state.local_port_scan_results = None


# --- Pantalla de Login ---
if not st.session_state.logged_in:
    st.title("Herramienta Diagnóstico de Red")
    st.caption("Acceso Profesional")
    st.write("")
    with st.form("login_form"):
        st.subheader("Iniciar Sesión")
        username_introducido = st.text_input('Usuario', key="login_user", label_visibility="hidden", placeholder="Usuario")
        password_introducida = st.text_input('Contraseña', type="password", key="login_pass", label_visibility="hidden", placeholder="Contraseña")
        submitted = st.form_submit_button("Entrar")
        if submitted:
            if username_introducido in USUARIOS_VALIDOS and USUARIOS_VALIDOS[username_introducido] == password_introducida:
                st.session_state.logged_in = True; st.session_state.username = username_introducido
                for key in ['ping_results', 'monitor_results', 'arp_results', 'arp_hostnames', 'vt_results', 'vt_file_hash', 'port_scan_results', 'selected_option', 'show_problem_solver', 'problem_details']:
                    if key in st.session_state: del st.session_state[key]
                st.rerun()
            else: st.error("Usuario o contraseña incorrectos.")

# --- Aplicación Principal ---
elif st.session_state.get('show_problem_solver', False):
     mostrar_pagina_solucionador() 

else:
    #-- barra lateral --
    with st.sidebar:
        st.title("Diagnóstico Red")
        st.success(f"Conectado: **{st.session_state.username}**")
        try:
            if ZoneInfo: tz_spain = ZoneInfo("Europe/Madrid")
            else: tz_spain = datetime.timezone(datetime.timedelta(hours=2))
            now_spain = datetime.datetime.now(tz_spain); tz_name = now_spain.strftime('%Z')
        except Exception: now_spain = datetime.datetime.now(); tz_name = now_spain.astimezone().tzname() if hasattr(now_spain, 'astimezone') else ""
        st.info(f"Hora (ES): {now_spain.strftime(f'%Y-%m-%d %H:%M:%S {tz_name}')}")
        st.markdown('<hr class="custom-hr" style="margin: 1rem 0;">', unsafe_allow_html=True)
        st.subheader("Herramientas")
        lista_opciones = [ "Monitor Tráfico Local", "Ping", "Dispositivos Red", "Analizar Archivo (VT)", "Escáner Puertos", "Información del Sistema" ]
        if 'selected_option' not in st.session_state: st.session_state.selected_option = lista_opciones[0]
        opcion_actual = st.session_state.selected_option
        try: current_index = lista_opciones.index(opcion_actual)
        except ValueError: current_index = 0; st.session_state.selected_option = lista_opciones[0]
        # Actualizar estado si cambia la selección del radio
        st.session_state.selected_option = st.radio( "Selecciona herramienta:", lista_opciones, key="main_nav_radio", index=current_index, label_visibility="collapsed" )
        st.markdown('<hr class="custom-hr" style="margin: 1rem 0;">', unsafe_allow_html=True)
        if st.button("Cerrar Sesión", type="secondary"):
            st.session_state.logged_in = False; st.session_state.username = ""
            for key in ['ping_results', 'monitor_results', 'arp_results', 'arp_hostnames', 'vt_results', 'vt_file_hash', 'port_scan_results', 'selected_option', 'show_problem_solver', 'problem_details']:
                if key in st.session_state: del st.session_state[key]
            st.rerun()
        st.markdown('<hr class="custom-hr" style="margin: 1rem 0;">', unsafe_allow_html=True)
        st.caption("©️ 2025 ") 

    # --- Contenido Principal (Basado en Selección Sidebar) ---
    st.header(f"{st.session_state.selected_option}")
    st.markdown('<hr class="custom-hr" style="margin-top:0; margin-bottom: 2rem;">', unsafe_allow_html=True)

    if st.session_state.selected_option == "Monitor Tráfico Local":

        # SECCIÓN Monitor Tráfico Local 

        st.subheader("Monitorizar Actividad de Red Local")
        st.caption(f"Analiza la tasa de Bytes/s y el estado por umbral segundo a segundo.")
        duracion_seleccionada = st.slider( "Duración (segundos):", min_value=5, max_value=60, value=15, step=5, key="monitor_duration_slider" )
        if st.button("Iniciar Monitorización", key="start_monitor_section"):
            st.session_state.monitor_results = None; datos_monitor_segundos = []
            with st.status(f"Ejecutando monitorización ({duracion_seleccionada}s)...", expanded=True) as status:
                try:
                    status.write("Obteniendo contadores iniciales..."); last_counters = psutil.net_io_counters();
                    if not last_counters: raise Exception("No se pudieron obtener contadores iniciales.")
                    last_time = time.time(); total_bytes_sent_periodo = 0; total_bytes_recv_periodo = 0
                    progress_bar_monitor = st.progress(0, text="Iniciando...")
                    for i in range(duracion_seleccionada):
                        progress_text = f"Segundo {i+1}/{duracion_seleccionada}..."; status.write(progress_text); time.sleep(1)
                        current_counters = psutil.net_io_counters(); current_time = time.time()
                        tasa_sent_bps = 0.0; tasa_recv_bps = 0.0; tasa_total_bps = 0.0; estado_segundo = "Indeterminado"
                        if current_counters:
                            delta_time = current_time - last_time; delta_sent = current_counters.bytes_sent - last_counters.bytes_sent; delta_recv = current_counters.bytes_recv - last_counters.bytes_recv
                            if delta_time > 0.1 and delta_sent >= 0 and delta_recv >= 0:
                                tasa_sent_bps = delta_sent / delta_time; tasa_recv_bps = delta_recv / delta_time; tasa_total_bps = tasa_sent_bps + tasa_recv_bps
                                total_bytes_sent_periodo += delta_sent; total_bytes_recv_periodo += delta_recv
                                if tasa_total_bps > TASA_MUY_ALTA_BPS: estado_segundo = "MUY ALTA"
                                elif tasa_total_bps > TASA_ALTA_BPS: estado_segundo = "ALTA"
                                elif tasa_total_bps < TASA_BAJA_BPS: estado_segundo = "MUY BAJA"
                                else: estado_segundo = "Normal"
                            else: estado_segundo = "Baja/Normal (Sin Delta)"
                            last_counters = current_counters; last_time = current_time
                        datos_monitor_segundos.append({ "segundo": i + 1, "tasa_sent_bps": tasa_sent_bps, "tasa_recv_bps": tasa_recv_bps, "tasa_total_bps": tasa_total_bps, "estado_umbral": estado_segundo })
                        progress_bar_monitor.progress((i + 1) / duracion_seleccionada)
                    status.update(label="✔️ Monitorización Completada", state="complete", expanded=False)
                    if datos_monitor_segundos:
                        df_resumen = pd.DataFrame(datos_monitor_segundos); max_rate = pd.to_numeric(df_resumen['tasa_total_bps'], errors='coerce').max(); avg_rate = pd.to_numeric(df_resumen['tasa_total_bps'], errors='coerce').mean()
                        summary_stats = { "max_rate_bps": max_rate if pd.notna(max_rate) else 0, "avg_rate_bps": avg_rate if pd.notna(avg_rate) else 0, "total_sent_bytes": total_bytes_sent_periodo, "total_recv_bytes": total_bytes_recv_periodo, "duration": duracion_seleccionada }
                        st.session_state.monitor_results = {"datos_detallados": datos_monitor_segundos, "summary": summary_stats}
                    else: st.warning("No se recogieron datos."); st.session_state.monitor_results = None
                except Exception as e: status.update(label="❌ Error en Monitorización", state="error", expanded=True); st.error(f"Detalle: {e}"); st.session_state.monitor_results = None
        monitor_results_data = st.session_state.get('monitor_results')
        if monitor_results_data:
            st.markdown('<hr class="custom-hr">', unsafe_allow_html=True)
            st.subheader("Resultados del Monitor Local")
            summary = monitor_results_data.get("summary", {})
            if summary:
                 st.write(f"**Resumen ({summary.get('duration', '?')}s):**"); col_sum1, col_sum2, col_sum3, col_sum4 = st.columns(4)
                 col_sum1.metric("Media Total", f"{summary.get('avg_rate_bps', 0):,.0f} B/s"); col_sum2.metric("Máxima Total", f"{summary.get('max_rate_bps', 0):,.0f} B/s")
                 col_sum3.metric("Total Enviado", f"{summary.get('total_sent_bytes', 0):,} Bytes"); col_sum4.metric("Total Recibido", f"{summary.get('total_recv_bytes', 0):,} Bytes"); st.write("")
            datos_completos_graph = monitor_results_data.get("datos_detallados", [])
            figura_plotly = crear_grafico_plotly_tasa(datos_completos_graph)
            if figura_plotly: st.plotly_chart(figura_plotly, use_container_width=True); st.caption("Pasa el ratón sobre los puntos del gráfico para ver detalles y sugerencias.")
            else: st.warning("No se pudo generar el gráfico.")
            st.markdown('<hr class="custom-hr">', unsafe_allow_html=True)
            st.subheader("Detalle Segundo a Segundo")
            datos_completos_list = monitor_results_data.get("datos_detallados", [])
            if datos_completos_list:
                for detalle in datos_completos_list:
                    seg = detalle.get('segundo') 
                    t_sent_raw = pd.to_numeric(detalle.get('tasa_sent_bps'), errors='coerce')
                    t_sent = t_sent_raw if pd.notna(t_sent_raw) else 0.0
                    t_recv_raw = pd.to_numeric(detalle.get('tasa_recv_bps'), errors='coerce')
                    t_recv = t_recv_raw if pd.notna(t_recv_raw) else 0.0
                    t_total_raw = pd.to_numeric(detalle.get('tasa_total_bps'), errors='coerce')
                    t_total = t_total_raw if pd.notna(t_total_raw) else 0.0
                    estado = detalle.get('estado_umbral', 'N/A'); resultado_sugerencia = sugerir_solucion_tasa(t_total)
                    causa_posible = resultado_sugerencia.get('causa', 'N/A'); accion_sugerida = resultado_sugerencia.get('accion', 'N/A')
                    clase_estado = f"status-{estado.lower().replace(' ','-').replace('(','').replace(')','')}"
                    st.markdown("---")
                    col_info, col_boton = st.columns([4, 1]) 
                    with col_info:
                        st.markdown(f'**Segundo {seg}** | Estado: <span class="{clase_estado}">{estado}</span>', unsafe_allow_html=True)
                        st.markdown(f"* Tasas (Total/Enviada/Recibida): `{t_total:,.0f}` / `{t_sent:,.0f}` / `{t_recv:,.0f}` B/s")
                        with st.expander("Ver Causa Posible y Evaluacion", expanded=False):
                             st.markdown(f"**Causa Posible:** {causa_posible}", unsafe_allow_html=True) 
                             st.markdown(f" {accion_sugerida}")
                    with col_boton:
                         estados_ok = ["Normal", "Normal (o Baja)", "Baja/Normal (Sin Delta)"]
                         if estado not in estados_ok and estado != 'Indeterminado':
                             if st.button(f"Solucionar (Seg. {seg})", key=f"solve_{seg}", help="Simula ir a una página de análisis detallado"):
                                 st.session_state.problem_details = detalle 
                                 st.session_state.show_problem_solver = True
                                 st.rerun() 
            else: st.write("No hay datos detallados para mostrar.")
        else: st.info("Inicia la monitorización para ver resultados.")

        # FIN SECCIÓN Monitor Tráfico Local

    elif st.session_state.selected_option == "Ping":

        # SECCIÓN Ping 

        st.subheader("Comprobación de Conexión (Ping)")
        st.caption("Mide la latencia y estabilidad hacia un servidor específico.")
        col_ping_host, col_ping_count = st.columns([3, 1])
        with col_ping_host:
             target_host_ping = st.text_input('Host o IP destino', value="8.8.8.8", key="ping_target_v130", label_visibility="collapsed", placeholder="Introduce Host o IP (ej: 8.8.8.8)")
        with col_ping_count:
             num_pings = st.number_input("Nº Pings", min_value=1, max_value=20, value=4, step=1, key="ping_count_v130", label_visibility="collapsed")
        if st.button("Realizar Prueba de Ping", key="start_ping_v130"):
            st.session_state.ping_results = None
            if target_host_ping:
                with st.status(f"Enviando {num_pings} pings a {target_host_ping}...", expanded=False) as status_ping:
                    ping_result_data = None
                    try:
                        ping_result_data = realizar_ping(target_host_ping, count=num_pings, timeout=2)
                    except Exception as e:
                        st.error(f"Error inesperado ejecutando ping: {e}") 
                    st.session_state.ping_results = ping_result_data 
                    if ping_result_data and hasattr(ping_result_data, 'success') and ping_result_data.success:
                         status_ping.update(label="✔️ Prueba Ping Completada", state="complete")
                    elif ping_result_data and hasattr(ping_result_data, 'packet_loss') and ping_result_data.packet_loss == 1.0:
                         status_ping.update(label="❌ Fallo: 100% paquetes perdidos", state="error")
                    elif ping_result_data: 
                         status_ping.update(label="⚠️ Prueba Ping Completada (con pérdida)", state="warning")
                    else: 
                         status_ping.update(label="❌ Error al ejecutar Ping", state="error")
            else: st.warning("Introduce un Host o IP.")
        ping_results_data = st.session_state.get('ping_results')
        if ping_results_data:
            st.markdown('<hr class="custom-hr">', unsafe_allow_html=True)
            st.subheader("Resultados del Ping")
            results_ping = ping_results_data
            avg_ms = getattr(results_ping, 'rtt_avg_ms', float('inf'))
            max_ms = getattr(results_ping, 'rtt_max_ms', float('inf'))
            min_ms = getattr(results_ping, 'rtt_min_ms', float('inf'))
            loss = getattr(results_ping, 'packet_loss', 1.0)
            rtts = getattr(results_ping, 'rtts', [])
            jitter_ms = np.std([rtt for rtt in rtts if rtt is not None]) if len(rtts) > 1 else 0.0
            fig_rtt = crear_grafico_ping_rtt(results_ping)
            if fig_rtt:
                st.plotly_chart(fig_rtt, use_container_width=True)
            elif loss == 1.0: st.info("No se recibieron respuestas para graficar la latencia.")
            st.write("**Estadísticas:**")
            col_ping_out1, col_ping_out2, col_ping_out3, col_ping_out4 = st.columns(4) # 4 columnas
            with col_ping_out1: st.metric("Latencia Media", f"{avg_ms:.2f} ms" if np.isfinite(avg_ms) else "N/A")
            with col_ping_out2: st.metric("Latencia Mínima", f"{min_ms:.2f} ms" if np.isfinite(min_ms) else "N/A") # Nueva Métrica
            with col_ping_out3: st.metric("Latencia Máxima", f"{max_ms:.2f} ms" if np.isfinite(max_ms) else "N/A")
            with col_ping_out4: st.metric("Jitter (StdDev)", f"{jitter_ms:.2f} ms") # Nueva Métrica
            st.metric("Paquetes Perdidos", f"{loss:.1%}", delta=f"-{int(loss*num_pings)} paquetes" if loss>0 else "0 paquetes", delta_color="inverse") # Mostrar paquetes perdidos absolutos
            with st.expander("Ver Interpretación y Sugerencias Detalladas"):
                velocidad = "Indeterminada"; sugerencia_ping = "Resultados no concluyentes."; estado_emoji = "❓"
                if loss > PERDIDA_PAQUETES_MAX_PERMITIDA:
                    velocidad = f"FALLO ALTO ({loss:.0%})"; estado_emoji = "❌"
                    sugerencia_ping = ("**Causa:** Congestión red, firewall bloquea ICMP, problemas ruta, destino sobrecargado.\n" "**Pasos:**\n* Verifica conexión local.\n* Ping a router.\n* Ping a 8.8.8.8.\n* Revisa firewalls.\n* Usa `tracert`/`traceroute`.\n* Contacta ISP si persiste.")
                    st.error(f"**{estado_emoji} Estado:** {velocidad}")
                elif avg_ms == float('inf'):
                    velocidad = f"INALCANZABLE (100% Pérdida)"; estado_emoji = "🚫"
                    sugerencia_ping = ("**Causa:** Host apagado/no existe, error DNS, firewall bloquea TODO, problema ruta.\n" "**Pasos:**\n* ¿Host/IP correcto?\n* ¿Resuelve DNS? Prueba IP directa.\n* Ping a router y 8.8.8.8.\n* Verifica firewalls.\n* Usa `tracert`/`traceroute`.\n* ¿Servicio online?")
                    st.error(f"**{estado_emoji} Estado:** {velocidad}")
                elif avg_ms > LATENCIA_ACEPTABLE_MS:
                    velocidad = f"LENTA (> {LATENCIA_ACEPTABLE_MS} ms)"; estado_emoji = "⚠️"
                    sugerencia_ping = ("**Causa:** Congestión en la ruta, distancia geográfica al servidor, problemas en el servidor destino, línea de baja calidad.\n" "**Acción:** Si es consistente, puede ser normal para ese destino lejano. Si es inusual o afecta a la experiencia, revisa si hay descargas/subidas activas, otros dispositivos usando la red, o considera contactar al ISP si afecta a múltiples sitios.")
                    st.warning(f"**{estado_emoji} Estado:** {velocidad}")
                elif avg_ms > LATENCIA_RAPIDA_MS:
                    velocidad = f"ACEPTABLE ({LATENCIA_RAPIDA_MS}-{LATENCIA_ACEPTABLE_MS} ms)"; estado_emoji = "✅"
                    sugerencia_ping = "Latencia dentro de rangos normales para la mayoría de usos (navegación, streaming). Podría ser ligeramente alta para juegos online muy sensibles."
                    st.success(f"**{estado_emoji} Estado:** {velocidad}")
                else:
                    velocidad = f"RÁPIDA (≤ {LATENCIA_RAPIDA_MS} ms)"; estado_emoji = "⚡"
                    sugerencia_ping = "Latencia excelente. Ideal para juegos online, videollamadas y otras aplicaciones sensibles al tiempo real."
                    st.success(f"**{estado_emoji} Estado:** {velocidad}")
                st.markdown("**Sugerencia Detallada:**"); st.markdown(sugerencia_ping.replace("\n","<br>"), unsafe_allow_html=True)

        # FIN SECCIÓN Ping

    elif st.session_state.selected_option == "Dispositivos Red":

        # SECCIÓN Dispositivos Red 

        st.subheader("Dispositivos en Red Local")
        st.caption("Consulta caché ARP (+Hostname+Fabricante) o realiza escaneo activo.")
        col_btn_1, col_btn_2 = st.columns(2)
        scan_executed = False
        arp_data_to_process = None 
        with col_btn_1:
            if st.button("Analizar Caché ARP (Rápido)", key="start_arp_scan_cache_v133"):
                st.session_state.arp_results = None; st.session_state.arp_detailed_results = None
                scan_executed = True
                with st.status("Consultando tabla ARP...", expanded=False) as status_arp:
                    arp_data = escanear_red_local_arp(active_scan=False)
                    if arp_data is not None: st.session_state.arp_results = arp_data; status_arp.update(label="✔️ Tabla ARP obtenida.", state="complete")
                    else: status_arp.update(label="❌ Error al consultar ARP.", state="error")
                arp_data_to_process = st.session_state.get('arp_results') 
        with col_btn_2:
            if st.button("Escaneo Activo (Lento)", key="start_arp_scan_active_v133"):
                st.session_state.arp_results = None; st.session_state.arp_detailed_results = None
                scan_executed = True
                st.warning("El escaneo activo puede tardar varios minutos.")
                with st.status("Ejecutando escaneo activo...", expanded=True) as status_arp_active:
                    arp_data = escanear_red_local_arp(active_scan=True)
                    if arp_data is not None: st.session_state.arp_results = arp_data; status_arp_active.update(label="✔️ Escaneo ARP activo completado.", state="running") # Cambiado a running para seguir
                    else: status_arp_active.update(label="❌ Error durante el escaneo ARP.", state="error")
                arp_data_to_process = st.session_state.get('arp_results')
        if scan_executed and arp_data_to_process is not None:
            enriched_results = []
            if len(arp_data_to_process) > 0:
                with st.spinner(f"Enriqueciendo {len(arp_data_to_process)} dispositivos (Hostname, Fabricante)..."):
                    local_ips, local_macs = obtener_info_local_simple()
                    network = obtener_red_local(); router_ip = None
                    if network:
                         potential_gw1 = str(network.network_address + 1); potential_gw2 = str(network.broadcast_address - 1)
                         for device in arp_data_to_process:
                              if device['IP'] == potential_gw1 or device['IP'] == potential_gw2: router_ip = device['IP']; break
                    for i, device in enumerate(arp_data_to_process):
                        ip = device['IP']; mac = device['MAC']; tipo = device.get('Tipo', 'N/A')
                        hostname = "No resuelto"; fabricante = "N/A"; notas = ""
                        try:
                            socket.setdefaulttimeout(0.3); hostname_rdns = socket.gethostbyaddr(ip)[0]
                            if hostname_rdns != ip: hostname = hostname_rdns
                        except (socket.herror, socket.timeout):
                            hostname_mdns = resolver_hostname_mdns(ip)
                            if hostname_mdns: hostname = hostname_mdns + " (mDNS)"
                        except Exception: hostname = "Error Res."
                        finally: socket.setdefaulttimeout(None)
                        if mac != 'FF:FF:FF:FF:FF:FF': fabricante = obtener_fabricante_mac(mac)
                        if ip in local_ips or mac in local_macs: notas += "(Tu Equipo) "
                        if ip == router_ip: notas += "(Router?)"
                        enriched_results.append({"IP": ip, "Hostname": hostname, "MAC": mac, "Fabricante": fabricante, "Tipo": tipo, "Notas": notas.strip()})
                st.session_state.arp_detailed_results = enriched_results 
            else:
                 st.session_state.arp_detailed_results = [] 
        arp_detailed_data = st.session_state.get('arp_detailed_results')
        if arp_detailed_data is not None:
            st.markdown('<hr class="custom-hr">', unsafe_allow_html=True)
            st.subheader(f"Dispositivos Encontrados y Detalles ({len(arp_detailed_data)})")
            if len(arp_detailed_data) > 0:
                df_arp_final = pd.DataFrame(arp_detailed_data)
                column_order = ["IP", "Hostname", "Fabricante", "MAC", "Tipo", "Notas"]
                df_arp_final = df_arp_final[column_order]
                st.dataframe(df_arp_final, use_container_width=True, hide_index=True)
                st.caption("Fabricante basado en MAC (API externa); Hostname vía rDNS/mDNS.")
            else:
                 if arp_detailed_data == []: st.warning("No se encontraron dispositivos en la caché ARP / escaneo.")
 
        # FIN SECCIÓN Dispositivos Red


    elif st.session_state.selected_option == "Analizar Archivo (VT)":

        # SECCIÓN Analizar Archivo (VT) 

        st.subheader("Analizar Archivo con VirusTotal")
        st.caption("Comprueba si un archivo ha sido detectado como malicioso por múltiples motores antivirus.")
        st.warning('**Requiere API Key gratuita de VirusTotal.** Consíguela registrándote en [VirusTotal.com](https://www.virustotal.com/).')
        vt_api_key = st.text_input("Introduce tu API Key de VirusTotal:", type="password", key="vt_api_key", help="Tu clave API no se guarda, solo se usa para esta consulta.")
        uploaded_file = st.file_uploader("Selecciona un archivo para analizar:", type=None, key="vt_file")
        sha256_hash = None
        if uploaded_file is not None:
            try:
                file_content = uploaded_file.getvalue(); sha256_hash = hashlib.sha256(file_content).hexdigest()
                st.session_state.vt_file_hash = sha256_hash
                st.write(f"**Hash SHA-256:** `{sha256_hash}`")
            except Exception as e: st.error(f"Error procesando archivo o calculando hash: {e}"); uploaded_file = None
        if st.button("Analizar Hash en VirusTotal", key="vt_analyze", disabled=(sha256_hash is None)):
            st.session_state.vt_results = None
            if sha256_hash and vt_api_key:
                with st.spinner("Consultando VirusTotal..."): vt_report = consultar_virustotal(sha256_hash, vt_api_key); st.session_state.vt_results = vt_report
            elif not vt_api_key: st.error("Por favor, introduce tu API Key de VirusTotal.")
            else: st.error("Calcula primero el Hash subiendo un archivo.")
        vt_results_data = st.session_state.get('vt_results', None)
        if vt_results_data:
            st.markdown('<hr class="custom-hr">', unsafe_allow_html=True)
            st.subheader("Resultados de VirusTotal")
            vt_data = vt_results_data
            hash_display = st.session_state.get('vt_file_hash', '...')
            if isinstance(vt_data, dict) and vt_data.get("error"):
                error_info = vt_data["error"]
                if error_info.get("code") == "NotFoundError":
                     st.info(f"**Archivo desconocido:** El hash `{hash_display}` no fue encontrado en VirusTotal.")
                     st.caption("Esto no significa que sea seguro, solo que VT no lo había analizado antes con este hash.")
            elif isinstance(vt_data, dict) and "data" in vt_data and "attributes" in vt_data["data"]:
                attributes = vt_data["data"]["attributes"]; stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0); suspicious = stats.get("suspicious", 0); undetected = stats.get("harmless", 0) + stats.get("undetected", 0)
                total_engines = malicious + suspicious + undetected
                st.write(f"**Nombre archivo (VT):** {attributes.get('meaningful_name', 'N/A')}")
                last_analysis_ts = attributes.get('last_analysis_date')
                if last_analysis_ts:
                     last_analysis_dt = datetime.datetime.fromtimestamp(last_analysis_ts, tz=datetime.timezone.utc)
                     st.write(f"**Último análisis VT:** {last_analysis_dt.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                st.write("**Resultados Detección:**")
                if total_engines > 0:
                     col_vt1, col_vt2, col_vt3 = st.columns(3)
                     with col_vt1: st.metric("Malicioso", f"{malicious}/{total_engines}")
                     with col_vt2: st.metric("Sospechoso", f"{suspicious}/{total_engines}")
                     with col_vt3: st.metric("Indetectado", f"{undetected}/{total_engines}")
                     if malicious > 5: st.error("Fichero detectado como **MALICIOSO** por múltiples motores.")
                     elif malicious > 0 or suspicious > 1 : st.warning("Fichero **POTENCIALMENTE PELIGROSO** (malicioso/sospechoso).")
                     else: st.success("Fichero **NO detectado** como malicioso por la mayoría de motores."); st.caption("Esto no garantiza al 100% que sea seguro.")
                else: st.info("No hay estadísticas de análisis disponibles para este hash.")
                if hash_display != "...": vt_link = f"https://www.virustotal.com/gui/file/{hash_display}"; st.markdown(f'[Ver reporte completo en VirusTotal]({vt_link})')
            else:
                 st.error("No se pudo obtener un reporte válido de VirusTotal.")

                      # FIN Seccion Analizar Archivo (VT)

    elif st.session_state.selected_option == "Escáner Puertos":

        # SECCIÓN Escáner Puertos 

        st.subheader("Escáner de Puertos TCP Comunes")
        st.caption("Comprueba qué puertos TCP comunes están abiertos en una IP específica.")
        st.info("Nota: Un puerto abierto indica un servicio activo. Los firewalls pueden bloquear este escaneo.")
        target_ip_scan = st.text_input("IP del dispositivo a escanear:", key="port_scan_ip", placeholder="Ej: 192.168.1.1")
        with st.expander("Puertos comunes a escanear"):
             st.caption(f"{', '.join(map(str, PUERTOS_COMUNES_TCP))}")
        if st.button("Escanear Puertos", key="start_port_scan"):
            if 'port_scan_results' not in st.session_state: st.session_state.port_scan_results = {}
            st.session_state.port_scan_results[target_ip_scan] = None
            ip_valida = False
            if target_ip_scan:
                try: ipaddress.ip_address(target_ip_scan); ip_valida = True
                except ValueError: st.error("La dirección IP introducida no parece válida.")
            if ip_valida:
                with st.status(f"Escaneando puertos comunes en {target_ip_scan}...", expanded=True) as status_ps:
                    st.write("Usando hilos para acelerar...")
                    puertos_encontrados = escanear_puertos_lista(target_ip_scan, PUERTOS_COMUNES_TCP)
                    if 'port_scan_results' not in st.session_state: st.session_state.port_scan_results = {}
                    st.session_state.port_scan_results[target_ip_scan] = puertos_encontrados
                    if puertos_encontrados is not None: status_ps.update(label=f"✔️ Escaneo completado. {len(puertos_encontrados)} puertos abiertos encontrados.", state="complete", expanded=False)
                    else: status_ps.update(label="❌ Error durante el escaneo de puertos.", state="error", expanded=True)
        resultados_ip_actual = st.session_state.get('port_scan_results', {}).get(target_ip_scan)
        if resultados_ip_actual is not None:
            st.markdown('<hr class="custom-hr">', unsafe_allow_html=True)
            st.subheader(f"Resultados para {target_ip_scan}")
            if len(resultados_ip_actual) > 0:
                st.write("**Puertos abiertos encontrados:**")
                output_lines = []
                for port in resultados_ip_actual:
                    description = PORT_DATA.get(port, "Servicio común desconocido")
                    output_lines.append(f"- **{port}**: {description}")
                st.markdown("\n".join(output_lines))
            else:
                st.info("No se encontraron puertos abiertos en la lista común escaneada (o estaban bloqueados por firewall).")


# ---  Información del Sistema ---
    elif st.session_state.selected_option == "Información del Sistema":
        st.subheader("Información del Sistema Operativo")
        so_info = obtener_info_so() 
        if "Error" in so_info:
            st.error(so_info["Error"])
        else:
            st.text(f"Sistema:      {so_info.get('Sistema', 'N/A')}")
            st.text(f"Versión OS:   {so_info.get('Versión', 'N/A')}")
            st.text(f"Arquitectura: {so_info.get('Arquitectura', 'N/A')}")
            st.text(f"Procesador:   {so_info.get('Procesador', 'N/A')}") 
        st.markdown('<hr class="custom-hr">', unsafe_allow_html=True) 
        st.subheader("Uso de Recursos Hardware")
        hw_info = obtener_info_hardware()
        if "CPU Error" in hw_info: st.error(f"Error CPU: {hw_info['CPU Error']}")
        else:
            st.text(f"CPU: {platform.processor()} ({hw_info.get('CPU Núcleos Físicos', '?')} Físicos / {hw_info.get('CPU Núcleos Lógicos', '?')} Lógicos)")
            cpu_usage = hw_info.get('CPU Uso', 0)
            st.progress(int(cpu_usage) / 100, text=f"Uso CPU Actual: {cpu_usage:.1f}%")
        if "RAM Error" in hw_info: st.error(f"Error RAM: {hw_info['RAM Error']}")
        else:
            ram_usage = hw_info.get('RAM Porcentaje Uso', 0)
            st.progress(int(ram_usage) / 100, text=f"Uso RAM: {ram_usage:.1f}% ({hw_info.get('RAM Usada (GB)', 'N/A')} GB / {hw_info.get('RAM Total (GB)', 'N/A')} GB)")
        if "Disco Error" in hw_info: st.error(f"Error Disco: {hw_info['Disco Error']}")
        else:
            disk_usage = hw_info.get('Disco Principal Porcentaje Uso', 0)
            st.progress(int(disk_usage) / 100, text=f"Uso Disco Principal ('/'): {disk_usage:.1f}% ({hw_info.get('Disco Principal Usado (GB)', 'N/A')} GB / {hw_info.get('Disco Principal Total (GB)', 'N/A')} GB)")
        st.markdown('<hr class="custom-hr">', unsafe_allow_html=True) 
        st.subheader("Red Local (Este Equipo)")
        try:
            hostname = socket.gethostname(); st.text(f"Nombre del Host: {hostname}")
        except Exception: st.text("Nombre del Host: No disponible")
        local_ips, _ = obtener_info_local_simple() 
        if local_ips: st.text(f"Direcciones IP: {', '.join(local_ips)}")
        else: st.text("Direcciones IP: No disponibles")
        st.markdown('<hr class="custom-hr">', unsafe_allow_html=True) 
        st.subheader("Comprobar Puertos Abiertos Localmente")
        st.caption("Escanea puertos TCP comunes en tu propio PC (127.0.0.1 / localhost).")
        if st.button("Escanear Puertos en Localhost", key="scan_local_ports"):
            st.session_state.local_port_scan_results = None 
            with st.spinner("Escaneando puertos comunes en 127.0.0.1..."):
                puertos_locales_abiertos = escanear_puertos_lista('127.0.0.1', PUERTOS_COMUNES_TCP, timeout=0.1, workers=15)
                st.session_state.local_port_scan_results = puertos_locales_abiertos
        resultados_locales = st.session_state.get('local_port_scan_results')
        if resultados_locales is not None: 
            st.write("---") 
            if len(resultados_locales) > 0:
                st.write("**Puertos locales abiertos encontrados (en lista común):**")
                output_lines = []
                for port in resultados_locales:
                    description = PORT_DATA.get(port, "Servicio común desconocido")
                    output_lines.append(f"- **{port}**: {description}")
                st.markdown("\n".join(output_lines))
                st.caption("Nota: Estos son servicios ejecutándose en tu propio PC.")
            else:
                st.success("No se encontraron puertos abiertos conocidos en localhost (127.0.0.1).")
