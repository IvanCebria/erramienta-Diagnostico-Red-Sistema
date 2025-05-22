# diccionario.py

# Diccionario que mapea puertos TCP comunes a sus descripciones/servicios habituales
PORT_DATA = {
    21: "FTP (Transferencia de Ficheros - Control)",
    22: "SSH (Secure Shell - Acceso Remoto Seguro) / SFTP",
    23: "Telnet (Acceso Remoto - Inseguro)",
    25: "SMTP (Envío de Correo Electrónico)",
    53: "DNS (Sistema de Nombres de Dominio)",
    80: "HTTP (Web - Tráfico No Cifrado)",
    110: "POP3 (Recepción de Correo Electrónico)",
    135: "RPC (Microsoft EPMAP / Localizador de Servicios)",
    139: "NetBIOS Session Service (Compartición Windows Antigua)",
    143: "IMAP (Recepción de Correo Electrónico)",
    443: "HTTPS (Web - Tráfico Seguro SSL/TLS)",
    445: "SMB/CIFS (Compartición Archivos/Impresoras Windows)",
    993: "IMAPS (IMAP Seguro SSL/TLS)",
    995: "POP3S (POP3 Seguro SSL/TLS)",
    1433: "Microsoft SQL Server (Base de Datos)",
    1723: "PPTP (VPN - Obsoleto/Inseguro)",
    3306: "MySQL / MariaDB (Base de Datos)",
    3389: "RDP (Escritorio Remoto Windows)",
    5900: "VNC (Control Remoto Gráfico)",
    8080: "HTTP Alternativo / Proxy / Apache Tomcat",
    8443: "HTTPS Alternativo / Tomcat SSL"
    # Puedes añadir más puertos y descripciones aquí si lo necesitas
    # Asegúrate de que los puertos coincidan con la lista PUERTOS_COMUNES_TCP en app.py
}
