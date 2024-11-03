import tkinter as tk
from tkinter import messagebox
from tkinter import font as tkfont
import socket
from concurrent.futures import ThreadPoolExecutor
import logging
from urllib.parse import urlparse

# Set up logging to append to the log file
log_file = "portscan_log.txt"
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

# Common services for some well-known ports
COMMON_PORTS = {
    20: 'FTP Data', 21: 'FTP Control', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP (Server)', 68: 'DHCP (Client)', 80: 'HTTP', 110: 'POP3',
    135: 'MS RPC', 137: 'NetBIOS Name Service', 138: 'NetBIOS Datagram Service',
    139: 'NetBIOS Session Service', 143: 'IMAP', 161: 'SNMP', 194: 'IRC',
    389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog',
    515: 'LPD', 587: 'SMTP Submission', 631: 'IPP (CUPS)', 902: 'VMware Server',
    993: 'IMAPS', 995: 'POP3S', 1025: 'NFS or IIS', 1080: 'SOCKS Proxy',
    1194: 'OpenVPN', 1433: 'MSSQL', 1521: 'Oracle Database', 1723: 'PPTP',
    2049: 'NFS', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
    5984: 'CouchDB', 6379: 'Redis', 6667: 'IRC', 8000: 'Common Web Servers',
    8080: 'HTTP Alternative', 8443: 'HTTPS Alternative', 9000: 'SonarQube',
    9092: 'Kafka', 9200: 'Elasticsearch', 10000: 'Webmin', 16080: 'Alternate HTTP',
    11211: 'Memcached', 27017: 'MongoDB', 50000: 'SAP Application Server',
}

TIMEOUT = 0.3  # Reduced timeout for faster scans

def scan_port(ip, port):
    """Attempts to connect to a port on the specified IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        result = s.connect_ex((ip, port))
        if result == 0:
            service = COMMON_PORTS.get(port, 'Unknown Service')
            return port, service
        return None

def scan_ports(ip, start_port, end_port):
    """Scans a range of ports on the specified IP address."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=200) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in range(start_port, end_port + 1)}
        for future in future_to_port:
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

def resolve_target(target):
    """Resolve the target, whether it's a URL, hostname, or IP address."""
    try:
        parsed_url = urlparse(target)
        hostname = parsed_url.hostname
        if hostname:
            return socket.gethostbyname(hostname), hostname
        try:
            ip_address = socket.gethostbyname(target)
            return ip_address, target
        except socket.gaierror:
            return None, None
    except Exception as e:
        print(f"Error resolving target: {e}")
        return None, None

def clear_text_widget(widget):
    """Clears the text widget."""
    widget.delete(1.0, tk.END)

def display_results(text_widget, open_ports):
    """Displays the scan results in the text widget."""
    clear_text_widget(text_widget)
    if open_ports:
        max_port_length = max(len(str(port)) for port, _ in open_ports) if open_ports else 5
        max_service_length = max(len(service) for _, service in open_ports) if open_ports else 18

        text_widget.insert(tk.END, "🔓 Open Ports:\n", 'header')
        text_widget.insert(tk.END, "┌" + "─" * (max_port_length + 2) + "┬" + "─" * (max_service_length + 2) + "┐\n", 'border')
        text_widget.insert(tk.END, f"│ {'Port':<{max_port_length}} │ {'Service':<{max_service_length}} │\n", 'header')
        text_widget.insert(tk.END, "├" + "─" * (max_port_length + 2) + "┼" + "─" * (max_service_length + 2) + "┤\n", 'border')

        for port, service in open_ports:
            text_widget.insert(tk.END, f"│ {port:<{max_port_length}} │ {service:<{max_service_length}} │\n", 'entry')
        
        text_widget.insert(tk.END, "└" + "─" * (max_port_length + 2) + "┴" + "─" * (max_service_length + 2) + "┘\n", 'border')
        
        text_widget.insert(tk.END, "\n📋 List of all open ports:\n", 'list_header')
        for port, service in open_ports:
            text_widget.insert(tk.END, f"Port {port} - {service}\n", 'list_entry')

        logging.info(f"Open Ports: {open_ports}")
    else:
        text_widget.insert(tk.END, "❌ No open ports found.\n", 'error')
        logging.info("No open ports found.")

def start_scan():
    """Starts the port scanning process based on user input."""
    target = entry_target.get().strip()
    start_port = entry_start_port.get().strip()
    end_port = entry_end_port.get().strip()

    if not target or not start_port or not end_port:
        messagebox.showwarning("Input Error", "Please enter all required fields.")
        return

    try:
        start_port = int(start_port)
        end_port = int(end_port)
    except ValueError:
        messagebox.showwarning("Input Error", "Port values must be integers.")
        return

    if start_port > end_port:
        messagebox.showwarning("Input Error", "Start port cannot be greater than end port.")
        return

    ip_address, resolved_target = resolve_target(target)
    if not ip_address:
        messagebox.showerror("Resolution Error", "Unable to resolve IP address or hostname.")
        return

    open_ports = scan_ports(ip_address, start_port, end_port)
    display_results(text_results, open_ports)

def create_gui():
    """Create the main GUI window."""
    global entry_target, entry_start_port, entry_end_port, text_results

    root = tk.Tk()
    root.title("Open Port Finder")
    root.geometry("800x600")
    root.configure(bg='#ffffff')

    # Title Label
    tk.Label(root, text="Open Port Finder", font=("Helvetica", 18, "bold"), bg='#ffffff', fg='#333333').pack(pady=20)

    # Target Entry
    tk.Label(root, text="Enter the IP address, hostname, or full URL:", font=("Helvetica", 14), bg='#ffffff').pack(pady=5)
    entry_target = tk.Entry(root, width=60, font=("Helvetica", 12))
    entry_target.pack(pady=5)

    # Port Range Entry
    tk.Label(root, text="Enter the range of ports to scan:", font=("Helvetica", 14), bg='#ffffff').pack(pady=10)

    frame_ports = tk.Frame(root, bg='#ffffff')
    frame_ports.pack(pady=5)

    tk.Label(frame_ports, text="Start Port:", font=("Helvetica", 12, 'bold', 'italic'), bg='#ffffff').pack(side=tk.LEFT, padx=10)
    entry_start_port = tk.Entry(frame_ports, width=10, font=("Helvetica", 12))
    entry_start_port.pack(side=tk.LEFT, padx=10)

    tk.Label(frame_ports, text="End Port:", font=("Helvetica", 12, 'bold', 'italic'), bg='#ffffff').pack(side=tk.LEFT, padx=10)
    entry_end_port = tk.Entry(frame_ports, width=10, font=("Helvetica", 12))
    entry_end_port.pack(side=tk.LEFT, padx=10)

    # Start Scan Button
    tk.Button(root, text="Start Scan", font=("Helvetica", 12, "bold"), bg="#007bff", fg="#ffffff", command=start_scan).pack(pady=20)

    # Results Text Widget
    text_results = tk.Text(root, wrap=tk.WORD, height=20, width=80, font=("Helvetica", 12))
    text_results.pack(pady=10)

    # Tags for formatting text
    text_results.tag_configure('header', font=('Helvetica', 12, 'bold'))
    text_results.tag_configure('list_header', font=('Helvetica', 12, 'bold'))
    text_results.tag_configure('list_entry', font=('Helvetica', 12))
    text_results.tag_configure('entry', font=('Helvetica', 12))
    text_results.tag_configure('border', font=('Helvetica', 12, 'bold'))
    text_results.tag_configure('error', foreground='red')

    root.mainloop()

if __name__ == "__main__":
    create_gui()
