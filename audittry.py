import socket
import requests
import ipaddress
from fpdf import FPDF
import streamlit as st
import concurrent.futures

# Function to validate IP address
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Function to scan ports
def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        if sock.connect_ex((ip, port)) == 0:
            return port
    except socket.error:
        return None
    finally:
        sock.close()
    return None

def scan_ports(ip, start_port=1, end_port=1024):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda port: scan_port(ip, port), range(start_port, end_port + 1))
        open_ports = [port for port in results if port is not None]
    return open_ports

# Service mappings
service_to_software = {
    "ssh": ("openbsd", "openssh"),
    "http": ("apache", "http_server"),
    "https": ("apache", "http_server"),
    "ftp": ("vsftpd", "vsftpd"),
    "smtp": ("postfix", "postfix"),
    "mysql": ("oracle", "mysql"),
    "postgresql": ("postgresql", "postgresql"),
    "dns": ("bind", "bind9"),
    "smb": ("microsoft", "smb"),
    "redis": ("redis", "redis"),
    "mongodb": ("mongodb", "mongodb"),
    "telnet": ("telnet", "telnet"),
    "pop3": ("cyrus", "cyrus_pop3d"),
    "imap": ("dovecot", "dovecot"),
    "vnc": ("realvnc", "vnc"),
    "docker": ("docker", "docker"),
}

# Get service name
def get_service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"

# Fetch CVE details
def get_cve_info(service_name, max_cves=3):
    if service_name not in service_to_software:
      return [{"id": "N/A", "description": "No CVE data available", "severity": "N/A"}]
    
    vendor, product = service_to_software[service_name]
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}&resultsPerPage={max_cves}"
    
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        data = response.json()
        
        if "vulnerabilities" in data and data["vulnerabilities"]:
            return [
                {
                    "id": vuln["cve"].get("id", "Unknown"),
                    # "name": vuln["cve"].get("id", "Unknown CVE"),
                    # "type": "Unknown",
                    "description": vuln["cve"].get("descriptions", [{}])[0].get("value", "No description available"),
                    "severity": vuln.get("cve", {}).get("metrics", {}).get("cvssMetricV2", [{}])[0].get("baseSeverity", "Unknown"),
                    "url": f"https://nvd.nist.gov/vuln/detail/{vuln['cve'].get('id', 'Unknown')}"
                }
                for vuln in data["vulnerabilities"][:max_cves]
            ]
        
        return [{"id": "N/A", "name": "Unknown", "type": "Unknown", "description": "No known CVEs found", "severity": "N/A"}]
    except requests.RequestException as e:
        return [{"id": "N/A", "name": "Unknown", "type": "Unknown", "description": f"Error fetching CVE data: {str(e)}", "severity": "N/A"}]

# Scan vulnerabilities
def scan_vulnerabilities(ip, open_ports, max_cves=3):
    results = {}
    for port in open_ports:
        service_name = get_service_name(port)
        cves = get_cve_info(service_name, max_cves)
        results[port] = {"service": service_name, "cves": cves}
    return results

# Generate PDF Report
def generate_pdf_report(data, filename="audit_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Security Audit Report", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, f"Target IP: {data['Target IP']}", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Port Scan Results:", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 10, str(data["Port Scan Results"]))
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Vulnerability Scan Results:", ln=True)
    pdf.set_font("Arial", size=10)
    for port, details in data["Vulnerability Results"].items():
        pdf.cell(0, 10, f"Port {port} ({details['service']}):", ln=True)
        for cve in details["cves"]:
            pdf.multi_cell(0, 10, f"- {cve.get('name', 'Unknown')} ({cve.get('id', 'Unknown')}) ({cve.get('type', 'Unknown')}) ({cve.get('severity', 'Unknown')})\n  {cve.get('description', 'No description available')}")
        pdf.ln(5)

    pdf.output(filename)
    return filename

# Streamlit UI
st.title("Security Audit Tool")

ip_input = st.text_input("Enter IP Address for Security Audit")
start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=1)
end_port = st.number_input("End Port", min_value=1, max_value=65535, value=1024)
max_cves = st.slider("Max CVEs per service", 1, 10, 3)

# Initialize session state
if "open_ports" not in st.session_state:
    st.session_state["open_ports"] = []

if "vuln_results" not in st.session_state:
    st.session_state["vuln_results"] = {}

# Port Scan Button
if st.button("Start Port Scan"):
    if ip_input and is_valid_ip(ip_input):
        with st.spinner("Scanning ports..."):
            st.session_state["open_ports"] = scan_ports(ip_input, start_port, end_port)
        st.write(f"Open Ports: {st.session_state['open_ports']}")

# Vulnerability Scan Button
if st.button("Scan for Vulnerabilities"):
    if ip_input and st.session_state["open_ports"]:
        with st.spinner("Scanning for vulnerabilities..."):
            st.session_state["vuln_results"] = scan_vulnerabilities(ip_input, st.session_state["open_ports"], max_cves)
        st.json(st.session_state["vuln_results"])
    else:
        st.error("Run port scan first!")

# PDF Report Button
if st.button("Generate PDF Report"):
    if ip_input and st.session_state["open_ports"] and st.session_state["vuln_results"]:
        report_data = {
            "Target IP": ip_input,
            "Port Scan Results": st.session_state["open_ports"],
            "Vulnerability Results": st.session_state["vuln_results"]
        }
        pdf_filename = generate_pdf_report(report_data)

        # Provide PDF download option
        with open(pdf_filename, "rb") as f:
            st.download_button("Download Report", f, file_name=pdf_filename, mime="application/pdf")
    else:
        st.error("Run scans before generating report!")
