import socket
import json
import ipaddress
import concurrent.futures
import streamlit as st
from fpdf import FPDF

# Load vulnerability database
def load_vulnerability_db(filename="vulnerabilities.json"):
    with open(filename, "r") as f:
        return json.load(f)

# Validate IP addresses
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Scan a single port
def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return port if sock.connect_ex((ip, port)) == 0 else None

# Scan ports concurrently
def scan_ports(ip, start_port=1, end_port=1024):
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(lambda port: scan_port(ip, port), range(start_port, end_port + 1))
    return [port for port in results if port is not None]

# Identify service name
def get_service_name(port):
    return {
        22: "ssh", 80: "http", 443: "https", 21: "ftp", 25: "smtp", 3306: "mysql", 
        5432: "postgresql", 3389: "rdp", 23: "telnet", 53: "dns", 445: "smb"
    }.get(port, "Unknown")

# Scan for vulnerabilities
def scan_vulnerabilities(ip, open_ports):
    db = load_vulnerability_db()
    results = {}
    for port in open_ports:
        service = get_service_name(port)
        cves = db.get(service, [{"id": "N/A", "name": "Unknown", "type": "Unknown", "severity": "N/A", "description": "No CVE data available"}])
        results[port] = {"service": service, "cves": cves}
    return results

# Generate PDF Report for multiple IPs
def generate_pdf_report(scan_data, filename="audit_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Security Audit Report", ln=True, align="C")
    
    for data in scan_data:
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, f"Target IP: {data['Target IP']}", ln=True)
        
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 10, "Vulnerability Scan Results:", ln=True)
        pdf.set_font("Arial", size=10)
        
        for port, details in data["Vulnerability Results"].items():
            pdf.multi_cell(0, 10, f"Port {port} ({details['service']}):")
            for cve in details["cves"]:
                pdf.multi_cell(0, 10, f"- {cve['name']} ({cve['id']}) ({cve['type']}) ({cve['severity']})\n  {cve['description']}")
        
        pdf.ln(5)
    
    pdf.output(filename)

# Streamlit UI
st.set_page_config(page_title="Security Audit Tool", layout="wide")

# Apply custom styling
st.markdown("""
    <style>
        .stButton>button {
            background-color: #4CAF50;
            color: white;
            font-size: 16px;
            border-radius: 10px;
            padding: 8px 16px;
        }
        .stTextArea textarea, .stNumberInput input {
            font-size: 16px;
        }
    </style>
""", unsafe_allow_html=True)

# Sidebar for input fields
st.sidebar.title("🔍 Security Audit Tool")
st.sidebar.markdown("Enter details below to begin the scan.")

ip_input = st.sidebar.text_area("🖥️ Enter IP Addresses (comma-separated)")
start_port = st.sidebar.number_input("🚪 Start Port", min_value=1, max_value=65535, value=1)
end_port = st.sidebar.number_input("🚪 End Port", min_value=1, max_value=65535, value=1024)

# Main page title
st.title("🛡️ Security Audit Dashboard")

# Start scan button
if st.sidebar.button("🚀 Start Scan"):
    ip_list = [ip.strip() for ip in ip_input.split(",") if is_valid_ip(ip.strip())]
    if not ip_list:
        st.sidebar.error("❌ Please enter at least one valid IP address.")
    else:
        scan_results = []
        progress_bar = st.progress(0)
        status_placeholder = st.empty()

        for index, ip in enumerate(ip_list):
            status_placeholder.info(f"Scanning {ip}...")
            open_ports = scan_ports(ip, start_port, end_port)
            vuln_results = scan_vulnerabilities(ip, open_ports)
            scan_data = {"Target IP": ip, "ports": open_ports, "Vulnerability Results": vuln_results}
            scan_results.append(scan_data)

            with st.expander(f"📌 Results for {ip}"):
                st.write(f"**Open Ports:** {open_ports}")
                st.json(vuln_results)

            progress_bar.progress((index + 1) / len(ip_list))
        
        status_placeholder.success("✅ Scan Completed!")
        
        if scan_results:
            scan_results_json = json.dumps(scan_results, indent=4)
            st.download_button(label="📥 Download Report (JSON)", data=scan_results_json, file_name="scan_results.json", mime="application/json")
            
            pdf_filename = "audit_report.pdf"
            generate_pdf_report(scan_results, pdf_filename)
            
            with open(pdf_filename, "rb") as f:
                st.download_button(label="📄 Download Report (PDF)", data=f, file_name=pdf_filename, mime="application/pdf")
