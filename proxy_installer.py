#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interactive Proxy Installer / Uninstaller for Ubuntu
Supported Protocols: VLESS Reality (TCP + XTLS-Vision / xHTTP)
Author: Antigravity AI
"""

import os
import sys
import json
import re
import uuid
import socket
import urllib.request
import urllib.parse
import subprocess
import shutil
import base64

# ANSI Color Codes for Premium Terminal UI
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
RESET = "\033[0m"

# Header logo
BANNER = f"""
{CYAN}{BOLD}┌──────────────────────────────────────────────────────────┐
│             MODERN PROXY INSTALLER & MANAGER             │
│            Powered by Xray-core & Reality Protocol       │
└──────────────────────────────────────────────────────────┘{RESET}
"""

def print_header(title):
    print(f"\n{BOLD}{CYAN}=== {title} ==={RESET}\n")

def print_success(msg):
    print(f"{GREEN}{BOLD}[✔] {msg}{RESET}")

def print_info(msg):
    print(f"{BLUE}[i] {msg}{RESET}")

def print_warning(msg):
    print(f"{YELLOW}{BOLD}[!] {msg}{RESET}")

def print_error(msg):
    print(f"{RED}{BOLD}[✘] {msg}{RESET}")

# ----------------- CRYPTOGRAPHIC HELPERS -----------------
# Curve25519 (X25519) prime field and constants
P_FIELD = 2**255 - 19
A24 = 121665

def curve25519_cswap(swap, x_2, x_3):
    """Constant-time swap helper for Montgomery ladder."""
    dummy = swap * ((x_2 - x_3) % P_FIELD)
    x_2 = (x_2 - dummy) % P_FIELD
    x_3 = (x_3 + dummy) % P_FIELD
    return x_2, x_3

def curve25519_eval(k, u=9):
    """Montgomery ladder for scalar multiplication on Curve25519 (RFC 7748)."""
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0
    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        x_2, x_3 = curve25519_cswap(swap, x_2, x_3)
        z_2, z_3 = curve25519_cswap(swap, z_2, z_3)
        swap = k_t
        
        A = (x_2 + z_2) % P_FIELD
        AA = (A * A) % P_FIELD
        B = (x_2 - z_2) % P_FIELD
        BB = (B * B) % P_FIELD
        E = (AA - BB) % P_FIELD
        C = (x_3 + z_3) % P_FIELD
        D = (x_3 - z_3) % P_FIELD
        DA = (D * A) % P_FIELD
        CB = (C * B) % P_FIELD
        
        x_3 = ((DA + CB) ** 2) % P_FIELD
        z_3 = (x_1 * (DA - CB) ** 2) % P_FIELD
        x_2 = (AA * BB) % P_FIELD
        z_2 = (E * (AA + A24 * E)) % P_FIELD
        
    x_2, x_3 = curve25519_cswap(swap, x_2, x_3)
    z_2, z_3 = curve25519_cswap(swap, z_2, z_3)
    return (x_2 * pow(z_2, P_FIELD - 2, P_FIELD)) % P_FIELD

def get_public_key_from_private(private_key_b64):
    """Derive X25519 public key from a base64url-encoded private key."""
    # Handle padding
    missing_padding = len(private_key_b64) % 4
    if missing_padding:
        private_key_b64 += '=' * (4 - missing_padding)
        
    priv_bytes = bytearray(base64.urlsafe_b64decode(private_key_b64))
    
    # Clamp private key as per RFC 7748
    priv_bytes[0] &= 248
    priv_bytes[31] &= 127
    priv_bytes[31] |= 64
    
    scalar = int.from_bytes(priv_bytes, 'little')
    pub_u = curve25519_eval(scalar, 9)
    pub_bytes = pub_u.to_bytes(32, 'little')
    
    pub_b64 = base64.urlsafe_b64encode(pub_bytes).decode('utf-8')
    return pub_b64.rstrip('=')

# ----------------- SYSTEM CHECKS -----------------

def check_root():
    """Verify that the script is run with sudo/root privileges."""
    if os.geteuid() != 0:
        print_error("This script must be run with root privileges (sudo).")
        print_info("Please run: sudo python3 proxy_installer.py")
        sys.exit(1)

def check_ubuntu():
    """Verify that the host OS is Ubuntu/Debian based."""
    if not os.path.exists("/etc/os-release"):
        print_warning("Could not verify OS type. Proceeding anyway...")
        return
    
    with open("/etc/os-release", "r") as f:
        content = f.read().lower()
        if "ubuntu" not in content and "debian" not in content:
            print_warning("This script is optimized for Ubuntu/Debian. You may experience issues.")

# ----------------- GEOIP & IP AUTO-DETECTION -----------------

def get_public_ip():
    """Detect the server's public IPv4 address with failover endpoints."""
    urls = ["https://api64.ipify.org", "https://ipinfo.io/ip", "https://icanhazip.com"]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                ip = response.read().decode('utf-8').strip()
                if ip:
                    return ip
        except Exception:
            continue
    return None

def get_geoip_info(ip):
    """Retrieve GeoIP details for nice link naming."""
    if not ip:
        return {}
    urls = [f"https://ipapi.co/{ip}/json/", f"https://ipinfo.io/{ip}/json"]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode('utf-8'))
                country_code = data.get("country_code") or data.get("country")
                country_name = data.get("country_name") or data.get("country")
                city = data.get("city")
                org = data.get("org") or data.get("asn") or data.get("company", {}).get("name")
                return {
                    "country_code": country_code,
                    "country_name": country_name,
                    "city": city,
                    "org": org
                }
        except Exception:
            continue
    return {}

def get_emoji_flag(country_code):
    """Generate Emoji Flag from a 2-letter country code."""
    if not country_code or len(country_code) != 2:
        return "🌐"
    return "".join(chr(127397 + ord(c)) for c in country_code.upper())

# ----------------- UTILITY FUNCTIONS -----------------

def run_cmd(cmd, check=True):
    """Execute a system command and return the result."""
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=check, shell=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed: {cmd}")
        print_error(f"Error: {e.stderr}")
        if check:
            sys.exit(1)
        return None

def is_port_in_use(port):
    """Check if the specified TCP port is already in use on the host."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', int(port)))
            return False
    except socket.error:
        return True

def generate_short_id():
    """Generate a valid short ID (8 bytes hex) for Reality."""
    return os.urandom(8).hex()

def generate_xray_keys():
    """Call xray to generate a public/private keypair with robust parsing."""
    try:
        xray_path = shutil.which("xray") or "/usr/local/bin/xray"
        output = run_cmd(f"{xray_path} x25519")
        if not output:
            return None, None
            
        private_key = ""
        public_key = ""
        
        # Method 1: Case-insensitive regex matching for key labels
        priv_match = re.search(r"private\s*key\s*:\s*([a-zA-Z0-9_\-]+)", output, re.IGNORECASE)
        pub_match = re.search(r"public\s*key\s*:\s*([a-zA-Z0-9_\-]+)", output, re.IGNORECASE)
        
        if priv_match:
            private_key = priv_match.group(1).strip()
        if pub_match:
            public_key = pub_match.group(1).strip()
            
        # Method 2: Fallback in case labels are slightly different (e.g. PrivateKey / PublicKey / Private Key)
        if not private_key or not public_key:
            for line in output.splitlines():
                line_lower = line.lower().replace(" ", "").replace("_", "").replace("-", "")
                if "privatekey" in line_lower:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        private_key = parts[1].strip()
                elif "publickey" in line_lower:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        public_key = parts[1].strip()
                        
        # Method 3: Absolute fallback if there are base64-like keys printed directly
        if not private_key or not public_key:
            lines = [line.strip() for line in output.splitlines() if line.strip()]
            potential_keys = []
            for line in lines:
                parts = line.split(":")
                val = parts[-1].strip() if parts else line.strip()
                # X25519 keys are usually 43 characters long
                if len(val) == 43:
                    potential_keys.append(val)
            if len(potential_keys) >= 2:
                private_key = potential_keys[0]
                public_key = potential_keys[1]
                
        return private_key, public_key
    except Exception as e:
        print_error(f"Failed to generate Reality keys using Xray: {e}")
        return None, None

# ----------------- DEPENDENCIES & XRAY INSTALLATION -----------------

def install_xray_core():
    """Install curl, unzip, and Xray-core via its official script."""
    print_info("Installing pre-requisites (curl, unzip)...")
    run_cmd("apt-get update && apt-get install -y curl unzip")
    
    print_info("Downloading and installing/updating Xray-core via official script...")
    # Using official install script in standalone mode
    run_cmd("bash -c \"$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ install")
    
    # Check if xray is installed either in PATH or in standard /usr/local/bin
    if shutil.which("xray") is None and not os.path.exists("/usr/local/bin/xray"):
        print_error("Xray-core installation failed or binary is not in PATH.")
        sys.exit(1)
    
    print_success("Xray-core installed successfully!")

# ----------------- VLESS REALITY CORE LOGIC -----------------

def setup_vless_reality(public_ip, geo_info):
    """Interactive wizard to configure VLESS Reality and start Xray-core."""
    print_header("VLESS Reality Configuration Wizard")
    
    # 1. IP Address confirmation
    ip_addr_input = input(f"{BOLD}Confirm your Server Public IP [{public_ip}]: {RESET}").strip()
    if not ip_addr_input or ip_addr_input.lower() in ["y", "yes", "ok"]:
        ip_addr = public_ip
    else:
        ip_addr = ip_addr_input
    
    # 2. Port choice
    default_port = 443
    while True:
        port_input = input(f"{BOLD}Enter Port for VLESS Reality [{default_port}]: {RESET}").strip()
        if not port_input:
            port = default_port
        else:
            try:
                port = int(port_input)
                if not (1 <= port <= 65535):
                    raise ValueError
            except ValueError:
                print_error("Invalid port number. Must be between 1 and 65535.")
                continue
        
        if is_port_in_use(port):
            print_warning(f"Port {port} seems to be in use by another process.")
            override = input(f"Do you want to use port {port} anyway? (y/N): ").strip().lower()
            if override != 'y':
                continue
        break
    
    # 3. SNI choice
    default_sni = "images.apple.com"
    print_info("Reality requires a popular website to mask traffic. Good options: images.apple.com, dl.google.com, apple.com")
    sni_domain = input(f"{BOLD}Enter SNI Domain [{default_sni}]: {RESET}").strip()
    if not sni_domain:
        sni_domain = default_sni
        
    # Dest is typically sni:443
    dest_address = f"{sni_domain}:443"
    
    # 4. Transport Type
    print("\nSelect Transport Type:")
    print(f"  1) {BOLD}TCP (with XTLS-Vision){RESET} - Recommended for standard use, highest speed.")
    print(f"  2) {BOLD}xHTTP{RESET} - Highly resilient modern transport protocol, great for bypassing DPI.")
    
    transport_choice = input(f"{BOLD}Choose option [1-2] (default 1): {RESET}").strip()
    if transport_choice == '2':
        transport_type = "xhttp"
    else:
        transport_type = "tcp"
        
    flow = ""
    xhttp_path = ""
    xhttp_mode = ""
    
    if transport_type == "tcp":
        use_vision = input(f"{BOLD}Enable XTLS-Vision flow control? (Y/n): {RESET}").strip().lower()
        if use_vision != 'n':
            flow = "xtls-rprx-vision"
    elif transport_type == "xhttp":
        default_path = "/xhttp-path"
        xhttp_path = input(f"{BOLD}Enter xHTTP Path [{default_path}]: {RESET}").strip()
        if not xhttp_path:
            xhttp_path = default_path
        if not xhttp_path.startswith("/"):
            xhttp_path = "/" + xhttp_path
            
        default_mode = "auto"
        xhttp_mode = input(f"{BOLD}Enter xHTTP Mode (auto/download/upload) [{default_mode}]: {RESET}").strip().lower()
        if xhttp_mode not in ["auto", "download", "upload"]:
            xhttp_mode = default_mode

    # 5. Nice Name / Location for Link
    flag = get_emoji_flag(geo_info.get("country_code"))
    city = geo_info.get("city") or "Server"
    org = geo_info.get("org") or ""
    # Simplify organization name (e.g. AWS, DigitalOcean, etc.)
    org_clean = "Server"
    if org:
        org_lower = org.lower()
        if "amazon" in org_lower or "aws" in org_lower:
            org_clean = "AWS"
        elif "digitalocean" in org_lower:
            org_clean = "DigitalOcean"
        elif "hetzner" in org_lower:
            org_clean = "Hetzner"
        elif "linode" in org_lower or "akamai" in org_lower:
            org_clean = "Linode"
        elif "google" in org_lower or "gcp" in org_lower:
            org_clean = "GCP"
        elif "cloudflare" in org_lower:
            org_clean = "Cloudflare"
        else:
            # Fallback to first few words
            org_clean = " ".join(org.split()[:2])

    default_link_name = f"{flag} ({org_clean}) {city}"
    link_name = input(f"{BOLD}Enter Location / Name for connection link [{default_link_name}]: {RESET}").strip()
    if not link_name:
        link_name = default_link_name

    # Make sure Xray-core is installed first to generate keys
    if shutil.which("xray") is None and not os.path.exists("/usr/local/bin/xray"):
        install_xray_core()
        
    # 6. Generate VLESS client parameters
    print_info("Generating Reality cryptographic keys...")
    private_key, public_key = generate_xray_keys()
    if not private_key or not public_key:
        print_error("Failed to generate keys. Aborting.")
        # Print debug command output
        try:
            xray_path = shutil.which("xray") or "/usr/local/bin/xray"
            debug_out = run_cmd(f"{xray_path} x25519", check=False)
            print_info(f"Debug - Raw output of '{xray_path} x25519' was:\n{debug_out}")
        except Exception as e:
            print_error(f"Could not run debug tool: {e}")
        return
        
    client_uuid = str(uuid.uuid4())
    short_id = generate_short_id()
    
    # 7. Create local HTTP fallback service using Python's built-in http.server
    # This prevents abrupt TCP RST connection drops on raw plain-text / malformed TCP probes
    print_info("Deploying local HTTP fallback service to prevent active probing TCP RST detection...")
    
    fallback_port = 18080
    while is_port_in_use(fallback_port):
        fallback_port += 1
        
    print_info(f"Local HTTP fallback server will run on 127.0.0.1:{fallback_port}")
    
    # Run with standard permissions (removing User=nobody) to avoid any Ubuntu permission/library limits
    fallback_service_content = f"""[Unit]
Description=Lightweight HTTP Fallback Service for Xray
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -m http.server {fallback_port} --bind 127.0.0.1
Restart=always

[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open("/etc/systemd/system/xray-fallback.service", "w") as f:
            f.write(fallback_service_content)
        run_cmd("systemctl daemon-reload")
        run_cmd("systemctl enable xray-fallback")
        run_cmd("systemctl restart xray-fallback")
        
        # Verify fallback service starts successfully
        fallback_status = run_cmd("systemctl is-active xray-fallback", check=False)
        if fallback_status != "active":
            print_warning("Fallback helper failed to start. Reading logs...")
            fallback_logs = run_cmd("journalctl -u xray-fallback --no-pager -n 10", check=False)
            print(fallback_logs)
            fallback_port = None
        else:
            print_success("Local HTTP fallback service deployed and started successfully!")
    except Exception as e:
        print_warning(f"Could not setup local http fallback service: {e}. Falling back directly to SNI domain.")
        fallback_port = None
        
    # 8. Build Xray Server config.json
    print_info("Building Xray server configuration file...")
    
    inbound_config = {
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": [
                {
                    "id": client_uuid
                }
            ],
            "decryption": "none"
        },
        "streamSettings": {
            "network": transport_type,
            "security": "reality",
            "realitySettings": {
                "show": False,
                "dest": dest_address,
                "xver": 0,
                "serverNames": [
                    sni_domain
                ],
                "privateKey": private_key,
                "minVersion": "",
                "maxVersion": "",
                "cipherSuites": "",
                "shortIds": [
                    short_id
                ]
            }
        }
    }
    
    # Configure fallbacks using strict integer dest as per standard VLESS config schema
    if fallback_port:
        inbound_config["settings"]["fallbacks"] = [
            {
                # Forward plain-text/malformed probes to local server returning standard HTTP 400 Bad Request
                "dest": fallback_port
            }
        ]
    else:
        # Remote fallback
        inbound_config["settings"]["fallbacks"] = [
            {
                "dest": f"{sni_domain}:80"
            }
        ]
    
    # Apply TCP Flow or xHTTP Settings
    if transport_type == "tcp" and flow:
        inbound_config["settings"]["clients"][0]["flow"] = flow
    elif transport_type == "xhttp":
        inbound_config["streamSettings"]["xhttpSettings"] = {
            "path": xhttp_path,
            "mode": xhttp_mode
        }
        
    xray_config = {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            inbound_config
        ],
        "outbounds": [
            {
                "protocol": "freedom"
            }
        ]
    }
    
    # Ensure config folder exists
    os.makedirs("/usr/local/etc/xray", exist_ok=True)
    config_path = "/usr/local/etc/xray/config.json"
    
    with open(config_path, "w") as f:
        json.dump(xray_config, f, indent=2)
        
    # Cache public key and link name for retrieval later
    try:
        with open("/usr/local/etc/xray/public_key.txt", "w") as f:
            f.write(public_key)
        with open("/usr/local/etc/xray/link_name.txt", "w") as f:
            f.write(link_name)
    except Exception as e:
        print_warning(f"Could not cache public key or link name: {e}")
        
    print_success(f"Config successfully written to {config_path}")
    
    # 9. Start and enable Xray Service via systemd
    print_info("Starting and enabling Xray systemd service...")
    run_cmd("systemctl daemon-reload")
    run_cmd("systemctl enable xray")
    run_cmd("systemctl restart xray")
    
    # Verify service is running
    status = run_cmd("systemctl is-active xray", check=False)
    if status != "active":
        print_warning("Xray service is not active. Checking logs...")
        logs = run_cmd("journalctl -u xray --no-pager -n 10", check=False)
        print(logs)
        print_error("Failed to start Xray. Please inspect logs above.")
        return

    print_success("Xray service started and enabled successfully!")
    
    # 10. Generate final client VLESS Link
    query_params = {
        "flow": flow,
        "type": transport_type,
        "host": "",
        "path": xhttp_path if transport_type == "xhttp" else "",
        "mode": xhttp_mode if transport_type == "xhttp" else "",
        "security": "reality",
        "fp": "chrome",
        "sni": sni_domain,
        "pbk": public_key,
        "sid": short_id
    }
    
    if transport_type == "tcp":
        query_params["headerType"] = "none"
        
    # Format query string manually to keep order clean and nice
    query_parts = []
    for k, v in query_params.items():
        query_parts.append(f"{k}={v}")
    
    query_str = "&".join(query_parts)
    
    # URL encode the hash name
    link_hash = urllib.parse.quote(link_name)
    vless_link = f"vless://{client_uuid}@{ip_addr}:{port}?{query_str}#{link_hash}"
    
    # 11. Display installation success and client link
    print_header("VLESS REALITY INSTALLED SUCCESSFULLY")
    print(f"{GREEN}{BOLD}Your client configuration details:{RESET}")
    print(f"  • {BOLD}Protocol:{RESET} VLESS")
    print(f"  • {BOLD}Transport:{RESET} {transport_type.upper()}")
    if transport_type == "tcp" and flow:
        print(f"  • {BOLD}Flow:{RESET} {flow}")
    elif transport_type == "xhttp":
        print(f"  • {BOLD}Path:{RESET} {xhttp_path}")
        print(f"  • {BOLD}Mode:{RESET} {xhttp_mode}")
    print(f"  • {BOLD}Port:{RESET} {port}")
    print(f"  • {BOLD}SNI (Mask domain):{RESET} {sni_domain}")
    print(f"  • {BOLD}Public Key:{RESET} {public_key}")
    print(f"  • {BOLD}Short ID (sid):{RESET} {short_id}")
    print(f"  • {BOLD}Client UUID:{RESET} {client_uuid}")
    print(f"  • {BOLD}Location/Name:{RESET} {link_name}")
    print("\n" + "="*80 + "\n")
    print(f"{CYAN}{BOLD}Copy and import this link into Streisand, hApp, Hiddify, FoXray or v2rayNG:{RESET}")
    print(f"\n{GREEN}{BOLD}{vless_link}{RESET}\n")
    print("="*80 + "\n")

# ----------------- URL RETRIEVAL LOGIC -----------------

def show_active_connection_url(public_ip):
    """Retrieve and display the currently active VLESS Reality connection URL."""
    print_header("Active Proxy Connection Details")
    
    config_path = "/usr/local/etc/xray/config.json"
    if not os.path.exists(config_path):
        print_error("No active Xray configuration found. Please run Option 1 first to install.")
        return
        
    try:
        with open(config_path, "r") as f:
            xray_config = json.load(f)
    except Exception as e:
        print_error(f"Failed to read or parse Xray config: {e}")
        return
        
    # Check if we have inbounds
    inbounds = xray_config.get("inbounds", [])
    if not inbounds:
        print_error("Configuration has no inbounds defined.")
        return
        
    inbound = inbounds[0]
    protocol = inbound.get("protocol")
    if protocol != "vless":
        print_error(f"Active protocol '{protocol}' is not supported for URL retrieval.")
        return
        
    # Extract settings
    settings = inbound.get("settings", {})
    clients = settings.get("clients", [])
    if not clients:
        print_error("No clients configured in the active inbound.")
        return
        
    client_uuid = clients[0].get("id")
    flow = clients[0].get("flow", "")
    port = inbound.get("port")
    
    stream_settings = inbound.get("streamSettings", {})
    transport_type = stream_settings.get("network", "tcp")
    reality_settings = stream_settings.get("realitySettings", {})
    
    sni_domain = reality_settings.get("serverNames", ["images.apple.com"])[0]
    short_id = reality_settings.get("shortIds", [""])[0]
    
    xhttp_path = ""
    xhttp_mode = ""
    if transport_type == "xhttp":
        xhttp_settings = stream_settings.get("xhttpSettings", {})
        xhttp_path = xhttp_settings.get("path", "")
        xhttp_mode = xhttp_settings.get("mode", "")
        
    # Try to load cached public key, or derive it from the private key in config.json!
    public_key = ""
    pubkey_path = "/usr/local/etc/xray/public_key.txt"
    if os.path.exists(pubkey_path):
        try:
            with open(pubkey_path, "r") as f:
                public_key = f.read().strip()
        except Exception:
            pass
            
    # If not in cache, mathematically derive it from the private key in config.json!
    if not public_key:
        private_key = reality_settings.get("privateKey", "")
        if private_key:
            try:
                public_key = get_public_key_from_private(private_key)
                # Cache it for next time
                try:
                    with open(pubkey_path, "w") as f:
                        f.write(public_key)
                except Exception:
                    pass
            except Exception as e:
                print_warning(f"Could not derive public key from private key: {e}")
                
    if not public_key:
        print_warning("Cryptographic public key (pbk) was not found in the local cache and could not be derived.")
        provide_key = input("If you have the public key, enter it now (or press Enter to skip): ").strip()
        if provide_key:
            public_key = provide_key
        else:
            public_key = "MISSING_PUBLIC_KEY"
            
    # Try to load cached link name
    link_name = ""
    linkname_path = "/usr/local/etc/xray/link_name.txt"
    if os.path.exists(linkname_path):
        try:
            with open(linkname_path, "r") as f:
                link_name = f.read().strip()
        except Exception:
            pass
            
    if not link_name:
        # Dynamically detect GeoIP location if cache is missing!
        geo_info = get_geoip_info(public_ip)
        if geo_info:
            flag = get_emoji_flag(geo_info.get("country_code"))
            city = geo_info.get("city") or "Server"
            org = geo_info.get("org") or ""
            org_clean = "Server"
            if org:
                org_lower = org.lower()
                if "amazon" in org_lower or "aws" in org_lower:
                    org_clean = "AWS"
                elif "digitalocean" in org_lower:
                    org_clean = "DigitalOcean"
                elif "hetzner" in org_lower:
                    org_clean = "Hetzner"
                elif "linode" in org_lower or "akamai" in org_lower:
                    org_clean = "Linode"
                elif "google" in org_lower or "gcp" in org_lower:
                    org_clean = "GCP"
                elif "cloudflare" in org_lower:
                    org_clean = "Cloudflare"
                else:
                    org_clean = " ".join(org.split()[:2])
            link_name = f"{flag} ({org_clean}) {city}"
            # Cache it for next time
            try:
                with open(linkname_path, "w") as f:
                    f.write(link_name)
            except Exception:
                pass
        else:
            link_name = "🌐 (AWS) Server"
        
    # Reconstruct VLESS Link
    query_params = {
        "flow": flow,
        "type": transport_type,
        "host": "",
        "path": xhttp_path if transport_type == "xhttp" else "",
        "mode": xhttp_mode if transport_type == "xhttp" else "",
        "security": "reality",
        "fp": "chrome",
        "sni": sni_domain,
        "pbk": public_key,
        "sid": short_id
    }
    
    if transport_type == "tcp":
        query_params["headerType"] = "none"
        
    # Format query string manually to keep order clean and nice
    query_parts = []
    for k, v in query_params.items():
        query_parts.append(f"{k}={v}")
    query_str = "&".join(query_parts)
    
    # URL encode the hash name
    link_hash = urllib.parse.quote(link_name)
    vless_link = f"vless://{client_uuid}@{public_ip}:{port}?{query_str}#{link_hash}"
    
    # Display details
    print_success("Active connection configuration successfully reconstructed!")
    print(f"  • {BOLD}Protocol:{RESET} VLESS")
    print(f"  • {BOLD}Transport:{RESET} {transport_type.upper()}")
    if transport_type == "tcp" and flow:
        print(f"  • {BOLD}Flow:{RESET} {flow}")
    elif transport_type == "xhttp":
        print(f"  • {BOLD}Path:{RESET} {xhttp_path}")
        print(f"  • {BOLD}Mode:{RESET} {xhttp_mode}")
    print(f"  • {BOLD}Port:{RESET} {port}")
    print(f"  • {BOLD}SNI (Mask domain):{RESET} {sni_domain}")
    print(f"  • {BOLD}Public Key (pbk):{RESET} {public_key}")
    print(f"  • {BOLD}Short ID (sid):{RESET} {short_id}")
    print(f"  • {BOLD}Client UUID:{RESET} {client_uuid}")
    print(f"  • {BOLD}Location/Name:{RESET} {link_name}")
    print("\n" + "="*80 + "\n")
    print(f"{CYAN}{BOLD}Copy and import this link into Streisand, hApp, Hiddify, FoXray or v2rayNG:{RESET}")
    print(f"\n{GREEN}{BOLD}{vless_link}{RESET}\n")
    print("="*80 + "\n")

# ----------------- UNINSTALL LOGIC -----------------

def run_uninstall():
    """Completely remove Xray-core, services, and configurations from the system."""
    print_header("UNINSTALL PROXY SERVICES")
    print_warning("This option will stop, disable, and completely remove Xray-core, its fallback helper, and all config files.")
    confirm = input("Are you absolutely sure you want to proceed? (y/N): ").strip().lower()
    if confirm != 'y':
        print_info("Uninstallation cancelled.")
        return
        
    print_info("Stopping and disabling Xray systemd service...")
    run_cmd("systemctl stop xray", check=False)
    run_cmd("systemctl disable xray", check=False)
    
    print_info("Stopping and disabling Xray HTTP fallback helper service...")
    run_cmd("systemctl stop xray-fallback", check=False)
    run_cmd("systemctl disable xray-fallback", check=False)
    if os.path.exists("/etc/systemd/system/xray-fallback.service"):
        try:
            os.remove("/etc/systemd/system/xray-fallback.service")
            print_info("Removed fallback service unit file.")
        except Exception as e:
            print_warning(f"Could not remove fallback service file: {e}")
            
    # Use official script removal flag if available, or do it manually
    print_info("Running Xray official uninstaller script...")
    run_cmd("bash -c \"$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)\" @ remove", check=False)
    
    # Manual deep cleaning to guarantee no residual files
    print_info("Performing deep cleaning of remaining files...")
    paths_to_remove = [
        "/usr/local/etc/xray",
        "/usr/local/share/xray",
        "/var/log/xray",
        "/etc/systemd/system/xray.service",
        "/etc/systemd/system/xray.service.d"
    ]
    
    for path in paths_to_remove:
        if os.path.exists(path):
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                print_info(f"Removed residual: {path}")
            except Exception as e:
                print_warning(f"Could not remove path {path}: {e}")
                
    # Also look for xray binary in standard paths just in case
    for binary_path in ["/usr/local/bin/xray", "/usr/bin/xray"]:
        if os.path.exists(binary_path):
            try:
                os.remove(binary_path)
                print_info(f"Removed binary: {binary_path}")
            except Exception as e:
                print_warning(f"Could not remove binary {binary_path}: {e}")
                
    print_info("Reloading systemd daemon...")
    run_cmd("systemctl daemon-reload", check=False)
    
    print_success("Proxy services have been completely uninstalled!")

# ----------------- MAIN CLI MENU -----------------

def main():
    print(BANNER)
    
    # Pre-run system audits
    check_root()
    check_ubuntu()
    
    # Auto-detection
    print_info("Auto-detecting Server Public IP and GeoIP location...")
    public_ip = get_public_ip()
    if not public_ip:
        print_warning("Could not detect public IP address automatically.")
        public_ip = "127.0.0.1"
    else:
        print_success(f"Detected Public IP: {public_ip}")
        
    geo_info = get_geoip_info(public_ip)
    if geo_info:
        flag = get_emoji_flag(geo_info.get("country_code"))
        print_success(f"Detected Location: {flag} {geo_info.get('city') or ''}, {geo_info.get('country_name') or ''} (Provider: {geo_info.get('org') or 'Unknown'})")
    else:
        print_warning("Could not determine GeoIP details automatically.")
    
    while True:
        print("\n" + "="*50)
        print(f"{BOLD}MAIN MENU:{RESET}")
        print(f"  1) {BOLD}{GREEN}Install / Reconfigure VLESS Reality{RESET} (TCP-Vision / xHTTP)")
        print(f"  2) {BOLD}{CYAN}Show active connection URL{RESET}")
        print(f"  3) {BOLD}{RED}Uninstall all proxy services{RESET}")
        print(f"  4) Exit")
        print("="*50)
        
        choice = input(f"{BOLD}Choose option [1-4]: {RESET}").strip()
        
        if choice == '1':
            setup_vless_reality(public_ip, geo_info)
        elif choice == '2':
            show_active_connection_url(public_ip)
        elif choice == '3':
            run_uninstall()
        elif choice == '4':
            print("\nGoodbye!\n")
            break
        else:
            print_error("Invalid option. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user. Exiting.")
        sys.exit(0)
