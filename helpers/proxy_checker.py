import socket
import ssl
import json
import re
import pycountry
import time
import http.client

IP_RESOLVER = "www.cloudflare.com"
PATH_RESOLVER = "/cdn-cgi/trace"
TIMEOUT = 5

def check(host, path, proxy):
    start_time = time.time()
    payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
        "Connection: close\r\n\r\n"
    )

    ip = proxy.get("ip", host)
    port = int(proxy.get("port", 443))

    try:
        # Create SSL context with disabled verification for better compatibility with various proxies
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as conn:
                conn.sendall(payload.encode())
                resp = b""
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    resp += data

                resp = resp.decode("utf-8", errors="ignore")
                if "\r\n\r\n" not in resp:
                    return {"error": "Invalid response format"}, "Unknown", 0

                headers, body = resp.split("\r\n\r\n", 1)
                end_time = time.time()
                connection_time = (end_time - start_time) * 1000

                # Parse Cloudflare trace format (key=value)
                try:
                    data_dict = {}
                    for line in body.splitlines():
                        if "=" in line:
                            key, value = line.split("=", 1)
                            data_dict[key] = value

                    if not data_dict:
                        return {"error": "Empty trace data"}, "Unknown", connection_time

                    http_protocol = data_dict.get("http", "Unknown")
                    # Map trace keys to keys expected by process_proxy for compatibility
                    mapped_data = {
                        "clientIp": data_dict.get("ip"),
                        "country": data_dict.get("loc"),
                        "colo": data_dict.get("colo"),
                        "httpProtocol": data_dict.get("http"),
                        # Trace doesn't provide ASN/Org/Lat/Lon easily without more parsing or other endpoints
                        # But we keep it as is or fill what we can
                        "asn": "Unknown",
                        "asOrganization": "Unknown"
                    }
                    return mapped_data, http_protocol, connection_time
                except Exception as e:
                    error_message = f"Error parsing trace from {ip}:{port}: {e}"
                    print(error_message)
                    return {"error": error_message}, "Unknown", connection_time

    except (socket.timeout, socket.error, ssl.SSLError) as e:
        error_message = f"Connection error from {ip}:{port}: {e}"
        print(error_message)
        return {"error": error_message}, "Unknown", 0

    return {}, "Unknown", 0

def clean_org_name(org_name):
    return re.sub(r'[^a-zA-Z0-9\s]', '', org_name) if org_name else org_name

def get_country_info(alpha_2):
    try:
        if alpha_2:
            country = pycountry.countries.get(alpha_2=alpha_2)
            if country:
                return country.name, getattr(country, 'flag', None)
        return "Unknown", None
    except Exception as e:
        print(f"Error getting country info: {e}")
        return "Unknown", None

def get_ip_metadata(ip):
    try:
        conn = http.client.HTTPConnection("ip-api.com", timeout=5)
        conn.request("GET", f"/json/{ip}")
        response = conn.getresponse()
        if response.status == 200:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return data
    except Exception as e:
        print(f"Error fetching metadata for {ip}: {e}")
    return {}

def process_proxy(ip, port):
    proxy_data = {"ip": ip, "port": port}

    # Use a single check to determine if the proxy is alive
    pxy, pxy_protocol, pxy_connection_time = check(IP_RESOLVER, PATH_RESOLVER, proxy_data)

    # If we got a valid response from the proxy, it's ACTIVE
    if pxy and not pxy.get("error") and pxy.get("clientIp"):
        detected_ip = pxy.get("clientIp")
        metadata = get_ip_metadata(detected_ip)

        org_name = clean_org_name(metadata.get("isp") or pxy.get("asOrganization"))
        proxy_country_code = metadata.get("countryCode") or pxy.get("country") or "Unknown"
        proxy_asn = metadata.get("as") or pxy.get("asn") or "Unknown"
        proxy_latitude = str(metadata.get("lat")) if metadata.get("lat") is not None else "Unknown"
        proxy_longitude = str(metadata.get("lon")) if metadata.get("lon") is not None else "Unknown"
        proxy_colo = pxy.get("colo") or "Unknown"
        proxy_country_name, proxy_country_flag = get_country_info(proxy_country_code)

        result_message = f"Cloudflare Proxy Alive {ip}:{port}"
        print(result_message)
        return "Active", result_message, proxy_country_code, proxy_asn, proxy_country_name, proxy_country_flag, pxy_protocol, org_name, pxy_connection_time, proxy_latitude, proxy_longitude, proxy_colo
    else:
        dead_message = f"Cloudflare Proxy Dead: {ip}:{port}"
        print(dead_message)
        return "Dead", dead_message, "Unknown", "Unknown", "Unknown", None, "Unknown", "Unknown", 0, "Unknown", "Unknown", "Unknown"
