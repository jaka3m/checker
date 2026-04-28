from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
import socket
import ssl
import json
import re
import pycountry
import time
import csv
import io
from concurrent.futures import ThreadPoolExecutor

# Constants
IP_RESOLVER = "speed.cloudflare.com"
PATH_RESOLVER = "/meta"
TIMEOUT = 7
MAX_BATCH_SIZE = 10

app = FastAPI()

# Helper Functions
def check(host, path, proxy):
    start_time = time.time()
    # Headers to simulate browser request and get JSON response from cloudflare /meta
    payload = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"
        "Accept: application/json\r\n"
        "Referer: https://speed.cloudflare.com/\r\n"
        "Connection: close\r\n\r\n"
    )

    ip = proxy.get("ip", host)
    port = int(proxy.get("port", 443))

    try:
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

                resp_str = resp.decode("utf-8", errors="ignore")
                if "\r\n\r\n" not in resp_str:
                    return {"error": "Invalid response format"}, "Unknown", 0

                headers, body = resp_str.split("\r\n\r\n", 1)
                end_time = time.time()
                connection_time = (end_time - start_time) * 1000

                try:
                    json_body = json.loads(body)
                    return json_body, json_body.get("httpProtocol", "Unknown"), connection_time
                except Exception as e:
                    return {"error": f"JSON Parse error: {e}"}, "Unknown", connection_time

    except Exception as e:
        return {"error": str(e)}, "Unknown", 0

def clean_org_name(org_name):
    return re.sub(r'[^a-zA-Z0-9\s]', '', org_name) if org_name else org_name

def get_country_info(alpha_2):
    try:
        if alpha_2:
            country = pycountry.countries.get(alpha_2=alpha_2)
            if country:
                return country.name, getattr(country, 'flag', None)
        return "Unknown", None
    except:
        return "Unknown", None

def measure_speed(ip, port):
    """Simple speed test by measuring time to receive headers from a known small endpoint"""
    start_time = time.time()
    payload = (
        "GET /gen_204 HTTP/1.1\r\n"
        "Host: www.google.com\r\n"
        "Connection: close\r\n\r\n"
    )
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            sock.sendall(payload.encode())
            sock.recv(1024)
            end_time = time.time()
            # This is a rough estimation of throughput based on latency of a tiny request
            return f"{round(1000 / (end_time - start_time), 2)} KB/s"
    except:
        return "N/A"

def process_single_proxy(raw_ip_input):
    parts = re.split(r'[:=-]', raw_ip_input.strip(), 1)
    ip_address = parts[0]
    port_str = parts[1] if len(parts) > 1 else "443"

    try:
        port_number = int(port_str)
    except:
        return {"ip": ip_address, "port": port_str, "status": "INVALID_PORT"}

    pxy, pxy_protocol, pxy_connection_time = check(IP_RESOLVER, PATH_RESOLVER, {"ip": ip_address, "port": port_number})

    if pxy and not pxy.get("error") and pxy.get("clientIp"):
        speed = measure_speed(ip_address, port_number)
        proxy_country_code = pxy.get("country") or "Unknown"
        proxy_country_name, proxy_country_flag = get_country_info(proxy_country_code)

        # Cloudflare provides colo as a dictionary or string
        colo_data = pxy.get("colo")
        if isinstance(colo_data, dict):
            colo_name = colo_data.get("iata") or "Unknown"
        else:
            colo_name = str(colo_data) if colo_data else "Unknown"

        return {
            "ip": ip_address,
            "port": port_number,
            "status": "ACTIVE",
            "isp": clean_org_name(pxy.get("asOrganization") or "Unknown"),
            "countryCode": proxy_country_code,
            "country": f"{proxy_country_name} {proxy_country_flag or ''}".strip(),
            "asn": f"AS{pxy.get('asn')}" if pxy.get('asn') else "Unknown",
            "colo": colo_name,
            "httpProtocol": pxy_protocol,
            "delay": f"{round(pxy_connection_time)} ms",
            "speed_est": speed,
            "latitude": str(pxy.get("latitude", "Unknown")),
            "longitude": str(pxy.get("longitude", "Unknown")),
        }
    else:
        return {
            "ip": ip_address,
            "port": port_number,
            "status": "DEAD",
            "error": pxy.get("error", "Unknown error")
        }

@app.get("/check")
def check_proxy_endpoint(
    request: Request,
    ip: str = Query(..., description="IP Proxy. Gunakan koma untuk batch check."),
    format: str = Query("json", description="Output format: json, text, csv")
):
    raw_inputs = ip.split(",")
    if len(raw_inputs) > MAX_BATCH_SIZE:
        return JSONResponse(status_code=400, content={"error": f"Maksimal {MAX_BATCH_SIZE} IP per request."})

    with ThreadPoolExecutor(max_workers=MAX_BATCH_SIZE) as executor:
        results = list(executor.map(process_single_proxy, raw_inputs))

    if format == "csv":
        if not results: return PlainTextResponse("")
        all_headers = []
        for r in results:
            for key in r.keys():
                if key not in all_headers:
                    all_headers.append(key)

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=all_headers)
        writer.writeheader()
        writer.writerows(results)
        return PlainTextResponse(output.getvalue())

    elif format == "text":
        output = ""
        for r in results:
            output += f"[{r.get('status')}] {r.get('ip')}:{r.get('port')} - {r.get('country', '')} ({r.get('isp', '')})\n"
        return PlainTextResponse(output)

    return results[0] if len(results) == 1 else results
