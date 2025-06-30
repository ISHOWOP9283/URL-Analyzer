from flask import Flask, render_template, request
import socket
import ssl
import whois
import requests
from bs4 import BeautifulSoup
from datetime import datetime

app = Flask(__name__)

def get_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return "IP not found"

def get_page_title(url):
    try:
        res = requests.get(url, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')
        return soup.title.string.strip() if soup.title else "No title found"
    except:
        return "Title not found"

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        expiration_date = w.expiration_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        return {
            "registrar": w.registrar,
            "creation_date": creation_date.strftime("%Y-%m-%d") if creation_date else "N/A",
            "expiration_date": expiration_date.strftime("%Y-%m-%d") if expiration_date else "N/A",
            "name_servers": w.name_servers,
            "country": w.country
        }
    except:
        return {
            "registrar": "N/A",
            "creation_date": "N/A",
            "expiration_date": "N/A",
            "name_servers": "N/A",
            "country": "N/A"
        }

def get_ip_location(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data["status"] == "success":
            return {
                "ip_country": data.get("country"),
                "ip_region": data.get("regionName"),
                "ip_city": data.get("city"),
                "ip_zip": data.get("zip"),
                "ip_timezone": data.get("timezone"),
                "ip_isp": data.get("isp"),
                "ip_lat": data.get("lat"),
                "ip_lon": data.get("lon")
            }
    except:
        pass
    return {
        "ip_country": "N/A",
        "ip_region": "N/A",
        "ip_city": "N/A",
        "ip_zip": "N/A",
        "ip_timezone": "N/A",
        "ip_isp": "N/A",
        "ip_lat": "N/A",
        "ip_lon": "N/A"
    }

def get_ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            days_left = (expires - datetime.utcnow()).days
            return {
                "ssl_valid": True,
                "ssl_expiry": expires.strftime('%Y-%m-%d'),
                "ssl_days_left": days_left
            }
    except:
        return {
            "ssl_valid": False,
            "ssl_expiry": "N/A",
            "ssl_days_left": "N/A"
        }

@app.route("/", methods=["GET", "POST"])
def index():
    result = {}
    if request.method == "POST":
        url = request.form["url"]
        if not url.startswith("http"):
            url = "https://" + url
        domain = url.split("//")[-1].split("/")[0]
        result["url"] = url
        result["ip"] = get_ip(domain)
        result["title"] = get_page_title(url)
        result.update(get_whois_info(domain))
        result.update(get_ip_location(result["ip"]))
        result.update(get_ssl_info(domain))
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
