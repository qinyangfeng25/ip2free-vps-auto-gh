#!/usr/bin/env python3
"""
ip2free-vps-auto 管理面板
===========================
Flask Web Panel for managing ip2free proxy rules and domain-based traffic control.

Features:
  - Dashboard: current status, exit IP, redsocks status
  - Domain Rules: whitelist/blacklist domain management
  - Settings: proxy strategy, timer, panel config
  - Logs: recent operation logs
  - Live iptables rule management
"""

import json
import secrets
import hmac
import os
import http.client
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
import urllib.parse

from flask import (
    Flask, jsonify, redirect, render_template, request,
    session, url_for, flash, abort,
)
import ipaddress

from domain_manager import DomainManager


# ==================== Residential Detection ====================

# Well-known datacenter ASNs (CIDR prefixes + ASN numbers)
DATACENTER_PREFIXES = [
    "8.8.8.0/24",       # Google DNS
    "1.1.1.0/24",       # Cloudflare
    "208.80.152.0/26",  # Amazon AWS us-east
    "54.239.0.0/16",    # Amazon AWS Global
    "34.192.0.0/12",    # Amazon AWS
    "35.160.0.0/12",    # Amazon AWS
    "52.0.0.0/12",      # Amazon AWS
    "18.0.0.0/8",       # Amazon AWS
    "13.32.0.0/15",     # Amazon CloudFront
    "13.224.0.0/14",    # Amazon CloudFront
    "100.0.0.0/8",      # Amazon AWS US
    "107.22.0.0/16",    # Amazon AWS us-east
    "107.23.0.0/16",    # Amazon AWS us-east
    "23.20.0.0/14",     # Akamai
    "104.16.0.0/12",    # Cloudflare
    "172.64.0.0/13",    # Cloudflare
    "188.114.96.0/20",  # Cloudflare
    "197.234.240.0/22", # Cloudflare
    "198.41.128.0/17",  # Cloudflare
    "198.41.192.0/18",  # Cloudflare
    "216.239.32.0/19",  # Google
    "8.34.0.0/15",      # Microsoft Azure
    "8.52.0.0/15",      # Microsoft Azure
    "8.54.0.0/15",      # Microsoft Azure
    "13.64.0.0/11",     # Microsoft Azure
    "13.96.0.0/13",     # Microsoft Azure
    "20.0.0.0/8",       # Microsoft Azure
    "40.64.0.0/10",     # Microsoft Azure
    "40.128.0.0/9",     # Microsoft Azure
    "52.128.0.0/12",    # Microsoft Azure
    "52.224.0.0/11",    # Microsoft Azure
    "52.248.0.0/14",    # Microsoft Azure
    "65.52.0.0/14",     # Microsoft Azure
    "104.40.0.0/15",    # Microsoft Azure
    "104.208.0.0/13",   # Microsoft Azure
    "137.116.0.0/14",   # Microsoft Azure
    "138.91.0.0/16",    # Microsoft Azure
    "138.192.0.0/14",   # Microsoft Azure
    "139.217.0.0/16",   # Microsoft Azure
    "141.232.0.0/16",   # Microsoft Azure
    "141.236.0.0/16",   # Microsoft Azure
    "152.228.0.0/16",   # Microsoft Azure
    "168.61.0.0/16",    # Microsoft Azure
    "168.62.0.0/15",    # Microsoft Azure
    "191.232.0.0/16",   # Microsoft Azure
    "191.233.0.0/16",   # Microsoft Azure
    "207.46.0.0/16",    # Microsoft Azure
    "213.199.0.0/17",   # Microsoft Azure
    "2.17.152.0/22",    # Hetzner
    "46.4.0.0/16",      # Hetzner
    "78.46.80.0/20",    # Hetzner
    "88.198.0.0/16",    # Hetzner
    "89.163.128.0/17",  # Hetzner
    "91.121.128.0/17",  # Hetzner
    "91.203.0.0/21",    # Hetzner
    "92.52.128.0/17",   # Hetzner
    "136.226.0.0/16",   # Hetzner
    "148.251.0.0/16",   # Hetzner
    "162.55.0.0/16",    # Hetzner
    "162.247.0.0/16",   # Hetzner
    "178.62.192.0/18",  # Hetzner
    "178.63.96.0/20",   # Hetzner
    "188.254.0.0/22",   # Hetzner
    "207.180.224.0/19", # Hetzner
    "213.239.0.0/18",   # Hetzner
    "155.91.0.0/16",    # Hetzner
    "155.190.0.0/16",   # Hetzner
    "165.22.0.0/16",    # DigitalOcean
    "138.68.0.0/14",    # DigitalOcean
    "46.101.0.0/16",    # DigitalOcean
    "134.209.0.0/16",   # DigitalOcean
    "135.181.0.0/16",   # DigitalOcean
    "157.245.0.0/16",   # DigitalOcean
    "167.172.0.0/16",   # DigitalOcean
    "178.62.128.0/17",  # DigitalOcean
    "188.166.0.0/15",   # DigitalOcean
    "192.185.0.0/16",   # DigitalOcean
    "206.188.0.0/15",   # DigitalOcean
    "139.59.0.0/16",    # Vultr
    "45.76.0.0/16",     # Vultr
    "66.42.0.0/16",     # Vultr
    "104.128.0.0/10",   # Vultr
    "157.245.0.0/16",   # Vultr
    "174.138.0.0/16",   # Vultr
    "155.138.0.0/16",   # Vultr
    "165.22.0.0/16",    # Vultr
    "188.226.0.0/16",   # Vultr
    "192.3.0.0/16",     # Vultr
    "206.189.0.0/16",   # Vultr
    "103.120.0.0/16",   # Vultr
    "103.121.0.0/16",   # Vultr
]

# ASN blocks known to be datacenter (by first octet pairs for common DC providers)
DATACENTER_FIRST_OCTETS = {
    (5, 1),       # 5.x.x.x - various DC
    (8, 8),       # 8.8.x.x - Google DNS
    (9, 1),       # 9.x.x.x
    (10, 0),      # 10.x.x.x - private
    (34, 192),    # AWS
    (35, 160),    # AWS
    (45, 33),     # OVH
    (46, 101),    # DigitalOcean
    (46, 4),      # Hetzner
    (51, 75),     # Rackspace
    (52, 0),      # AWS
    (52, 4),      # AWS
    (52, 128),    # Azure
    (52, 224),    # Azure
    (63, 245),    # OVH
    (66, 42),     # Vultr
    (67, 205),    # Vultr
    (69, 164),    # Scaleway
    (77, 247),    # OVH
    (78, 46),     # Hetzner
    (80, 67),     # OVH
    (82, 102),    # OVH
    (84, 53),     # DigitalOcean
    (87, 236),    # Vultr
    (88, 198),    # Hetzner
    (89, 163),    # Hetzner
    (91, 121),    # Hetzner
    (91, 203),    # Hetzner
    (92, 52),     # Hetzner
    (92, 118),    # DigitalOcean
    (94, 130),    # OVH
    (95, 216),    # Hetzner
    (103, 120),   # Vultr
    (104, 16),    # Cloudflare
    (104, 239),   # DigitalOcean
    (107, 170),   # OVH
    (109, 70),    # DigitalOcean
    (128, 199),   # Vultr
    (137, 74),    # DigitalOcean
    (138, 68),    # DigitalOcean
    (138, 91),    # Azure
    (138, 192),   # Azure
    (139, 59),    # Vultr
    (139, 217),   # Azure
    (141, 8),     # DigitalOcean
    (141, 192),   # DigitalOcean
    (141, 232),   # Azure
    (141, 236),   # Azure
    (144, 76),    # DigitalOcean
    (148, 251),   # Hetzner
    (155, 91),    # Hetzner
    (155, 138),   # Vultr
    (155, 190),   # Hetzner
    (157, 245),   # DigitalOcean
    (158, 69),    # Cloudflare
    (159, 89),    # DigitalOcean
    (160, 0),     # Amazon
    (162, 247),   # Hetzner
    (162, 55),    # Hetzner
    (163, 172),   # OVH
    (165, 22),    # DigitalOcean
    (167, 172),   # DigitalOcean
    (168, 61),    # Azure
    (168, 62),    # Azure
    (174, 138),   # Vultr
    (176, 9),     # OVH
    (176, 58),    # Hetzner
    (178, 32),    # Hetzner
    (178, 62),    # Hetzner/DigitalOcean
    (178, 63),    # Hetzner
    (178, 128),   # DigitalOcean
    (178, 154),   # Hetzner
    (185, 10),    # DigitalOcean
    (185, 36),    # DigitalOcean
    (185, 58),    # DigitalOcean
    (185, 67),    # DigitalOcean
    (185, 72),    # DigitalOcean
    (185, 87),    # DigitalOcean
    (185, 199),   # OVH
    (185, 220),   # DigitalOcean
    (185, 230),   # DigitalOcean
    (188, 166),   # DigitalOcean
    (188, 213),   # Hetzner
    (188, 226),   # Vultr
    (188, 254),   # Hetzner
    (192, 185),   # DigitalOcean
    (192, 250),   # DigitalOcean
    (193, 106),   # OVH
    (193, 200),   # OVH
    (198, 41),    # Cloudflare
    (198, 98),    # DigitalOcean
    (198, 100),   # DigitalOcean
    (198, 108),   # OVH
    (206, 81),    # Vultr
    (206, 188),   # DigitalOcean
    (206, 189),   # Vultr
    (207, 180),   # Hetzner
    (209, 9),     # DigitalOcean
    (212, 70),    # Vultr
    (213, 171),   # Vultr
    (213, 239),   # Hetzner
}


def _is_in_datacenter_cidr(ip_str):
    """Check if IP falls in known datacenter CIDR ranges"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for prefix in DATACENTER_PREFIXES:
        try:
            if ip in ipaddress.ip_network(prefix, strict=False):
                return True
        except ValueError:
            continue
    return False


def _is_known_datacenter_asn(ip_str):
    """Check if IP matches known datacenter first octets"""
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        first_two = (int(parts[0]), int(parts[1]))
    except ValueError:
        return False
    return first_two in DATACENTER_FIRST_OCTETS


def _is_privacy_proxy(ip_str):
    """
    Check DNSBL for privacy proxy indicators.
    Uses abuse.ch URHBL and Spamhaus ZEN as reference.
    Privacy proxies often show up in specific DNSBL lists.
    """
    # Privacy Proxies DNSBL (abuse.ch)
    privacy_bl = "privacyproxy.zen.spamhaus.org"

    if not ip_str:
        return False

    # Reverse DNS lookup (privacy proxies have PTR records)
    try:
        octets = ip_str.split(".")
        if len(octets) == 4:
            reverse = ".".join(reversed(octets)) + ".in-addr.arpa"
            ptr, _, _ = socket.gethostbyaddr(ip_str)
            if ptr and (
                "proxy" in ptr.lower() or
                "residential" in ptr.lower() or
                "isp" in ptr.lower() or
                "dynamic" in ptr.lower() or
                "dsl" in ptr.lower() or
                "cable" in ptr.lower() or
                "broadband" in ptr.lower() or
                "o2.pl" in ptr.lower() or
                "upcbroadband" in ptr.lower() or
                "suddenlink" in ptr.lower() or
                "charter" in ptr.lower() or
                "comcast" in ptr.lower() or
                "verizon" in ptr.lower() or
                "at&t" in ptr.lower() or
                "att.net" in ptr.lower() or
                "frontier" in ptr.lower() or
                "windstream" in ptr.lower() or
                "mediacom" in ptr.lower() or
                "cogent" in ptr.lower() or
                "telstra" in ptr.lower() or
                "t-mobile" in ptr.lower() or
                "tmobile" in ptr.lower() or
                "vodafone" in ptr.lower() or
                "o2.de" in ptr.lower() or
                "deutschtelekom" in ptr.lower() or
                "telekom" in ptr.lower() or
                "orange.fr" in ptr.lower() or
                "free.fr" in ptr.lower() or
                "boulanger" in ptr.lower() or
                "sfr" in ptr.lower() or
                "alice.it" in ptr.lower() or
                "tin.it" in ptr.lower() or
                "fastweb" in ptr.lower() or
                "alice" in ptr.lower()
            ):
                return True
    except (socket.herror, socket.gaierror, Exception):
        pass

    return False


def detect_ip_type(ip_str):
    """
    Detect whether an IP is residential or datacenter.
    Returns: {type, score, details, confidence}
    type: 'residential' | 'datacenter' | 'unknown'
    score: 0-100 (higher = more likely residential)
    confidence: 'high' | 'medium' | 'low'
    """
    if not ip_str:
        return {"type": "unknown", "score": 50, "details": "空IP", "confidence": "low"}

    details = []
    score = 50  # neutral
    confidence = "low"

    # Check 1: Known datacenter CIDR
    if _is_in_datacenter_cidr(ip_str):
        score -= 40
        details.append("匹配已知机房网段")
        confidence = "high"

    # Check 2: Known datacenter first octets
    if _is_known_datacenter_asn(ip_str):
        score -= 25
        details.append("匹配已知机房运营商")
        if confidence != "high":
            confidence = "medium"

    # Check 3: Privacy proxy DNS (PTR) check
    is_privacy = _is_privacy_proxy(ip_str)
    if is_privacy:
        score += 40
        details.append("PTR记录显示住宅ISP")
        confidence = "high"

    # Check 4: IP range heuristics
    # Residential IPs tend to be in dynamic allocation ranges
    parts = ip_str.split(".")
    if len(parts) == 4:
        try:
            first = int(parts[0])
            second = int(parts[1])

            # Common residential patterns
            if (first, second) in {(38, 154), (38, 153), (38, 155),
                                   (38, 156), (38, 157), (38, 158),
                                   (38, 159), (38, 160), (38, 161),
                                   (38, 162), (38, 163), (38, 164),
                                   (38, 165), (38, 166), (38, 167),
                                   (38, 168), (38, 169), (38, 170)}:
                score += 25
                details.append("IP段符合住宅特征")
                confidence = "high"

            if (first, second) == (198, 1):
                score += 30
                details.append("RFC5735 测试网段(可能为隐私代理)")
                confidence = "high"
        except ValueError:
            pass

    # Clamp score
    score = max(0, min(100, score))

    if score >= 70:
        ip_type = "residential"
    elif score >= 40:
        ip_type = "datacenter"
        confidence = "medium"
    else:
        ip_type = "datacenter"
        if confidence == "low":
            confidence = "medium"

    return {
        "type": ip_type,
        "score": score,
        "details": "; ".join(details) if details else "无明确特征",
        "confidence": confidence,
    }


def get_all_proxies_list():
    """Get the full list of currently available proxies from state + agent"""
    state = get_proxy_state()

    proxies = []

    # Try to fetch the live full list through the ip2free agent module.
    try:
        from ip2free_agent import Config, IP2FreeAPI, ProxySelector
        cfg = Config()
        ok, _ = cfg.validate()
        if ok:
            api = IP2FreeAPI(cfg)
            api.login()
            raw_proxies = api.get_all_proxies()
            proxies = [ProxySelector._normalize(p) for p in raw_proxies]
            active_ip = state.get("ip") if state else None
            for p in proxies:
                p["is_active"] = (p.get("ip") == active_ip)
            return proxies
    except Exception as e:
        log_message(f"[proxy-list] 完整列表拉取失败，使用当前状态: {e}")

    if state:
        proxies.append({
            "ip": state.get("ip", ""),
            "port": state.get("port", 0),
            "protocol": state.get("protocol", "socks5"),
            "username": state.get("username", ""),
            "password": state.get("password", ""),
            "source": state.get("source", "unknown"),
            "country": state.get("country", "XX"),
            "city": state.get("city", "unknown"),
            "is_active": True,
            "detected": None,
        })

    return proxies


def _normalize_proxy_for_detect(proxy):
    """Return a proxy record that can be safely tested."""
    return {
        "ip": proxy.get("ip", ""),
        "port": int(proxy.get("port") or 0),
        "protocol": proxy.get("protocol", "socks5"),
        "username": proxy.get("username", ""),
        "password": proxy.get("password", ""),
        "country": proxy.get("country", "XX"),
        "city": proxy.get("city", "unknown"),
        "source": proxy.get("source", "unknown"),
        "is_active": bool(proxy.get("is_active")),
    }


def _test_proxy_availability(proxy, timeout=8):
    """Return availability metrics for one proxy without touching iptables."""
    from ip2free_agent import ProxyVerifier

    normalized = {
        "ip": proxy["ip"],
        "port": proxy["port"],
        "protocol": proxy["protocol"],
        "username": proxy["username"],
        "password": proxy["password"],
    }

    try:
        start = time.perf_counter()
        success, detected_ip, err = ProxyVerifier.verify(normalized, timeout=timeout)
        latency = round((time.perf_counter() - start) * 1000)
        return {
            "available": bool(success),
            "detected_ip": detected_ip or "",
            "latency_ms": latency,
            "error": err or "",
        }
    except Exception as exc:
        return {
            "available": False,
            "detected_ip": "",
            "latency_ms": 0,
            "error": str(exc),
        }


def detect_all_proxies(limit=30, concurrency=4):
    """Fetch fresh proxy list and detect availability plus IP purity."""
    proxies = get_all_proxies_list()[:limit]

    results = []
    active_ip = get_proxy_state().get("ip") if get_proxy_state() else None

    from concurrent.futures import ThreadPoolExecutor, as_completed

    def work(proxy):
        proxy = _normalize_proxy_for_detect(proxy)
        availability = _test_proxy_availability(proxy)
        purity = detect_ip_type(availability["detected_ip"] or proxy["ip"])
        if availability["available"]:
            purity["verified_residential"] = purity["type"] == "residential" and purity.get("score", 0) >= 70
        else:
            purity["verified_residential"] = False
        return {
            "ip": proxy["ip"],
            "port": proxy["port"],
            "protocol": proxy["protocol"],
            "country": proxy["country"],
            "city": proxy["city"],
            "source": proxy["source"],
            "username": proxy["username"],
            "password": proxy["password"],
            "availability": availability,
            "detected": purity,
            "is_active": bool(proxy["is_active"]) or proxy["ip"] == active_ip,
        }

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(work, proxy): proxy for proxy in proxies}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                proxy = futures[future]
                results.append({
                    "ip": proxy.get("ip", ""),
                    "port": proxy.get("port", 0),
                    "protocol": proxy.get("protocol", ""),
                    "country": proxy.get("country", ""),
                    "city": proxy.get("city", ""),
                    "source": proxy.get("source", ""),
                    "username": proxy.get("username", ""),
                    "password": proxy.get("password", ""),
                    "availability": {
                        "available": False,
                        "detected_ip": "",
                        "latency_ms": 0,
                        "error": str(exc),
                    },
                    "detected": detect_ip_type(proxy.get("ip", "")),
                    "is_active": bool(proxy.get("is_active")),
                })

    results.sort(
        key=lambda r: (
            r["availability"].get("available", False),
            r["detected"].get("score", 0),
            -r["availability"].get("latency_ms", 0),
        ),
        reverse=True,
    )
    return results


def switch_proxy(ip, port, protocol="socks5", username="", password=""):
    """Switch to a different proxy"""
    proxy = {
        "ip": ip,
        "port": int(port),
        "username": username,
        "password": password,
        "protocol": protocol,
    }

    # Update redsocks config
    from ip2free_agent import RedsocksManager

    redsocks_mgr = RedsocksManager(dm.config)
    redsocks_mgr.write_config(proxy)

    redsocks_mgr.restart()

    # Update iptables (skip old proxy, use new)
    apply_iptables_rules(proxy_ip=ip)

    # Keep the panel's proxy state in sync with the redsocks service.
    dm.save_proxy_state({
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "username": username,
        "password": password,
        "source": "manual",
        "country": "XX",
        "city": "manual",
        "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })

    return True


APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "panel_config.json"
DATA_DIR = APP_DIR / "data"
LOG_FILE = DATA_DIR / "panel.log"

app = Flask(__name__)

def _load_server_secret():
    secret_path = DATA_DIR / "server_secret.key"
    if secret_path.exists():
        secret = secret_path.read_text(encoding="utf-8").strip()
        if secret:
            return secret

    secret = "ip2free-panel-" + os.urandom(16).hex()
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    secret_path.write_text(secret, encoding="utf-8")
    try:
        os.chmod(secret_path, 0o600)
    except OSError:
        pass
    return secret


app.secret_key = _load_server_secret()
app.config["JSON_AS_ASCII"] = False

dm = DomainManager(CONFIG_PATH)


# ==================== Auth ====================

def get_panel_password():
    return dm.config.get("panel_password", "") or os.environ.get("PANEL_PASSWORD", "")


def get_panel_username():
    return dm.config.get("panel_username", "admin") or os.environ.get("PANEL_USERNAME", "admin")


def is_authenticated():
    if not get_panel_password():
        return True
    return bool(session.get("authenticated"))


def require_auth():
    if not is_authenticated():
        return redirect(url_for("login"))
    return None


@app.before_request
def protect_api_routes():
    """Do not expose proxy credentials or firewall controls on the public port."""
    if request.endpoint in {"login", "api_login", "static"}:
        return None
    if request.path.startswith("/api/") and not request.path.startswith("/api/login") and not is_authenticated():
        return jsonify({"ok": False, "error": "authentication required"}), 401
    return None


# ==================== Utils ====================

def run_cmd(cmd, timeout=10):
    """Run a shell command and return (returncode, stdout, stderr)"""
    if isinstance(cmd, dict):
        command = cmd.get("cmd", [])
        if isinstance(command, str):
            import shlex
            command = shlex.split(command)
        command = list(command) if command else []
        shell = bool(cmd.get("shell"))
        merge_stderr = bool(cmd.get("merge_stderr"))
    elif isinstance(cmd, (list, tuple)):
        command = list(cmd)
        shell = False
        merge_stderr = False
    else:
        import shlex
        command = shlex.split(cmd)
        shell = False
        merge_stderr = False

    try:
        if merge_stderr:
            result = subprocess.run(
                command, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=timeout,
            )
            return result.returncode, result.stdout.strip(), result.stdout.strip()

        result = subprocess.run(
            command, shell=shell, capture_output=True, text=True, timeout=timeout,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def log_message(msg):
    """Write to log file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _https_get_ipv4(url, timeout=8):
    """HTTP GET over a manually resolved IPv4 address (avoids IPv6 preference)."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or 443
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    addr = infos[0][4]
    ctx = ssl.create_default_context()

    class _IPv4HTTPSConnection(http.client.HTTPSConnection):
        def connect(self):
            self.sock = socket.create_connection(addr, self.timeout, self.source_address)
            if self._tunnel_host:
                self._tunnel()
            self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)

    conn = _IPv4HTTPSConnection(host, timeout=timeout)
    conn.request("GET", path, headers={"User-Agent": "ip2free-panel/1.0"})
    resp = conn.getresponse()
    body = resp.read(timeout + 5).decode("utf-8", "ignore").strip()
    conn.close()
    return body


def get_exit_ip():
    """Get current exit IP (IPv4), forcing IPv4 so redsocks is inspected correctly."""
    for url in ("https://ifconfig.me", "https://api.ipify.org/"):
        try:
            body = _https_get_ipv4(url, timeout=8)
            if re.search(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", body):
                return body
        except Exception:
            continue
    return None


def get_redsocks_status():
    """Get redsocks service status"""
    rc, out, err = run_cmd(["systemctl", "is-active", "redsocks"])
    if out == "active":
        return "active"
    return "inactive"


def get_iptables_status():
    """Get iptables chain status"""
    rc, out, err = run_cmd(["iptables", "-t", "nat", "-L", "IP2FREE_AUTO", "-n", "--line-numbers"])
    if rc == 0 and out.strip():
        return True, out
    return False, "无规则"


def get_ip6tables_status():
    """Get ip6tables chain status"""
    rc, out, err = run_cmd(["ip6tables", "-L", "IPV6_BLOCK_GOOGLE", "-n", "--line-numbers"])
    if rc == 0 and out.strip():
        return True, out
    return False, "无规则"


def apply_iptables_rules(proxy_ip=None):
    """Apply iptables rules from domain manager"""
    try:
        # Remove all historical duplicate jumps before rebuilding.  A single
        # `-D` only removes one matching rule, so old deployments could leave
        # a chain referenced multiple times.
        while run_cmd(["iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "-j", "IP2FREE_AUTO"], timeout=5)[0] == 0:
            pass
        rules = dm.generate_iptables_rules(proxy_server_ip=proxy_ip)
        results = []
        for cmd, desc in rules:
            rc, out, err = run_cmd(cmd, timeout=5)
            # Creating an existing chain is the expected idempotent case.
            status = "ok" if rc == 0 or "already exists" in err.lower() else f"fail: {err[:50]}"
            results.append({"cmd": desc, "status": status})
            log_message(f"[iptables] {desc} → {status}")
        return results
    except Exception as e:
        log_message(f"[iptables] 错误: {e}")
        return [{"cmd": "出错", "status": str(e)}]


def apply_ip6tables_rules():
    """Apply ip6tables rules from domain manager"""
    try:
        while run_cmd(["ip6tables", "-D", "OUTPUT", "-j", "IPV6_BLOCK_GOOGLE"], timeout=5)[0] == 0:
            pass
        rules = dm.generate_ip6tables_rules()
        results = []
        for cmd, desc in rules:
            rc, out, err = run_cmd(cmd, timeout=5)
            status = "ok" if rc == 0 or "already exists" in err.lower() else f"fail: {err[:50]}"
            results.append({"cmd": desc, "status": status})
            log_message(f"[ip6tables] {desc} → {status}")
        return results
    except Exception as e:
        log_message(f"[ip6tables] 错误: {e}")
        return [{"cmd": "出错", "status": str(e)}]


def restart_redsocks():
    """Restart redsocks service"""
    rc, out, err = run_cmd(["systemctl", "restart", "redsocks"])
    time.sleep(1)
    rc2, out2, _ = run_cmd(["systemctl", "is-active", "redsocks"])
    return out2 == "active"


def get_json_body():
    """Return a JSON object or a consistent API error response."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, (jsonify({"ok": False, "error": "请求体必须是 JSON 对象"}), 400)
    return data, None


def refresh_proxy():
    """Run ip2free_agent.py to refresh proxy"""
    script = APP_DIR / "ip2free_agent.py"
    venv = APP_DIR / "venv"
    python = venv / "bin/python3" if venv.exists() else "/usr/bin/python3"

    log_message("[refresh] 开始刷新代理...")
    rc, out, err = run_cmd([str(python), str(script), "run", "--force"], timeout=120)

    success = "代理配置完成" in out or "出口 IP" in out
    if success:
        # The agent updates redsocks and proxy_state.  Rebuild the panel's
        # whitelist rules as well, otherwise the old upstream bypass remains
        # and the newly selected upstream can be redirected into itself.
        state = get_proxy_state()
        apply_iptables_rules(state.get("ip") if state else None)
        apply_ip6tables_rules()
    log_message(f"[refresh] 完成: {'成功' if success else '失败'}")
    return success, (out + "\n" + err)[-2000:]


def get_proxy_state():
    """Get current proxy state"""
    return dm.get_proxy_state()


def get_redsocks_config():
    """Get current redsocks config"""
    conf_path = Path("/etc/redsocks.conf")
    if conf_path.exists():
        return conf_path.read_text(encoding="utf-8")
    conf_path = APP_DIR / "redsocks.conf"
    if conf_path.exists():
        return conf_path.read_text(encoding="utf-8")
    return ""


def get_panel_logs():
    """Get recent panel logs"""
    if LOG_FILE.exists():
        lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
        return lines[-200:]
    return []


def get_systemd_timer_status():
    """Get timer status"""
    rc, out, err = run_cmd(
        ["systemctl", "list-timers", "ip2free-auto.timer", "--no-pager"]
    )
    if rc == 0 and "1 timers" in out:
        return "active"
    return "inactive"


def get_nginx_status():
    """Get nginx reverse proxy status and configuration errors."""
    rc, out, err = run_cmd(["systemctl", "is-active", "nginx"])
    active = out.strip() == "active"
    test_rc, test_out, test_err = run_cmd({"cmd": ["nginx", "-t"], "merge_stderr": True}, timeout=10)
    combined = f"{test_out}\n{test_err}".strip()
    valid = test_rc == 0 and "test failed" not in combined and "[emerg]" not in combined
    site_file = Path("/etc/nginx/sites-available/ip2free-panel")
    cert_file = Path("/etc/ssl/ip2free-panel/panel.crt")
    key_file = Path("/etc/ssl/ip2free-panel/panel.key")
    return {
        "active": active,
        "config_valid": valid,
        "site_config_exists": site_file.exists(),
        "ssl_cert_exists": cert_file.exists(),
        "ssl_key_exists": key_file.exists(),
        "test_output": combined[-1200:],
        "panel_port": int(dm.config.get("panel_port", 8889)),
        "https_port": int(dm.config.get("https_port", 8899)),
    }


# ==================== API Routes ====================

@app.route("/api/status")
def api_status():
    """API: Get current status"""
    status = dm.get_status()
    status.update({
        "exit_ip": get_exit_ip(),
        "redsocks": get_redsocks_status(),
        "iptables_active": get_iptables_status()[0],
        "ip6tables_active": get_ip6tables_status()[0],
        "timer_active": get_systemd_timer_status(),
        "proxy_state": get_proxy_state(),
        "last_resolve": dm.get_last_resolve_time(),
        "nginx": get_nginx_status(),
    })
    return jsonify(status)


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    """API: Get/Set configuration"""
    if request.method == "GET":
        return jsonify(dm.config)

    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "请求体必须是 JSON 对象"}), 400
    for key, value in data.items():
        if key in dm.config:
            dm.config[key] = value
            log_message(f"[config] {key} = {value}")
    dm._save_config()
    return jsonify({"ok": True, "config": dm.config})


@app.route("/api/proxy-enable", methods=["POST"])
def api_proxy_enable():
    """API: Enable/disable proxy"""
    data, error = get_json_body()
    if error:
        return error
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        return jsonify({"ok": False, "error": "enabled 必须是布尔值"}), 400
    dm.set_proxy_enabled(enabled)

    if enabled:
        proxy_state = get_proxy_state()
        proxy_ip = proxy_state.get("ip") if proxy_state else None
        apply_iptables_rules(proxy_ip)
        restart_redsocks()
    else:
        apply_iptables_rules()

    return jsonify({"ok": True, "enabled": enabled, "redsocks": get_redsocks_status()})


@app.route("/api/proxy-mode", methods=["POST"])
def api_proxy_mode():
    """API: Set proxy mode (blacklist/whitelist)"""
    data, error = get_json_body()
    if error:
        return error
    mode = data.get("mode", "blacklist")
    try:
        dm.set_proxy_mode(mode)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    # Re-apply iptables
    proxy_state = get_proxy_state()
    proxy_ip = proxy_state.get("ip") if proxy_state else None
    apply_iptables_rules(proxy_ip)
    apply_ip6tables_rules()

    return jsonify({"ok": True, "mode": mode})


@app.route("/api/domains/proxy", methods=["POST", "DELETE"])
def api_proxy_domains():
    """API: Add/Remove proxy domain"""
    data, error = get_json_body()
    if error:
        return error
    domain = data.get("domain", "")

    try:
        if request.method == "POST":
            ok = dm.add_proxy_domain(domain)
        else:
            ok = dm.remove_proxy_domain(domain)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    log_message(f"[domain] {'添加' if request.method == 'POST' else '移除'}代理域名: {domain}")

    if ok:
        proxy_state = get_proxy_state()
        proxy_ip = proxy_state.get("ip") if proxy_state else None
        apply_iptables_rules(proxy_ip)
        apply_ip6tables_rules()

    return jsonify({"ok": ok})


@app.route("/api/domains/bypass", methods=["POST", "DELETE"])
def api_bypass_domains():
    """API: Add/Remove bypass domain"""
    data, error = get_json_body()
    if error:
        return error
    domain = data.get("domain", "")

    try:
        if request.method == "POST":
            ok = dm.add_bypass_domain(domain)
        else:
            ok = dm.remove_bypass_domain(domain)
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    log_message(f"[domain] {'添加' if request.method == 'POST' else '移除'}绕过域名: {domain}")

    if ok:
        proxy_state = get_proxy_state()
        proxy_ip = proxy_state.get("ip") if proxy_state else None
        apply_iptables_rules(proxy_ip)
        apply_ip6tables_rules()

    return jsonify({"ok": ok})


@app.route("/api/domains/batch", methods=["POST"])
def api_domains_batch():
    """API: Batch update domain lists"""
    data, error = get_json_body()
    if error:
        return error

    mode = data.get("mode", "blacklist")
    try:
        dm.set_proxy_mode(mode)
        if "proxy_domains" in data:
            dm.set_proxy_domains(data["proxy_domains"])
        if "bypass_domains" in data:
            dm.set_bypass_domains(data["bypass_domains"])
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    proxy_state = get_proxy_state()
    proxy_ip = proxy_state.get("ip") if proxy_state else None
    apply_iptables_rules(proxy_ip)
    apply_ip6tables_rules()

    return jsonify({"ok": True})


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    """API: Refresh proxy from ip2free"""
    log_message("[refresh] 手动刷新请求")
    success, output = refresh_proxy()
    return jsonify({"ok": success, "output": output[-500:]})


@app.route("/api/apply-rules", methods=["POST"])
def api_apply_rules():
    """API: Apply iptables rules"""
    proxy_state = get_proxy_state()
    proxy_ip = proxy_state.get("ip") if proxy_state else None

    ipt_results = apply_iptables_rules(proxy_ip)
    ip6_results = apply_ip6tables_rules()
    redsocks_ok = restart_redsocks()

    ok = all(item["status"] == "ok" for item in ipt_results + ip6_results) and redsocks_ok
    return jsonify({
        "ok": ok,
        "iptables": ipt_results,
        "ip6tables": ip6_results,
        "redsocks": redsocks_ok,
    })


@app.route("/api/logs")
def api_logs():
    """API: Get logs"""
    logs = get_panel_logs()
    return jsonify({"logs": logs})


@app.route("/api/nginx-check")
def api_nginx_check():
    """API: Validate nginx config and restart if valid."""
    rc, out, err = run_cmd({"cmd": ["nginx", "-t"], "merge_stderr": True}, timeout=10)
    valid = rc == 0
    result = {
        "valid": valid,
        "output": (out + "\n" + err)[-1600:],
        "restarted": False,
    }
    if valid:
        restart_rc, restart_out, restart_err = run_cmd(["systemctl", "restart", "nginx"], timeout=10)
        state_rc, state_out, state_err = run_cmd(["systemctl", "is-active", "nginx"], timeout=10)
        result["restarted"] = restart_rc == 0 and state_out.strip() == "active"
        result["output"] += "\nrestart:" + restart_out + restart_err + state_out + state_err
    return jsonify(result)


@app.route("/api/iptables", methods=["GET"])
def api_iptables():
    """API: Get iptables rules"""
    ipt_ok, ipt_out = get_iptables_status()
    ip6_ok, ip6_out = get_ip6tables_status()
    return jsonify({
        "iptables": ipt_out if ipt_ok else "无规则",
        "ip6tables": ip6_out if ip6_ok else "无规则",
    })


@app.route("/api/redsocks-config")
def api_redsocks_config():
    """API: Get redsocks config"""
    return jsonify({"config": get_redsocks_config()})


@app.route("/api/resolved-ips")
def api_resolved_ips():
    """Resolve current domain targets and atomically refresh transparent rules."""
    proxy_ips = dm.get_proxy_ips()
    bypass_ips = dm.get_bypass_ips()
    proxy_state = get_proxy_state()
    proxy_ip = proxy_state.get("ip") if proxy_state else None
    iptables = apply_iptables_rules(proxy_ip)
    return jsonify({
        "proxy_ips": proxy_ips,
        "bypass_ips": bypass_ips,
        "mode": dm.config.get("proxy_mode", "blacklist"),
        # This is set by the resolver, rather than the HTTP handler, so API
        # consumers can prove a fresh DNS evaluation happened on each call.
        "resolved_at": dm._last_resolve_time,
        "dynamic_refresh": True,
        "iptables": iptables,
    })


@app.route("/api/proxy-list")
def api_proxy_list():
    """API: Get all available proxies with detection info"""
    proxies = get_all_proxies_list()
    for p in proxies:
        p["detected"] = detect_ip_type(p.get("ip", ""))
    return jsonify({"proxies": proxies})


@app.route("/api/proxy-detect-all", methods=["POST"])
def api_proxy_detect_all():
    """API: Fetch fresh proxy list and detect all"""
    log_message("[detect] 开始检测所有代理IP类型...")
    data = request.get_json(silent=True) or {}
    try:
        limit = int(data.get("limit", 30))
        concurrency = int(data.get("concurrency", 4))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "limit 和 concurrency 必须是整数"}), 400
    limit = max(1, min(limit, 50))
    concurrency = max(1, min(concurrency, 8))
    results = detect_all_proxies(limit=limit, concurrency=concurrency)
    ok_count = sum(1 for r in results if r["availability"]["available"])
    pure_count = sum(1 for r in results if r["availability"]["available"] and r["detected"].get("verified_residential"))
    log_message(f"[detect] 检测完成: {len(results)} 个IP, 可用 {ok_count}, 纯净 {pure_count}")
    return jsonify({
        "results": results,
        "total": len(results),
        "available": ok_count,
        "pure": pure_count,
    })


@app.route("/api/proxy-switch", methods=["POST"])
def api_proxy_switch():
    """API: Switch to a different proxy"""
    data, error = get_json_body()
    if error:
        return error
    ip = data.get("ip", "")
    port = data.get("port", 0)
    protocol = data.get("protocol", "socks5")
    username = data.get("username", "")
    password = data.get("password", "")

    if not ip:
        return jsonify({"ok": False, "error": "缺少IP地址"}), 400

    log_message(f"[switch] 切换代理到 {ip}:{port}")

    try:
        # Update redsocks config directly
        port_val = str(int(port)) if port else str(dm.config.get("redsocks_port", 12345))
        if not 1 <= int(port_val) <= 65535:
            raise ValueError("端口必须在 1-65535 之间")
        if protocol not in {"socks5", "http", "http_connect", "socks4", "ss5"}:
            return jsonify({"ok": False, "error": "不支持的代理协议"}), 400
        if any(ch in str(username) + str(password) for ch in ('"', '\\n', '\\r')):
            return jsonify({"ok": False, "error": "账号或密码包含不支持的字符"}), 400
        log_message(f"[switch] 目标端口规范化: {port_val}")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({"ok": False, "error": "IP 地址格式错误"}), 400
        conf = f"""base {{
    log_debug = off;
    log_info = on;
    daemon = on;
    redirector = iptables;
}}

redsocks {{
    local_ip = 127.0.0.1;
    local_port = {dm.config.get('redsocks_port', 12345)};

    ip = "{ip}";
    port = {port_val};
    type = {protocol};

    login = "{username}";
    password = "{password}";
}}
"""
        Path("/etc/redsocks.conf").write_text(conf, encoding="utf-8")
        APP_DIR.joinpath("redsocks.conf").write_text(conf, encoding="utf-8")
        if not restart_redsocks():
            return jsonify({"ok": False, "error": "redsocks 重启失败，未切换代理"}), 502

        apply_iptables_rules(proxy_ip=ip)

        # Verify
        time.sleep(2)
        exit_ip = get_exit_ip()
        proxy_state = {
            "ip": ip,
            "port": int(port) if port else 0,
            "protocol": protocol,
            "username": username,
            "password": password,
            "source": "manual",
            "country": "XX",
            "city": "manual",
            "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        dm.save_proxy_state(proxy_state)

        return jsonify({
            "ok": True,
            "ip": ip,
            "port": port_val,
            "exit_ip": exit_ip,
            # A generic exit-IP request can legitimately be direct in
            # whitelist mode.  Do not label it as proxy verification.
            "configured": True,
            "verified": False,
            "verification_note": "配置已应用；请通过目标代理域名验证出口",
        })
    except Exception as e:
        log_message(f"[switch] 失败: {e}")
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/login", methods=["POST"])
def api_login():
    """API: Login"""
    data, error = get_json_body()
    if error:
        return error
    username = data.get("username", "")
    password = data.get("password", "")
    expected = get_panel_password()
    expected_username = get_panel_username()

    if not expected or (hmac.compare_digest(username, expected_username) and hmac.compare_digest(password, expected)):
        session["authenticated"] = True
        log_message(f"[login] 登录成功")
        return jsonify({"ok": True})

    log_message(f"[login] 登录失败")
    return jsonify({"ok": False, "error": "密码错误"}), 401


@app.route("/api/logout", methods=["POST"])
def api_logout():
    """API: Logout"""
    session.clear()
    return jsonify({"ok": True})


# ==================== Web Routes ====================

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_authenticated():
        return redirect(url_for("dashboard"))

    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        expected = get_panel_password()
        expected_username = get_panel_username()
        if not expected or (hmac.compare_digest(username, expected_username) and hmac.compare_digest(password, expected)):
            session["authenticated"] = True
            return redirect(url_for("dashboard"))
        error = "密码错误"

    return render_template("login.html", error=error)


@app.route("/")
def dashboard():
    resp = require_auth()
    if resp:
        return resp
    return render_template("dashboard.html")


@app.route("/domains")
def domains_page():
    resp = require_auth()
    if resp:
        return resp
    return render_template("domains.html")


@app.route("/proxies")
def proxies_page():
    resp = require_auth()
    if resp:
        return resp
    return render_template("proxies.html")


@app.route("/settings")
def settings_page():
    resp = require_auth()
    if resp:
        return resp
    return render_template("settings.html")


@app.route("/logs")
def logs_page():
    resp = require_auth()
    if resp:
        return resp
    return render_template("logs.html")


@app.route("/iptables")
def iptables_page():
    resp = require_auth()
    if resp:
        return resp
    return render_template("iptables.html")


# ==================== Main ====================

def main():
    data_dir = Path(DATA_DIR)
    data_dir.mkdir(parents=True, exist_ok=True)

    port = dm.config.get("panel_port", 8889)
    https_port = dm.config.get("https_port", 8899)
    if not get_panel_password():
        dm.config["panel_password"] = secrets.token_urlsafe(24)
        dm.config["panel_secret"] = secrets.token_urlsafe(32)
        dm._save_config()
        log_message("[panel] generated missing panel credentials")

    log_message(f"[panel] 面板启动，端口: {port}")

    print(f"\n  面板已启动: http://127.0.0.1:{port}")
    print(f"  HTTPS 反代: https://0.0.0.0:{https_port}")
    print(f"  配置文件: {CONFIG_PATH}")
    print(f"  日志文件: {LOG_FILE}")
    if os.environ.get("PANEL_PASSWORD"):
        print("  密码来源: PANEL_PASSWORD 环境变量")
    print()

    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
