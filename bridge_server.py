#!/usr/bin/env python3
"""
DPI Engine Bridge Server
------------------------
Lightweight local HTTP server (Zero external dependencies, standard library only).
Bridges the web dashboard with the C++ DPI engine running in WSL.
"""

import http.server
import socketserver
import subprocess
import json
import urllib.parse
import os
import sys
import struct
import socket
import webbrowser
import threading
import atexit
import signal
import ipaddress
import re
import shlex
import hashlib
from collections import Counter

PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
INPUT_PCAP = os.path.join(BASE_DIR, "test_dpi.pcap")
LIVE_PCAP = os.path.join(BASE_DIR, "live_capture.pcap")
OUTPUT_PCAP = os.path.join(BASE_DIR, "output.pcap")

# WSL project path mapping (if running on Windows)
if sys.platform == "win32" and len(BASE_DIR) > 1 and BASE_DIR[1] == ":":
    drive_letter = BASE_DIR[0].lower()
    WSL_PROJECT_DIR = f"/mnt/{drive_letter}/" + BASE_DIR[2:].replace("\\", "/").lstrip("/")
else:
    WSL_PROJECT_DIR = BASE_DIR


# Hosts entries are exact names; observed subdomains are added after inspection.
APP_DOMAINS = {
    "YouTube": ["youtube.com", "www.youtube.com", "youtu.be", "googlevideo.com", "ytimg.com"],
    "Netflix": ["netflix.com", "www.netflix.com", "nflxvideo.net", "nflximg.net"],
    "Facebook": ["facebook.com", "www.facebook.com", "fb.com", "fbcdn.net", "meta.com"],
    "Instagram": ["instagram.com", "www.instagram.com", "cdninstagram.com"],
    "WhatsApp": ["whatsapp.com", "web.whatsapp.com", "whatsapp.net", "wa.me"],
    "Twitter/X": ["twitter.com", "www.twitter.com", "x.com", "www.x.com", "t.co", "twimg.com"],
    "Google": ["google.com", "www.google.com", "googleapis.com", "gstatic.com"],
    "Amazon": ["amazon.com", "www.amazon.com", "amazonaws.com", "cloudfront.net"],
    "Microsoft": ["microsoft.com", "www.microsoft.com", "office.com", "outlook.com", "bing.com"],
    "Apple": ["apple.com", "www.apple.com", "icloud.com", "itunes.apple.com"],
    "Telegram": ["telegram.org", "web.telegram.org", "t.me"],
    "TikTok": ["tiktok.com", "www.tiktok.com", "tiktokcdn.com"],
    "Spotify": ["spotify.com", "open.spotify.com", "scdn.co"],
    "Zoom": ["zoom.us", "www.zoom.us", "zoom.com"],
    "Discord": ["discord.com", "discord.gg", "discordapp.com"],
    "GitHub": ["github.com", "www.github.com", "githubusercontent.com"],
    "Cloudflare": ["cloudflare.com", "www.cloudflare.com"],
}
HOST_START = "# >>> DPI-ENGINE-BLOCK-START"
HOST_END = "# <<< DPI-ENGINE-BLOCK-END"
ENFORCEMENT_LOCK = threading.RLock()
PF_ANCHOR = "com.apple/dpi-engine"
_pf_token = None


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def available_interfaces():
    try:
        return [name for _, name in socket.if_nameindex()]
    except (OSError, AttributeError):
        return []


def valid_domain(value):
    value = str(value).strip().lower().rstrip(".")
    if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in value.split(".")):
        raise ValueError("Invalid domain: " + value)
    return value


def system_command(args, warnings, content=None, optional=False):
    try:
        proc = subprocess.run(args, input=content, text=True, capture_output=True, timeout=10)
        if proc.returncode and not optional:
            warnings.append(" ".join(args) + ": " + (proc.stderr.strip() or "command failed"))
        return proc
    except (OSError, subprocess.TimeoutExpired) as exc:
        if not optional:
            warnings.append(" ".join(args) + ": " + str(exc))
        return None


def update_hosts(domains):
    with open("/etc/hosts", "r") as f:
        original = f.read()
    cleaned = re.sub(r"(?m)^" + re.escape(HOST_START) + r"\n.*?^" + re.escape(HOST_END) + r"(?:\n|$)", "", original, flags=re.S)
    text = cleaned
    if domains:
        text = cleaned.rstrip("\n") + "\n" + HOST_START + "\n"
        text += "".join(f"0.0.0.0 {d}\n:: {d}\n" for d in sorted(domains))
        text += HOST_END + "\n"
    if text != original:
        with open("/etc/hosts", "w") as f:
            f.write(text)


def enforce_host_blocks(enabled=False, ips=(), domains=(), apps=(), packets=()):
    """Replace only this engine's rules; report partial failures without hiding them."""
    global _pf_token
    with ENFORCEMENT_LOCK:
        warnings = []
        if not is_root():
            return {"success": False, "enabled": False, "warnings": ["Permission denied: OS blocking/cleanup requires root privileges."]}
        if sys.platform not in ("darwin", "linux"):
            return {"success": False, "enabled": False, "warnings": ["OS blocking is supported on macOS and Linux."]}
        targets, names = set(), set()
        try:
            if enabled:
                targets.update(str(ipaddress.ip_address(ip)) for ip in ips)
                names.update(valid_domain(d) for d in domains)
                for app in apps:
                    for key, values in APP_DOMAINS.items():
                        if key.lower() == app.lower():
                            names.update(values)
                # Domain-only policies use exact hosts entries, without inferred IP blocks.
                matched_flows = set()
                def flow_key(pkt):
                    return (pkt.get("src_ip"), pkt.get("dest_ip"), pkt.get("src_port"), pkt.get("dest_port"), pkt.get("protocol"))
                for pkt in packets:
                    domain = pkt.get("domain", "-").lower()
                    if (pkt.get("src_ip") in ips or pkt.get("dest_ip") in ips
                            or any(app.lower() == pkt.get("app", "").lower() for app in apps)
                            or any(d.lower() in domain for d in domains)):
                        matched_flows.add(flow_key(pkt))
                for pkt in packets:
                    if (apps or ips) and pkt.get("status") == "DROP" and pkt.get("has_ip") and flow_key(pkt) in matched_flows:
                        targets.add(str(ipaddress.ip_address(pkt["dest_ip"])))
                        if pkt.get("domain", "-") != "-":
                            names.add(valid_domain(pkt["domain"]))
            update_hosts(names)
        except (OSError, ValueError) as exc:
            warnings.append(str(exc))
        if sys.platform == "darwin":
            system_command(["dscacheutil", "-flushcache"], warnings)
            system_command(["killall", "-HUP", "mDNSResponder"], warnings)
            # Apple's default pf.conf evaluates com.apple/* anchors.
            rules = ""
            for version in (4, 6):
                addresses = sorted(ip for ip in targets if ipaddress.ip_address(ip).version == version)
                if addresses:
                    table = f"dpi_block{version}"
                    rules += f"table <{table}> persist {{ " + ", ".join(addresses) + " }\n"
                    family = "inet" if version == 4 else "inet6"
                    rules += f"block drop quick {family} from <{table}> to any\nblock drop quick {family} from any to <{table}>\n"
            system_command(["pfctl", "-a", PF_ANCHOR, "-f", "-"], warnings, rules)
            if not targets:
                system_command(["pfctl", "-a", PF_ANCHOR, "-F", "Tables"], warnings)
            if targets and _pf_token is None:
                proc = system_command(["pfctl", "-E"], warnings)
                if proc:
                    match = re.search(r"Token\s*:\s*(\d+)", proc.stdout + proc.stderr)
                    if match:
                        _pf_token = match.group(1)
            if not targets and _pf_token:
                system_command(["pfctl", "-X", _pf_token], warnings)
                _pf_token = None
            if targets:
                warnings.append("PF requires the system ruleset to evaluate the com.apple/* anchor; existing PF states may persist.")
        else:
            system_command(["resolvectl", "flush-caches"], warnings)
            for tool, version in (("iptables", 4), ("ip6tables", 6)):
                addresses = sorted(ip for ip in targets if ipaddress.ip_address(ip).version == version)
                for direction, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
                    chain = "DPI_ENGINE_" + direction
                    exists = system_command([tool, "-w", "-S", chain], warnings, optional=True)
                    if not addresses and (not exists or exists.returncode):
                        continue
                    if not exists or exists.returncode:
                        system_command([tool, "-w", "-N", chain], warnings)
                    system_command([tool, "-w", "-F", chain], warnings)
                    if addresses:
                        for ip in addresses:
                            system_command([tool, "-w", "-A", chain, flag, ip, "-j", "DROP"], warnings)
                        check = system_command([tool, "-w", "-C", direction, "-j", chain], warnings, optional=True)
                        if not check or check.returncode:
                            system_command([tool, "-w", "-I", direction, "1", "-j", chain], warnings)
                    else:
                        system_command([tool, "-w", "-D", direction, "-j", chain], warnings, optional=True)
                        system_command([tool, "-w", "-X", chain], warnings)
        return {"success": not warnings, "enabled": enabled, "blocked_ips": sorted(targets), "blocked_domains": sorted(names), "warnings": warnings}


def cleanup_blocks():
    enforce_host_blocks(False)


atexit.register(cleanup_blocks)


def extract_sni_from_payload(payload):
    """Extract TLS SNI (Server Name Indication) from payload."""
    if len(payload) < 43:
        return None
    # Check TLS Handshake (0x16) and Client Hello (0x01)
    if payload[0] != 0x16 or payload[5] != 0x01:
        return None
    try:
        offset = 43  # Skip to session ID length
        session_len = payload[offset]
        offset += 1 + session_len
        if offset + 2 > len(payload): return None
        cipher_len = struct.unpack(">H", payload[offset:offset + 2])[0]
        offset += 2 + cipher_len
        if offset + 1 > len(payload): return None
        comp_len = payload[offset]
        offset += 1 + comp_len
        if offset + 2 > len(payload): return None
        ext_len = struct.unpack(">H", payload[offset:offset + 2])[0]
        offset += 2
        ext_end = min(offset + ext_len, len(payload))
        while offset + 4 <= ext_end:
            ext_type, dlen = struct.unpack(">HH", payload[offset:offset + 4])
            offset += 4
            if ext_type == 0x0000:  # SNI extension
                if offset + 5 <= len(payload):
                    sni_len = struct.unpack(">H", payload[offset + 3:offset + 5])[0]
                    return payload[offset + 5:offset + 5 + sni_len].decode("ascii", errors="ignore")
            offset += dlen
    except Exception:
        pass
    return None


def extract_http_host(payload):
    """Extract HTTP Host header from payload."""
    try:
        sample = payload[:300].decode("latin-1", errors="ignore")
        for line in sample.split("\r\n"):
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def extract_dns_query(payload):
    """Extract DNS QNAME from payload."""
    try:
        if len(payload) < 12:
            return None
        parts = []
        idx = 12
        while idx < len(payload):
            length = payload[idx]
            if length == 0:
                break
            idx += 1
            if idx + length > len(payload):
                break
            parts.append(payload[idx:idx + length].decode("ascii", errors="ignore"))
            idx += length
        return ".".join(parts) if parts else None
    except Exception:
        return None


def read_pcap_packets(pcap_path):
    """Parse PCAP file and extract packet headers, metadata, and payloads."""
    if not os.path.exists(pcap_path):
        return []
    packets = []
    try:
        with open(pcap_path, "rb") as f:
            gh = f.read(24)
            if len(gh) < 24:
                return []
            pkt_id = 0
            while True:
                ph = f.read(16)
                if len(ph) < 16:
                    break
                pkt_id += 1
                sec, usec, incl_len, orig_len = struct.unpack("<IIII", ph)
                data = f.read(incl_len)
                
                pkt_info = {
                    "_fingerprint": hashlib.sha256(data).hexdigest(),
                    "id": pkt_id,
                    "sec": sec,
                    "usec": usec,
                    "timestamp": f"{sec}.{usec:06d}",
                    "length": incl_len,
                    "has_ip": False,
                    "src_ip": "-",
                    "dest_ip": "-",
                    "protocol": "OTHER",
                    "src_port": "-",
                    "dest_port": "-",
                    "app": "Unknown",
                    "domain": "-",
                    "hex_preview": data[:32].hex(" "),
                    "payload_preview": ""
                }
                
                # Check Ethernet IPv4 (EtherType 0x0800)
                if len(data) >= 34 and data[12:14] == b"\x08\x00":
                    pkt_info["has_ip"] = True
                    ihl = (data[14] & 0x0F) * 4
                    proto_num = data[23]
                    pkt_info["src_ip"] = socket.inet_ntoa(data[26:30])
                    pkt_info["dest_ip"] = socket.inet_ntoa(data[30:34])
                    
                    if proto_num == 6 and len(data) >= 14 + ihl + 20:
                        pkt_info["protocol"] = "TCP"
                        pkt_info["src_port"] = struct.unpack(">H", data[14 + ihl:14 + ihl + 2])[0]
                        pkt_info["dest_port"] = struct.unpack(">H", data[14 + ihl + 2:14 + ihl + 4])[0]
                        tcp_off = ((data[14 + ihl + 12] >> 4) & 0x0F) * 4
                        payload = data[14 + ihl + tcp_off:]
                        if payload:
                            pkt_info["payload_preview"] = payload[:48].hex(" ")
                            sni = extract_sni_from_payload(payload)
                            http = extract_http_host(payload)
                            if sni:
                                pkt_info["domain"] = sni
                                pkt_info["app"] = classify_app_by_domain(sni) or "HTTPS"
                            elif http:
                                pkt_info["domain"] = http
                                pkt_info["app"] = classify_app_by_domain(http) or "HTTP"
                            elif pkt_info["dest_port"] == 443 or pkt_info["src_port"] == 443:
                                pkt_info["app"] = "HTTPS"
                            elif pkt_info["dest_port"] == 80 or pkt_info["src_port"] == 80:
                                pkt_info["app"] = "HTTP"
                    elif proto_num == 17 and len(data) >= 14 + ihl + 8:
                        pkt_info["protocol"] = "UDP"
                        pkt_info["src_port"] = struct.unpack(">H", data[14 + ihl:14 + ihl + 2])[0]
                        pkt_info["dest_port"] = struct.unpack(">H", data[14 + ihl + 2:14 + ihl + 4])[0]
                        payload = data[14 + ihl + 8:]
                        if payload:
                            dns = extract_dns_query(payload)
                            if dns:
                                pkt_info["domain"] = dns
                                app_name = classify_app_by_domain(dns)
                                pkt_info["app"] = app_name if app_name else "DNS"
                            else:
                                pkt_info["app"] = "UDP"
                # Identify common non-IPv4 frames even though the DPI pipeline skips them.
                if len(data) >= 14 and data[12:14] == b"\x86\xdd":
                    pkt_info["protocol"] = "IPv6"
                    if len(data) >= 54:
                        pkt_info["has_ip"] = True
                        pkt_info["src_ip"] = socket.inet_ntop(socket.AF_INET6, data[22:38])
                        pkt_info["dest_ip"] = socket.inet_ntop(socket.AF_INET6, data[38:54])
                elif len(data) >= 14 and data[12:14] == b"\x08\x06":
                    pkt_info["protocol"] = "ARP"
                packets.append(pkt_info)
    except Exception as e:
        print(f"Error reading PCAP: {e}", file=sys.stderr)
    return packets


def classify_app_by_domain(domain):
    """Categorize domain name into friendly application name."""
    dom = domain.lower()
    
    # YouTube (checked before Google)
    if "googlevideo" in dom or "youtube" in dom or "ytimg" in dom or "youtu.be" in dom or "yt3.ggpht" in dom:
        return "YouTube"
    # Google
    if "google" in dom or "gstatic" in dom or "googleapis" in dom or "ggpht" in dom or "gvt1" in dom:
        return "Google"
    # Instagram (checked before general Facebook/Meta)
    if "instagram" in dom or "cdninstagram" in dom:
        return "Instagram"
    # WhatsApp
    if "whatsapp" in dom or dom == "wa.me" or ".wa.me" in dom:
        return "WhatsApp"
    # Facebook / Meta
    if "facebook" in dom or "fbcdn" in dom or dom == "fb.com" or ".fb.com" in dom or "fbsbx" in dom or dom == "meta.com" or ".meta.com" in dom:
        return "Facebook"
    # Twitter / X
    if "twitter" in dom or "twimg" in dom or dom == "x.com" or ".x.com" in dom or dom == "t.co" or ".t.co" in dom:
        return "Twitter/X"
    # Netflix
    if "netflix" in dom or "nflxvideo" in dom or "nflximg" in dom:
        return "Netflix"
    # Amazon
    if "amazon" in dom or "amazonaws" in dom or "cloudfront" in dom or dom == "aws" or ".aws." in dom or "aws.amazon" in dom:
        return "Amazon"
    # Microsoft
    if "microsoft" in dom or "msn.com" in dom or "office" in dom or "azure" in dom or "live.com" in dom or "outlook" in dom or "bing.com" in dom:
        return "Microsoft"
    # Apple
    if "apple.com" in dom or "icloud" in dom or "mzstatic" in dom or "itunes" in dom:
        return "Apple"
    # Telegram
    if "telegram" in dom or dom == "t.me" or ".t.me" in dom:
        return "Telegram"
    # TikTok
    if "tiktok" in dom or "tiktokcdn" in dom or "musical.ly" in dom or "bytedance" in dom:
        return "TikTok"
    # Spotify
    if "spotify" in dom or "scdn.co" in dom:
        return "Spotify"
    # Zoom
    if "zoom.us" in dom or "zoom.com" in dom:
        return "Zoom"
    # Discord
    if "discord" in dom or "discordapp" in dom:
        return "Discord"
    # GitHub
    if "github" in dom or "githubusercontent" in dom:
        return "GitHub"
    # Cloudflare
    if "cloudflare" in dom or "cf-" in dom:
        return "Cloudflare"

    return None


def mark_packet_verdicts(packets, forwarded, blocked_ips, blocked_apps, blocked_domains):
    """Report unsupported/unmatched packets without inventing a blocked flow."""
    def flow_key(pkt):
        return (pkt["src_ip"], pkt["dest_ip"], pkt["src_port"], pkt["dest_port"], pkt["protocol"])

    def matching_reason(pkt):
        if pkt["src_ip"] in blocked_ips:
            return "Blocked source IP: " + pkt["src_ip"]
        if any(app.lower() == pkt["app"].lower() for app in blocked_apps):
            return "Blocked app match: " + pkt["app"]
        if pkt["domain"] != "-" and any(d.lower() in pkt["domain"].lower() for d in blocked_domains):
            return "Blocked domain match: " + pkt["domain"]
        return None

    matched_flows = {flow_key(p) for p in packets if p["has_ip"] and p["protocol"] in ("TCP", "UDP") and matching_reason(p)}
    for pkt in packets:
        identity = (pkt["sec"], pkt["usec"], pkt.pop("_fingerprint"))
        if forwarded[identity]:
            forwarded[identity] -= 1
            pkt.update(status="FORWARD", reason="Present in filtered output")
        elif not pkt["has_ip"] or pkt["protocol"] not in ("TCP", "UDP"):
            pkt.update(status="UNINSPECTED", reason=f"Not inspected: {pkt['protocol']} is outside the IPv4 TCP/UDP inspection path, or the packet is incomplete")
        else:
            reason = matching_reason(pkt)
            if reason or flow_key(pkt) in matched_flows:
                pkt.update(status="DROP", reason=reason or "Same flow as a packet matching a blocking rule")
            else:
                pkt.update(status="UNINSPECTED", reason="Not in filtered output; no matching blocking rule established")


def run_dpi_engine(blocked_apps=None, blocked_ips=None, blocked_domains=None, num_lbs=2, fps_per_lb=2, mode="synthetic", capture_new=False, interface="auto", duration=5, enforce_block=False):
    """Run the C++ DPI engine natively (macOS/Linux) or in WSL (Windows) with specified parameters."""
    blocked_apps = blocked_apps or []
    blocked_ips = blocked_ips or []
    blocked_domains = blocked_domains or []
    
    input_pcap = LIVE_PCAP if mode == "live" else INPUT_PCAP
    if mode not in ("synthetic", "live") or not 1 <= duration <= 30:
        return {"success": False, "error": "mode must be synthetic/live; duration must be 1-30"}
    if num_lbs < 1 or fps_per_lb < 1 or num_lbs * fps_per_lb > 64:
        return {"success": False, "error": "Thread counts must be positive, with at most 64 workers"}
    if type(capture_new) is not bool or type(enforce_block) is not bool or not isinstance(interface, str):
        return {"success": False, "error": "capture_new/enforce_block must be booleans; interface must be a string"}
    enforcement_status = enforce_host_blocks(enforce_block, blocked_ips, blocked_domains, blocked_apps)
    # Clean up any stale output.pcap so old results are never served if engine fails
    if os.path.exists(OUTPUT_PCAP):
        try:
            os.remove(OUTPUT_PCAP)
        except OSError:
            pass

    cmd_args = ["./dpi_engine", os.path.basename(input_pcap), "output.pcap"]
    if mode == "live" and capture_new:
        cmd_args.extend(["--live", interface, "--duration", str(duration)])
    for app in blocked_apps:
        cmd_args.extend(["--block-app", app])
    for ip in blocked_ips:
        cmd_args.extend(["--block-ip", ip])
    for dom in blocked_domains:
        cmd_args.extend(["--block-domain", dom])
    cmd_args.extend(["--lbs", str(num_lbs), "--fps", str(fps_per_lb)])
    
    if sys.platform == "win32":
        inner_cmd = f"cd {shlex.quote(WSL_PROJECT_DIR)} && " + shlex.join(cmd_args)
        full_cmd = ["wsl", "-d", "Ubuntu-24.04", "bash", "-c", inner_cmd]
        run_cwd = None
    else:
        full_cmd = [os.path.join(BASE_DIR, "dpi_engine")] + cmd_args[1:]
        run_cwd = BASE_DIR
    
    engine_ok = False
    try:
        proc = subprocess.run(full_cmd, cwd=run_cwd, capture_output=True, timeout=duration + 15)
        engine_ok = proc.returncode == 0
        raw_output = proc.stdout.decode("utf-8", errors="replace")
        err_output = proc.stderr.decode("utf-8", errors="replace")
    except Exception as e:
        raw_output = ""
        err_output = str(e)
    
    if not engine_ok:
        return {"success": False, "error": err_output or "DPI engine failed", "raw_output": raw_output, "enforcement_status": enforcement_status}
    # Read output.pcap to determine which packets were forwarded
    forwarded_packets = Counter()
    if os.path.exists(OUTPUT_PCAP):
        try:
            with open(OUTPUT_PCAP, "rb") as f:
                f.read(24)
                while True:
                    ph = f.read(16)
                    if len(ph) < 16:
                        break
                    sec, usec, incl_len, _ = struct.unpack("<IIII", ph)
                    data = f.read(incl_len)
                    forwarded_packets[(sec, usec, hashlib.sha256(data).hexdigest())] += 1
        except Exception:
            pass
            
    # Read all input packets and mark status
    input_packets = read_pcap_packets(input_pcap)
    mark_packet_verdicts(input_packets, forwarded_packets, blocked_ips, blocked_apps, blocked_domains)

    # Parse summary and statistics from raw output
    stats = {
        "total_packets": len(input_packets),
        "forwarded": len([p for p in input_packets if p["status"] == "FORWARD"]),
        "dropped": len([p for p in input_packets if p["status"] == "DROP"]),
        "uninspected": sum(p["status"] == "UNINSPECTED" for p in input_packets),
        "tcp_packets": len([p for p in input_packets if p["protocol"] == "TCP"]),
        "udp_packets": len([p for p in input_packets if p["protocol"] == "UDP"]),
        "total_bytes": sum(p["length"] for p in input_packets),
        "apps": {},
        "threads": {"lbs": {}, "fps": {}},
        "detected_snis": []
    }
    
    # Calculate app breakdown
    for pkt in input_packets:
        app_name = pkt["app"]
        stats["apps"][app_name] = stats["apps"].get(app_name, 0) + 1
        if pkt["domain"] != "-" and pkt["domain"] not in [x["domain"] for x in stats["detected_snis"]]:
            stats["detected_snis"].append({
                "domain": pkt["domain"],
                "app": pkt["app"],
                "protocol": pkt["protocol"]
            })
            
    # Parse thread dispatch info from raw output
    for line in raw_output.splitlines():
        if "LB" in line and "dispatched:" in line:
            parts = line.split("dispatched:")
            lb_name = parts[0].replace("║", "").replace(" ", "")
            try:
                cnt = int(parts[1].replace("║", "").strip())
                stats["threads"]["lbs"][lb_name] = cnt
            except ValueError:
                pass
        elif "FP" in line and "processed:" in line:
            parts = line.split("processed:")
            fp_name = parts[0].replace("║", "").replace(" ", "")
            try:
                cnt = int(parts[1].replace("║", "").strip())
                stats["threads"]["fps"][fp_name] = cnt
            except ValueError:
                pass

    if enforce_block:
        enforcement_status = enforce_host_blocks(True, blocked_ips, blocked_domains, blocked_apps, input_packets)
    return {
        "enforcement_status": enforcement_status,
        "success": True,
        "active_rules": {
            "blocked_apps": blocked_apps,
            "blocked_ips": blocked_ips,
            "blocked_domains": blocked_domains,
            "num_lbs": num_lbs,
            "fps_per_lb": fps_per_lb
        },
        "stats": stats,
        "packets": input_packets,
        "raw_output": raw_output,
        "stderr": err_output
    }


class DPIRequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler providing REST API and serving web dashboard."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            engine_ready = os.path.exists(os.path.join(BASE_DIR, "dpi_engine"))
            pcap_ready = os.path.exists(INPUT_PCAP)
            if sys.platform == "darwin":
                sys_label = "macOS Native (Clang C++17)"
            elif sys.platform == "win32":
                sys_label = "WSL2 Ubuntu 24.04 (GCC 13.3 C++17)"
            else:
                sys_label = "Linux Native (GCC C++17)"
            resp = {
                "engine_ready": engine_ready,
                "is_root": is_root(),
                "live_pcap_ready": os.path.exists(LIVE_PCAP),
                "interfaces": available_interfaces(),
                "pcap_ready": pcap_ready,
                "input_pcap": "test_dpi.pcap",
                "system": sys_label
            }
            self.wfile.write(json.dumps(resp).encode("utf-8"))
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(length) if length > 0 else b"{}"
        
        try:
            body = json.loads(post_data.decode("utf-8"))
        except Exception:
            body = {}

        if parsed.path == "/api/inspect":
            blocked_apps = body.get("blocked_apps", [])
            blocked_ips = body.get("blocked_ips", [])
            blocked_domains = body.get("blocked_domains", [])
            num_lbs = body.get("num_lbs", 2)
            fps_per_lb = body.get("fps_per_lb", 2)
            
            try:
                result = run_dpi_engine(blocked_apps, blocked_ips, blocked_domains, int(num_lbs), int(fps_per_lb),
                                        mode=body.get("mode", "synthetic"), capture_new=body.get("capture_new", False),
                                        interface=body.get("interface", "auto"), duration=int(body.get("duration", 5)),
                                        enforce_block=body.get("enforce_block", False))
            except (ValueError, TypeError) as exc:
                result = {"success": False, "error": str(exc)}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode("utf-8"))
            
        elif parsed.path == "/api/clear_blocks":
            status = enforce_host_blocks(False)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": status["success"], "enforcement_status": status}).encode("utf-8"))
        elif parsed.path == "/api/regenerate":
            # Run generate_test_pcap.py
            cmd = [sys.executable, os.path.join(BASE_DIR, "generate_test_pcap.py")]
            res = subprocess.run(cmd, capture_output=True, text=True)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": res.returncode == 0, "log": res.stdout}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()


def start_server():
    os.chdir(BASE_DIR)
    if not os.path.exists(WEB_DIR):
        os.makedirs(WEB_DIR, exist_ok=True)
    
    server_address = ("", PORT)
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(server_address, DPIRequestHandler) as httpd:
        url = f"http://localhost:{PORT}"
        print("=" * 60)
        print(f"  DPI Engine Visual Console Running at: {url}")
        print("  Press Ctrl+C to stop the server")
        print("=" * 60)
        
        # Open in default browser after 0.6 seconds
        def open_browser():
            import time
            time.sleep(0.6)
            webbrowser.open(url)
            
        threading.Thread(target=open_browser, daemon=True).start()
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    start_server()
