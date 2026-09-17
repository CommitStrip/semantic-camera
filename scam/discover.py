"""discover.py —— 局域网摄像头自动发现（三层递进，P4）。

L1 ONVIF WS-Discovery（UDP 239.255.255.250:3702 组播）
L2 RTSP 端口探测（554/8000）
L3 品牌 RTSP URL 模式穷举 + ffprobe 验证

用法: python -m scam.discover [--range 192.168.1.0/24] [--user u] [--password p]
"""

import argparse
import ipaddress
import socket
import sys
import time

BRAND_PATTERNS = [
    "rtsp://{user}:{pass}@{ip}:554/Streaming/Channels/{ch}",       # Hikvision
    "rtsp://{user}:{pass}@{ip}:554/cam/realmonitor?channel=1&subtype={sub}",  # Dahua
    "rtsp://{user}:{pass}@{ip}:554/live/ch00_{sub}",               # 通用
    "rtsp://{user}:{pass}@{ip}:554/",                              # 兜底
]

ONVIF_PROBE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    '<SOAP-ENV:Header><wsa:Action>'
    'http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
    '<wsa:MessageID>urn:uuid:scam-probe-001</wsa:MessageID>'
    '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
    '</SOAP-ENV:Header><SOAP-ENV:Body><dn:Probe>'
    '<dn:Types>dn:NetworkVideoTransmitter</dn:Types>'
    '</dn:Probe></SOAP-ENV:Body></SOAP-ENV:Envelope>'
)


def _recv_until(sock, timeout, collector):
    """组播接收直到超时；返回收集到的设备 IP 集合。"""
    sock.settimeout(timeout)
    seen = set()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(4096)
            ip = addr[0]
            if b"NetworkVideoTransmitter" in data or b"ProbeMatch" in data:
                seen.add(ip)
        except socket.timeout:
            break
        except OSError:
            break
    return seen


def discover_onvif(timeout=3):
    """L1: ONVIF WS-Discovery 组播，返回发现的设备 IP 集合。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.bind(("0.0.0.0", 0))
        sock.sendto(ONVIF_PROBE.encode(), ("239.255.255.250", 3702))
        return _recv_until(sock, timeout, None)
    except OSError:
        return set()
    finally:
        sock.close()


def probe_port(ip, port, timeout=2):
    """TCP 端口连通测试。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except OSError:
        return False


def subnet_hosts(range_str):
    """解析 CIDR 或单 IP → 主机 IP 列表（≤254）。"""
    net = ipaddress.ip_network(range_str, strict=False)
    return [str(h) for h in net.hosts()][:254]


def scan_rtsp_ports(hosts, ports=(554, 8000), timeout=1):
    """对主机列表探 RTSP 端口，返回开放的 (ip, port) 集合。"""
    open_ports = set()
    for ip in hosts:
        for port in ports:
            if probe_port(ip, port, timeout):
                open_ports.add((ip, port))
    return open_ports


def verify_rtsp(url, timeout=5):
    """ffprobe 验证 RTSP URL 可解码。返回 True/False。"""
    import subprocess
    try:
        r = subprocess.run(
            ["ffprobe", "-v", "quiet", "-timeout", str(timeout * 1000000),
             "-print_format", "json", "-show_streams", url],
            capture_output=True, timeout=timeout + 2)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def discover(range_str=None, user="", password="", timeout=3):
    """主发现流程：返回 [{ip, onvif, rtsp_ok, url}] 列表。"""
    if range_str:
        hosts = subnet_hosts(range_str)
    else:
        # 自动获取本机网段（简化：取主网卡 IP 的 /24）
        import socket as s
        try:
            tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            tmp.connect(("8.8.8.8", 80))
            local_ip = tmp.getsockname()[0]
            tmp.close()
        except Exception:
            local_ip = "192.168.1.1"
        net = ipaddress.ip_network(local_ip + "/24", strict=False)
        hosts = [str(h) for h in net.hosts()][:254]

    # L1 ONVIF 组播
    onvif_ips = discover_onvif(timeout)
    # L2 端口探测（合并 ONVIF 结果）
    rtsp_hosts = {ip for ip, _ in scan_rtsp_ports(hosts)}
    all_ips = onvif_ips | rtsp_hosts

    results = []
    for ip in sorted(all_ips):
        onvif = ip in onvif_ips
        rtsp_ok = ip in rtsp_hosts
        url = None
        if user and password and rtsp_ok:
            for pat in BRAND_PATTERNS:
                u = pat.format(user=user, password=password, ip=ip,
                               ch="101", sub="0")
                if verify_rtsp(u):
                    url = u
                    break
        results.append({"ip": ip, "onvif": onvif, "rtsp_ok": rtsp_ok,
                        "url": url})
    return results


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="局域网摄像头发现")
    ap.add_argument("--range", default=None, help="网段 CIDR（缺省自动检测）")
    ap.add_argument("--user", default="", help="RTSP 用户名")
    ap.add_argument("--password", default="", help="RTSP 密码")
    ap.add_argument("--timeout", type=int, default=3, help="组播等待秒数")
    args = ap.parse_args()
    results = discover(args.range, args.user, args.password, args.timeout)
    for r in results:
        status = "✅ RTSP 可用" if r["rtsp_ok"] else "⚠️ 端口通但取流未验证"
        print(f"  {r['ip']}  {status}  url={r.get('url') or '未验证'}")
    if not results:
        print("未发现摄像头（检查网段/ONVIF 开启状态）")
