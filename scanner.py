#!/usr/bin/env python3
"""
scanner.py  –  SNI-Spoofing project scanner + Trojan/Xray config tester
─────────────────────────────────────────────────────────────────────────
Phase 1 : fake-TCP bypass test (wrong_seq via WinDivert) — OR — plain TLS
Phase 2 : for every (ip, port, sni) that passed phase-1, substitute those
          values into xray.txt Trojan config, start xray.exe, then probe
          the local Trojan port with a real HTTPS request to verify tunnel.

Usage:
    py scanner.py --fake-tcp              # both phases
    py scanner.py                         # plain TLS phase-1, then Trojan phase-2
    py scanner.py --no-trojan             # skip phase-2 entirely

Flags:
    --sni              sni.txt     SNI hostnames file        (default: sni.txt)
    --ips              ip.txt      IP:port file               (default: ip.txt)
    --xray             xray.txt    Trojan URL template file   (default: xray.txt)
    --xray-exe         xray.exe    Path to xray executable   (default: xray.exe)
    --threads          20          Parallel workers           (default: 20)
    --timeout          5           Socket timeout secs        (default: 5)
    --trojan-timeout   8           Timeout for Trojan test    (default: 8)
    --output           results.csv CSV output                 (default: results.csv)
    --fake-tcp                     Use fake-TCP bypass (needs WinDivert + Admin)
    --no-trojan                    Skip Trojan/Xray phase
"""

import argparse
import csv
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, fields as dc_fields
from typing import Optional
from urllib.parse import urlparse, parse_qs, unquote

# ── make sure project root is always on sys.path ─────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# ── project imports ───────────────────────────────────────────────────────────
try:
    from utils.packet_templates import ClientHelloMaker
except ImportError as _e:
    print(f"[!] Cannot import utils.packet_templates: {_e}")
    print(f"    Script dir : {_HERE}")
    print(f"    Contents   : {os.listdir(_HERE)}")
    sys.exit(1)

try:
    from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
    from utils.network_tools import get_default_interface_ipv4
    WINDIVERT_AVAILABLE = True
except ImportError:
    WINDIVERT_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Result:
    ip:                str
    port:              int
    sni:               str
    mode:              str            # "tls" | "fake-tcp"
    bypass_ok:         bool
    trojan_ok:         Optional[bool]  = None
    tls_version:       Optional[str]   = None
    cipher:            Optional[str]   = None
    cert_cn:           Optional[str]   = None
    latency_ms:        Optional[float] = None
    bypass_error:      Optional[str]   = None
    trojan_latency_ms: Optional[float] = None
    trojan_error:      Optional[str]   = None


# ─────────────────────────────────────────────────────────────────────────────
# File parsers
# ─────────────────────────────────────────────────────────────────────────────

def parse_sni_file(path: str) -> list:
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    return [t.strip() for t in re.split(r"[\s,]+", raw) if t.strip()]


def parse_ip_file(path: str) -> list:
    pairs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or ":" not in line:
                continue
            host, port_str = line.rsplit(":", 1)
            try:
                pairs.append((host.strip(), int(port_str.strip())))
            except ValueError:
                print(f"[WARN] bad port: {line!r}", file=sys.stderr)
    return pairs


# ─────────────────────────────────────────────────────────────────────────────
# Trojan URL parser + Xray config builder
# ─────────────────────────────────────────────────────────────────────────────

def parse_trojan_url(url: str) -> dict:
    u = urlparse(url)
    qs = parse_qs(u.query)

    def q(key, default=""):
        return unquote(qs.get(key, [default])[0])

    return {
        "password": unquote(u.username or ""),
        "host":     u.hostname or "",
        "port":     u.port or 443,
        "sni":      q("sni", u.hostname or ""),
        "security": q("security", "tls"),
        "type":     q("type", "tcp"),
        "ws_host":  q("host", u.hostname or ""),
        "ws_path":  q("path", "/"),
        "insecure": q("insecure", "0") == "1" or q("allowInsecure", "0") == "1",
        "tag":      unquote(u.fragment) if u.fragment else "proxy",
    }


def build_xray_config(tpl: dict, ip: str, port: int, sni: str, listen_port: int) -> dict:
    stream: dict = {
        "network":     tpl["type"],
        "security":    tpl["security"],
        "tlsSettings": {"serverName": sni, "allowInsecure": tpl["insecure"]},
    }
    if tpl["type"] == "ws":
        stream["wsSettings"] = {
            "path":    tpl["ws_path"],
            "headers": {"Host": tpl["ws_host"]},
        }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks-in", "port": listen_port, "listen": "127.0.0.1",
            "protocol": "socks", "settings": {"udp": False},
        }],
        "outbounds": [{
            "tag":      tpl["tag"],
            "protocol": "trojan",
            "settings": {"servers": [{"address": ip, "port": port, "password": tpl["password"]}]},
            "streamSettings": stream,
        }],
    }


def find_free_port(start: int = 10800) -> int:
    for p in range(start, start + 500):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    raise RuntimeError("No free port found")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 2: Trojan / Xray probe
# ─────────────────────────────────────────────────────────────────────────────

_xray_sem = threading.Semaphore(3)   # max 3 xray processes at once


def _socks5_https_check(proxy_host: str, proxy_port: int, timeout: float):
    """Connect through SOCKS5 proxy → 1.1.1.1:443 and do a HEAD request."""
    import struct
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 handshake failed")
        req = struct.pack("!BBBB4sH", 5, 1, 0, 1, socket.inet_aton("1.1.1.1"), 443)
        sock.sendall(req)
        rep = sock.recv(10)
        if len(rep) < 2 or rep[1] != 0:
            raise RuntimeError(f"SOCKS5 CONNECT refused: {rep!r}")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(sock, server_hostname="one.one.one.one")
        tls.sendall(b"HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\n\r\n")
        data = tls.recv(256)
        if not data.startswith(b"HTTP"):
            raise RuntimeError(f"Bad response: {data[:40]!r}")
        tls.close()
    finally:
        sock.close()


def probe_trojan(ip: str, port: int, sni: str, tpl: dict,
                 xray_exe: str, timeout: float):
    """Returns (success, latency_ms, error_str)"""
    with _xray_sem:
        listen_port = find_free_port()
        cfg = build_xray_config(tpl, ip, port, sni, listen_port)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(cfg, f)
            cfg_path = f.name

        proc = None
        try:
            cflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            proc = subprocess.Popen(
                [xray_exe, "run", "-c", cfg_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=cflags,
            )
            time.sleep(1.2)   # wait for xray to bind

            t0 = time.monotonic()
            _socks5_https_check("127.0.0.1", listen_port, timeout)
            return True, round((time.monotonic() - t0) * 1000, 1), None

        except Exception as exc:
            return False, None, str(exc)

        finally:
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            try:
                os.unlink(cfg_path)
            except OSError:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: TLS probe
# ─────────────────────────────────────────────────────────────────────────────

def _cert_cn(cert: dict) -> Optional[str]:
    for entry in cert.get("subject", []):
        for k, v in entry:
            if k == "commonName":
                return v
    return None


def probe_tls(ip: str, port: int, sni: str, timeout: float) -> Result:
    t0 = time.monotonic()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        raw.settimeout(timeout)
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        lat = round((time.monotonic() - t0) * 1000, 1)
        cert, cipher, ver = tls.getpeercert(), tls.cipher(), tls.version()
        tls.close(); raw.close()
        return Result(ip=ip, port=port, sni=sni, mode="tls", bypass_ok=True,
                      tls_version=ver, cipher=cipher[0] if cipher else None,
                      cert_cn=_cert_cn(cert) if cert else None, latency_ms=lat)
    except Exception as exc:
        return Result(ip=ip, port=port, sni=sni, mode="tls", bypass_ok=False,
                      latency_ms=round((time.monotonic() - t0) * 1000, 1),
                      bypass_error=f"{type(exc).__name__}: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# Phase 1: fake-TCP probe
# ─────────────────────────────────────────────────────────────────────────────

_fake_injector = None
_fake_conns: dict = {}
_fake_lock = threading.Lock()


def _ensure_injector(src_ip: str, dst_ip: str):
    global _fake_injector
    with _fake_lock:
        if _fake_injector is None:
            wf = (f"tcp and ((ip.SrcAddr == {src_ip} and ip.DstAddr == {dst_ip})"
                  f" or (ip.SrcAddr == {dst_ip} and ip.DstAddr == {src_ip}))")
            _fake_injector = FakeTcpInjector(wf, _fake_conns)
            threading.Thread(target=_fake_injector.run, daemon=True).start()


def probe_fake_tcp(ip: str, port: int, sni: str,
                   timeout: float, iface_ip: str) -> Result:
    import asyncio

    if not WINDIVERT_AVAILABLE:
        return Result(ip=ip, port=port, sni=sni, mode="fake-tcp", bypass_ok=False,
                      bypass_error="pydivert not available / not Administrator")

    t0 = time.monotonic()

    async def _do():
        fake_data = ClientHelloMaker.get_client_hello_with(
            os.urandom(32), os.urandom(32), sni.encode(), os.urandom(32))
        _ensure_injector(iface_ip, ip)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.bind((iface_ip, 0))
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        src_port = sock.getsockname()[1]
        dummy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        conn = FakeInjectiveConnection(sock, iface_ip, ip, src_port, port,
                                       fake_data, "wrong_seq", dummy)
        _fake_conns[conn.id] = conn
        loop = asyncio.get_running_loop()

        try:
            await loop.sock_connect(sock, (ip, port))
        except Exception as e:
            conn.monitor = False; _fake_conns.pop(conn.id, None)
            sock.close(); dummy.close()
            raise RuntimeError(f"connect: {e}")

        try:
            await asyncio.wait_for(conn.t2a_event.wait(), timeout)
        except asyncio.TimeoutError:
            conn.monitor = False; _fake_conns.pop(conn.id, None)
            sock.close(); dummy.close()
            raise RuntimeError("timeout waiting for ACK")

        conn.monitor = False; _fake_conns.pop(conn.id, None)
        if conn.t2a_msg != "fake_data_ack_recv":
            sock.close(); dummy.close()
            raise RuntimeError(f"t2a_msg={conn.t2a_msg}")

        sock.setblocking(True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try:
            tls = ctx.wrap_socket(sock, server_hostname=sni)
            cert, cipher, ver = tls.getpeercert(), tls.cipher(), tls.version()
            tls.close()
        except Exception:
            cert = cipher = ver = None
        dummy.close()
        return cert, cipher, ver

    try:
        loop = asyncio.new_event_loop()
        cert, cipher, ver = loop.run_until_complete(_do())
        loop.close()
        return Result(ip=ip, port=port, sni=sni, mode="fake-tcp", bypass_ok=True,
                      tls_version=ver, cipher=cipher[0] if cipher else None,
                      cert_cn=_cert_cn(cert) if cert else None,
                      latency_ms=round((time.monotonic() - t0) * 1000, 1))
    except Exception as exc:
        return Result(ip=ip, port=port, sni=sni, mode="fake-tcp", bypass_ok=False,
                      latency_ms=round((time.monotonic() - t0) * 1000, 1),
                      bypass_error=str(exc))


# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────

CSV_HEADER = [f.name for f in dc_fields(Result)]
_print_lock = threading.Lock()


def log(phase: str, r: Result):
    with _print_lock:
        if phase == "bypass":
            icon = "✓" if r.bypass_ok else "✗"
            line = f"[bypass] {icon} {r.ip}:{r.port}  SNI={r.sni}"
            print(line + (f"  {r.tls_version}  {r.latency_ms}ms" if r.bypass_ok
                          else f"  {r.bypass_error}"))
        else:
            icon = "✓" if r.trojan_ok else "✗"
            line = f"[trojan] {icon} {r.ip}:{r.port}  SNI={r.sni}"
            print(line + (f"  {r.trojan_latency_ms}ms  ← WORKING" if r.trojan_ok
                          else f"  {r.trojan_error}"))


def write_csv(results: list, path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CSV_HEADER)
        w.writeheader()
        for r in results:
            w.writerow({f.name: getattr(r, f.name) for f in dc_fields(r)})
    print(f"[✓] Results CSV  → {path}")


def write_working(results: list, path: str, tpl: dict):
    working = [r for r in results if r.trojan_ok]
    if not working:
        print("[i] No fully-working Trojan combos found.")
        return
    with open(path, "w", encoding="utf-8") as f:
        for r in working:
            url = (f"trojan://{tpl['password']}@{r.ip}:{r.port}"
                   f"?security={tpl['security']}&sni={r.sni}"
                   f"&insecure={'1' if tpl['insecure'] else '0'}"
                   f"&type={tpl['type']}&host={tpl['ws_host']}"
                   f"&path={tpl['ws_path']}#{r.sni}_{r.ip}")
            f.write(url + "\n")
    print(f"[✓] Working URLs → {path}  ({len(working)} combos)")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sni",            default="sni.txt")
    ap.add_argument("--ips",            default="ip.txt")
    ap.add_argument("--xray",           default="xray.txt")
    ap.add_argument("--xray-exe",       default="xray.exe")
    ap.add_argument("--threads",        type=int,   default=20)
    ap.add_argument("--timeout",        type=float, default=5)
    ap.add_argument("--trojan-timeout", type=float, default=8)
    ap.add_argument("--output",         default="results.csv")
    ap.add_argument("--fake-tcp",       action="store_true")
    ap.add_argument("--no-trojan",      action="store_true")
    args = ap.parse_args()

    def p(name):   # resolve path relative to script dir
        v = getattr(args, name.replace("-", "_"))
        return v if os.path.isabs(v) else os.path.join(_HERE, v)

    sni_list = parse_sni_file(p("sni"))
    ip_list  = parse_ip_file(p("ips"))

    # ── Trojan template ───────────────────────────────────────────────────────
    run_trojan = not args.no_trojan
    tpl = None
    xray_exe = p("xray_exe")

    if run_trojan:
        xray_txt = p("xray")
        if not os.path.exists(xray_txt):
            print(f"[!] {xray_txt} not found — skipping Trojan phase")
            run_trojan = False
        else:
            with open(xray_txt, encoding="utf-8") as f:
                tpl = parse_trojan_url(f.read().strip())
            print(f"[*] Trojan template parsed:")
            print(f"    password={tpl['password']}  host={tpl['host']}:{tpl['port']}")
            print(f"    sni={tpl['sni']}  type={tpl['type']}  path={tpl['ws_path']}")

        if run_trojan and not os.path.exists(xray_exe):
            found = shutil.which("xray") or shutil.which("xray.exe")
            if found:
                xray_exe = found
                print(f"[*] Found xray at: {xray_exe}")
            else:
                print(f"[!] xray.exe not found — skipping Trojan phase")
                run_trojan = False

    # ── fake-TCP check ────────────────────────────────────────────────────────
    use_fake = args.fake_tcp
    if use_fake and not WINDIVERT_AVAILABLE:
        print("[!] --fake-tcp needs pydivert + Administrator. Exiting.")
        sys.exit(1)

    iface_ip = get_default_interface_ipv4() if use_fake else None
    total = len(sni_list) * len(ip_list)
    mode = "fake-tcp (wrong_seq)" if use_fake else "standard TLS"

    print(f"\n{'═'*65}")
    print(f"  PHASE 1 — {mode}")
    print(f"  {len(sni_list)} SNIs × {len(ip_list)} IP:ports = {total} probes")
    print(f"{'═'*65}\n")

    # ── Phase 1 ───────────────────────────────────────────────────────────────
    results = []
    done = 0
    tasks = [(ip, port, sni) for ip, port in ip_list for sni in sni_list]

    def p1(ip, port, sni):
        return probe_fake_tcp(ip, port, sni, args.timeout, iface_ip) if use_fake \
               else probe_tls(ip, port, sni, args.timeout)

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futs = {pool.submit(p1, ip, port, sni): None for ip, port, sni in tasks}
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            done += 1
            log("bypass", r)
            if done % 100 == 0:
                ok = sum(1 for x in results if x.bypass_ok)
                print(f"  … {done}/{total} ({done/total*100:.0f}%)  ok={ok}")

    passed = [r for r in results if r.bypass_ok]
    print(f"\n{'─'*65}")
    print(f"  Phase 1 done — {len(passed)}/{total} passed")
    print(f"{'─'*65}\n")

    # ── Phase 2 ───────────────────────────────────────────────────────────────
    if run_trojan and passed:
        print(f"{'═'*65}")
        print(f"  PHASE 2 — Trojan tunnel test ({len(passed)} combos)")
        print(f"  xray: {xray_exe}")
        print(f"{'═'*65}\n")

        def p2(r: Result):
            ok, lat, err = probe_trojan(r.ip, r.port, r.sni, tpl, xray_exe, args.trojan_timeout)
            r.trojan_ok = ok
            r.trojan_latency_ms = lat
            r.trojan_error = err
            return r

        with ThreadPoolExecutor(max_workers=3) as pool:
            for fut in as_completed({pool.submit(p2, r): r for r in passed}):
                log("trojan", fut.result())

        working = [r for r in passed if r.trojan_ok]
        print(f"\n{'─'*65}")
        print(f"  Phase 2 done — {len(working)}/{len(passed)} Trojan combos working")
        print(f"{'─'*65}\n")

        write_working(results, os.path.join(_HERE, "working_trojan.txt"), tpl)

    elif run_trojan:
        print("[i] No combos passed bypass — skipping Trojan phase.")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{'═'*65}")
    print(f"  Total         : {total}")
    print(f"  Bypass passed : {sum(1 for r in results if r.bypass_ok)}")
    if run_trojan:
        print(f"  Trojan OK     : {sum(1 for r in results if r.trojan_ok)}  ← usable combos")
    print(f"{'═'*65}\n")

    write_csv(results, os.path.join(_HERE, args.output))


if __name__ == "__main__":
    main()
