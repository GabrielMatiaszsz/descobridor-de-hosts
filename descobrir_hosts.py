#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import concurrent.futures as cf
import ipaddress
import os
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

# ------------------------- Utilidades de rede -------------------------

def is_private_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def detect_local_cidr() -> str | None:
    """
    Tenta descobrir a rede local (CIDR) de forma portátil.
    Retorna algo como '192.168.0.0/24' ou None se não conseguir.
    """
    system = platform.system().lower()

    # Windows: ipconfig (em PT/EN)
    if "windows" in system:
        try:
            out = subprocess.check_output(["ipconfig"], stderr=subprocess.STDOUT)
            text = out.decode("cp850", errors="ignore")
            ipv4_re = re.compile(r"IPv4.*?:\s*([\d\.]+)", re.IGNORECASE)
            mask_re = re.compile(r"(Subnet Mask|Máscara.*Sub-rede).*?:\s*([\d\.]+)", re.IGNORECASE)

            ip = None
            mask = None
            for line in text.splitlines():
                m1 = ipv4_re.search(line)
                if m1:
                    cand = m1.group(1)
                    if is_private_ipv4(cand):
                        ip = cand
                        mask = None  # reseta; a máscara costuma vir nas linhas seguintes
                        continue
                m2 = mask_re.search(line)
                if m2 and ip:
                    mask = m2.group(2)
                    # monta CIDR pela dupla ip/mask
                    try:
                        net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                        return str(net)
                    except Exception:
                        ip = None
                        mask = None
            return None
        except Exception:
            return None

    # Linux: ip -o -f inet addr show
    if "linux" in system:
        for cmd in (["ip", "-o", "-f", "inet", "addr", "show", "scope", "global"],
                    ["ip", "-o", "-f", "inet", "addr", "show"]):
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
                text = out.decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    # ... inet 192.168.1.5/24 ...
                    m = re.search(r"inet\s+([\d\.]+)/(\d+)", line)
                    if m:
                        ip = m.group(1)
                        prefix = int(m.group(2))
                        if is_private_ipv4(ip):
                            net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                            return str(net)
            except Exception:
                pass
        return None

    # macOS/BSD: ifconfig
    if "darwin" in system or "bsd" in system:
        try:
            out = subprocess.check_output(["ifconfig"], stderr=subprocess.STDOUT)
            text = out.decode("utf-8", errors="ignore")
            # Padrão típico: "inet 192.168.1.12 netmask 0xffffff00"
            for block in text.split("\n\n"):
                if "status: active" not in block and "status: active" not in block.lower():
                    # Nem sempre há 'status: active'; tentaremos assim mesmo
                    pass
                m_ip = re.search(r"\binet\s+([\d\.]+)\b", block)
                if not m_ip:
                    continue
                ip = m_ip.group(1)
                if not is_private_ipv4(ip):
                    continue
                m_mask_hex = re.search(r"netmask\s+0x([0-9a-fA-F]+)", block)
                if m_mask_hex:
                    val = int(m_mask_hex.group(1), 16)
                    # converte máscara em prefixo
                    prefix = bin(val).count("1")
                    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
                    return str(net)
                # fallback: às vezes vem em dotted-decimal
                m_mask_dec = re.search(r"netmask\s+([\d\.]{7,15})", block)
                if m_mask_dec:
                    mask = m_mask_dec.group(1)
                    net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    return str(net)
            return None
        except Exception:
            return None

    return None

def ping_once(ip: str, timeout: float = 0.8) -> tuple[bool, float]:
    """
    Faz 1 ping ao IP. Retorna (alcançável, elapsed_ms).
    Usa o utilitário do sistema operacional.
    """
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif "darwin" in system:
        # macOS/BSD: -W em ms
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        # Linux: -W em segundos
        cmd = ["ping", "-c", "1", "-W", str(int(round(timeout))), ip]

    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 1)
        ok = (proc.returncode == 0)
    except subprocess.TimeoutExpired:
        ok = False
    except Exception:
        ok = False
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return ok, elapsed_ms

def read_arp_table() -> dict[str, str]:
    """
    Lê a tabela ARP e retorna {ip: mac}.
    Tenta 'ip neigh' (Linux), depois 'arp -a' (Windows/macOS/Linux).
    """
    macmap: dict[str, str] = {}

    # Linux: ip neigh show
    try:
        out = subprocess.check_output(["ip", "neigh", "show"], stderr=subprocess.STDOUT)
        text = out.decode("utf-8", errors="ignore")
        for line in text.splitlines():
            # 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            m_ip = re.search(r"(^|\s)(\d{1,3}(?:\.\d{1,3}){3})(\s|$)", line)
            m_mac = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", line)
            if m_ip and m_mac:
                macmap[m_ip.group(2)] = m_mac.group(1).lower()
        if macmap:
            return macmap
    except Exception:
        pass

    # arp -a (Windows/macOS/Linux)
    try:
        out = subprocess.check_output(["arp", "-a"], stderr=subprocess.STDOUT)
        text = out.decode("utf-8", errors="ignore")
        for line in text.splitlines():
            # Ex.: "192.168.1.1       00-11-22-33-44-55     dynamic"
            m_ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            m_mac = re.search(r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}", line)
            if m_ip and m_mac:
                mac = m_mac.group(0).lower().replace("-", ":")
                macmap[m_ip.group(0)] = mac
    except Exception:
        pass

    return macmap

def reverse_dns(ip: str, timeout_s: float = 0.3) -> str | None:
    """
    Faz um reverse DNS rápido (com timeout curto).
    """
    # socket.gethostbyaddr não tem timeout próprio; usamos threads
    name: list[str | None] = [None]

    def _lookup():
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            name[0] = host
        except Exception:
            name[0] = None

    with cf.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_lookup)
        try:
            fut.result(timeout=timeout_s)
        except Exception:
            return None
    return name[0]

# ------------------------- Pipeline principal -------------------------

def scan_network(cidr: str, timeout: float, workers: int, do_dns: bool) -> list[dict]:
    net = ipaddress.ip_network(cidr, strict=False)
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > 8192:
        print(f"[!] Atenção: {len(hosts)} endereços para varrer. Isso pode demorar.", file=sys.stderr)

    results: list[dict] = []

    # ping em paralelo
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(ping_once, ip, timeout): ip for ip in hosts}
        for fut in cf.as_completed(futs):
            ip = futs[fut]
            ok, elapsed = fut.result()
            if ok:
                results.append({"ip": ip, "rtt_ms": elapsed})

    # cruza com ARP para obter MACs
    arp = read_arp_table()
    for item in results:
        mac = arp.get(item["ip"])
        item["mac"] = mac or "-"

    # DNS reverso (opcional)
    if do_dns and results:
        with cf.ThreadPoolExecutor(max_workers=min(64, workers)) as ex:
            futs = {ex.submit(reverse_dns, item["ip"]): item for item in results}
            for fut in cf.as_completed(futs):
                item = futs[fut]
                try:
                    hostname = fut.result()
                except Exception:
                    hostname = None
                item["host"] = hostname or "-"

    # ordena por IP
    results.sort(key=lambda d: tuple(map(int, d["ip"].split("."))))
    return results

def main():
    parser = argparse.ArgumentParser(
        description="Descobrir máquinas no mesmo domínio de broadcast (sub-rede) e salvar em .txt"
    )
    parser.add_argument("--cidr", help="Rede no formato CIDR (ex.: 192.168.1.0/24). Se não passar, tento detectar.")
    parser.add_argument("--timeout", type=float, default=0.8, help="Timeout do ping (segundos). Padrão: 0.8")
    parser.add_argument("--workers", type=int, default=max(32, (os.cpu_count() or 2) * 32),
                        help="Número de threads para pings. Padrão: CPUs*32 (mín. 32)")
    parser.add_argument("--dns", action="store_true", help="Fazer DNS reverso para tentar obter hostname.")
    parser.add_argument("--outfile", default=None, help="Arquivo de saída (.txt). (opcional)")

    args = parser.parse_args()

    cidr = args.cidr or detect_local_cidr()
    if not cidr:
        print("[!] Não consegui detectar sua rede automaticamente.", file=sys.stderr)
        print("    Dê a rede via --cidr, ex.: --cidr 192.168.1.0/24", file=sys.stderr)
        sys.exit(2)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = args.outfile or f"hosts_descobertos_{ts}.txt"

    print(f"[i] Rede alvo: {cidr}")
    print(f"[i] Iniciando varredura (timeout={args.timeout}s, workers={args.workers})...")

    t0 = time.perf_counter()
    results = scan_network(cidr, args.timeout, args.workers, args.dns)
    dt = time.perf_counter() - t0

    print(f"[i] Encontrados {len(results)} hosts ativos em {dt:.1f}s")
    print(f"[i] Salvando em: {outfile}")

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(f"# Descoberta de hosts na rede {cidr}\n")
        f.write(f"# Gerado em: {datetime.now().isoformat(timespec='seconds')}\n")
        f.write(f"# Timeout: {args.timeout}s | Workers: {args.workers} | DNS reverso: {bool(args.dns)}\n")
        f.write("# IP; MAC; RTT(ms); HOSTNAME\n")
        for item in results:
            ip = item["ip"]
            mac = item.get("mac", "-")
            rtt = f"{item.get('rtt_ms', 0.0):.1f}"
            host = item.get("host", "-")
            f.write(f"{ip}; {mac}; {rtt}; {host}\n")

    print("[✓] Concluído.")

if __name__ == "__main__":
    main()
