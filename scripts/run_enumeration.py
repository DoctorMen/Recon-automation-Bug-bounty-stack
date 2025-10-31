#!/usr/bin/env python3
"""Opinionated reconnaissance orchestrator for bug bounty enumeration.

The script wires together common tooling (subfinder, amass, dnsx, httpx, nmap, etc.)
and falls back to standard-library techniques when dependencies are missing. It is
designed to prioritize medium-to-high severity hunting by quickly surfacing
live assets and high-signal services.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
from json import JSONDecodeError
import socket
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:
    import yaml  # type: ignore
except ImportError as exc:  # pragma: no cover - dependency notice
    sys.exit(
        "Missing optional dependency 'pyyaml'. Install requirements with "
        "`pip install -r requirements.txt` before running this script."
    )


TOOL_GROUPS: Dict[str, Sequence[str]] = {
    "subdomain": ("subfinder", "amass", "assetfinder"),
    "resolver": ("dnsx",),
    "http_probe": ("httpx",),
    "port_scan": ("masscan", "nmap"),
}


class RunnerError(RuntimeError):
    """Raised when an external command fails."""


def log(msg: str) -> None:
    timestamp = _dt.datetime.utcnow().strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}")


def check_available_tools() -> Dict[str, Optional[str]]:
    import shutil

    mapping: Dict[str, Optional[str]] = {}
    for group_tools in TOOL_GROUPS.values():
        for tool in group_tools:
            if tool not in mapping:
                mapping[tool] = shutil.which(tool)
    return mapping


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def run_command(
    command: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    input_data: Optional[str] = None,
    capture_output: bool = True,
    timeout: Optional[int] = None,
) -> subprocess.CompletedProcess[str]:
    log(f"Running: {' '.join(command)}")
    result = subprocess.run(
        command,
        cwd=cwd,
        input=input_data,
        text=True,
        capture_output=capture_output,
        check=False,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RunnerError(
            f"Command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout: {result.stdout}\n"
            f"stderr: {result.stderr}"
        )
    return result


def load_scope(scope_path: Path) -> Dict[str, List[str]]:
    if not scope_path.exists():
        raise FileNotFoundError(f"Scope file not found: {scope_path}")

    with scope_path.open("r", encoding="utf-8") as handle:
        parsed = yaml.safe_load(handle) or {}

    def ensure_list(key: str) -> List[str]:
        values = parsed.get(key, [])
        if values is None:
            return []
        if not isinstance(values, list):
            raise TypeError(f"Scope key '{key}' must be a list")
        return [str(item).strip() for item in values if str(item).strip()]

    return {
        "domains": ensure_list("domains"),
        "ip_ranges": ensure_list("ip_ranges"),
        "asns": ensure_list("asns"),
    }


def write_lines(path: Path, items: Iterable[str]) -> None:
    ensure_dir(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        for line in sorted(set(item.strip() for item in items if item.strip())):
            handle.write(f"{line}\n")


def read_lines(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8") as handle:
        return {line.strip() for line in handle if line.strip()}


def enumerate_subdomains(
    domain: str,
    output_dir: Path,
    tool_paths: Dict[str, Optional[str]],
) -> Set[str]:
    domain_dir = ensure_dir(output_dir / "subdomains" / domain)
    discovered: Set[str] = set()

    # subfinder
    if tool_paths.get("subfinder"):
        outfile = domain_dir / "subfinder.txt"
        try:
            run_command(
                [
                    tool_paths["subfinder"],
                    "-d",
                    domain,
                    "-o",
                    str(outfile),
                    "-silent",
                ]
            )
            discovered.update(read_lines(outfile))
        except RunnerError as err:
            log(f"subfinder failed for {domain}: {err}")
    else:
        log("subfinder not available. Skipping.")

    # amass
    if tool_paths.get("amass"):
        outfile = domain_dir / "amass.txt"
        try:
            run_command(
                [
                    tool_paths["amass"],
                    "enum",
                    "-passive",
                    "-d",
                    domain,
                    "-o",
                    str(outfile),
                ]
            )
            discovered.update(read_lines(outfile))
        except RunnerError as err:
            log(f"amass failed for {domain}: {err}")
    else:
        log("amass not available. Skipping.")

    # assetfinder
    if tool_paths.get("assetfinder"):
        outfile = domain_dir / "assetfinder.txt"
        try:
            result = run_command(
                [tool_paths["assetfinder"], domain], capture_output=True
            )
            ensure_dir(outfile.parent)
            with outfile.open("w", encoding="utf-8") as handle:
                handle.write(result.stdout)
            discovered.update(read_lines(outfile))
        except RunnerError as err:
            log(f"assetfinder failed for {domain}: {err}")
    else:
        log("assetfinder not available. Skipping.")

    if not discovered:
        log(f"No subdomains discovered for {domain} via available tooling.")

    combined_path = domain_dir / "combined.txt"
    write_lines(combined_path, discovered)

    return discovered


def resolve_hosts(
    hosts: Iterable[str],
    output_dir: Path,
    tool_paths: Dict[str, Optional[str]],
) -> Tuple[Set[str], Dict[str, List[str]]]:
    hosts = sorted(set(hosts))
    if not hosts:
        return set(), {}

    live_hosts: Set[str] = set()
    host_ip_mapping: Dict[str, List[str]] = {}

    dnsx_path = tool_paths.get("dnsx")
    if dnsx_path:
        host_list_path = output_dir / "tmp" / "dnsx_input.txt"
        write_lines(host_list_path, hosts)
        resolved_path = output_dir / "subdomains" / "live.txt"
        try:
            result = run_command(
                [
                    dnsx_path,
                    "-silent",
                    "-l",
                    str(host_list_path),
                    "-resp",
                    "-json",
                ],
                capture_output=True,
            )
        except RunnerError as err:
            log(f"dnsx failed, falling back to socket resolution: {err}")
        else:
            for line in result.stdout.splitlines():
                try:
                    parsed = json.loads(line)
                    host = parsed.get("host")
                    ips = parsed.get("a") or []
                    if host:
                        live_hosts.add(host)
                        host_ip_mapping[host] = ips
                except JSONDecodeError:
                    continue
            write_lines(resolved_path, live_hosts)
            return live_hosts, host_ip_mapping

    # fallback resolution
    log("Resolving hosts via socket.getaddrinfo fallback.")
    for host in hosts:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            continue
        ips = sorted({info[4][0] for info in infos if info[4]})
        if ips:
            live_hosts.add(host)
            host_ip_mapping[host] = ips

    resolved_path = output_dir / "subdomains" / "live.txt"
    write_lines(resolved_path, live_hosts)
    return live_hosts, host_ip_mapping


def http_probe(
    hosts: Iterable[str],
    output_dir: Path,
    tool_paths: Dict[str, Optional[str]],
    timeout: int,
) -> None:
    hosts = sorted(set(hosts))
    if not hosts:
        return

    httpx_path = tool_paths.get("httpx")
    output_file = output_dir / "http" / "probe.jsonl"

    if httpx_path:
        host_list_path = output_dir / "tmp" / "httpx_input.txt"
        write_lines(host_list_path, hosts)
        try:
            result = run_command(
                [
                    httpx_path,
                    "-silent",
                    "-json",
                    "-l",
                    str(host_list_path),
                    "-timeout",
                    str(timeout),
                    "-follow-redirects",
                    "-tls-probe",
                ],
                capture_output=True,
            )
            ensure_dir(output_file.parent)
            with output_file.open("w", encoding="utf-8") as handle:
                handle.write(result.stdout)
        except RunnerError as err:
            log(f"httpx failed; falling back to Python probing: {err}")
        else:
            return

    # fallback using urllib
    import ssl
    from urllib import request

    log("Fallback HTTP probing via urllib (HEAD requests).")
    ensure_dir(output_file.parent)
    ctx = ssl.create_default_context()
    with output_file.open("w", encoding="utf-8") as handle:
        for host in hosts:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}"
                req = request.Request(url, method="HEAD")
                try:
                    with request.urlopen(req, timeout=timeout, context=ctx) as resp:
                        record = {
                            "url": url,
                            "status": resp.status,
                            "headers": dict(resp.getheaders()),
                        }
                        handle.write(json.dumps(record) + "\n")
                        break
                except Exception:
                    continue


def masscan_sweep(
    ip_ranges: Sequence[str],
    output_dir: Path,
    tool_paths: Dict[str, Optional[str]],
    rate: int,
    top_ports: int,
) -> Set[str]:
    if not ip_ranges:
        log("No IP ranges provided for masscan sweep.")
        return set()

    masscan_path = tool_paths.get("masscan")
    if not masscan_path:
        log("masscan not available. Skipping fast port sweep.")
        return set()

    ensure_dir(output_dir / "ports")
    output_json = output_dir / "ports" / "masscan.json"
    open_ports_path = output_dir / "ports" / "masscan_open.txt"

    command = [
        masscan_path,
        "--rate",
        str(rate),
        "--top-ports",
        str(top_ports),
        "-oJ",
        str(output_json),
    ]
    command.extend(ip_ranges)

    try:
        run_command(command, capture_output=False)
    except RunnerError as err:
        log(f"masscan execution failed: {err}")
        return set()

    discovered_ips: Set[str] = set()
    try:
        with output_json.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (FileNotFoundError, JSONDecodeError) as err:
        log(f"Failed to read masscan output: {err}")
        return set()

    with open_ports_path.open("w", encoding="utf-8") as ports_handle:
        for entry in data:
            ip = entry.get("ip")
            if not ip:
                continue
            discovered_ips.add(ip)
            for port_info in entry.get("ports", []):
                port = port_info.get("port")
                proto = port_info.get("proto")
                status = port_info.get("status")
                ports_handle.write(
                    f"{ip},{port or ''},{proto or ''},{status or ''}\n"
                )

    log(f"masscan discovered {len(discovered_ips)} unique IPs with open ports.")
    return discovered_ips


def nmap_scan(
    hosts: Iterable[str],
    output_dir: Path,
    tool_paths: Dict[str, Optional[str]],
    top_ports: int,
) -> None:
    if not hosts:
        return
    nmap_path = tool_paths.get("nmap")
    if not nmap_path:
        log("nmap not available. Skipping port scan.")
        return

    host_list_path = output_dir / "tmp" / "nmap_hosts.txt"
    write_lines(host_list_path, hosts)

    xml_output = output_dir / "ports" / "nmap.xml"
    ensure_dir(xml_output.parent)
    try:
        run_command(
            [
                nmap_path,
                "-iL",
                str(host_list_path),
                "--top-ports",
                str(top_ports),
                "-sV",
                "-sC",
                "-oX",
                str(xml_output),
            ]
        )
    except RunnerError as err:
        log(f"nmap execution failed: {err}")


def summarize(
    run_dir: Path,
    domains: Sequence[str],
    discovered_subdomains: Dict[str, Set[str]],
    live_hosts: Set[str],
    masscan_ips: Optional[Set[str]] = None,
) -> None:
    summary = {
        "run_dir": str(run_dir),
        "timestamp": _dt.datetime.utcnow().isoformat() + "Z",
        "domains": list(domains),
        "subdomain_counts": {
            domain: len(discovered_subdomains.get(domain, set())) for domain in domains
        },
        "total_subdomains": sum(
            len(discovered_subdomains.get(domain, set())) for domain in domains
        ),
        "live_hosts": sorted(live_hosts),
        "live_count": len(live_hosts),
    }

    if masscan_ips is not None:
        summary["masscan_ip_count"] = len(masscan_ips)
        summary["masscan_ips"] = sorted(masscan_ips)

    summary_path = run_dir / "summary.json"
    with summary_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)
    log(f"Summary written to {summary_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bug bounty enumeration orchestrator")
    parser.add_argument(
        "--scope",
        type=Path,
        default=Path("scope/targets.yaml"),
        help="Path to scope YAML file (default: scope/targets.yaml)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/runs"),
        help="Directory to store run outputs (default: data/runs)",
    )
    parser.add_argument(
        "--http-timeout",
        type=int,
        default=10,
        help="HTTP probing timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--nmap-top-ports",
        type=int,
        default=100,
        help="Number of top ports for nmap scans (default: 100)",
    )
    parser.add_argument(
        "--skip-nmap",
        action="store_true",
        help="Skip nmap port scanning even if available",
    )
    parser.add_argument(
        "--run-masscan",
        action="store_true",
        help="Enable masscan fast sweep for defined IP ranges",
    )
    parser.add_argument(
        "--masscan-rate",
        type=int,
        default=5000,
        help="Packets per second rate for masscan (default: 5000)",
    )
    parser.add_argument(
        "--masscan-top-ports",
        type=int,
        default=100,
        help="Number of top ports for masscan sweeps (default: 100)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    scope = load_scope(args.scope)
    if not scope["domains"]:
        log("No domains defined in scope. Exiting.")
        return

    run_id = _dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    run_dir = ensure_dir(args.output_dir / run_id)
    ensure_dir(run_dir / "tmp")

    tool_paths = check_available_tools()
    log(
        "Tool availability: "
        + ", ".join(
            f"{tool}={'yes' if path else 'no'}" for tool, path in sorted(tool_paths.items())
        )
    )

    discovered_subdomains: Dict[str, Set[str]] = {}

    for domain in scope["domains"]:
        log(f"=== Enumerating {domain} ===")
        discovered = enumerate_subdomains(domain, run_dir, tool_paths)
        discovered_subdomains[domain] = discovered

    all_hosts = sorted({host for hosts in discovered_subdomains.values() for host in hosts})
    log(f"Total unique subdomains discovered: {len(all_hosts)}")

    live_hosts, host_ip_mapping = resolve_hosts(all_hosts, run_dir, tool_paths)
    log(f"Live host count: {len(live_hosts)}")

    http_probe(live_hosts, run_dir, tool_paths, args.http_timeout)

    masscan_ips: Set[str] = set()
    if args.run_masscan:
        if scope["ip_ranges"]:
            masscan_ips = masscan_sweep(
                scope["ip_ranges"],
                run_dir,
                tool_paths,
                args.masscan_rate,
                args.masscan_top_ports,
            )
        elif scope["asns"]:
            log(
                "ASN targets defined but ASN-to-IP resolution is not implemented. "
                "Provide IP ranges to run masscan."
            )
        else:
            log("No IP ranges configured for masscan sweep.")

    if not args.skip_nmap:
        nmap_targets: Set[str] = set()
        if masscan_ips:
            nmap_targets.update(masscan_ips)
        for ips in host_ip_mapping.values():
            nmap_targets.update(ips)
        # fallback: if DNS resolution missing IPs, try hostnames directly
        if not nmap_targets:
            nmap_targets = live_hosts
        nmap_scan(nmap_targets, run_dir, tool_paths, args.nmap_top_ports)

    summarize(
        run_dir,
        scope["domains"],
        discovered_subdomains,
        live_hosts,
        masscan_ips if args.run_masscan else None,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("Interrupted by user.")
        sys.exit(1)
