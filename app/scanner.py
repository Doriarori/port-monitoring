import nmap
import logging

logger = logging.getLogger(__name__)

# TCP: top 1000 ports with version detection
TCP_ARGS = "-sV --open -T4"
# UDP: top 100 common ports (needs root)
UDP_ARGS = "-sU --top-ports 100 --open -T4"


def run_scan(host: str, scan_type: str) -> tuple[list[dict], str | None]:
    """
    Returns (ports_list, error_message).
    ports_list is empty on failure.
    """
    nm = nmap.PortScanner()
    ports: list[dict] = []

    try:
        if scan_type in ("tcp", "both"):
            ports.extend(_scan_proto(nm, host, "tcp", TCP_ARGS))
    except Exception as e:
        logger.error("TCP scan failed for %s: %s", host, e)
        return [], f"TCP scan error: {e}"

    try:
        if scan_type in ("udp", "both"):
            ports.extend(_scan_proto(nm, host, "udp", UDP_ARGS))
    except Exception as e:
        # UDP failures are often just missing root — log and continue with TCP results
        logger.warning("UDP scan failed for %s: %s (root required for UDP)", host, e)
        if scan_type == "udp":
            return [], f"UDP scan error (root/sudo required): {e}"

    return ports, None


def _scan_proto(nm: nmap.PortScanner, host: str, proto: str, args: str) -> list[dict]:
    nm.scan(hosts=host, arguments=args)
    results = []
    for h in nm.all_hosts():
        proto_data = nm[h].get(proto, {})
        for port_num, port_info in proto_data.items():
            if port_info.get("state") in ("open", "open|filtered"):
                results.append({
                    "port": port_num,
                    "protocol": proto,
                    "state": port_info.get("state", "open"),
                    "service": port_info.get("name") or None,
                    "product": port_info.get("product") or None,
                    "version": port_info.get("version") or None,
                    "extra_info": port_info.get("extrainfo") or None,
                })
    return results
