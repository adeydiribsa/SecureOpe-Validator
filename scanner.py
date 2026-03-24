import nmap

def scan_target(target):
    nm = nmap.PortScanner()

    results = {
        "open_ports": [],
        "services": [],
        "os": "Unknown",
        "host_status": "unreachable",
        "scripts": [],
        "error": None
    }

    try:
        nm.scan(target, arguments='-O -sV -sC --osscan-guess -T4 -p 1-1000')

        # ✅ Check if host exists in scan result
        if target not in nm.all_hosts():
            results["error"] = "Host not found / unreachable"
            return results

        results["host_status"] = nm[target].state()

        # OS detection
        try:
            if 'osmatch' in nm[target] and nm[target]['osmatch']:
                os_match = nm[target]['osmatch'][0]
                results["os"] = f"{os_match['name']} ({os_match['accuracy']}%)"
        except:
            pass

        # Ports and services
        for proto in nm[target].all_protocols():
            for port in nm[target][proto].keys():
                port_data = nm[target][proto][port]

                if port_data['state'] == 'open':
                    results["open_ports"].append(port)

                    results["services"].append({
                        "port": port,
                        "service": port_data.get('name'),
                        "product": port_data.get('product'),
                        "version": port_data.get('version')
                    })

                    if 'script' in port_data:
                        for s, output in port_data['script'].items():
                            results["scripts"].append({
                                "port": port,
                                "script": s,
                                "output": output
                            })

    except Exception as e:
        results["error"] = str(e)

    return results


def advanced_checks(scan_results):
    issues = []

    ports = scan_results["open_ports"]

    if 3389 in ports:
        issues.append("RDP exposed to internet (HIGH RISK)")

    if 21 in ports:
        issues.append("FTP detected (HIGH RISK)")

    if 23 in ports:
        issues.append("Telnet detected (CRITICAL)")

    if 445 in ports:
        issues.append("SMB port open (HIGH RISK)")

    for svc in scan_results["services"]:
        if svc["service"] == "http":
            issues.append(f"HTTP service on port {svc['port']} (MEDIUM RISK)")

    for script in scan_results["scripts"]:
        if "vulnerable" in script["output"].lower():
            issues.append(f"Vulnerability detected on port {script['port']} (HIGH RISK)")

    return issues