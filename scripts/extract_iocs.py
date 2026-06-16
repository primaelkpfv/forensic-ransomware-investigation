#!/usr/bin/env python3
"""
Script d'extraction automatique d'IOCs depuis logs Volatility/Autopsy
Projet: Investigation Forensique Ransomware
Auteur: Fèmi KPONOU
"""

import re
import json
import hashlib
from pathlib import Path
from datetime import datetime


IOC_PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "domain": r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "url": r"https?://[^\s<>"{}|\\^`\[\]]+",
    "registry": r"HK(?:LM|CU|CR|U|CC)\\[^\n\r]+",
    "mutex": r"(?:Global|Local)\\[A-Za-z0-9_\-]+",
}

WHITELIST_IPS = {
    "127.0.0.1", "0.0.0.0", "255.255.255.255",
    "192.168.1.1", "10.0.0.1", "172.16.0.1"
}

WHITELIST_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com",
    "google.com", "github.com"
}


class IOCExtractor:
    def __init__(self):
        self.iocs = {k: set() for k in IOC_PATTERNS}
        self.results = []

    def extract_from_file(self, filepath: str) -> dict:
        path = Path(filepath)
        if not path.exists():
            print(f"[!] Fichier introuvable: {filepath}")
            return {}

        content = path.read_text(errors="ignore")
        print(f"[*] Analyse de {path.name} ({len(content)} caractères)...")

        for ioc_type, pattern in IOC_PATTERNS.items():
            matches = set(re.findall(pattern, content))
            if ioc_type == "ipv4":
                matches -= WHITELIST_IPS
                # Filtrer IPs privées
                matches = {ip for ip in matches if not (
                    ip.startswith("192.168.") or
                    ip.startswith("10.") or
                    ip.startswith("172.")
                )}
            elif ioc_type == "domain":
                matches -= WHITELIST_DOMAINS

            self.iocs[ioc_type].update(matches)
            if matches:
                print(f"  [+] {ioc_type}: {len(matches)} IOC(s) trouvé(s)")

        return {k: list(v) for k, v in self.iocs.items() if v}

    def export_misp(self, output_file: str = "iocs_misp.json"):
        """Exporter au format compatible MISP"""
        misp_event = {
            "Event": {
                "info": f"Ransomware Investigation IOCs — {datetime.now().strftime('%Y-%m-%d')}",
                "threat_level_id": "1",
                "analysis": "2",
                "Attribute": []
            }
        }

        type_mapping = {
            "ipv4": "ip-dst",
            "domain": "domain",
            "md5": "md5",
            "sha256": "sha256",
            "url": "url",
            "registry": "regkey",
            "mutex": "mutex"
        }

        for ioc_type, values in self.iocs.items():
            misp_type = type_mapping.get(ioc_type, "text")
            for value in values:
                misp_event["Event"]["Attribute"].append({
                    "type": misp_type,
                    "value": value,
                    "to_ids": True,
                    "category": "Network activity" if ioc_type in ["ipv4","domain","url"] else "Artifacts dropped"
                })

        with open(output_file, "w") as f:
            json.dump(misp_event, f, indent=2)
        print(f"[✓] Export MISP: {output_file} ({len(misp_event['Event']['Attribute'])} attributs)")

    def export_yaml(self, output_file: str = "iocs_list.yaml"):
        """Exporter en YAML pour documentation"""
        lines = [f"# IOCs — Investigation Ransomware — {datetime.now().strftime('%Y-%m-%d')}\n"]
        for ioc_type, values in self.iocs.items():
            if values:
                lines.append(f"\n{ioc_type}:")
                for v in sorted(values):
                    lines.append(f"  - "{v}"")
        with open(output_file, "w") as f:
            f.write("\n".join(lines))
        print(f"[✓] Export YAML: {output_file}")


if __name__ == "__main__":
    import sys
    extractor = IOCExtractor()

    if len(sys.argv) > 1:
        for filepath in sys.argv[1:]:
            extractor.extract_from_file(filepath)
    else:
        print("[*] Usage: python3 extract_iocs.py <volatility_output.txt> [autopsy_report.txt]")
        print("[*] Exemple avec données de démonstration...")
        demo_content = """
        Process: powershell.exe PID: 4832
        Connection: 185.234.219.45:4444 ESTABLISHED
        Domain queried: update-windows.xyz
        Registry: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
        Hash: a1b2c3d4e5f6789012345678901234ab
        Mutex: Global\\MutexRansomLock2025
        """
        Path("/tmp/demo_volatility.txt").write_text(demo_content)
        extractor.extract_from_file("/tmp/demo_volatility.txt")

    extractor.export_misp()
    extractor.export_yaml()
    print("\n[✓] Extraction IOCs terminée.")
