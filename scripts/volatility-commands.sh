#!/bin/bash
# Volatility 3 — Commandes investigation ransomware
# Auteur : Fèmi KPONOU

MEM_FILE=$1
OUTPUT_DIR="./volatility-output"
mkdir -p $OUTPUT_DIR

echo "[*] Analyse mémoire : $MEM_FILE"
echo "[*] Résultats dans : $OUTPUT_DIR"

echo "[+] 1. Liste des processus..."
python3 vol.py -f "$MEM_FILE" windows.pslist > "$OUTPUT_DIR/pslist.txt"

echo "[+] 2. Arbre des processus..."
python3 vol.py -f "$MEM_FILE" windows.pstree > "$OUTPUT_DIR/pstree.txt"

echo "[+] 3. Détection injections DLL (malfind)..."
python3 vol.py -f "$MEM_FILE" windows.malfind > "$OUTPUT_DIR/malfind.txt"

echo "[+] 4. Connexions réseau..."
python3 vol.py -f "$MEM_FILE" windows.netstat > "$OUTPUT_DIR/netstat.txt"

echo "[+] 5. DLLs chargées..."
python3 vol.py -f "$MEM_FILE" windows.dlllist > "$OUTPUT_DIR/dlllist.txt"

echo "[+] 6. Fichiers ouverts..."
python3 vol.py -f "$MEM_FILE" windows.filescan > "$OUTPUT_DIR/filescan.txt"

echo "[+] 7. Clés registry suspectes..."
python3 vol.py -f "$MEM_FILE" windows.registry.printkey --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" > "$OUTPUT_DIR/registry_run.txt"

echo "[+] 8. Commandes cmd/PowerShell..."
python3 vol.py -f "$MEM_FILE" windows.cmdline > "$OUTPUT_DIR/cmdline.txt"

echo ""
echo "[✓] Analyse terminée. Vérifiez $OUTPUT_DIR/"
echo "[!] Cherchez dans malfind.txt les processus suspects"
echo "[!] Cherchez dans netstat.txt les connexions vers IPs externes"
