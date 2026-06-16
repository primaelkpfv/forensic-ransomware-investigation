# Commandes Volatility 3 — Investigation Ransomware

## Analyse des Processus

```bash
# Liste complète des processus
python3 vol.py -f memdump.raw windows.pslist.PsList

# Arbre des processus (détecter processus parents suspects)
python3 vol.py -f memdump.raw windows.pstree.PsTree

# Processus cachés (rootkit detection)
python3 vol.py -f memdump.raw windows.psscan.PsScan

# Comparer pslist vs psscan (différences = processus cachés)
diff <(python3 vol.py -f memdump.raw windows.pslist.PsList)      <(python3 vol.py -f memdump.raw windows.psscan.PsScan)
```

## Détection Injections DLL

```bash
# Rechercher injections mémoire (MZ headers dans zones RWX)
python3 vol.py -f memdump.raw windows.malfind.Malfind

# Lister DLLs chargées par processus suspect (PID 4832)
python3 vol.py -f memdump.raw windows.dlllist.DllList --pid 4832

# Dumps des DLLs pour analyse statique
python3 vol.py -f memdump.raw windows.dumpfiles --pid 4832
```

## Analyse Réseau

```bash
# Connexions réseau actives et fermées
python3 vol.py -f memdump.raw windows.netstat.NetStat

# Connexions établies uniquement
python3 vol.py -f memdump.raw windows.netstat.NetStat | grep ESTABLISHED
```

## Artefacts Système

```bash
# Clés de registre (autoruns/persistence)
python3 vol.py -f memdump.raw windows.registry.printkey --key "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Commandes cmdline de chaque processus
python3 vol.py -f memdump.raw windows.cmdline.CmdLine

# Variables d'environnement
python3 vol.py -f memdump.raw windows.envars.Envars --pid 4832

# Fichiers ouverts par processus
python3 vol.py -f memdump.raw windows.handles.Handles --pid 4832 --object-type File
```

## Extraction et Hash

```bash
# Extraire exécutable suspect
python3 vol.py -f memdump.raw windows.dumpfiles --physaddr 0x7f000000

# Hasher pour recherche sur VirusTotal
sha256sum extracted.*.dat
```

## Timeline Mémoire

```bash
# Créer super-timeline depuis mémoire
python3 vol.py -f memdump.raw timeliner.Timeliner --create-bodyfile |   mactime -b - -d > timeline_memory.csv
```
