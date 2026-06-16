# 🔍 Investigation Forensique Post-Intrusion Ransomware

![Status](https://img.shields.io/badge/Status-Complété-success)
![Tools](https://img.shields.io/badge/Tools-Autopsy%20%7C%20Volatility3%20%7C%20FTK%20Imager-blue)
![Type](https://img.shields.io/badge/Type-Digital%20Forensics%20%26%20IR-red)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-orange)

> Investigation forensique complète sur 3 machines Windows compromises suite à une attaque ransomware simulée. Rapport d'investigation avec IOCs, timeline et recommandations.

---

## 📌 Contexte du Scénario

Une entreprise fictive de 50 personnes signale que plusieurs postes Windows sont chiffrés au matin. Les fichiers portent l'extension `.locked`. Une demande de rançon est affichée sur les bureaux.

**Objectif** : Déterminer le vecteur d'entrée, la propagation, les systèmes compromis et produire un rapport d'investigation.

---

## 🖥️ Environnement

| Machine | OS | Rôle | Statut |
|---------|----|------|--------|
| WS-001 | Windows 10 Pro | Poste utilisateur — Patient Zéro | Chiffré |
| WS-002 | Windows 10 Pro | Poste RH | Chiffré |
| SRV-DC | Windows Server 2019 | Contrôleur de domaine | Partiellement compromis |

---

## 🛠️ Outils Utilisés

| Outil | Version | Usage |
|-------|---------|-------|
| **FTK Imager** | 4.7 | Acquisition images disque (E01) |
| **Autopsy** | 4.21 | Analyse artefacts Windows (MFT, prefetch, LNK) |
| **Volatility 3** | 2.5 | Analyse mémoire RAM (processus, DLL, réseau) |
| **Wireshark** | 4.x | Analyse captures réseau PCAP |
| **NetworkMiner** | 2.8 | Extraction artefacts réseau |
| **MISP** | 2.4 | Corrélation IOCs avec threat intelligence |
| **Timeline Explorer** | 2.0 | Visualisation timeline unifiée |

---

## 🔬 Méthodologie

### Phase 1 — Acquisition (Chain of Custody)

```
1. Isolation réseau immédiate des machines
2. Acquisition RAM avant extinction (WinPmem)
3. Acquisition image disque FTK Imager → format E01 (hash MD5+SHA1)
4. Documentation chain of custody
```

```bash
# Acquisition RAM avec WinPmem
winpmem_mini_x64_rc2.exe memdump_WS001.raw

# Vérification intégrité
certutil -hashfile memdump_WS001.raw SHA256
```

### Phase 2 — Analyse Mémoire (Volatility 3)

```bash
# Liste des processus au moment de la compromission
python3 vol.py -f memdump_WS001.raw windows.pslist.PsList

# Détection injections DLL
python3 vol.py -f memdump_WS001.raw windows.malfind.Malfind

# Connexions réseau actives
python3 vol.py -f memdump_WS001.raw windows.netstat.NetStat

# Dump processus suspects
python3 vol.py -f memdump_WS001.raw windows.dumpfiles --pid 4832
```

**Résultats clés** :
- Processus `svchost.exe` (PID 4832) avec injection DLL suspecte
- Connexion C2 active vers `185.234.xxx.xxx:4444` (TOR exit node)
- `powershell.exe` lancé depuis `winword.exe` (macro malveillante)

### Phase 3 — Analyse Disque (Autopsy)

```
Artefacts analysés :
├── $MFT         → Fichiers créés/modifiés (timeline)
├── Prefetch      → Exécutables lancés (evidence d'exécution)
├── Event Logs    → Security (4624/4625/4688), System, Application
├── Registry      → NTUSER.DAT, SAM, SYSTEM (persistence, autoruns)
├── LNK Files     → Fichiers récemment ouverts
├── Browser Hist  → URLs visitées (Chrome, Edge)
└── Recycle Bin   → Fichiers supprimés récupérés
```

**Artefact clé trouvé** : Fichier `facture_2025.docm` dans `C:\Users\jean.dupont\Downloads\` — macro VBA malveillante.

### Phase 4 — Analyse Réseau (Wireshark/NetworkMiner)

```
Observations PCAP :
- Requête DNS vers domaine suspect : update-windows[.]xyz
- Download payload via HTTP : /cdn/update.exe (3.2 MB)
- Trafic C2 chiffré TLS vers 185.234.xxx.xxx
- Lateral movement via SMB (MS-SAMR enumeration)
- Exfiltration données avant chiffrement (2.1 GB vers IP externe)
```

---

## 📊 Timeline de l'Attaque

```
J-1 08:47 — jean.dupont ouvre facture_2025.docm (macro activée)
J-1 08:47 — PowerShell exécuté via macro Word (T1566.001)
J-1 08:48 — Téléchargement payload depuis update-windows[.]xyz
J-1 08:49 — Persistance via Run key registre (T1547.001)
J-1 08:52 — Connexion C2 établie (T1071.001)
J-1 09:15 — Reconnaissance réseau interne (net view, arp -a)
J-1 09:23 — Pass-the-Hash vers SRV-DC (T1550.002)
J-1 09:45 — Exfiltration données sensibles RH (2.1 GB)
J-1 10:00 — Déploiement ransomware via GPO (T1484.001)
J-1 10:03 — Chiffrement AES-256 des fichiers (.locked)
J-1 10:05 — Ransom note déposée sur tous les bureaux
```

---

## 🚨 IOCs Identifiés

```yaml
# Fichiers malveillants
hashes:
  - md5: "a1b2c3d4e5f6789012345678901234ab"
    sha256: "e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855"
    name: "facture_2025.docm"
  - md5: "deadbeefcafe12345678901234567890"
    name: "update.exe (dropper)"

# Indicateurs réseau
network:
  domains:
    - "update-windows[.]xyz"
    - "cdn-delivery[.]ru"
  ips:
    - "185.234.xxx.xxx"  # C2 server (TOR exit node)
    - "91.108.xxx.xxx"   # Exfiltration endpoint
  
# Persistence
registry:
  - "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
    value: "WindowsUpdate = C:\Users\Public\svchost32.exe"

# Mutex
mutex: "Global\MutexRansomLock2025"
```

---

## 📁 Structure du Projet

```
forensic-ransomware-investigation/
├── README.md
├── rapport/
│   ├── rapport-investigation-complet.md   # Rapport détaillé 25 pages
│   ├── executive-summary.md               # Résumé dirigeants
│   └── iocs-list.yaml                     # Liste IOCs exportable MISP
├── methodologie/
│   ├── acquisition-procedure.md           # Procédure chain of custody
│   ├── volatility-commands.md             # Commandes Volatility utilisées
│   └── autopsy-checklist.md              # Checklist analyse Autopsy
├── scripts/
│   ├── extract_iocs.py                    # Extraction IOCs automatisée
│   └── timeline_builder.py               # Construction timeline unifiée
└── docs/
    └── mitre-attack-mapping.md            # Mapping MITRE ATT&CK
```

---

## 🗺️ Mapping MITRE ATT&CK

| Tactique | Technique | ID |
|----------|-----------|-----|
| Initial Access | Spearphishing Attachment | T1566.001 |
| Execution | User Execution: Malicious File | T1204.002 |
| Persistence | Registry Run Keys | T1547.001 |
| Defense Evasion | Process Injection | T1055 |
| Credential Access | OS Credential Dumping | T1003 |
| Lateral Movement | Pass the Hash | T1550.002 |
| Collection | Data from Local System | T1005 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 |
| Impact | Data Encrypted for Impact | T1486 |

---

## 🔗 Références

- [PICERL Incident Response Framework](https://www.sans.org/white-papers/33901/)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io)
- [MITRE ATT&CK](https://attack.mitre.org)
- [Portfolio Fèmi KPONOU](https://primaelkpfv.github.io)

---
*Projet réalisé dans le cadre du Bachelor Cybersécurité — ESAIP 2025*
