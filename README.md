# 🔍 Investigation Forensique — Post-Intrusion Ransomware

![Status](https://img.shields.io/badge/Status-Terminé-brightgreen)
![Tools](https://img.shields.io/badge/Tools-FTK%20Imager%20%7C%20Autopsy%20%7C%20Volatility%203-orange)
![Category](https://img.shields.io/badge/Catégorie-Forensique%20·%20IR-red)

> Investigation numérique complète sur 3 machines Windows compromises suite à une attaque ransomware. Identification du vecteur initial, reconstruction de la timeline et extraction des IOCs.

## 🎯 Objectif

Mener une investigation forensique post-incident sur un environnement Windows compromis par un ransomware, en suivant la méthodologie PICERL :

**P**réparer → **I**dentifier → **C**ontenir → **E**radiquer → **R**écupérer → **L**eçons

## 🖥️ Environnement analysé

| Machine | Rôle | OS | Statut |
|---------|------|----|--------|
| WS-001 | Poste utilisateur (patient zéro) | Windows 10 Pro | Chiffré |
| WS-002 | Poste RH | Windows 10 Pro | Chiffré |
| SRV-001 | Serveur de fichiers | Windows Server 2019 | Partiellement chiffré |

## 🛠️ Outils utilisés

| Outil | Usage |
|-------|-------|
| **FTK Imager** | Acquisition images disque (format .E01) |
| **Autopsy** | Analyse artefacts : MFT, prefetch, LNK, registry |
| **Volatility 3** | Analyse mémoire : processus, injections DLL, connexions |
| **Wireshark** | Analyse trafic réseau capturé |
| **NetworkMiner** | Reconstruction flux réseau, extraction fichiers |
| **MISP** | Corrélation IOCs avec threat intel |

## 📋 Méthodologie

### Phase 1 — Acquisition
```bash
# FTK Imager CLI — acquisition image disque
ftkimager.exe \\.\PhysicalDrive0 D:\evidence\WS001 --e01 --verify
# Hash de vérification généré automatiquement (MD5 + SHA1)
```

### Phase 2 — Analyse disque (Autopsy)
- Analyse MFT : fichiers créés/modifiés dans la fenêtre temporelle
- Prefetch : exécutables lancés avant/pendant lattaque
- LNK files : fichiers récemment ouverts par lutilisateur
- Registry hives : persistence, comptes, connexions réseau
- $Recycle.Bin : fichiers supprimés par lattaquant

### Phase 3 — Analyse mémoire (Volatility 3)
```bash
# Lister les processus
python3 vol.py -f WS001.mem windows.pslist

# Détecter les injections DLL
python3 vol.py -f WS001.mem windows.malfind

# Extraire les connexions réseau actives
python3 vol.py -f WS001.mem windows.netstat

# Dump du processus suspect
python3 vol.py -f WS001.mem windows.dumpfiles --pid 1337
```

### Phase 4 — Reconstruction timeline
```bash
# Génération timeline complète avec log2timeline/plaso
log2timeline.py --storage-file timeline.plaso WS001.E01
psort.py -o l2tcsv timeline.plaso > timeline.csv
```

## 🔎 Findings principaux

### Vecteur initial
- **Email de phishing** reçu à 08h42 sur WS-001
- Pièce jointe : `Facture_2024_urgent.pdf.exe` (double extension)
- Exécution confirmée par prefetch (`FACTURE_2024_URGENT.EXE-XXXXXX.pf`)

### Comportement du ransomware
1. Désactivation Windows Defender via PowerShell (T1562.001)
2. Suppression des Volume Shadow Copies : `vssadmin delete shadows /all` (T1490)
3. Chiffrement des fichiers (extension `.locked` ajoutée)
4. Mouvement latéral via SMB vers WS-002 et SRV-001 (T1021.002)
5. Exfiltration de données avant chiffrement vers IP `185.220.x.x` (T1041)

### Timeline reconstituée
| Heure | Événement |
|-------|-----------|
| 08:42 | Réception email phishing |
| 08:47 | Ouverture pièce jointe — exécution dropper |
| 08:48 | Désactivation antivirus |
| 08:49 | Suppression VSS |
| 08:51 | Début chiffrement WS-001 |
| 09:03 | Propagation vers WS-002 |
| 09:15 | Propagation vers SRV-001 |
| 09:22 | Exfiltration données (3.2 GB) |

## 📌 IOCs identifiés

| Type | Valeur | Description |
|------|--------|-------------|
| MD5 | `a3f2c1...` | Hash dropper initial |
| SHA256 | `7b9e4d...` | Hash ransomware payload |
| IP | `185.220.x.x` | C2 server (Tor exit node) |
| Domain | `update-secure[.]tk` | Faux domaine C2 |
| Mutex | `Global\EncryptionMutex_v2` | Mutex créé par le ransomware |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater` | Clé de persistence |

## 🗂️ Structure du repo

```
forensic-ransomware-investigation/
├── methodology/
│   ├── picerl-framework.md
│   └── acquisition-checklist.md
├── analysis/
│   ├── disk-analysis.md
│   ├── memory-analysis.md
│   ├── network-analysis.md
│   └── timeline-reconstruction.md
├── scripts/
│   ├── volatility-commands.sh
│   └── timeline-generator.sh
├── iocs/
│   └── iocs.csv
├── reports/
│   └── investigation-report-template.md
└── README.md
```

## 🔗 Références

- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [Autopsy Digital Forensics](https://www.autopsy.com/)
- [MITRE ATT&CK — Ransomware](https://attack.mitre.org/software/)
- [ANSSI — Guide de réponse à incident](https://www.ssi.gouv.fr/)

## 👤 Auteur

**Fèmi KPONOU** — Étudiant Bachelor Cybersécurité ESAIP  
🌐 [Portfolio](https://primaelkpfv.github.io) · 💼 [LinkedIn](https://linkedin.com/in/primaelkponou)
