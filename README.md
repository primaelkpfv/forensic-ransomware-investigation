# 🔍 Investigation Forensique — Ransomware Post-Intrusion

[![Repo Badge](https://img.shields.io/badge/GitHub-Forensics-red?logo=github&style=flat-square)](https://github.com/primaelkpfv/forensic-ransomware-investigation)
[![Tools](https://img.shields.io/badge/Tools-Volatility%20%7C%20Autopsy%20%7C%20FTK-orange?style=flat-square)](.)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen?style=flat-square)](.)

> Investigation numérique d'un incident ransomware sur 3 machines Windows. Reconstruction timeline complète, extraction IOCs et rapport d'incident détaillé.

---

## 📊 Résumé exécutif

<details open>
<summary><b>🎯 Findings clés</b> — Cliquez pour développer</summary>

```
┌──────────────────────────────────────────────────────────┐
│        RÉSUMÉ INVESTIGATION RANSOMWARE                  │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  🕐 Durée totale infection : 40 minutes                 │
│  🔴 Machines compromises : 3/3                          │
│  💾 Données chiffrées : ~12 GB                          │
│  📤 Données exfiltrées : 3.2 GB                         │
│                                                          │
│  Vecteur initial : Email phishing + pièce jointe       │
│  Extension fichiers : .locked                           │
│  C2 Server : 185.220.x.x (Tor exit)                    │
│                                                          │
│  ⚠️  Verdict : Ransomware sophistiqué - GandCrab v5.x  │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

**Timeline reconstituée** :
```
08:42 ─→ Réception email phishing
08:47 ─→ Exécution dropper (facture_urgent.exe)
08:48 ─→ Désactivation Windows Defender
08:49 ─→ Suppression Volume Shadow Copies
08:51 ─→ 🔴 Début chiffrement WS-001
09:03 ─→ Propagation SMB vers WS-002
09:15 ─→ Propagation SMB vers SRV-001
09:22 ─→ 📤 Exfiltration données vers C2
09:45 ─→ 🛑 Détection antivirus (trop tard)
```

</details>

---

## 🛠️ Outils utilisés

| Outil | Version | Usage |
|-------|---------|-------|
| **Volatility 3** | 3.14 | Analyse mémoire RAM |
| **Autopsy** | 4.20 | Analyse système de fichiers |
| **FTK Imager** | 4.7 | Acquisition disques |
| **Wireshark** | 4.0 | Analyse trafic réseau |
| **NetworkMiner** | 2.8 | Reconstruction flux |

---

## 📋 Méthodologie PICERL

```
P →  Préparation des outils & environnement
│
I →  Identification des indicateurs compromission (IOCs)
│    ├─ Fichiers malveillants
│    ├─ Connexions réseau suspectes
│    └─ Clés registry modifiées
│
C →  Confinement & Containment
│    └─ Isolation réseau immédiate
│
E →  Éradication du malware
│    ├─ Suppression fichiers malveillants
│    └─ Nettoyage registry
│
R →  Récupération des données
│    └─ Restauration depuis sauvegardes saines
│
L →  Leçons apprises & recommandations
    └─ Amélioration sécurité future
```

---

## 🔍 Découvertes principales

### 🚨 IOCs identifiés

| Type | Valeur | Confiance |
|------|--------|-----------|
| 🔴 MD5 Dropper | `a3f2c1d4e5f6...` | Critique |
| 🔴 SHA256 Payload | `7b9e4d2f1a3c...` | Critique |
| 🔴 IP C2 | `185.220.101.45` | Critique |
| 🟠 Domain C2 | `update-secure.tk` | Élevée |
| 🟡 Mutex | `Global\EncryptionMutex_v2` | Moyenne |

### 🎯 Comportement ransomware

```
Étape 1 : Reconnaissance
  ├─ Enumération comptes locaux
  └─ Scan réseau SMB

Étape 2 : Escalade privilèges
  ├─ Exploitation UAC bypass
  └─ Token impersonation

Étape 3 : Persistance
  ├─ Création tâche planifiée
  └─ Modification registry autorun

Étape 4 : Mouvement latéral
  ├─ Pass-the-Hash via SMB
  └─ Exploitation EternalBlue (optionnel)

Étape 5 : Exfiltration données
  ├─ Collecte fichiers sensibles
  └─ Upload vers C2 Tor

Étape 6 : Chiffrement
  ├─ AES-256 symétrique
  ├─ RSA-2048 asymétrique
  └─ Affichage message rançon
```

---

## 📁 Structure

```
forensic-ransomware-investigation/
├── README.md (vous êtes ici)
├── analysis/
│   ├── disk-analysis.md
│   ├── memory-analysis.md
│   ├── network-analysis.md
│   └── timeline-reconstruction.md
├── scripts/
│   ├── volatility-commands.sh
│   ├── extract_iocs.py
│   └── timeline-generator.sh
├── iocs/
│   ├── iocs.csv
│   └── iocs-misp-format.json
└── reports/
    ├── investigation-report.md
    └── incident-response-checklist.md
```

---

## 🔗 Ressources

- 📚 [Volatility 3 Docs](https://volatility3.readthedocs.io/)
- 📚 [Autopsy Guide](https://www.autopsy.com/)
- 📚 [NIST Incident Response](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)

---

<p align="center">
  <b>Made with 🔍 for Digital Forensics</b>
</p>
