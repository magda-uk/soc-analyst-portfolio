# 📥 Sysmon Event ID 22 : DNS Query
### LenovoSecurityAddin → filedownload.lenovo.com (Akamai CDN Resolution)

This evidence captures a **DNS Query** performed by the Lenovo Vantage module **LenovoSecurityAddin**, resolving the domain `filedownload.lenovo.com`. This domain is legitimate and used by Lenovo to distribute updates, drivers, security components, and OEM configuration files. The DNS resolution chain shows multiple CNAME hops through **Akamai CDN**, which is expected and benign.

---

## 📸 Evidence Screenshot

![EVENT22-LenovoDNS](/3.log-analysis/sysmon/id22-dns-queries/screenshots/EVENT22-LENOVO.png)

---

## 📋 Evidence Extract

| Field | Value | Interpretation |
| :--- | :--- | :--- |
| **QueryName** | `filedownload.lenovo.com` | Official Lenovo update/content domain |
| **QueryStatus** | `0 (SUCCESS)` | Query resolved cleanly without errors |
| **Image** | `LenovoSecurityAddin.exe` | Legitimate Lenovo Vantage OEM security module |
| **User** | `Azul_Fifty\magda` | Standard user context |
| **Timestamp** | `2026-08-28 23:30:23.669` | Local system event execution time |

**QueryResults (CNAME Chain & IP):**
```text
filedownload.lenovo.com.akadns.net
filedownload.lenovo.com.edgekey.net
e7741.g.akamaiedge.net
::ffff:23.37.197.88
```
## 🔍 Highlighted Indicators (Why This Event Is Benign)

* 🟩 **QueryName (`filedownload.lenovo.com`):** Official OEM domain used by Lenovo Vantage services for integrity verification, drivers, and definitions.
* 🟦 **QueryStatus (`0 - SUCCESS`):** The query completed without error codes, `SERVFAIL`, or `NXDOMAIN` flags.
* 🟨 **QueryResults (Akamai CDN Chain):** Demonstrates multi-stage canonical name (CNAME) routing ending in an IPv4-mapped IPv6 address (`::ffff:23.37.197.88`), standard for Akamai Edge delivery networks.
* 🟩 **Image Path:** Located in `C:\Program Files (x86)\Lenovo\VantageService\...\LenovoSecurityAddin.exe`, aligning with genuine OEM software architecture.
* ⬜ **User Context (`Azul_Fifty\magda`):** Initiated under standard interactive session execution.

---

## 🔹 Understanding Akamai CDN Resolution Chain

Large vendors rely on Akamai for high-availability payload delivery. The resolution hops follow a standard CDN lifecycle:

1. `filedownload.lenovo.com.akadns.net` → Akamai Authoritative DNS layer
2. `filedownload.lenovo.com.edgekey.net` → Customer-specific edge routing zone
3. `e7741.g.akamaiedge.net` → Optimal geographic edge node selection
4. `::ffff:23.37.197.88` → Final IPv4-mapped IPv6 endpoint

---

## ⚖️ Benign vs. Malicious DNS Behaviour

| Evaluation Factor | 🟢 Benign (Observed Case) | 🔴 Malicious Indicators |
| :--- | :--- | :--- |
| **Domain Reputation** | Trusted OEM infrastructure (`lenovo.com`) | Newly registered domains (NRDs), DGA, Dynamic DNS |
| **Resolution Chain** | Valid enterprise CDN CNAME hops | Fast-flux DNS, high-entropy hostnames |
| **Process Binary** | Digitally signed Lenovo Vantage service | Unknown binary from `\AppData\`, `\Temp\`, or LOLBins |
| **Traffic Characteristics** | Standard update lookup | High-frequency TXT lookups, DNS tunnelling/exfiltration |

---

## 🛡️ SOC Triage Assessment

* **Verdict:** Benign Positive (Legitimate OEM Maintenance Traffic)
* **Rationale:** The binary path, parent context, domain ownership, and CDN resolution pattern reflect expected operational behaviour for Lenovo Vantage endpoint management. No anomalous C2 or tunnelling characteristics detected.

---

## 🗺️ MITRE ATT&CK Mapping

While benign in this instance, DNS lookups align structurally with:

* **T1071.004** — Application Layer Protocol: DNS
* **T1568** — Dynamic Resolution

---

## 📝 Analyst Notes

This case illustrates standard OEM software interaction with global CDN infrastructure. Recognising legitimate CNAME delegation chains and IPv4-mapped IPv6 formats prevents false-positive escalations during routine DNS log hunting and baseline profiling.

---

## ♟️ **Authored by:** **Magda Dominguez**  
Security Operations • Detection Engineering • Blue Team
