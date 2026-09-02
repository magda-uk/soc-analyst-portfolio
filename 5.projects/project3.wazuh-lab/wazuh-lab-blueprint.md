# Case Study: Wazuh SIEM Detection & Telemetry Lab

## 1. Executive Summary & Objective
* **Objective:** Deploy an end-to-end detection monitoring pipeline using Wazuh and Sysmon to capture, decode, and alert on adversary tactics.
* **Scope:** Windows endpoint monitoring, correlation against MITRE ATT&CK techniques, and validation of custom/default detection rules.

---

## 2. Lab Topology & Environment Specs
* **SIEM / Manager:** Wazuh Manager & Indexer (All-in-One Deployment on Linux VM / Dedicated Host).
* **Monitored Endpoint (Agent):** Windows 10/11 VM running Wazuh Agent + Sysmon (SwiftOnSecurity / custom config).
* **Attacking Machine:** Kali Linux VM (simulating network scans and credential attacks).
* **Network Isolation:** Configured via VirtualBox Internal Network / NAT Network to prevent leakage to the local LAN.

---

## 3. Telemetry Pipeline Configuration
### 3.1 Sysmon Ingestion (`ossec.conf`)
Fragmento de configuración en el agente Windows para reenviar los eventos de Sysmon al Wazuh Manager:
```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
## 4. Adversary Emulation & Detection Scenarios
Scenario A: Suspicious PowerShell 

Execution (MITRE T1059.001)
Emulation Command:

```
powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "Write-Output 'SOC Test Execution'"
```
Scenario B: Living-off-the-Land Binary (LotL) - WScript / CScript Execution
Emulation Command:
cscript.exe //nologo test-script.vbs

Telemetry Difference Observed:

Comparativa entre la ejecución interactiva vs. no interactiva en los logs de Sysmon Event ID 1 y Windows Event 4688.

Scenario C: Network Scanning & Host Enumeration (MITRE T1046)
Emulation (From Kali):
```
nmap -sS -p 135,445,3389 <WINDOWS_IP>
```
Telemetry Captured:

Conexiones de red entrantes capturadas en Sysmon Event ID 3 o registros de firewall correlacionados en Wazuh.

## 5. SOC Analyst Triage Workflow

Para cada alerta analizada, se aplicó un proceso estructurado de validación e investigación L1:

* **1. Context Verification (Metadata Extraction):**
  * Extracción y análisis de campos críticos a partir del JSON bruto indexado en Wazuh:
    * `data.win.system.computer`: Identificación del host de origen.
    * `data.win.eventdata.user`: Validación de la cuenta ejecutora (contexto de usuario vs. privilegios `SYSTEM`).
    * `data.win.eventdata.parentImage` y `parentCommandLine`: Rastreo del proceso ancestro para determinar el vector de ejecución.

* **2. False Positive Assessment:**
  * Evaluación de la legitimidad de la actividad observada:
    * Verificación contra rutas estándar de binarios administrativos legítimos.
    * Detección de anomalías de ubicación (ejecuciones originadas en `%APPDATA%`, `%TEMP%` o directorios de usuario no estándar).
    * Revisión de horarios y patrones para descartar scripts de mantenimiento programados.

* **3. Pivoting & Telemetry Correlation:**
  * Búsqueda cruzada en el Wazuh Dashboard utilizando el `ProcessId` (`data.win.eventdata.processId`):
    * Correlación con eventos posteriores de red (**Sysmon Event ID 3**) para identificar intentos de comunicación externa hacia infraestructura C2.
    * Inspección de modificaciones en el sistema de archivos (**Sysmon Event ID 11**) asociadas a la misma cadena de ejecución.

---

## 6. Key Takeaways & Lessons Learned

* **Resolución de Telemetría con Sysmon:** Los canales de eventos predeterminados de Windows frecuentemente omiten argumentos completos en la línea de comandos y hashes criptográficos. La integración de Sysmon resultó indispensable para alimentar a Wazuh con telemetría de alta granularidad (`CommandLine`, `ParentCommandLine`, SHA256).
* **Ingeniería de Detección y Reducción de Ruido:** La dependencia exclusiva de reglas genéricas genera fatiga de alertas. Es fundamental ajustar umbrales y definir excepciones basadas en contexto operacional dentro de `local_rules.xml` para optimizar la respuesta del analista SOC.