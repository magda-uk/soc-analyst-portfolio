# 🛡️ Full Sysmon Investigation Compendium
### Complete SOC Analyst Portfolio — Behavioural Analysis, DNS, OEM Noise & MITRE Mapping

Este documento consolida las investigaciones de telemetría de **Sysmon**, abarcando eventos de creación de procesos (**ProcessCreate**), consultas de resolución de nombres (**DNS Query**), flujos alternativos de datos (**ADS / FileStreamCreated**) y el baseline de ruido OEM. Diseñado como referencia operativa para **Blue Team y SOC Triage**.

---

## 🗺️ 1. Sysmon Event Map — SOC Priority Matrix

| Prioridad | ID de Evento | Nombre del Evento | Caso de Uso Principal en Detección |
| :--- | :--- | :--- | :--- |
| **Alta** | `1` | **ProcessCreate** | Detección de CLI anómala, LOLBins, ejecución de scripts |
| **Alta** | `2` | **FileCreateTime** | Detección de técnicas de *Timestomping* (evasión forense) |
| **Alta** | `3` | **NetworkConnect** | Tráfico C2, exfiltración de datos, puertos no estándar |
| **Alta** | `7` | **ImageLoaded** | Cargas de DLL sospechosas, DLL Hijacking / Side-loading |
| **Alta** | `8` | **CreateRemoteThread** | Inyección de código en procesos remotos (Process Injection) |
| **Alta** | `10` | **ProcessAccess** | Dumping de credenciales en memoria (`lsass.exe`, token stealing) |
| **Alta** | `11` | **FileCreate** | *Drop* de ejecutables, *staging* de payloads en `%TEMP%` / `%APPDATA%` |
| **Alta** | `13` | **RegistryEvent** | Persistencia vía RunKeys, servicios, hijack de extensiones |
| **Alta** | `22` | **DNSQuery** | Trazabilidad C2, balizamiento DGA, túneles DNS |
| **Media** | `15` | **FileStreamCreated** | Control de Mark-of-the-Web (MOTW) y abuso de Alternate Data Streams |
| **Media** | `17 / 18` | **PipeEvent** | Comunicación interproceso en frameworks como Cobalt Strike / Metasploit |
| **Media** | `19 / 20 / 21` | **WMI / Tampering / FileDelete** | Persistencia WMI, deshabilitación de defensas, borrado de evidencia |
| **Baja** | `23 - 25` | **Advanced Tampering & Delete** | Cacería avanzada (*Threat Hunting*) y análisis de integridad |

---

## 📄 2. Sysmon Event ID 15 — Alternate Data Stream (ADS) Analysis

**Event Summary:** El proceso `chrome.exe` generó un flujo alternativo de datos adjunto denominado `:Zone.Identifier` al descargar un archivo PDF. Esta operación corresponde a la asignación estándar de **Mark-of-the-Web (MOTW)** impuesta por los navegadores modernos para restringir la ejecución de archivos externos.

### 📋 Evidence Extract

| Campo | Valor Observado |
| :--- | :--- |
| **Image** | `C:\Program Files\Google\Chrome\Application\chrome.exe` |
| **TargetFilename** | `BRS Magdalena Dominguez Escudero_CV.pdf:Zone.Identifier` |
| **User Context** | `Azul_Fifty\magda` |
| **Contenido del Stream** | `[ZoneTransfer] ZoneId=3` (Internet Zone) |

### 🟢 Criterios de Triage Benigno
* El identificador del stream es estrictamente `Zone.Identifier` (MOTW nativo).
* No se detectan nombres de stream anómalos o arbitrarios (e.g., `:evil.exe`, `:payload.bin`).
* No existen eventos correlacionados de ejecución inmediata (`Event ID 1`) ni inyección en memoria (`Event ID 8` / `10`).

---

## 🌐 3. Sysmon Event ID 22 — WPAD Resolution Attempt

**Event Summary:** El sistema operativo ejecutó una consulta DNS automática buscando el nombre de host `wpad` para autoconfiguración de proxies de red. La resolución retornó un código de error de dominio inexistente (`NXDOMAIN`), descartando un ataque activo de proxy spoofing.

### 📋 Evidence Extract

| Campo | Valor Observado |
| :--- | :--- |
| **QueryName** | `wpad` |
| **QueryStatus** | `9003 (NXDOMAIN)` |
| **Image** | `<unknown process>` (Terminación rápida / Proceso efímero) |
| **User Context** | `Azul_Fifty\magda` |

### 🟢 Criterios de Triage Benigno
* El estado `NXDOMAIN` confirma la ausencia de servidores WPAD no autorizados en el segmento de red.
* Ausencia de eventos subsiguientes de descarga HTTP de archivos `wpad.dat` / `proxy.pac`.
* No se evidencian modificaciones de directiva de red en el registro ni conexiones de red anómalas (`Event ID 3`).

---

## 📡 4. Sysmon Event ID 22 — OEM CDN Resolution (Lenovo)

**Event Summary:** El módulo `LenovoSecurityAddin.exe` generó una consulta para resolver `filedownload.lenovo.com`. La resolución completó exitosamente a través de una arquitectura CDN global de **Akamai Edge**.

### 📋 Evidence Extract

```text
QueryName:    filedownload.lenovo.com
QueryStatus:  0 (SUCCESS)
Image:        LenovoVantage-(LenovoSecurityAddin).exe
User:         Azul_Fifty\magda

QueryResults (Cadena CNAME & IP):
  ├── filedownload.lenovo.com.akadns.net
  ├── filedownload.lenovo.com.edgekey.net
  ├── e7741.g.akamaiedge.net
  └── ::ffff:23.37.197.88 (IPv4-mapped IPv6)
 ```
 ### 🟢 Criterios de Triage Benigno
* La cadena CNAME muestra delegación autoritativa hacia la infraestructura global de Akamai.
* La dirección IP final mapeada corresponde a nodos legítimos de entrega de contenido.
* El proceso origen reside en la ruta oficial firmada de Lenovo Vantage.

---

## ⚙️ 5. Process Baseline — OEM Noise Profiling (Lenovo Vantage)

Los módulos de Lenovo Vantage se ejecutan de manera modular e independiente bajo el contexto de servicio del sistema. Comprender esta línea base permite evitar alertas de falsos positivos en el SOC:

```text
[System Context / Services]
  └── LenovoVantageService.exe
        ├── LenovoHardwareScanAddin.exe   (Diagnóstico de componentes físicos)
        ├── SmartPanelAddin.exe           (Gestión de interfaz y panel táctil)
        ├── SmartPerformanceAddin.exe     (Perfiles de energía y rendimiento)
        └── LenovoSecurityAddin.exe       (Validación de certificados y parches OEM) 
```
## 🔄 6. ProcessCreate — Google Updater Maintenance

**Event Summary:** Ejecución de rutina del componente `updater.exe` para la validación y descarga de parches para el ecosistema Google Chrome.

### 📋 Evidence Extract

| Campo | Valor Observado |
| :--- | :--- |
| **Image** | `C:\Program Files (x86)\Google\GoogleUpdater\updater.exe` |
| **Publisher** | Google LLC |
| **User Context** | `Azul_Fifty\magda` |
| **Parent Process** | `svchost.exe` (Tareas programadas de Windows) |

### 🟢 Criterios de Triage Benigno
* Binario firmado y ubicado en su ruta de instalación oficial.
* Parámetros de línea de comando habituales (`/c`, `/ping`, `/install`).
* Ausencia de llamadas directas a intérpretes de comandos (`cmd.exe`, `powershell.exe`) o inyecciones de memoria.

---

## 🗺️ 7. MITRE ATT&CK Framework Mapping

| Sysmon Event ID | ID MITRE | Técnica / Táctica | Comportamiento Asociado |
| :--- | :--- | :--- | :--- |
| **ID 1 (ProcessCreate)** | **T1059** / **T1204** | Command and Scripting Interpreter / User Execution | Ejecución de scripts LOLBins o binarios interactivos |
| **ID 2 (Timestomp)** | **T1070.006** | Indicator Removal: Timestomp | Alteración maliciosa de metadatos de creación de archivo |
| **ID 3 (NetworkConnect)** | **T1071** / **T1041** | Application Layer Protocol / Exfiltration Over C2 | Conexiones remotas, balizamiento y salida de datos |
| **ID 8 (CreateRemoteThread)** | **T1055** | Process Injection | Evasión de defensas mediante inyección de hilos en memoria |
| **ID 10 (ProcessAccess)** | **T1003.001** | OS Credential Dumping: LSASS Memory | Apertura de manejadores de proceso para volcado de credenciales |
| **ID 11 (FileCreate)** | **T1105** | Ingress Tool Transfer | Descarga e implantación de ejecutables secundarios |
| **ID 13 (RegistryEvent)** | **T1547.001** | Boot or Logon Autostart Execution: Registry Run Keys | Persistencia del adversario mediante claves Run/RunOnce |
| **ID 15 (FileStreamCreated)** | **T1564.004** | Hide Artifacts: Alternate Data Streams | Ocultamiento de payloads o bypass de controles MOTW |
| **ID 22 (DNSQuery)** | **T1071.004** / **T1568** | DNS Protocol / Dynamic Resolution (DGA, Fast Flux) | Canales encubiertos de resolución de mando y control (C2) |

---

## 🧠 8. SOC Analyst Methodological Summary

* **Triangulación de Telemetría:** Correlación continua entre creación de procesos (`ID 1`), tráfico de red (`ID 3`) y resolución de nombres (`ID 22`).
* **Supresión de Ruido OEM:** Diferenciación precisa entre actividad sospechosa y procesos de mantenimiento de proveedores (Lenovo, Google).
* **Análisis Estructural DNS:** Inspección rigurosa de saltos CNAME, dominios DGA y mapeos IPv6/IPv4 antes de clasificar un evento.
* **Triage Basado en Comportamiento:** Validación de firmas digitales, linaje de procesos padres y contexto de privilegios (*User vs. SYSTEM*).

---

**Authored by:** **Magda Dominguez**  
Security Operations • Detection Engineering • Blue Team
