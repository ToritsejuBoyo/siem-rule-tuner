# MITRE ATT&CK Living Off The Land Binaries (LOLBins) Exclusion Guardrails

This reference enumerates dual-use operating system binaries that must **NEVER** be excluded from SIEM detection rules using broad or single-attribute filters.

---

## High-Risk Dual-Use System Binaries

Excluding any binary in this table requires **at least three distinct telemetry constraints** ($\text{Binary Path} + \text{Parent Binary} + \text{CommandLine / Hash / User}$).

| Binary Name | MITRE ATT&CK ID | Legitimate Enterprise Use | Common Adversary Abuse Technique | Mandatory Exclusion Constraints |
| :--- | :--- | :--- | :--- | :--- |
| `powershell.exe` / `pwsh.exe` | T1059.001 | IT automation, administration, SCCM/Intune scripts. | Download cradles, obfuscated memory execution, credential dumping. | Must constrain Parent Image (e.g. `AgentExecutor.exe`) AND specific script parameter. Never exclude by filename alone. |
| `cmd.exe` | T1059.003 | Batch scripts, software installers. | Interactive command shells, discovery reconnaissance. | Must constrain exact Parent Image and working directory. |
| `certutil.exe` | T1105, T1140 | Certificate enrollment and verification. | Ingress tool transfer (`-urlcache -split -f`), decoding base64 payloads. | Prohibited from command-line wildcard exclusion. Must match specific enterprise CA flag or hash. |
| `mshta.exe` | T1218.005 | HTML application execution. | Bypassing application whitelisting, executing remote VBScript/JScript. | High risk. Never exclude network-initiating `mshta.exe`. |
| `rundll32.exe` | T1218.011 | Running 32-bit/64-bit dynamic link libraries. | Proxy execution of malicious DLL exports, loading shellcode. | Must specify exact DLL export name and full DLL file path. |
| `regsvr32.exe` | T1218.010 | Registering and unregistering OLE controls. | Squiblydoo attack, proxying scriptlet payloads (`scrobj.dll`). | Never exclude executions with `/s /u /i` network parameters. |
| `wmic.exe` | T1047 | WMI system queries and software inventory. | Defense evasion, process enumeration, lateral movement. | Must specify exact read-only query parameter. |
| `bitsadmin.exe` | T1197 | Background file transfers. | Stealthy download of malicious payloads. | High risk. Prohibited from general exclusion. |
| `cscript.exe` / `wscript.exe` | T1059.005 | VBScript/JScript system automation. | Macro execution, malicious staging scripts. | Must specify exact script filename and parent process. |
| `curl.exe` / `wget` | T1105 | Command-line HTTP queries, software downloads. | External C2 communication, payload retrieval. | Must constrain target enterprise domain or IP. |

---

## Prohibited Exclusion Anti-Patterns

1. **Path-Only Wildcard Exclusions:**
   - Prohibited: `win.eventdata.image: *\\AppData\\Local\\Temp\\*`
   - Danger: Attackers stage malware in `%TEMP%` to evade detection.
2. **User-Only Exclusions:**
   - Prohibited: `win.eventdata.user: Administrator`
   - Danger: Compromised administrator accounts will be completely invisible to the SOC.
3. **Binary-Name-Only Exclusions:**
   - Prohibited: `Image: powershell.exe`
   - Danger: Silences all PowerShell detections across the entire fleet.
4. **Disabling Parent Rule IDs:**
   - Prohibited: Removing rule `60103` from `local_rules.xml`.
   - Danger: Eliminates visibility for all subsequent attacks matching that technique.

