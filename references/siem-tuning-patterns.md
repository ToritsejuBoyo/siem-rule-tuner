# SIEM Exclusion Patterns & Schemas

This reference provides syntactical specifications and templated architectures for formulating surgical child rule exclusions in Wazuh and Microsoft Defender XDR.

---

## 1. Wazuh XML Child Rule Pattern (OSSEC Engine)

Wazuh processes alerts using a hierarchical decoders-and-rules engine. To tune a false-positive without disabling the parent rule:
1. Define a child rule with `<rule id="NEW_RULE_ID" level="0">`. Level 0 explicitly drops/silences the alert from firing notifications or writing to `alerts.json`.
2. Reference the noisy parent rule via `<if_sid>PARENT_RULE_ID</if_sid>`.
3. Constrain the exclusion using multiple precise `<field>` tags. Always escape regex backslashes.

### Wazuh Architecture Template
```xml
<group name="sysmon,windows,">
  <!-- Tune out legitimate IT administrative backup agent -->
  <rule id="100101" level="0">
    <if_sid>60103</if_sid>
    <!-- Field 1: Exact Image File Path (escaped backslashes) -->
    <field name="win.eventdata.image">^C:\\\\Program Files\\\\Veeam\\\\Backup\\\\VeeamGuestHelper\.exe$</field>
    <!-- Field 2: Legitimate Parent Process -->
    <field name="win.eventdata.parentImage">^C:\\\\Windows\\\\System32\\\\services\.exe$</field>
    <!-- Field 3: Expected Service Account -->
    <field name="win.eventdata.user">^NT AUTHORITY\\\\SYSTEM$</field>
    <!-- Field 4: Specific command-line signature -->
    <field name="win.eventdata.commandLine">-runAsService</field>
    <description>Tuned Exclusion: Exclude legitimate Veeam Guest Helper service activity from Sysmon process alerts.</description>
  </rule>
</group>
```

---

## 2. Microsoft Defender XDR / Sentinel KQL Pattern

In Microsoft Defender XDR (Advanced Hunting) and Microsoft Sentinel, exclusions must be formulated as multi-condition negated boolean clauses (`| where not (...)`).

### Defender KQL Architecture Template
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ActionType == "ProcessCreated"
| where FileName =~ "powershell.exe"
// Multi-Attribute Surgical Exclusion: Intune Management Extension agent execution
| where not (
    FolderPath =~ @"c:\windows\system32\windowspowershell\v1.0\powershell.exe"
    and InitiatingProcessFolderPath =~ @"c:\program files (x86)\microsoft intune management extension\agentexecutor.exe"
    and AccountName =~ "system"
    and ProcessCommandLine has "-executionpolicy bypass"
    and ProcessCommandLine has_any ("detect.ps1", "remediate.ps1")
)
```

---

## 3. Splunk Enterprise Search Processing Language (SPL) Pattern

In Splunk, tuned exclusions are expressed as negated boolean compound sub-searches or search filters:

### Splunk SPL Architecture Template
```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
NOT (
    Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    AND ParentImage="C:\\Program Files (x86)\\Microsoft Intune Management Extension\\AgentExecutor.exe"
    AND User="NT AUTHORITY\\SYSTEM"
)
```
