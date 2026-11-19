# Lab 142 – Investigation Notes

## 1. Investigation Overview

The objective was to validate file-based IOC investigation across a Windows endpoint and a centralized Wazuh environment.

A controlled text file was created, its SHA256 hash was calculated, and Sysmon telemetry was examined to identify file-creation activity.

The investigation then followed the relevant event through the Wazuh agent, manager archive, Filebeat, and Elasticsearch.

## 2. Endpoint Validation

### Sysmon Service

The Sysmon service was checked using:

```powershell
Get-Service -Name Sysmon64
```

**Observation:**

- Service status: Running
- Service name: Sysmon64

Recent events were inspected:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 |
Select-Object TimeCreated, Id, ProviderName
```

Events included:

- Event ID 1 – Process creation
- Event ID 11 – File creation

This confirmed that Sysmon was generating endpoint telemetry.

## 3. Controlled IOC Creation

The initial test file was created under:

`C:\Lab142\ioc-test.txt`

PowerShell commands:

```powershell
$LabPath = "C:\Lab142"

New-Item -Path $LabPath -ItemType Directory -Force

$TestFile = Join-Path $LabPath "ioc-test.txt"

Set-Content -Path $TestFile -Value "Lab142 controlled IOC pivoting test"
```

The SHA256 hash was calculated:

```powershell
Get-FileHash -Path $TestFile -Algorithm SHA256
```

**Observed SHA256:**

`9D90548AC10D8499BF3F88C4B240C3E203F0E3F1B0AFE9D1FCB27A672095262B`

File properties were examined:

```powershell
Get-Item $TestFile |
Select-Object FullName, Length, CreationTime, LastWriteTime
```

Observed properties:

- File: `C:\Lab142\ioc-test.txt`
- Length: 37 bytes
- Creation time: Approximately 14:42
- Last write time: Approximately 14:44

## 4. Initial Sysmon Event Investigation

The following query was used to locate Event ID 11 for the initial test file:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 11
    StartTime = (Get-Date).AddMinutes(-30)
} -ErrorAction SilentlyContinue |
Where-Object {
    $_.Message -match 'C:\\Lab142\\ioc-test.txt'
} |
Select-Object TimeCreated, Id, Message
```

**Observation:**

No matching event was returned for the `C:\Lab142\ioc-test.txt` path.

Therefore, the initial file creation was confirmed locally through file properties and hashing, but the corresponding Sysmon event was not established through this query.

A separate PowerShell execution test was also performed:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'Lab142 IOC pivoting test execution'"
```

This demonstrated command execution but was not itself evidence of malicious activity.

## 5. Wazuh Agent Validation

The Wazuh manager was used to check connected agents:

```bash
sudo /var/ossec/bin/agent_control -l
```

The agent list showed:

- Agent ID: 001
- Agent name: DESKTOP-9MMM37V
- Status: Active

This confirmed that the Windows endpoint was connected to the Wazuh manager.

## 6. Confirmed Sysmon Event

A subsequent controlled file creation was observed under:

`C:\Users\Dell\Downloads\Lab142\ioc-test.txt`

The matching Sysmon event contained:

| Field | Value |
|---|---|
| Event ID | 11 |
| Computer | DESKTOP-9MMM37V |
| Channel | Microsoft-Windows-Sysmon/Operational |
| Target filename | C:\Users\Dell\Downloads\Lab142\ioc-test.txt |
| Process | pwsh.exe |
| Process ID | 15700 |
| Process GUID | {6a3a75f0-bd36-6afe-18ca-000000002d00} |
| Rule name | Downloads |
| Event record ID | 2226667 |
| UTC event time | 2026-11-19 09:24:04.039 |

The file creation was recorded at approximately 14:54 local time.

The independently calculated SHA256 was:

`9D90548AC10D8499BF3F88C4B240C3E203F0E3F1B0AFE9D1FCB27A672095262B`

**Important:** Sysmon Event ID 11 recorded the file-creation activity but did not provide the SHA256 hash of the created file. The hash was calculated separately using `Get-FileHash`.

## 7. Wazuh Manager Archive Verification

The manager's configuration was inspected.

Relevant settings:

```xml
<global>
  <jsonout_output>yes</jsonout_output>
  <alerts_log>yes</alerts_log>
  <logall>no</logall>
  <logall_json>yes</logall_json>
</global>
```

JSON archive logging was enabled.

The archive was searched using:

```bash
sudo grep -F 'ioc-test.txt' /var/ossec/logs/archives/archives.json | tail -10
```

A matching event was found.

Observed archive details:

- Timestamp: `2026-11-19T14:54:05.371+0530`
- Agent ID: 001
- Agent name: DESKTOP-9MMM37V
- Agent IP: 192.168.174.1
- Event ID: 11
- Channel: Microsoft-Windows-Sysmon/Operational
- Target filename: `C:\Users\Dell\Downloads\Lab142\ioc-test.txt`
- Decoder: windows_eventchannel

The timestamp closely matched the original Windows event.

This confirmed successful event collection and manager-side archival.

## 8. Filebeat Archive Configuration

The Filebeat Wazuh module initially contained:

```yaml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false
```

The archive setting was changed to:

```yaml
filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: true
```

A backup was created before the configuration change:

`/etc/filebeat/filebeat.yml.lab142-backup`

Configuration validation:

```bash
sudo filebeat test config -c /etc/filebeat/filebeat.yml
```

Result:

`Config OK`

Filebeat was restarted:

```bash
sudo systemctl restart filebeat
```

The service subsequently reported an active running state.

## 9. Filebeat Archive Harvesting

Filebeat logs confirmed:

- Wazuh alerts and archives filesets were enabled.
- The archive input path was `/var/ossec/logs/archives/archives.json`.
- A harvester started for the archive file.
- The Elasticsearch endpoint was reachable.
- The Wazuh archive ingest pipeline was loaded.

This confirmed that Filebeat was configured to harvest the manager's JSON archive.

## 10. Indexing Warning Investigation

Filebeat logs contained repeated indexing warnings:

`mapper_parsing_exception`

The affected field was:

`data.port.local_ip`

Elasticsearch expected an IP address but received malformed IPv6 values such as:

`fe80:::283d:13b4:3a22:747f`

These records were associated with Syscollector port information.

The warning established that certain archive documents were rejected because of invalid IP formatting.

It did not establish that all archive events were rejected.

## 11. Elasticsearch Archive Index Verification

The archive index was checked through the authenticated Dashboard Dev Tools Console:

```http
GET _cat/indices/wazuh-archives-*?v
```

Observed result:

| Property | Value |
|---|---|
| Index | wazuh-archives-4.x-2026.11.19 |
| Health | green |
| Status | open |
| Primary shards | 3 |
| Documents | 15,762 |
| Deleted documents | 0 |
| Store size | 24.9 MB |

This confirmed that the archive index existed and contained indexed documents.

## 12. Exact Event Search in Elasticsearch

The following query was executed:

```http
GET wazuh-archives-4.x-2026.11.19/_search
{
  "size": 5,
  "query": {
    "wildcard": {
      "data.win.eventdata.targetFilename": {
        "value": "*ioc-test.txt*"
      }
    }
  },
  "_source": [
    "timestamp",
    "agent",
    "data.win.system.eventID",
    "data.win.eventdata.targetFilename",
    "data.win.eventdata.image",
    "decoder"
  ]
}
```

**Result:**

- Matching documents: 1
- Successful shards: 3
- Failed shards: 0

The returned document contained:

- Agent: DESKTOP-9MMM37V
- Agent ID: 001
- Event ID: 11
- Target filename: `C:\Users\Dell\Downloads\Lab142\ioc-test.txt`
- Timestamp: `2026-11-19T14:54:05.371+0530`
- Decoder: windows_eventchannel

This was the strongest confirmation that the controlled Sysmon event had successfully reached Elasticsearch.

## 13. Discover Visibility Investigation

The Wazuh Dashboard Discover interface initially displayed only:

`wazuh-alerts-*`

The archive index was not available in the index-pattern selector.

Navigation identified the following location:

`Dashboards Management → Index patterns`

The next configuration step is to create:

`wazuh-archives-*`

The selected time field should be:

`timestamp`

**Status:** Pending creation and verification.

