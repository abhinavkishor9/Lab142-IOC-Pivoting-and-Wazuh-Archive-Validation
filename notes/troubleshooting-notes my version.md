# Troubleshooting Notes

## 1. Initial File Creation Event Not Found

### Issue

The controlled file was created at:

`C:\Lab142\ioc-test.txt`

However, the PowerShell query for Sysmon Event ID 11 returned no matching event.

### Diagnostic Query

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

### Observation

The query returned no matching records.

The file's existence, properties, and SHA256 were independently confirmed.

### Follow-up

A separate controlled file creation under the Downloads directory produced a matching Sysmon Event ID 11.

The exact reason the initial path did not return a matching event was not established.

---

## 2. Wazuh Archive Index Not Available in Discover

### Issue

The Discover interface initially displayed only:

`wazuh-alerts-*`

The archive index was not available for selection.

### Investigation

The Wazuh manager's JSON archive was inspected and contained the controlled Sysmon event.

Filebeat configuration initially showed:

```yaml
archives:
  enabled: false
```

### Resolution

Archive collection was enabled:

```yaml
archives:
  enabled: true
```

A backup of the original Filebeat configuration was created before editing.

The Filebeat configuration was validated successfully, and the service was restarted.

### Verification

Filebeat logs confirmed:

- Wazuh archive fileset enabled.
- Archive JSON path configured.
- Archive harvester started.
- Elasticsearch connection established.
- Wazuh archive pipeline loaded.

The archive index subsequently existed in Elasticsearch.

---

## 3. Elasticsearch Authentication

### Issue

An unauthenticated request to the Elasticsearch endpoint returned:

```text
HTTP Status: 401
```

### Explanation

The endpoint was reachable, but authentication was required.

Filebeat's keystore contained:

```text
password
username
```

### Resolution

The authenticated Wazuh Dashboard Dev Tools Console was used for read-only Elasticsearch queries.

This avoided manually entering or exposing the Elasticsearch password.

---

## 4. Filebeat Indexing Warnings

### Issue

Filebeat reported:

```text
mapper_parsing_exception
```

The affected field was:

`data.port.local_ip`

Some values contained malformed IPv6 formatting, for example:

```text
fe80:::283d:13b4:3a22:747f
```

### Explanation

Elasticsearch expected a valid IP address but could not parse the supplied value.

These warnings were associated with archived Syscollector port information.

### Investigation Result

The warning established that certain documents were rejected during indexing.

It did not prove that all archive events were rejected.

### Action Taken

No index mappings were changed.

No indices were deleted or recreated.

The exact Lab 142 Sysmon event was searched independently.

### Result

The controlled Sysmon event was found successfully in the archive index.

---

## 5. Archive Index Verification

### Query

```http
GET _cat/indices/wazuh-archives-*?v
```

### Result

The following index was available:

`wazuh-archives-4.x-2026.11.19`

Observed properties:

- Health: green
- Status: open
- Documents: 15,762
- Storage: 24.9 MB

This confirmed that the archive index was available and contained indexed documents.

---

## 6. Exact Sysmon Event Search

### Query

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
  }
}
```

### Result

One matching document was returned.

The result contained:

- Agent ID: 001
- Host: DESKTOP-9MMM37V
- Event ID: 11
- File: `C:\Users\Dell\Downloads\Lab142\ioc-test.txt`
- Timestamp: `2026-11-19T14:54:05.371+0530`

This confirmed successful indexing of the exact event.

---

## 7. Discover Does Not Display Archive Events

### Issue

Discover displayed only:

`wazuh-alerts-*`

The archive index was already present in Elasticsearch.

### Root Cause Identified

The archive index pattern had not yet been created in the Dashboard.

### Navigation Identified

```text
Dashboards Management
    └── Index patterns
```

### Pending Resolution

Create the following index pattern:

```text
wazuh-archives-*
```

Select:

```text
timestamp
```

as the time field.

After creation:

1. Return to Discover.
2. Select `wazuh-archives-*`.
3. Set a time range covering November 19, 2026, around 14:54 IST.
4. Search for `ioc-test.txt`.

### Current Status

The exact event is already verified in Elasticsearch. Dashboard index-pattern creation remains pending.

---

