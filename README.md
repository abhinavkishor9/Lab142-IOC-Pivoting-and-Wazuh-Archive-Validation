# Lab 142: IOC Pivoting and Wazuh Archive Validation

## Overview

This lab demonstrates how to investigate a controlled file-based Indicator of Compromise (IOC) across Windows endpoint telemetry and a centralized Wazuh monitoring environment.

The investigation focuses on identifying a known file using its SHA256 hash and file path, validating Sysmon file-creation telemetry, and tracing the event through the Wazuh agent, manager, Filebeat, and Elasticsearch.

The lab also explores the difference between successful event collection and successful event visibility in the Wazuh Dashboard.

## Objectives

- Generate a controlled file-based IOC.
- Calculate and document its SHA256 hash.
- Examine Sysmon Event ID 11 for file creation activity.
- Validate Wazuh agent connectivity and event collection.
- Confirm that the Wazuh manager receives the endpoint event.
- Enable and validate Filebeat archive forwarding.
- Verify the archived event in Elasticsearch.
- Investigate why archive documents may not appear in Discover.
- Distinguish collection, forwarding, indexing, and dashboard visibility issues.

## Lab Environment

| Component | Details |
|---|---|
| Endpoint | Windows 11 |
| Endpoint hostname | DESKTOP-9MMM37V |
| Telemetry source | Microsoft Sysmon |
| Sysmon event | Event ID 11 |
| SIEM / Monitoring | Wazuh 4.13.1 |
| Agent ID | 001 |
| Agent | Wazuh Windows Agent |
| Manager | Rocky Linux 9.8 |
| Log forwarding | Filebeat 7.10.2 |
| Search and indexing | Wazuh Indexer / Elasticsearch-compatible API |
| Dashboard | Wazuh Dashboard |

## Controlled IOC Details

**File name:** `ioc-test.txt`

**SHA256:**

`9D90548AC10D8499BF3F88C4B240C3E203F0E3F1B0AFE9D1FCB27A672095262B`

**File content:**

`Lab142 controlled IOC pivoting test`

Two file locations were used during testing:

1. `C:\Lab142\ioc-test.txt`
2. `C:\Users\Dell\Downloads\Lab142\ioc-test.txt`

The file hash was independently calculated using PowerShell. The hash was not extracted from Sysmon Event ID 11.

## Investigation Workflow

1. Confirm Sysmon service status and inspect recent Sysmon events.
2. Create the controlled IOC file and calculate its SHA256.
3. Examine file properties and attempt to locate the corresponding Sysmon file-creation event.
4. Validate the Wazuh agent's active status.
5. Confirm that the relevant Sysmon event reaches the Wazuh manager.
6. Inspect the manager's JSON archive.
7. Enable archive collection in the Filebeat Wazuh module.
8. Validate Filebeat configuration and service status.
9. Investigate Filebeat indexing warnings.
10. Query Elasticsearch directly to verify the exact archived event.
11. Identify the missing archive index pattern in Discover.

## Key Findings

- Sysmon was running and generating Windows telemetry.
- The controlled file's SHA256 was successfully calculated.
- The initial `C:\Lab142` file-creation query returned no matching event.
- A subsequent file creation under the Downloads directory generated Sysmon Event ID 11.
- Wazuh agent 001 was active.
- The matching event appeared in `/var/ossec/logs/archives/archives.json`.
- Filebeat archive collection was initially disabled.
- Archive collection was enabled and Filebeat successfully started harvesting `archives.json`.
- The archive index `wazuh-archives-4.x-2026.11.19` existed and had green health.
- The exact Sysmon Event ID 11 was found in Elasticsearch.
- Some unrelated archived Syscollector events generated indexing warnings because malformed IPv6 values could not be parsed.
- Discover displayed only `wazuh-alerts-*`; the archive index pattern had not yet been created.

## Confirmed Elasticsearch Evidence

**Index:** `wazuh-archives-4.x-2026.11.19`

**Matching document ID:** `JDws86EBhYgs0h8fuumm`

**Agent:** `DESKTOP-9MMM37V`

**Agent ID:** `001`

**Event ID:** `11`

**File path:**

`C:\Users\Dell\Downloads\Lab142\ioc-test.txt`

**Timestamp:** `2026-11-19T14:54:05.371+0530`

**Decoder:** `windows_eventchannel`

## Conclusion

The investigation successfully demonstrated end-to-end collection and indexing of a controlled Sysmon file-creation event.

The event was generated on the Windows endpoint, collected by the Wazuh agent, received by the manager, written to the JSON archive, forwarded by Filebeat, and indexed in Elasticsearch.

The remaining dashboard task is to create the `wazuh-archives-*` index pattern so that archive documents can be searched in Discover.

This investigation reinforces an important SOC principle:

**An event being generated, collected, forwarded, indexed, and displayed are separate stages that must be independently verified.**

