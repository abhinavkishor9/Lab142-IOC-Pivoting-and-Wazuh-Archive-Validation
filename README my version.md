# Lab142-IOC-Pivoting-and-Wazuh-Archive-Validation
## Overview
### Introduction

An Indicator of Compromise (IOC) is an observable artifact that may help identify suspicious or potentially malicious activity within an environment.

Common file-based IOCs include:

- SHA256 hashes
- File names
- File paths
- File sizes
- File creation and modification timestamps

SOC analysts use these indicators to investigate endpoint activity, identify potentially related events, and determine whether an artifact appears across multiple systems.

However, an IOC match is an investigative lead rather than automatic proof of compromise.

### File-Based IOC Investigation

A file-based investigation commonly begins with a known file hash or path.

For example, an analyst may receive a SHA256 value and search endpoint telemetry for related file activity.

The investigation may involve:

1. Calculating the file's SHA256 hash.
2. Identifying the file's location.
3. Reviewing file creation and modification times.
4. Examining the process responsible for creating the file.
5. Correlating the activity with the endpoint and user.
6. Searching for additional occurrences across monitored systems.

The purpose is to establish whether the observed artifact is associated with expected activity or requires further investigation.

### Sysmon Event ID 11 – File Creation

Sysmon provides detailed Windows endpoint telemetry.

Event ID 11 records file creation activity and can provide:

- Target filename
- Creating process image
- Process ID
- Process GUID
- User context
- Event timestamp
- Computer name

This information helps analysts establish which process created a file and where the activity occurred.

Event ID 11 does not independently provide the SHA256 hash of the created file. A separate hashing operation is required when file content identification is needed.

### Wazuh Agent and Manager

Wazuh provides centralized security monitoring by collecting and processing endpoint telemetry.

The Wazuh agent collects configured Windows event sources and forwards them to the manager.

The manager processes incoming events and can retain raw event information in its JSON archive when archive logging is enabled.

The archive provides useful evidence for investigating events that may not generate security alerts.

### Filebeat and Archive Forwarding

Filebeat forwards log data from the Wazuh manager to the indexer.

The Wazuh Filebeat module supports separate collection paths for:

- Alerts
- Archives

Alert records represent events that have matched applicable alerting rules.

Archive records provide broader visibility into collected event data, including events that may not trigger alerts.

Enabling archive collection allows the relevant archive data to be forwarded for centralized searching.

### Elasticsearch Indexing

Elasticsearch-compatible indexing allows analysts to search and retrieve centralized event documents.

For this investigation, the archive index used was:

`wazuh-archives-4.x-2026.11.19`

A document being present in the manager archive does not automatically prove that it was indexed.

Likewise, a successful index creation does not guarantee that every incoming document was accepted.

Indexing warnings, field mappings, and data-format inconsistencies must be investigated independently.

### Dashboard Discover and Index Patterns

Discover provides an interface for searching indexed documents.

An index pattern or data view defines which indices can be searched through the interface.

For example:

- `wazuh-alerts-*` searches Wazuh alert indices.
- `wazuh-archives-*` searches Wazuh archive indices.

The existence of an Elasticsearch index does not guarantee that the corresponding pattern is available in Discover.

The index pattern must be created and configured with the appropriate timestamp field.

### Event Ingestion and Visibility

A centralized monitoring pipeline consists of several independent stages:

1. Event generation on the endpoint.
2. Collection by the monitoring agent.
3. Forwarding to the manager.
4. Processing and archival by the manager.
5. Harvesting and forwarding by Filebeat.
6. Acceptance and indexing by Elasticsearch.
7. Search and visibility through the dashboard.

An analyst should validate these stages separately instead of assuming that an event missing from Discover was never generated or collected.

### Investigation Principle

**Follow the evidence, not the assumption.**

A file hash match, file creation event, or archive document should be interpreted in context.

Analysts should distinguish between:

- Confirmed observations
- Plausible explanations
- Unverified hypotheses
- Unknown or missing evidence

This approach prevents false conclusions and supports accurate incident documentation.

This lab demonstrates how to investigate a controlled file-based Indicator of Compromise (IOC) across Windows endpoint telemetry and a centralized Wazuh monitoring environment.

The investigation focuses on identifying a known file using its SHA256 hash and file path, validating Sysmon file-creation telemetry, and tracing the event through the Wazuh agent, manager, Filebeat, and Elasticsearch.

The lab also explores the difference between successful event collection and successful event visibility in the Wazuh Dashboard.

## Lab Objectives

### Primary Objectives

1. **Understand file-based IOCs**

   Learn how file hashes, paths, names, and timestamps can be used as investigative indicators during endpoint security investigations.

2. **Validate Windows file activity**

   Use PowerShell and Sysmon to observe controlled file creation and identify the relevant endpoint telemetry.

3. **Understand Sysmon Event ID 11**

   Examine file-creation records and identify the process, user, timestamp, and target filename associated with the activity.

4. **Calculate and validate SHA256**

   Use PowerShell to generate a cryptographic hash and understand how it can help identify a file independently of its name or location.

5. **Verify centralized endpoint collection**

   Confirm that the Wazuh agent is active and that endpoint events reach the manager.

6. **Investigate raw event archives**

   Examine Wazuh JSON archive records to distinguish raw event collection from alert generation.

7. **Understand archive forwarding**

   Explore the role of Filebeat in forwarding Wazuh archive data to the indexer.

8. **Validate Elasticsearch indexing**

   Use read-only queries to confirm whether a specific endpoint event exists in the archive index.

9. **Troubleshoot telemetry visibility**

   Investigate indexing warnings, authentication requirements, index availability, and missing dashboard index patterns.

10. **Apply evidence-based investigation**

    Maintain a clear distinction between confirmed activity, possible explanations, and unverified conclusions.

### Expected Learning Outcomes

By completing this lab, the analyst should be able to:

- Explain the difference between an IOC and proof of compromise.
- Interpret important fields in Sysmon Event ID 11.
- Calculate and document SHA256 hashes.
- Trace an event through the Wazuh collection pipeline.
- Distinguish alerts from raw archived events.
- Identify common causes of indexing and dashboard visibility issues.
- Verify an event directly in Elasticsearch.
- Document investigation limitations without overstating findings.

## Lab Scenario

### Scenario: Investigating a Controlled File-Based IOC

A SOC analyst is asked to investigate a file-based indicator that has been introduced into a monitored Windows endpoint as part of a controlled security exercise.

The analyst is provided with a test file named `ioc-test.txt` and must determine how its identifying attributes can be used to investigate endpoint activity.

The initial investigation involves creating the file, calculating its SHA256 hash, examining its properties, and reviewing Sysmon telemetry for file-creation activity.

Two file locations are used during the exercise. The initial file under `C:\Lab142` is successfully created and hashed, but the corresponding Sysmon Event ID 11 query does not return a matching record.

A subsequent controlled file creation under the user's Downloads directory produces a matching Sysmon Event ID 11. The event provides the target filename, creating process, process ID, user context, computer name, and timestamp.

### Investigation Challenge

Although the Windows endpoint records the file-creation event, the analyst must determine whether the same event reaches the centralized monitoring infrastructure.

The investigation therefore moves beyond local Windows logs.

The analyst validates the Wazuh agent's connectivity, examines the manager's JSON archive, and checks whether Filebeat is configured to forward archive records.

During this process, archive forwarding is found to be disabled in the Filebeat Wazuh module. After enabling it and validating the configuration, Filebeat successfully begins harvesting the archive file.

However, Filebeat logs also contain indexing warnings involving malformed IPv6 values in unrelated Syscollector records.

The analyst must determine whether these warnings affect the specific Sysmon event or represent a separate data-quality issue.

### Final Investigation Task

The analyst queries Elasticsearch directly and searches for the controlled file-creation event.

The exact Sysmon Event ID 11 document is found in the Wazuh archive index, confirming that the event successfully travelled through the collection and indexing pipeline.

Despite this, the event does not initially appear in Discover because the dashboard exposes only the alert index pattern.

The remaining task is to configure the archive index pattern and validate dashboard visibility.

### Expected Analyst Conclusion

The controlled Downloads file-creation event was successfully generated, collected, archived, forwarded, and indexed.

The absence of the event from Discover was not evidence of failed endpoint collection or failed Elasticsearch indexing.

The investigation demonstrated the importance of validating each stage of a SIEM pipeline independently and documenting the difference between an indexed event and an event visible through a dashboard.


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

