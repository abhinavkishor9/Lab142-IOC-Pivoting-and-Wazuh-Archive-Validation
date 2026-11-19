# Lab 142 – Investigation Timeline

**Date:** 19 November 2026

All times below are local unless explicitly marked UTC.

| Time | Activity | Observation / Result |
|---|---|---|
| 14:41 | Sysmon service and recent events inspected | Sysmon running; Event IDs 1 and 11 observed |
| 14:42 | Initial test directory created | `C:\Lab142` created |
| 14:42 | Controlled IOC file created | `C:\Lab142\ioc-test.txt` |
| 14:42 | SHA256 calculated | Hash recorded successfully |
| 14:44 | File properties inspected | File length 37 bytes; last-write time approximately 14:44 |
| 14:44 onward | Initial Sysmon Event ID 11 search | No matching event returned for `C:\Lab142\ioc-test.txt` |
| Later | Separate Downloads test performed | File created under Downloads directory |
| 14:54:04 | Sysmon file-creation event generated | Event ID 11 for Downloads path |
| 14:54:05.371 | Wazuh manager received event | Matching JSON archive record found |
| 14:xx | Wazuh agent connectivity inspected | Agent 001 reported Active |
| 15:xx | Filebeat archive configuration inspected | Archive collection initially disabled |
| 15:xx | Filebeat configuration updated | Archive collection enabled |
| 15:xx | Filebeat configuration validated | Config OK |
| 15:09 | Filebeat restarted | Service active |
| 15:xx | Archive harvesting verified | Harvester started for archives.json |
| 15:xx | Filebeat indexing warnings investigated | Malformed IPv6 values reported |
| 15:xx | Elasticsearch archive index inspected | Green index found with 15,762 documents |
| 15:xx | Exact Sysmon event queried | One matching document returned |
| Later | Discover interface inspected | Only `wazuh-alerts-*` available |
| Later | Dashboard navigation investigated | `Dashboards Management → Index patterns` located |

## Final Timeline Assessment

The controlled Downloads file-creation event was successfully traced from the Windows endpoint to Elasticsearch.

The initial `C:\Lab142` file test did not produce a matching event in the query performed. It is documented separately rather than being treated as the source of the confirmed 14:54 event.

The remaining dashboard task is to create the archive index pattern.
