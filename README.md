# Telegram RAT Investigation

## Overview

This project documents the investigation of a Telegram-based Remote Access Trojan (RAT) in a controlled SOC laboratory environment.

The objective was to identify malicious process execution, reconstruct the process tree, analyze network communications, extract Indicators of Compromise (IOCs), and map observed behavior to the MITRE ATT&CK framework.

---

## Investigation Objectives

* Analyze suspicious executable behavior
* Identify parent-child process relationships
* Detect command execution activity
* Investigate DNS and TLS communications
* Extract Indicators of Compromise (IOCs)
* Map techniques to MITRE ATT&CK
* Develop detection opportunities

---

## Lab Environment

| Component        | Description                |
| ---------------- | -------------------------- |
| OS               | Windows 10 Virtual Machine |
| Logging          | Sysmon                     |
| Network Analysis | Wireshark                  |
| Analysis Type    | Dynamic Analysis           |
| Sample           | WindowsUpdateHelper.exe    |

---

## Process Analysis

### Process Tree

WindowsUpdateHelper.exe

└── cmd.exe /c <cmd>

└── conhost.exe

### Findings

The executable spawned cmd.exe using the `/c` switch, indicating command execution capability.

A subsequent conhost.exe process was created, confirming console-based command execution.

### Evidence

Screenshots available in:

screenshots/sysmon/

---

## Network Analysis

### DNS Activity

Multiple DNS requests were observed for:

api.telegram.org

### TLS Analysis

TLSv1.3 Client Hello packets revealed:

SNI = api.telegram.org

### External Infrastructure

149.154.166.110

### Beaconing Pattern

The host established recurring short-lived TLS sessions to Telegram infrastructure, consistent with polling-based command-and-control communication.

### Evidence

Screenshots available in:

screenshots/wireshark/

---

## Indicators of Compromise (IOCs)

### Domains

api.telegram.org

### IP Addresses

149.154.166.110

### Processes

WindowsUpdateHelper.exe

cmd.exe

conhost.exe

---

## MITRE ATT&CK Mapping

| Technique ID | Technique                  |
| ------------ | -------------------------- |
| T1059.003    | Windows Command Shell      |
| T1071.001    | Application Layer Protocol |
| T1105        | Ingress Tool Transfer      |
| T1219        | Remote Access Software     |

---

## Detection Opportunities

### Sigma Rule Concept

Detect command shell execution spawned by unknown user-space applications.

### Elastic Security Query

process.parent.name:"WindowsUpdateHelper.exe"
and process.name:"cmd.exe"

### Additional Monitoring

* DNS requests to Telegram infrastructure
* TLS Client Hello SNI containing api.telegram.org
* Suspicious parent-child process chains
* Recurring outbound beaconing behavior

---

## Recommendations

### Immediate Actions

* Isolate affected host
* Preserve Sysmon logs
* Acquire memory image
* Collect malware sample

### Detection Improvements

* Enable Sysmon Event ID 1 collection
* Enable Sysmon Event ID 3 collection
* Correlate process creation with network telemetry
* Alert on Telegram API communications from non-approved applications

### Long-Term Improvements

* Deploy EDR
* Implement application allowlisting
* Conduct periodic threat hunting

---

## Lessons Learned

* Parent-child process relationships are critical for malware investigations.
* DNS evidence alone is insufficient.
* TLS SNI provides valuable destination visibility.
* Correlating Sysmon and Wireshark significantly increases confidence.
* Telegram Bot API can be abused as a command-and-control channel.

---

## Final Assessment

Verdict: Confirmed Malicious Activity

Threat Type: Telegram RAT

Severity: High

Confidence: High

The investigation confirmed command execution capability and encrypted communications with Telegram infrastructure. The observed behavior is consistent with a Telegram-based Remote Access Trojan using HTTPS polling for command-and-control communications.
