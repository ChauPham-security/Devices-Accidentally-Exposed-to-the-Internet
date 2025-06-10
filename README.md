# 🔎 Devices Accidentally Exposed to the Internet

This project showcases a real-world internal threat hunt focused on identifying misconfigured virtual machines (VMs) that were unintentionally exposed to the public internet. The investigation highlights potential brute-force attempts and outlines mitigation actions taken to reduce future risk.

---

## 🛍️ Scenario Overview

### 🎯 Goal

During routine maintenance, the security team was tasked with identifying shared services VMs (e.g., DNS, DHCP, Domain Controllers) that were accidentally exposed to the internet. The goal was to determine whether:

* Any VMs were vulnerable to remote access.
* Brute-force login attempts or compromises occurred.
* There were gaps in account lockout or multi-factor authentication policies.

### 🧠 Hypothesis

If a VM was internet-facing and lacked an account lockout policy, it may have been targeted by brute-force login attempts, and a successful compromise could have occurred.

---

## 📊 Threat Hunting Process

### 🛠️ 1. Preparation

* Defined scope: Shared service VMs in the cluster.
* Identified risk: Internet exposure + weak authentication controls.
* Tools used: Microsoft Defender for Endpoint (MDE), Kusto Query Language (KQL), MITRE ATT\&CK mapping.

### 🛅 2. Data Collection

Gathered relevant logs from:

* `DeviceInfo`
* `DeviceLogonEvents`

### 🔎 3. Data Analysis

#### ✅ Confirmed Internet Exposure

```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == 1
| order by Timestamp desc
```

* `windows-target-1` was publicly exposed as of: `2025-05-29T19:12:46Z`

#### ❌ Brute-Force Attempts Detected: Several bad actors have been discovered attempting to log onto the target machine.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any ("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP )
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
<img width="559" alt="Screenshot 2025-06-10 at 6 22 07 PM" src="https://github.com/user-attachments/assets/eda977ee-fc81-4f44-aea2-2490a6b922ec" />



#### ✅ No Evidence of Compromise: The top 5 most failed login attempt IP addresses have not been able to successfully break into the VM.

```kql
// Take the top 5 IPs with the most logon failures and see if any succeeded to logon
let RemoteIPsInQuestion = dynamic(["65.21.227.213","37.27.96.174", "102.88.21.215", "88.214.25.117", "20.64.248.197"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

* No successful logins from brute-force IPs.

#### ✅ Legitimate Account Logon Activity: `labuser`

The only successful remote network logon in the last 30 days was for the `labuser` account (2 total logins):

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```

There were **zero (0) failed logon attempts** for the `labuser` account, which indicates that:
- No brute force attempts were made against this account.
- A one-time password guess is highly unlikely.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()
```

We also checked all successful logon IP addresses for `labuser` to identify any unusual or unexpected sources. All observed IPs were from expected locations.

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```
<img width="728" alt="Screenshot 2025-06-10 at 6 29 51 PM" src="https://github.com/user-attachments/assets/170ea634-a23c-48bc-ada1-3d8699591dfb" />


---

### 🟢 Final Analysis

Although the device was exposed to the internet and experienced repeated brute force login attempts from external IPs, **no successful unauthorized logins occurred**, and **the legitimate `labuser` account was not compromised**.


---

## MITRE ATT\&CK Mapping

| Tactic                        | Technique ID | Description                                                        |
| ----------------------------- | ------------ | ------------------------------------------------------------------ |
| Initial Access                | **T1190**    | Exploit Public-Facing Application (VM was exposed to the internet) |
| Credential Access             | **T1110**    | Brute Force (Repeated failed logins from external IPs)             |
| Defense Evasion / Persistence | **T1078**    | Valid Accounts (Use of a legitimate account: ‘labuser’)            |

---

## 🛡️ Response & Mitigation

* 🔐 **Network security group (NSG)** was updated to only allow RDP from trusted internal sources.
* 🚫 **Account lockout policy** enabled to prevent future brute-force attempts.
* 🔑 **Multi-factor authentication (MFA)** enforced for remote access accounts.

---

## 📘 Lessons Learned & Improvements

### What We Did Well

* Proactively identified exposed VMs before compromise.
* Thoroughly reviewed logs to rule out successful brute-force attempts.
* Mapped activity to MITRE ATT\&CK for structured analysis.

### Areas for Improvement

* Automate exposure detection using cloud posture tools.
* Apply baseline lockout/MFA policies to all accounts by default.
* Set up alerting for excessive login failures from external IPs.

---

## ✅ Summary

Although `windows-target-1` was exposed to the internet and received brute-force attempts from multiple remote IPs, no successful compromises occurred. Mitigations were immediately implemented, and all findings were documented to strengthen future defenses.
