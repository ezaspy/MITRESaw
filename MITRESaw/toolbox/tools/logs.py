#!/usr/bin/env python3 -tt

def tidy_log_sources(dataset):
    logsource = (
        dataset
        .replace(
            "Active Directory: Active Directory Credential Request",
            "Command-line logging; Windows event logs",
        )
        .replace(
            "Active Directory: Active Directory Object Access",
            "Command-line logging; Windows event logs",
        )
        .replace(
            "Active Directory: Active Directory Object Creation",
            "Command-line logging; Windows event logs",
        )
        .replace(
            "Active Directory: Active Directory Object Deletion",
            "Command-line logging; Windows event logs",
        )
        .replace(
            "Active Directory: Active Directory Object Modification",
            "Command-line logging; Windows event logs",
        )
        .replace(
            "Application Log: Application Log Content",
            "Application Log Content",
        )
        .replace("Cloud Service: Cloud Service Disable", "Cloud API logging; Cloud Audit logging")
        .replace(
            "Cloud Service: Cloud Service Enumeration", "Cloud API logging; Cloud Audit logging"
        )
        .replace(
            "Cloud Service: Cloud Service Modification", "Cloud API logging; Cloud Audit logging"
        )
        .replace("Cloud Storage: Cloud Storage Access", "Cloud API logging; Cloud Audit logging")
        .replace("Cloud Storage: Cloud Storage Creation", "Cloud API logging; Cloud Audit logging")
        .replace("Cloud Storage: Cloud Storage Deletion", "Cloud API logging; Cloud Audit logging")
        .replace(
            "Cloud Storage: Cloud Storage Enumeration", "Cloud API logging; Cloud Audit logging"
        )
        .replace(
            "Cloud Storage: Cloud Storage Modification", "Cloud API logging; Cloud Audit logging"
        )
        .replace("Drive: Drive Access", "Windows event logs; setupapi.dev.log")
        .replace("Drive: Drive Modification", "Windows event logs; setupapi.dev.log")
        .replace("Driver: Driver Load", "Sysmon")
        .replace("Command: Command Execution", "Command-line logging")
        .replace("Container: Container Creation", "Command-line logging")
        .replace("Container: Container Enumeration", "Command-line logging")
        .replace("Container: Container Start", "Command-line logging")
        .replace(
            "File: File Access",
            "Command-line logging; Windows event logs; Sysmon",
        )
        .replace(
            "File: File Creation",
            "Command-line logging; Windows event logs; Sysmon",
        )
        .replace(
            "File: File Deletion",
            "Command-line logging; Windows event logs; Sysmon",
        )
        .replace("File: File Metadata", "Artefact acquisition")
        .replace(
            "File: File Modification",
            "Command-line logging; Windows event logs; Sysmon",
        )
        .replace(
            "Firewall: Firewall Disable",
            "Command-line logging; Windows event logs",
        )
        .replace("Firewall: Firewall Enumeration", "Command-line logging")
        .replace(
            "Firewall: Firewall Rule Modification",
            "Command-line logging; Windows event logs",
        )
        .replace(
            "Group: Group Enumeration",
            "Command-line logging; Windows event logs",
        )
        .replace(
            "Group: Group Modification",
            "Command-line logging; Windows event logs",
        )
        .replace("Image: Image Creation", "Cloud API logging; Cloud Audit logging")
        .replace("Image: Image Deletion", "Cloud API logging; Cloud Audit logging")
        .replace("Image: Image Metadata", "Cloud API logging; Cloud Audit logging")
        .replace("Image: Image Modification", "Cloud API logging; Cloud Audit logging")
        .replace("Instance: Instance Creation", "Cloud API logging; Cloud Audit logging")
        .replace("Instance: Instance Deletion", "Cloud API logging; Cloud Audit logging")
        .replace("Instance: Instance Enumeration", "Cloud API logging; Cloud Audit logging")
        .replace("Instance: Instance Modification", "Cloud API logging; Cloud Audit logging")
        .replace("Instance: Instance Start", "Cloud API logging; Cloud Audit logging")
        .replace("Instance: Instance Stop", "Cloud API logging; Cloud Audit logging")
        .replace("Kernel: Kernel Module Load", "/lib/module logging")
        .replace(
            "Logon Session: Logon Session Creation",
            "Windows event logs; *nix /var/log",
        )
        .replace("Module: Module Load", "Command-line logging; Sysmon")
        .replace(
            "Named Pipe: Named Pipe Metadata", "Command-line logging; Sysmon"
        )
        .replace(
            "Network Share: Network Share Access",
            "Command-line logging; Windows event logs",
        )
        .replace(
            "Network Traffic: Network Connection Creation",
            "Process monitoring; Windows event logs; Sysmon; Zeek conn.log",
        )
        .replace("Network Traffic: Network Traffic Content", "PCAP")
        .replace("Network Traffic: Network Traffic Flow", "netflow")
        .replace(
            "Process: OS API Execution",
            "Process monitoring; PowerShell Script Block logging; Command-line logging",
        )
        .replace("Process: Process Access", "Sysmon")
        .replace(
            "Process: Process Creation",
            "Command-line logging; Windows event logs; Sysmon",
        )
        .replace(
            "Process: Process Metadata",
            "Sysmon",
        )
        .replace("Process: Process Modification", "Artefact acquisition")
        .replace("Process: Process Termination", "Windows event logs; Sysmon")
        .replace(
            "Scheduled Job: Scheduled Job Creation",
            "Windows event logs; *nix /var/log",
        )
        .replace(
            "Scheduled Job: Scheduled Job Metadata",
            "",
        )
        .replace(
            "Scheduled Job: Scheduled Job Modification",
            "Windows event logs; *nix /var/log",
        )
        .replace(
            "Script: Script Execution",
            "PowerShell Script Block logging; Command-line logging; Windows event logs; Microsoft-Windows-WMI-Activity/Trace & WMITracing.log",
        )
        .replace("Sensor Health: Host Status", "Host Availability logging")
        .replace(
            "Service: Service Creation", "Windows event logs; *nix /var/log"
        )
        .replace(
            "Service: Service Metadata",
            "Command-line logging; Windows event logs; *nix /var/log",
        )
        .replace(
            "Service: Service Modification", "Windows event logs; *nix /var/log"
        )
        .replace("Snapshot: Snapshot Creation", "Cloud API logging; Cloud Audit logging")
        .replace("Snapshot: Snapshot Deletion", "Cloud API logging; Cloud Audit logging")
        .replace("Snapshot: Snapshot Enumeration", "Cloud API logging; Cloud Audit logging")
        .replace("Snapshot: Snapshot Modification", "Cloud API logging; Cloud Audit logging")
        .replace(
            "User Account: User Account Authentication",
            "Windows event logs; *nix /var/log/auth.log",
        )
        .replace(
            "User Account: User Account Creation",
            "Windows event logs; *nix /etc/passwd logging",
        )
        .replace(
            "User Account: User Account Deletion",
            "Windows event logs; *nix /var/log/auth & access/authentication",
        )
        .replace(
            "User Account: User Account Metadata",
            "",
        )
        .replace(
            "User Account: User Account Modification",
            "Windows event logs; *nix /var/log/auth & access/authentication",
        )
        .replace("User Account: User Account Authentication", "")
        .replace("Volume: Volume Creation", "Cloud API logging; Cloud Audit logging")
        .replace("Volume: Volume Deletion", "Cloud API logging; Cloud Audit logging")
        .replace("Volume: Volume Enumeration", "Cloud API logging; Cloud Audit logging")
        .replace("Volume: Volume Modification", "Cloud API logging; Cloud Audit logging")
        .replace(
            "Windows Registry: Windows Registry Key Access",
            "Windows Registry monitoring",
        )
        .replace(
            "Windows Registry: Windows Registry Key Creation",
            "Windows Registry monitoring",
        )
        .replace(
            "Windows Registry: Windows Registry Key Deletion",
            "Windows Registry monitoring",
        )
        .replace(
            "Windows Registry: Windows Registry Key Modification",
            "Windows Registry monitoring",
        )
        .replace(
            "WMI: WMI Creation",
            "Command-line logging; Microsoft-Windows-WMI-Activity/Trace & WMITracing.log; Sysmon",
        )
    )
    return logsource
