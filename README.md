# ZeroChatter-Windows11
Aggressive Windows 11 Enterprise network hardening and monitoring scripts designed to enforce a strict &lt;100 MB/month data budget for extreme low-bandwidth satellite deployments.

# Win11-MicroBandwidth-Toolkit

> This repository provides a rigorous, data-driven approach to silencing Windows 11 Enterprise telemetry and background network chatter, originally developed for extreme low-bandwidth environments like Iridium satellite deployments.
> 
> It consists of two primary, independent tools used in a reconnaissance-and-block workflow:
> * **Network Traffic Monitor (v4.3):** A PowerShell monitoring tool that captures network activity over 48-72 hour periods[cite: 1]. It bypasses fragile parsing tools by reading native adapter statistics, automatically stripping out local broadcast and multicast subnet noise (like Proxmox cluster chatter or mDNS) to provide an accurate, ground-truth measurement of true WAN-capable egress.
> * **Aggressive Network Hardening (v2.2):** A surgical, defense-in-depth script that blocks Microsoft's background chatter using exact-path firewall discovery, targeted service disables, policy tweaks, and a massive dual-stack HOSTS sinkhole. It successfully reduces OS-generated background bandwidth to <100 MB per month while leaving core operator applications and on-box Defender real-time AV functional.

## The Problem: Extreme Bandwidth Constraints

Modern operating systems assume a constantly connected, high-bandwidth environment. Windows 11 Enterprise natively generates hundreds of megabytes of background chatter per month through services like Windows Update, Defender cloud telemetry, MSN Widget feeds, and Edge WebView2 CDN pulls. 

For remote field deployments, this behavior is catastrophic. Many isolated rigs rely on Iridium satellite modems operating at 19,200 baud, or have strict 1 GB/month data caps across the entire site[cite: 2]. When the OS consumes this limited bandwidth, operational traffic is choked out. 

Previous attempts to measure this OS traffic were flawed. Standard monitoring tools captured all Layer-2 NIC traffic, meaning local subnet flooding (ARP, LLMNR, SSDP, and Proxmox cluster chatter) severely inflated the data, making it look like the endpoint was leaking WAN data when it was just receiving local noise.

## The Workflow: Monitor, Identify, Sinkhole

These two scripts are completely independent of one another. The monitoring script is deployed strictly as a reconnaissance tool to find the telemetry leaks. Once the chatty domains and processes are identified in the resulting CSV logs, that data is fed into the hardening script to aggressively sinkhole it all. 

### Tool 1: Network Monitor v4.3 (Reconnaissance)
The monitor script is designed to establish ground truth for what is actually leaving the WAN port. 

**Key Solutions:**
* **Native Per-Cast Counters:** Drops fragile parsing tools (like `pktmon`) and directly reads the native `MSFT_NetAdapterStatisticsSettingData` from the NIC.
* **Clean vs. Noise Split:** Automatically separates Unicast bytes (true WAN-capable traffic) from Broadcast/Multicast bytes (local subnet noise that never traverses the satellite link).
* **Connection Tagging:** Classifies every outbound connection into WAN, LAN, Listen, or Loopback to isolate real external traffic.

### Tool 2: Aggressive Hardening v2.2 (Execution)
The hardening script takes the reconnaissance data and enforces silence through a multi-layered, defense-in-depth approach.

**Key Solutions:**
* **Exact-Path Firewall Discovery:** Windows Firewall does not evaluate wildcards dynamically at runtime. This script recursively searches the disk to find the exact, versioned paths for resilient binaries like `msedgewebview2.exe` and `MsMpEng.exe`, writing explicit block rules for each one.
* **Surgical Disablement:** Disables only the cloud-communication components of Defender (MAPS, SpyNet, signature internet updates) while keeping on-box real-time AV scanning active.
* **Dual-Stack Sinkhole:** Implements a massive, curated HOSTS file sinkhole (routing to `0.0.0.0` and `::1`) targeting specifically observed telemetry endpoints, Microsoft accounts, and delivery CDNs. 

## Usage Instructions

### Running the Monitor
Launch the script from an elevated PowerShell prompt to begin logging:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "NetMonitor_v4.3.ps1" # Adjust the file path to match where you saved the script

### Running the Hardening Script
Launch the script from an elevated PowerShell prompt:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "Windows11_Enterprise_Hardening_v2.2.ps1" # Adjust the file path to match where you saved the script
