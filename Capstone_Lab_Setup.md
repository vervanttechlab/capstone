# CAPSTONE — LAB SETUP GUIDE
## Build your one-person security desk, step by step
### Operation Night Watch · Days 13–14 · For trainees and the trainer

> **Read this first.** You are setting up **your own computer** to be watched, and (Track B) a small **virtual** computer that lives inside it. Nothing you set up here can reach anyone else. Every command below is typed exactly as shown. Commands marked **(Admin)** need PowerShell **run as administrator**: Start → type `PowerShell` → right-click → **Run as administrator** → Yes.

> **Time needed:** Track A about **45 minutes**. Track B about **90 minutes** (most of it is the Kali download). Do §1–§3 on Day 12 afternoon (Task 6). Do the rest before 8:00 on Day 13.

---

## §0 — CHOOSE YOUR TRACK

Check your machine: Start → Settings → System → About.

| If your computer has... | Choose |
|-------------------------|--------|
| Less than 8 GB RAM, **or** no admin rights to install VirtualBox, **or** you are not sure | **Track A — Windows only.** Do §1, §2, §3, §5 |
| 8 GB RAM or more, 30 GB free disk, and admin rights | **Track B — Windows + VirtualBox + Kali.** Do §1 to §5 |

Both tracks can earn full marks. Track B lets you see real network traffic between two machines.

**Check virtualisation (Track B only):** press `Ctrl+Shift+Esc` → **Performance** → **CPU**. Look for **Virtualization: Enabled**. If it says Disabled, see §8, problem 1.

---

## §1 — PREPARE WINDOWS (both tracks)

### 1.1 Make your evidence folders
```powershell
New-Item -ItemType Directory -Force "$HOME\Evidence\Capstone\Day13", "$HOME\Evidence\Capstone\Day14\scans" | Out-Null
explorer "$HOME\Evidence\Capstone"
```
Copy `Capstone_Shift_Simulator.ps1` and `Capstone_Evidence_Collector.ps1` into `$HOME\Evidence\Capstone\`.

### 1.2 Allow the two capstone scripts to run (Admin)
```powershell
Set-Location "$HOME\Evidence\Capstone"
Unblock-File .\Capstone_Shift_Simulator.ps1, .\Capstone_Evidence_Collector.ps1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```
*`-Scope Process` means "only for this window". When you close it, the setting goes back to normal. You repeat the last line each time you open a new Admin window for the capstone.*

### 1.3 Check that Microsoft Defender is working and up to date
```powershell
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated
Update-MpSignature
```
**You want:** all three `True`, and a signature date of today after the update. If another antivirus is installed, Defender may be off: tell the trainer (you will use that antivirus's own history instead).

### 1.4 Switch on the firewall log (Admin)
```powershell
Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogMaxSizeKilobytes 16384
Get-NetFirewallProfile | Select-Object Name, Enabled, LogBlocked, LogFileName
```
**You want:** `Enabled True` and `LogBlocked True` for all three. The log is at `C:\Windows\System32\LogFiles\Firewall\pfirewall.log`.

### 1.5 Switch on the Windows audit settings you need (Admin)
```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
auditpol /get /category:"Logon/Logoff","Account Management"
```
*On a non-English Windows the sub-category names are translated. If you get an error, tell the trainer: they will give you the GUID version of these lines.*

### 1.6 Install Nmap and Python
Already done on Day 12. Check:
```powershell
nmap --version
python --version
```

---

## §2 — MAKE YOUR MONITORING VIEW (both tracks)

### 2.1 Sysmon (recommended, 10 minutes, Admin)
Sysmon records process starts, network connections and file creation. It makes Day 13 much easier.
1. Download **Sysmon** from https://learn.microsoft.com/sysinternals/downloads/sysmon and unzip it to `C:\Tools\Sysmon`.
2. Download the SwiftOnSecurity configuration: https://github.com/SwiftOnSecurity/sysmon-config → `sysmonconfig-export.xml` → save it into `C:\Tools\Sysmon`.
3. Install:
```powershell
Set-Location C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
Get-Service Sysmon64
```
**You want:** `Running`.

### 2.2 The Event Viewer custom view "CTM Capstone"
1. Start → `eventvwr.msc`.
2. Right pane → **Create Custom View…** → tab **XML** → tick **Edit query manually** → Yes.
3. Delete everything and paste:
```xml
<QueryList>
  <Query Id="0">
    <Select Path="Security">*[System[(EventID=4625 or EventID=4720 or EventID=4726 or EventID=4732 or EventID=4698 or EventID=1102)]]</Select>
    <Select Path="System">*[System[(EventID=7045 or EventID=104)]]</Select>
    <Select Path="Microsoft-Windows-Windows Defender/Operational">*[System[(EventID=1116 or EventID=1117 or EventID=5001)]]</Select>
    <Select Path="Microsoft-Windows-TaskScheduler/Operational">*[System[(EventID=106)]]</Select>
  </Query>
</QueryList>
```
4. OK → Name: `CTM Capstone` → OK. It appears under **Custom Views**.

*If Sysmon is installed, make a second view `CTM Sysmon` with Path `Microsoft-Windows-Sysmon/Operational` and EventID 1, 3, 11.*

### 2.3 Know what each event means

| Log | Event ID | Meaning | Why it matters |
|-----|----------|---------|----------------|
| Security | **4625** | An account failed to log on | Many in a row = someone guessing a password |
| Security | **4720** | A user account was created | New accounts should be expected and ticketed |
| Security | **4732** | A member was added to a security-enabled local group | Check which group. **Administrators** = high risk |
| Security | **4698** | A scheduled task was created | A common way to make something run again later (persistence) |
| Security | **1102** | The audit log was cleared | Someone may be hiding tracks |
| System | **7045** | A new service was installed | Another way to stay on a machine |
| Defender | **1116** | Malware or unwanted software detected | The alert |
| Defender | **1117** | Action taken to protect the system | What Defender did about it: quarantine, remove, block |
| Defender | **5001** | Real-time protection was turned off | A red flag before ransomware |
| TaskScheduler | **106** | A task was registered | Same as 4698, from the Task Scheduler side |

---

## §3 — SETUP CHECKLIST (screenshot this for Day 12 Task 6)

| # | Check | ✔ |
|---|-------|:-:|
| 1 | Evidence folders exist, both scripts copied and unblocked | |
| 2 | Defender: three `True`, signatures updated today | |
| 3 | Firewall logging on for all three profiles | |
| 4 | Audit policy: Logon success+failure, User Account Mgmt, Security Group Mgmt, Other Object Access | |
| 5 | Nmap and Python answer with a version | |
| 6 | Custom view `CTM Capstone` exists | |
| 7 | *(Recommended)* Sysmon64 running | |
| 8 | *(Track B)* VirtualBox installed, Kali imported, host-only network works (§4.6) | |

---

## §4 — TRACK B: VIRTUALBOX AND KALI LINUX

### 4.1 Turn off Hyper-V features that slow VirtualBox (Admin, only if you use them)
If **Windows Sandbox**, **Hyper-V** or **Virtual Machine Platform** is on, VirtualBox runs very slowly. Check: Start → `optionalfeatures` → untick **Hyper-V**, **Windows Sandbox**, **Virtual Machine Platform**, **Windows Hypervisor Platform** → OK → restart. *(You can switch them back on after the capstone.)*

### 4.2 Install VirtualBox
Download **VirtualBox for Windows hosts** from https://www.virtualbox.org/wiki/Downloads and install with all defaults. Accept the network driver prompts. If it asks for the **Microsoft Visual C++ Redistributable**, install that first from the link it shows.

### 4.3 Get the Kali Linux virtual machine
Your trainer may give you a **Kali `.ova` file** on a USB drive or shared folder. If so, go to **4.4a**.

Otherwise download the official pre-built image: https://www.kali.org/get-kali/#kali-virtual-machines → **VirtualBox** (64-bit) → a `.7z` file of about 3 GB. Extract it with **7-Zip** (https://www.7-zip.org). Go to **4.4b**.

*Check the download: on the Kali page, copy the SHA256 sum, then `Get-FileHash .\kali-linux-*.7z` and compare. Same = not corrupted, not tampered with.*

### 4.4a Import an OVA
VirtualBox → **File → Import Appliance…** → choose the `.ova` → Next → set **RAM 2048 MB**, **CPUs 2** → **Finish**. Wait for the import.

### 4.4b Add the pre-built image
VirtualBox → **Machine → Add…** → open the extracted folder → select the `.vbox` file → Open.

### 4.5 Put Kali on the private lab network
Select the Kali VM → **Settings**:
1. **System → Motherboard:** Base Memory **2048 MB** (use 3072 if you have 16 GB).
2. **Display → Screen:** Graphics Controller **VMSVGA**.
3. **Network → Adapter 1:** Enable, Attached to: **Host-only Adapter**, Name: **VirtualBox Host-Only Ethernet Adapter**.
4. **Network → Adapter 2:** Enable, Attached to: **NAT** *(only so Kali can download updates; you switch it off in 4.7)*.
5. OK.

> **Why host-only?** A host-only network is a private cable between your Windows machine and Kali, and nothing else. Your Windows side is **192.168.56.1**. Kali gets **192.168.56.101** (or .102, .103…). No one on your home network or the internet can see it.

### 4.6 First boot and check
1. **Start** the VM. Log in with **kali / kali**.
2. Open **Terminal** (the black icon at the top). Change the password straight away:
```bash
passwd
```
3. Update the package list, and note your address:
```bash
sudo apt update
ip -brief address
```
**You want:** an `eth0` line with **192.168.56.10x**. Write it down: this is **LAB-KALI-01**.
4. Test the private cable. On **Windows** PowerShell:
```powershell
ping 192.168.56.101
```
**You want:** `Reply from 192.168.56.101`. *(Use your own .10x number.)*
From **Kali**:
```bash
ping -c 4 192.168.56.1
```
*It is normal if Windows does **not** reply: its firewall blocks ping on this network. That blocked ping is your first firewall-log entry.*

### 4.7 Close the door to the internet, take a snapshot
1. Shut Kali down: `sudo poweroff`.
2. Settings → Network → **Adapter 2** → **untick Enable Network Adapter** → OK. Kali now talks to your Windows machine only.
3. Select the VM → **Snapshots** (the list icon next to the VM) → **Take** → name: `clean-baseline`.

> **If anything goes wrong later**, restore `clean-baseline` and you are back to this point in one minute.

### 4.8 Prepare the Kali "notice page" (used on Day 13 card K2 and on Day 14)
Start Kali again. In Terminal:
```bash
mkdir -p ~/ctm-web && cd ~/ctm-web
echo '<html><head><title>Kalinaw Coop Notices</title></head><body><h1>Member notices</h1><p>Meeting on Saturday.</p></body></html>' > index.html
ls -l
```
That is all for now. You start the web server only when a card tells you to.

---

## §5 — BEFORE 8:00 ON DAY 13

1. Open an **Admin PowerShell**, go to your evidence folder, and allow the scripts for this window (§1.2).
2. Open **Event Viewer** on your custom view, and **Windows Security → Virus & threat protection → Protection history**.
3. Track B: Kali running, Terminal open, `cd ~/ctm-web`.
4. Have `Capstone_Templates.docx` open.

**Do not run the Shift Simulator until the trainer says "start your shift".**

---

## §6 — OPTIONAL: ENROL IN THE CLASS WAZUH SERVER

Only if the trainer says the class server is running and gives you its address.
1. Download the **Wazuh agent for Windows** (MSI) from the version the trainer names: https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html
2. (Admin) — replace `<SERVER-IP>` and `<YOUR-NAME>`:
```powershell
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="<SERVER-IP>" WAZUH_AGENT_NAME="LAB-WKS-01-<YOUR-NAME>"
NET START WazuhSvc
```
3. In the dashboard (browser, `https://<SERVER-IP>`), check your agent shows **active**. Wazuh alerts then count as a detection source on Day 13 and **Vulnerability Detection** as the agent method on Day 14.

---

## §7 — CLEAN-UP AFTER THE CAPSTONE (Day 14, 5:00 PM)

| Step | Command / action |
|------|------------------|
| 1. Remove the test items (Admin) | `.\Capstone_Shift_Simulator.ps1 -Cleanup` |
| 2. Zip your evidence | Right-click `Evidence\Capstone` → Compress to ZIP → submit it |
| 3. Firewall log (optional, keep it on if you like) | `Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked False` |
| 4. Kali (Track B) | Keep it for practice, or VirtualBox → right-click → Remove → Delete all files |
| 5. Hyper-V features | Switch back on in `optionalfeatures` if you turned them off in §4.1 |
| 6. Sysmon (optional removal) | `C:\Tools\Sysmon\Sysmon64.exe -u` |

---

## §8 — IF SOMETHING GOES WRONG

| # | Problem | Fix |
|---|---------|-----|
| 1 | "VT-x is disabled" or Virtualization: Disabled | Restart → enter BIOS/UEFI (usually F2, F10, Del or Esc) → find **Intel Virtualization Technology** or **SVM Mode** → Enable → Save and exit. Not allowed on a work laptop? Use Track A |
| 2 | Kali is extremely slow, or the turtle icon shows in the VM's status bar | Hyper-V is still on. Do §4.1, restart. Also check in Admin cmd: `bcdedit /set hypervisorlaunchtype off`, restart |
| 3 | No "VirtualBox Host-Only Ethernet Adapter" in the list | VirtualBox → **File → Tools → Network Manager** → **Host-only Networks** → **Create**. Set IPv4 192.168.56.1 / 255.255.255.0, DHCP server on |
| 4 | Kali shows a black screen after login | Settings → Display → Graphics Controller **VMSVGA**, Video Memory 128 MB |
| 5 | Kali has no 192.168.56.x address | In Kali: `sudo dhclient eth0`, then `ip -brief address`. Still nothing: Adapter 1 is not set to Host-only |
| 6 | `running scripts is disabled on this system` | You forgot §1.2 in this window |
| 7 | `Get-MpComputerStatus` errors | Another antivirus replaced Defender. Tell the trainer; use that product's history |
| 8 | `auditpol` "error 0x00000057" | Non-English sub-category names. Ask the trainer for the GUID lines |
| 9 | 4 GB machine, everything slow | Close the browser tabs you do not need. Track A only. Skip Sysmon |
