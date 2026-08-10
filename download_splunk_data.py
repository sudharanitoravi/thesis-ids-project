import os
import urllib.request

# ─────────────────────────────────────────────────────────────────────────────
# Download attack logs for 6 MITRE ATT&CK techniques from Splunk Attack Data
# Source: https://github.com/splunk/attack_data
# These 6 URLs are verified working
# ─────────────────────────────────────────────────────────────────────────────

folders = [
    "data/raw/T1566_Phishing",
    "data/raw/T1110_BruteForce",
    "data/raw/T1059_CommandShell",
    "data/raw/T1055_ProcessInjection",
    "data/raw/T1082_SystemInfo",
    "data/raw/T1021_RemoteServices",
    "data/processed",
    "models",
    "results",
    "results/figures",
]

for folder in folders:
    os.makedirs(folder, exist_ok=True)

print("Created all folders\n")

files_to_download = [
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon.log",
        "save_to": "data/raw/T1566_Phishing/windows-sysmon.log",
        "technique": "T1566.001 - Phishing"
    },
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_disabled_users_kerberos/windows-security.log",
        "save_to": "data/raw/T1110_BruteForce/windows-security.log",
        "technique": "T1110.003 - Brute Force"
    },
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/hidden_powershell/windows-powershell.log",
        "save_to": "data/raw/T1059_CommandShell/windows-powershell.log",
        "technique": "T1059.001 - PowerShell"
    },
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log",
        "save_to": "data/raw/T1055_ProcessInjection/windows-sysmon.log",
        "technique": "T1055 - Process Injection"
    },
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1082/atomic_red_team/windows-sysmon.log",
        "save_to": "data/raw/T1082_SystemInfo/windows-sysmon.log",
        "technique": "T1082 - System Information Discovery"
    },
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.002/atomic_red_team/windows-security.log",
        "save_to": "data/raw/T1021_RemoteServices/windows-security.log",
        "technique": "T1021.002 - Remote Services"
    },
]

success_count = 0
for item in files_to_download:
    print(f"Downloading: {item['technique']}")
    try:
        urllib.request.urlretrieve(item["url"], item["save_to"])
        size = os.path.getsize(item["save_to"])
        print(f"  Saved: {item['save_to']} ({size/1024:.1f} KB)\n")
        success_count += 1
    except Exception as e:
        print(f"  ERROR: {e}\n")

print(f"Download complete: {success_count}/6 succeeded")
