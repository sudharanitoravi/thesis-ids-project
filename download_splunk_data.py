import os
import urllib.request

# ─────────────────────────────────────────────────────────────────────────────
# Download attack logs for ALL 8 MITRE ATT&CK techniques from Splunk Attack Data
# Source: https://github.com/splunk/attack_data
# ─────────────────────────────────────────────────────────────────────────────

folders = [
    "data/raw/T1566_Phishing",
    "data/raw/T1110_BruteForce", 
    "data/raw/T1078_ValidAccounts",
    "data/raw/T1059_CommandShell",
    "data/raw/T1055_ProcessInjection",
    "data/raw/T1082_SystemInfo",
    "data/raw/T1021_RemoteServices",
    "data/raw/T1041_Exfiltration",
    "data/processed",
    "models",
    "results",
    "results/figures",
    "notebooks"
]

for folder in folders:
    os.makedirs(folder, exist_ok=True)

print("Created all folders")
print()

# NOTE: These URLs point to the Splunk Attack Data repository.
# If a URL is broken, replace it with a working one from:
# https://github.com/splunk/attack_data/tree/master/datasets/attack_techniques

files_to_download = [
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/spearphishing_attachment/windows-sysmon.log",
        "save_to": "data/raw/T1566_Phishing/windows-sysmon.log",
        "technique": "T1566 - Phishing"
    },
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_disabled_users_kerberos/windows-security.log",
        "save_to": "data/raw/T1110_BruteForce/windows-security.log",
        "technique": "T1110 - Brute Force"
    },
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.001/local_admin/windows-security.log",
        "save_to": "data/raw/T1078_ValidAccounts/windows-security.log",
        "technique": "T1078 - Valid Accounts"
    },
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/encoded_powershell/windows-powershell.log",
        "save_to": "data/raw/T1059_CommandShell/windows-powershell.log",
        "technique": "T1059 - Command & Scripting Interpreter"
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
        "technique": "T1021 - Remote Services"
    },
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1041/icedid_exfiltration/zeek.log",
        "save_to": "data/raw/T1041_Exfiltration/zeek.log",
        "technique": "T1041 - Exfiltration Over C2"
    },
]

for item in files_to_download:
    print(f"Downloading: {item['technique']}")
    print(f"  From: {item['url'][:70]}...")
    try:
        urllib.request.urlretrieve(item["url"], item["save_to"])
        size = os.path.getsize(item["save_to"])
        print(f"  Saved to: {item['save_to']}")
        print(f"  Size: {size / 1024:.1f} KB")
        print()
    except Exception as e:
        print(f"  ERROR: {e}")
        print(f"  >>> Go to https://github.com/splunk/attack_data and find a replacement URL for {item['technique']}")
        print()

print("Download complete!")
print("Next: Run 02_preprocessing.ipynb to parse all 8 techniques.")
