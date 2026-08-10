import os
import urllib.request

# ─────────────────────────────────────────────────────────────────────────────
# This script downloads real attack log files from Splunk's Attack Data repo
# Each file contains Windows Security Event logs from a real attack simulation
# Each file corresponds to one MITRE ATT&CK technique
# ─────────────────────────────────────────────────────────────────────────────

# Create folders
os.makedirs("data/raw/T1110_BruteForce", exist_ok=True)
os.makedirs("data/raw/T1059_CommandShell", exist_ok=True)
os.makedirs("data/raw/T1078_ValidAccounts", exist_ok=True)
os.makedirs("data/raw/T1055_ProcessInjection", exist_ok=True)
os.makedirs("data/raw/T1082_SystemInfo", exist_ok=True)
os.makedirs("data/raw/T1021_RemoteServices", exist_ok=True)
os.makedirs("data/processed", exist_ok=True)
os.makedirs("models", exist_ok=True)
os.makedirs("results", exist_ok=True)
os.makedirs("notebooks", exist_ok=True)

print("Created all folders")
print()

# ─────────────────────────────────────────────────────────────────────────────
# DOWNLOAD FILES
# These are direct links to log files in the Splunk Attack Data GitHub repo
# Each file contains real Windows Security Event logs from an attack simulation
# ─────────────────────────────────────────────────────────────────────────────

files_to_download = [
    {
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/purplesharp_disabled_users_kerberos/windows-security.log",
        "save_to": "data/raw/T1110_BruteForce/windows-security.log",
        "technique": "T1110 - Brute Force"
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
        "url": "https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.002/atomic_red_team/windows-security.log",
        "save_to": "data/raw/T1021_RemoteServices/windows-security.log",
        "technique": "T1021 - Remote Services"
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
        print()

print("Download complete!")
print()
print("Your data/raw/ folder now contains log files for each ATT&CK technique.")
print("Next step: Run the notebook to parse and explore this data.")