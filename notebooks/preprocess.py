import pandas as pd
import numpy as np
import json, os, glob, re
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

print('=== PREPROCESSING ===')

RAW_DIR = '../data/raw'
PROCESSED_DIR = '../data/processed'
os.makedirs(PROCESSED_DIR, exist_ok=True)

TECHNIQUE_MAP = {
    'T1566_Phishing': 'T1566',
    'T1110_BruteForce': 'T1110',
    'T1059_CommandShell': 'T1059',
    'T1055_ProcessInjection': 'T1055',
    'T1082_SystemInfo': 'T1082',
    'T1021_RemoteServices': 'T1021',
}

# ─── PARSE LOGS ───
all_records = []

for folder_name, technique_id in TECHNIQUE_MAP.items():
    folder_path = os.path.join(RAW_DIR, folder_name)
    if not os.path.exists(folder_path):
        print(f'WARNING: {folder_path} not found')
        continue

    log_files = glob.glob(os.path.join(folder_path, '*.log'))
    print(f'Processing {technique_id}: {len(log_files)} file(s)')

    for log_file in log_files:
        count = 0
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                event = None

                # Try JSON
                try:
                    result = json.loads(line)
                    if isinstance(result, dict):
                        event = result
                except:
                    pass

                # Try key=value
                if event is None:
                    matches = re.compile(r'(\w+)[=:]([^\s]+|"[^"]*")').findall(line)
                    if len(matches) > 2:
                        event = {}
                        for key, val in matches:
                            event[key] = val.strip('"')

                if event is not None:
                    event['technique_id'] = technique_id
                    all_records.append(event)
                    count += 1

        print(f'  {os.path.basename(log_file)}: {count} events')

print(f'\nTotal events: {len(all_records)}')

if len(all_records) == 0:
    raise ValueError('No events parsed!')

# ─── CREATE DATAFRAME ───
df = pd.DataFrame(all_records)
print(f'DataFrame shape: {df.shape}')
print(f'Columns: {list(df.columns)}')

# ─── FEATURES ───
print('\nExtracting features...')
n = len(df)
features = pd.DataFrame()

features['raw_length'] = df.apply(lambda row: len(str(row)), axis=1)

# EventCode
if 'EventCode' in df.columns:
    features['EventCode'] = pd.to_numeric(df['EventCode'], errors='coerce').fillna(0)
else:
    features['EventCode'] = 0

# Source type
if 'sourcetype' in df.columns:
    features['source_type'] = df['sourcetype'].astype(str)
elif 'SourceName' in df.columns:
    features['source_type'] = df['SourceName'].astype(str)
else:
    features['source_type'] = 'unknown'

# Process name
if 'Image' in df.columns:
    process = df['Image'].astype(str)
elif 'ProcessName' in df.columns:
    process = df['ProcessName'].astype(str)
elif 'NewProcessName' in df.columns:
    process = df['NewProcessName'].astype(str)
else:
    process = pd.Series([''] * n)
features['process_name'] = process
features['process_name_length'] = features['process_name'].str.len()
features['has_process'] = (features['process_name'] != '').astype(int)

# CommandLine
if 'CommandLine' in df.columns:
    cmd = df['CommandLine'].astype(str)
else:
    cmd = pd.Series([''] * n)
features['command_line'] = cmd
features['command_line_length'] = features['command_line'].str.len()
features['has_command_line'] = (features['command_line'] != '').astype(int)

# Parent process
if 'ParentImage' in df.columns:
    parent = df['ParentImage'].astype(str)
elif 'ParentProcessName' in df.columns:
    parent = df['ParentProcessName'].astype(str)
else:
    parent = pd.Series([''] * n)
features['has_parent_process'] = (parent != '').astype(int)

# User
if 'User' in df.columns:
    user = df['User'].astype(str)
elif 'AccountName' in df.columns:
    user = df['AccountName'].astype(str)
elif 'SubjectUserName' in df.columns:
    user = df['SubjectUserName'].astype(str)
else:
    user = pd.Series([''] * n)
features['user_present'] = (user != '').astype(int)

# Computer
if 'Computer' in df.columns:
    computer = df['Computer'].astype(str)
elif 'ComputerName' in df.columns:
    computer = df['ComputerName'].astype(str)
else:
    computer = pd.Series(['unknown'] * n)
features['computer'] = computer

# Time
if '_time' in df.columns:
    time_parsed = pd.to_datetime(df['_time'], errors='coerce', utc=True)
elif 'TimeCreated' in df.columns:
    time_parsed = pd.to_datetime(df['TimeCreated'], errors='coerce', utc=True)
else:
    time_parsed = pd.Series([pd.NaT] * n)
features['hour_of_day'] = time_parsed.dt.hour.fillna(0)
features['day_of_week'] = time_parsed.dt.dayofweek.fillna(0)

# Log type
if 'Channel' in df.columns:
    log_type = df['Channel'].astype(str)
elif 'LogName' in df.columns:
    log_type = df['LogName'].astype(str)
else:
    log_type = pd.Series(['unknown'] * n)
features['log_type'] = log_type

# Target
if 'TargetObject' in df.columns:
    target = df['TargetObject'].astype(str)
elif 'TargetFilename' in df.columns:
    target = df['TargetFilename'].astype(str)
else:
    target = pd.Series([''] * n)
features['has_target'] = (target != '').astype(int)

# Number of keys
features['num_keys'] = df.apply(lambda row: len([k for k in row.keys() if pd.notna(row[k]) and str(row[k]) != '']), axis=1)

# Label
features['technique_id'] = df['technique_id'].values

print(f'Feature matrix: {features.shape}')
print(f'Features: {list(features.columns)}')

# ─── ENCODE ───
le_technique = LabelEncoder()
features['technique_encoded'] = le_technique.fit_transform(features['technique_id'])

for col in ['source_type', 'process_name', 'command_line', 'computer', 'log_type']:
    le = LabelEncoder()
    features[col] = le.fit_transform(features[col].astype(str))

X = features.drop(['technique_id', 'technique_encoded'], axis=1)
y = features['technique_encoded']

print(f'\nClass distribution:')
print(y.value_counts().sort_index())
print(f'Total classes: {y.nunique()}')

# ─── SPLIT ───
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
print(f'\nTrain: {X_train.shape}, Test: {X_test.shape}')

# ─── SAVE ───
X_train.to_csv(f'{PROCESSED_DIR}/X_train.csv', index=False)
X_test.to_csv(f'{PROCESSED_DIR}/X_test.csv', index=False)
y_train.to_csv(f'{PROCESSED_DIR}/y_train.csv', index=False)
y_test.to_csv(f'{PROCESSED_DIR}/y_test.csv', index=False)

label_map_df = pd.DataFrame({'encoded': range(len(le_technique.classes_)), 'technique': le_technique.classes_})
label_map_df.to_csv(f'{PROCESSED_DIR}/label_map.csv', index=False)
pd.DataFrame({'feature': X.columns}).to_csv(f'{PROCESSED_DIR}/feature_names.csv', index=False)

print(f'\nSaved to {PROCESSED_DIR}/')
print(label_map_df.to_string(index=False))
print('\n=== DONE ===')
