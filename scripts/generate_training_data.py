#!/usr/bin/env python3
"""
Generate realistic training data for ML model
Creates 100+ samples by running actual programs
"""

import subprocess
import json
import os
import time
import sys

# Ensure we're in project root
os.chdir('/mnt/c/Users/Rohan/Desktop/os_el/sandbox-project')

print("=" * 70)
print("GENERATING TRAINING DATA")
print("=" * 70)
print()

# Test programs with known labels
programs = [
    # Benign programs (40 samples)
    {'path': 'samples/sleep', 'args': '1', 'label': 'Benign', 'runs': 10},
    {'path': '/bin/echo', 'args': 'Hello World', 'label': 'Benign', 'runs': 10},
    {'path': '/bin/ls', 'args': '-la', 'label': 'Benign', 'runs': 10},
    {'path': '/bin/date', 'args': '', 'label': 'Benign', 'runs': 10},
    
    # Malicious programs (40 samples)
    {'path': 'samples/cpu_hog', 'args': '', 'label': 'Malicious', 'runs': 20},
    {'path': 'samples/fork_bomb', 'args': '', 'label': 'Malicious', 'runs': 20},
    
    # Suspicious programs (20 samples)
    {'path': 'samples/fs_attack', 'args': '', 'label': 'Suspicious', 'runs': 20},
]

training_data = []
total = sum(p['runs'] for p in programs)
count = 0

for prog in programs:
    print(f"Running {prog['path']} ({prog['runs']} times)...")
    
    for i in range(prog['runs']):
        count += 1
        print(f"  [{count}/{total}] Run {i+1}/{prog['runs']}...", end='', flush=True)
        
        try:
            # Run without eBPF for now (faster)
            cmd = ['./runner/launcher', prog['path']]
            if prog['args']:
                cmd.append(prog['args'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Find the most recent log file
            log_files = sorted([f for f in os.listdir('logs') if f.startswith('run_')], 
                              key=lambda x: os.path.getmtime(f'logs/{x}'), reverse=True)
            
            if log_files:
                with open(f'logs/{log_files[0]}', 'r') as f:
                    log_data = json.load(f)
                    log_data['true_label'] = prog['label']
                    training_data.append(log_data)
                print(" ✓")
            else:
                print(" ✗ (no log)")
        
        except subprocess.TimeoutExpired:
            print(" ✗ (timeout)")
        except Exception as e:
            print(f" ✗ ({e})")
        
        time.sleep(0.1)  # Brief pause

print()
print(f"Generated {len(training_data)} samples")

# Save training dataset
os.makedirs('data', exist_ok=True)
with open('data/training_dataset.json', 'w') as f:
    json.dump(training_data, f, indent=2)

print(f"Saved to: data/training_dataset.json")

# Train model immediately
print()
print("Training ML model on generated data...")
sys.path.insert(0, 'dashboard')

from analytics import load_all_logs, extract_features
from ml_ensemble import EnsembleRiskClassifier

# Load features
logs = load_all_logs('logs')
df = extract_features(logs)

if len(df) > 0:
    print(f"Extracted features from {len(df)} logs")
    
    # Train ensemble
    clf = EnsembleRiskClassifier()
    clf.train(df)
    
    # Save model
    import pickle
    with open('data/trained_model.pkl', 'wb') as f:
        pickle.dump(clf, f)
    
    print("✓ Model trained and saved to: data/trained_model.pkl")
    print()
    print("Model Performance:")
    print(f"  Training samples: {len(df)}")
    print(f"  Features: {clf.feature_names}")
    print(f"  Model type: {clf.get_model_comparison()}")
else:
    print("✗ No features extracted, check logs/")

print()
print("=" * 70)
print("TRAINING DATA GENERATION COMPLETE")
print("=" * 70)
