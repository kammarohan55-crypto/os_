import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import os
import json

class RiskClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Hardcoded seed data to ensure we have a model even with few logs
        # Features: [runtime_ms, cpu_usage, memory_kb, minor_faults, major_faults]
        # Labels: 0 (Benign), 1 (Malicious)
        self.X_seed = np.array([
            [10, 5, 200, 10, 0],       # Quick benign ls
            [50, 10, 1024, 50, 0],     # Normal calc
            [5000, 99, 1024, 100, 0],  # CPU Hug (High CPU, long time)
            [100, 10, 512000, 5000, 10], # Memory Eater (High Mem, faults)
            [200, 30, 400, 10000, 0]   # Fork Bomb-like (High activity/faults usually)
        ])
        self.y_seed = np.array(["Benign", "Benign", "Malicious", "Malicious", "Malicious"])
        
        self.train_on_seed()

    def train_on_seed(self):
        self.scaler.fit(self.X_seed)
        X_scaled = self.scaler.transform(self.X_seed)
        self.model.fit(X_scaled, self.y_seed)
        self.is_trained = True

    def train(self, logs_data):
        # logs_data is list of dicts from app.py
        if len(logs_data) < 5:
            return # Not enough new data to override seed
            
        df = pd.DataFrame(logs_data)
        
        # Extract features
        # We need a way to label them for 'real' training. 
        # For this academic project, we might just assume:
        # If exit_reason contains "VIOLATION" or "SIGNALED", it's likely "Malicious/Buggy"
        # If exit_reason is "EXITED(0)", it's "Benign"
        
        features = df[['runtime_ms', 'cpu_usage_percent', 'memory_peak_kb', 'page_faults_minor', 'page_faults_major']].fillna(0)
        
        def get_label(row):
            if "VIOLATION" in str(row.get('exit_reason', '')):
                return "Malicious"
            if "SIGNALED" in str(row.get('exit_reason', '')):
                return "Buggy"
            return "Benign"

        labels = df.apply(get_label, axis=1)
        
        X = features.values
        y = labels.values
        
        # Combine with seed
        X_combined = np.vstack([self.X_seed, X])
        y_combined = np.concatenate([self.y_seed, y])
        
        self.scaler.fit(X_combined)
        X_scaled = self.scaler.transform(X_combined)
        self.model.fit(X_scaled, y_combined)
        self.is_trained = True

    def predict(self, log_entry):
        if not self.is_trained:
            self.train_on_seed()
            
        features = np.array([[
            log_entry.get('runtime_ms', 0),
            log_entry.get('cpu_usage_percent', 0),
            log_entry.get('memory_peak_kb', 0),
            log_entry.get('page_faults_minor', 0),
            log_entry.get('page_faults_major', 0)
        ]])
        
        features_scaled = self.scaler.transform(features)
        prediction = self.model.predict(features_scaled)[0]
        probs = self.model.predict_proba(features_scaled)[0]
        confidence = max(probs)
        
        return {
            "prediction": prediction,
            "confidence": round(confidence * 100, 1),
            "reason": self.explain(prediction, log_entry)
        }

    def explain(self, prediction, log):
        # Simple rule-based explanation to complement ML
        reasons = []
        if log.get('cpu_usage_percent', 0) > 80:
            reasons.append("High CPU")
        if log.get('memory_peak_kb', 0) > 100000:
            reasons.append("High Memory")
        if log.get('page_faults_minor', 0) > 1000:
            reasons.append("High Activity")
        if "VIOLATION" in log.get('exit_reason', ''):
            reasons.append("Syscall Violation")
            
        if not reasons:
            return "Normal behavior"
        return " + ".join(reasons)
