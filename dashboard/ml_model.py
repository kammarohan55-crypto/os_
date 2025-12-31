import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

class RiskClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Seed data for cold start
        self.X_seed = np.array([
            [10, 5, 200, 0, 0],      # Quick benign
            [50, 10, 1024, 0, 0],    # Normal
            [5000, 99, 1024, 0, 0],  # CPU hog
            [100, 10, 512000, 0, 10],  # Memory eater
            [200, 30, 400, 0, 0]     # Suspicious
        ])
        self.y_seed = np.array(["Benign", "Benign", "Malicious", "Malicious", "Malicious"])
        
        self.train_on_seed()

    def train_on_seed(self):
        """Train on seed data (cold start)"""
        self.scaler.fit(self.X_seed)
        X_scaled = self.scaler.transform(self.X_seed)
        self.model.fit(X_scaled, self.y_seed)
        self.is_trained = True

    def train(self, feature_df):
        """
        Train on real telemetry (feature DataFrame)
        
        CRITICAL: This uses the EXTRACTED FEATURES, not raw logs
        """
        if len(feature_df) < 5:
            return  # Not enough data
        
        # Select ML features
        feature_cols = ['runtime_ms', 'peak_cpu', 'peak_memory_kb', 
                       'page_faults_minor', 'page_faults_major']
        
        X = feature_df[feature_cols].fillna(0).values
        
        # Auto-labeling based on exit reason
        def get_label(row):
            if "VIOLATION" in str(row.get('exit_reason', '')):
                return "Malicious"
            if "KILL" in str(row.get('exit_reason', '')) or "ADAPATION" in str(row.get('exit_reason', '')):
                return "Malicious"
            if "EXITED(0)" in str(row.get('exit_reason', '')):
                return "Benign"
            return "Buggy"
        
        y = feature_df.apply(get_label, axis=1).values
        
        # Combine with seed
        X_combined = np.vstack([self.X_seed, X])
        y_combined = np.concatenate([self.y_seed, y])
        
        self.scaler.fit(X_combined)
        X_scaled = self.scaler.transform(X_combined)
        self.model.fit(X_scaled, y_combined)
        self.is_trained = True

    def predict(self, feature_row):
        """
        Predict on a single feature row (dict or Series)
        
        Args:
            feature_row: dict with keys matching feature_cols
        """
        if not self.is_trained:
            self.train_on_seed()
        
        # Extract features in correct order
        features = np.array([[
            feature_row.get('runtime_ms', 0),
            feature_row.get('peak_cpu', 0),
            feature_row.get('peak_memory_kb', 0),
            feature_row.get('page_faults_minor', 0),
            feature_row.get('page_faults_major', 0)
        ]])
        
        features_scaled = self.scaler.transform(features)
        prediction = self.model.predict(features_scaled)[0]
        probs = self.model.predict_proba(features_scaled)[0]
        confidence = max(probs)
        
        return {
            "prediction": prediction,
            "confidence": round(confidence * 100, 1),
            "reason": self.explain(prediction, feature_row)
        }

    def explain(self, prediction, feature_row):
        """Rule-based explanation"""
        reasons = []
        if feature_row.get('peak_cpu', 0) > 80:
            reasons.append("High CPU")
        if feature_row.get('peak_memory_kb', 0) > 100000:
            reasons.append("High Memory")
        if "VIOLATION" in feature_row.get('exit_reason', ''):
            reasons.append("Syscall Violation")
        if feature_row.get('runtime_ms', 0) > 2000:
            reasons.append("Long Runtime")
        
        if not reasons:
            return "Normal behavior"
        return " + ".join(reasons)

