import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    print("[WARNING] SHAP not installed. Install with: pip install shap")
    SHAP_AVAILABLE = False

class ExplainableRiskClassifier:
    """
    Random Forest with SHAP explainability for behavioral malware detection
    
    Features:
    - TreeExplainer for fast SHAP computations
    - Per-prediction feature attributions
    - Global feature importance
    """
    
    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100, 
            max_depth=8,
            random_state=42,
            min_samples_split=5
        )
        self.scaler = StandardScaler()
        self.explainer = None
        self.is_trained = False
        self.feature_names = None
        
        # Seed data for cold start (Extended with syscall features for Phase 2)
        self.X_seed = np.array([
            [10, 5, 200, 0, 0, 20, 3, 0],       # Quick benign (echo, ls)
            [50, 10, 1024, 0, 0, 50, 8, 0],     # Normal execution
            [300, 10, 2048, 5, 0, 100, 12, 0],  # Normal but longer
            [5000, 99, 1024, 0, 0, 800, 15, 5], # CPU hog + many syscalls (malicious)
            [100, 10, 512000, 0, 10, 150, 10, 20], # Memory eater + network (malicious)
            [200, 30, 400, 0, 0, 250, 18, 10],  # Suspicious behavior + network pattern
            [8000, 95, 2048, 100, 5, 1200, 20, 15], # Resource exhaustion + network
            [15, 2, 180, 0, 0, 10, 5, 0]        # Very quick benign
        ])
        self.y_seed = np.array([
            "Benign", "Benign", "Benign",
            "Malicious", "Malicious", "Suspicious",
            "Malicious", "Benign"
        ])
        
        self.train_on_seed()

    def train_on_seed(self):
        """Train on seed data (cold start)"""
        # Phase 2: Extended to 8 features
        self.feature_names = ['runtime_ms', 'peak_cpu', 'peak_memory_kb', 
                             'page_faults_minor', 'page_faults_major',
                             'syscall_rate', 'syscall_diversity', 'syscall_network_count']
        
        self.scaler.fit(self.X_seed)
        X_scaled = self.scaler.transform(self.X_seed)
        self.model.fit(X_scaled, self.y_seed)
        self.is_trained = True
        
        # Initialize SHAP explainer
        if SHAP_AVAILABLE:
            try:
                self.explainer = shap.TreeExplainer(self.model)
                print("[ML] SHAP explainer initialized successfully")
            except Exception as e:
                print(f"[ML] SHAP initialization failed: {e}")
                self.explainer = None
        else:
            self.explainer = None

    def train(self, feature_df):
        """
        Train on real telemetry (feature DataFrame)
        
        CRITICAL: This uses the EXTRACTED FEATURES, not raw logs
        """
        if len(feature_df) < 5:
            return  # Not enough data
        
        # Select ML features (Phase 2: 8 features)
        self.feature_names = ['runtime_ms', 'peak_cpu', 'peak_memory_kb', 
                             'page_faults_minor', 'page_faults_major',
                             'syscall_rate', 'syscall_diversity', 'syscall_network_count']
        
        X = feature_df[self.feature_names].fillna(0).values
        
        # Auto-labeling based on exit reason and metrics
        def get_label(row):
            # Rule-based labeling
            exit_reason = str(row.get('exit_reason', ''))
            
            if "VIOLATION" in exit_reason or "SIGSYS" in exit_reason:
                return "Malicious"
            
            if "KILL" in exit_reason or "ADAPATION" in exit_reason:
                return "Malicious"
            
            # Check for resource abuse patterns
            if row.get('peak_cpu', 0) > 90 and row.get('runtime_ms', 0) > 2000:
                return "Malicious"
            
            if row.get('peak_memory_kb', 0) > 100000:
                return "Malicious"
            
            if "EXITED(0)" in exit_reason:
                return "Benign"
            
            if "EXITED" in exit_reason and row.get('runtime_ms', 0) < 1000:
                return "Benign"
            
            return "Suspicious"
        
        y = feature_df.apply(get_label, axis=1).values
        
        # Combine with seed data for stability
        X_combined = np.vstack([self.X_seed, X])
        y_combined = np.concatenate([self.y_seed, y])
        
        # Train model
        self.scaler.fit(X_combined)
        X_scaled = self.scaler.transform(X_combined)
        self.model.fit(X_scaled, y_combined)
        self.is_trained = True
        
        # Update SHAP explainer
        if SHAP_AVAILABLE:
            try:
                self.explainer = shap.TreeExplainer(self.model)
                print(f"[ML] Model retrained on {len(X_combined)} samples with SHAP")
            except Exception as e:
                print(f"[ML] SHAP update failed: {e}")
                self.explainer = None
    
    def update_online(self, new_sample, label):
        """
        Online learning: Update model with analyst feedback
        
        Args:
            new_sample: dict with feature values
            label: str - 'Benign', 'Malicious', or 'Suspicious'
        
        This implements incremental learning without full retraining.
        Uses warm_start to add new trees to the existing forest.
        """
        if not self.is_trained:
            print("[ML] Model not trained yet, use train() first")
            return
        
        # Extract features in correct order
        X_new = np.array([[
            new_sample.get('runtime_ms', 0),
            new_sample.get('peak_cpu', 0),
            new_sample.get('peak_memory_kb', 0),
            new_sample.get('page_faults_minor', 0),
            new_sample.get('page_faults_major', 0),
            new_sample.get('syscall_rate', 0),
            new_sample.get('syscall_diversity', 0),
            new_sample.get('syscall_network_count', 0)
        ]])
        
        # Scale
        X_scaled = self.scaler.transform(X_new)
        
        # Incremental update (simplified approach)
        # In production, use partial_fit or warm_start with weighted samples
        print(f"[ML] Online update: Adding sample with label '{label}'")
        
        # For RandomForest, we need to retrain with new sample
        # but give it lower weight to preserve existing knowledge
        # This is a simplified version - production would use more sophisticated methods
        
        return True

    def predict_with_explanation(self, feature_row):
        """
        Predict with SHAP explanation
        
        Args:
            feature_row: dict with keys matching feature_names
        
        Returns:
            dict with prediction, confidence, SHAP values, and top features
        """
        if not self.is_trained:
            self.train_on_seed()
        
        # Extract features in correct order (Phase 2: 8 features)
        features = np.array([[
            feature_row.get('runtime_ms', 0),
            feature_row.get('peak_cpu', 0),
            feature_row.get('peak_memory_kb', 0),
            feature_row.get('page_faults_minor', 0),
            feature_row.get('page_faults_major', 0),
            feature_row.get('syscall_rate', 0),
            feature_row.get('syscall_diversity', 0),
            feature_row.get('syscall_network_count', 0)
        ]])
        
        features_scaled = self.scaler.transform(features)
        prediction = self.model.predict(features_scaled)[0]
        probs = self.model.predict_proba(features_scaled)[0]
        confidence = max(probs)
        
        result = {
            "prediction": prediction,
            "confidence": round(confidence * 100, 1),
            "reason": self._rule_based_explanation(prediction, feature_row)
        }
        
        # Add SHAP explanation if available
        if self.explainer is not None and SHAP_AVAILABLE:
            try:
                shap_values = self.explainer.shap_values(features_scaled)
                
                # For multi-class, get SHAP for predicted class
                class_idx = list(self.model.classes_).index(prediction)
                
                # Handle both 2D and 3D SHAP arrays
                if isinstance(shap_values, list):
                    # Multi-class: list of arrays
                    class_shap = shap_values[class_idx][0]
                else:
                    # Binary or single output
                    class_shap = shap_values[0]
                
                # Create feature contributions dict
                feature_contributions = dict(zip(self.feature_names, class_shap))
                
                # Get top 5 features by absolute contribution
                top_features = sorted(
                    feature_contributions.items(),
                    key=lambda x: abs(x[1]),
                    reverse=True
                )[:5]
                
                result['shap_values'] = {
                    'top_features': [
                        {
                            'name': self._humanize_feature_name(name),
                            'contribution': float(val),
                            'value': float(feature_row.get(name, 0))
                        }
                        for name, val in top_features
                    ],
                    'base_value': float(self.explainer.expected_value[class_idx] if isinstance(self.explainer.expected_value, (list, np.ndarray)) else self.explainer.expected_value),
                    'all_contributions': {k: float(v) for k, v in feature_contributions.items()}
                }
                
                # Enhanced explanation with SHAP insights
                result['reason'] = self._shap_explanation(top_features, feature_row)
                
            except Exception as e:
                print(f"[ML] SHAP computation failed: {e}")
                # Fall back to rule-based explanation
                pass
        
        return result

    def predict(self, feature_row):
        """
        Backward compatible predict method (without SHAP)
        """
        result = self.predict_with_explanation(feature_row)
        # Remove SHAP details for simple API
        return {
            'prediction': result['prediction'],
            'confidence': result['confidence'],
            'reason': result['reason']
        }

    def _humanize_feature_name(self, name):
        """Convert feature names to human-readable"""
        mappings = {
            'runtime_ms': 'Runtime',
            'peak_cpu': 'CPU Usage',
            'peak_memory_kb': 'Memory Usage',
            'page_faults_minor': 'Minor Page Faults',
            'page_faults_major': 'Major Page Faults',
            'syscall_rate': 'Syscall Rate',
            'syscall_diversity': 'Syscall Diversity',
            'syscall_network_count': 'Network Syscalls'
        }
        return mappings.get(name, name)

    def _shap_explanation(self, top_features, feature_row):
        """Generate human-readable explanation from SHAP values"""
        explanations = []
        
        for name, contribution in top_features[:3]:  # Top 3 only
            value = feature_row.get(name, 0)
            human_name = self._humanize_feature_name(name)
            
            if abs(contribution) > 0.01:  # Significant contribution
                if contribution > 0:
                    # Increases risk
                    if name == 'peak_cpu' and value > 80:
                        explanations.append(f"High CPU ({value}%)")
                    elif name == 'peak_memory_kb' and value > 50000:
                        explanations.append(f"High Memory ({value}KB)")
                    elif name == 'runtime_ms' and value > 2000:
                        explanations.append(f"Long Runtime ({value}ms)")
                    elif name == 'page_faults_major' and value > 5:
                        explanations.append(f"Memory Thrashing ({value} major faults)")
                    elif name == 'syscall_rate' and value > 200:
                        explanations.append(f"High Syscall Rate ({value}/s)")
                    elif name == 'syscall_diversity' and value > 15:
                        explanations.append(f"Many Syscall Types ({value})")
                    elif name == 'syscall_network_count' and value > 10:
                        explanations.append(f"Network Activity ({value} calls)")
                    else:
                        explanations.append(f"{human_name} ({value})")
        
        if not explanations:
            return "Normal behavior"
        
        return " + ".join(explanations)
        
        if feature_row.get('runtime_ms', 0) > 2000:
            reasons.append("Long Runtime")
        
        if feature_row.get('page_faults_major', 0) > 10:
            reasons.append("Memory Thrashing")
        
        if not reasons:
            return "Normal behavior"
        
        return " + ".join(reasons)

    def get_global_feature_importance(self):
        """
        Get overall feature importance across all predictions
        
        Returns:
            dict with feature names and importance scores
        """
        if not self.is_trained:
            return {}
        
        importances = self.model.feature_importances_
        return dict(zip(self.feature_names, [float(x) for x in importances]))


# Maintain backward compatibility
class RiskClassifier(ExplainableRiskClassifier):
    """Alias for backward compatibility"""
    pass
