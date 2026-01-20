from flask import Flask, render_template, jsonify
import pandas as pd
import traceback
import os
import pickle

# Try to use ensemble model first, fallback to basic
try:
    from ml_ensemble import EnsembleRiskClassifier as RiskClassifier
    print("[ML] Using Ensemble Classifier (RF + XGBoost)")
except ImportError:
    from ml_model import RiskClassifier
    print("[ML] Using Basic RandomForest Classifier")

from analytics import load_all_logs, extract_features, compute_statistics, get_syscall_frequency, get_syscall_stats
import sys
sys.path.insert(0, '../runner')
from compute_aggregates import normalize_for_api
import glob
import json

app = Flask(__name__)

# Global state (cached)
if os.path.exists('../data/trained_model.pkl'):
    print("[ML] Loading pretrained model...")
    with open('../data/trained_model.pkl', 'rb') as f:
        classifier = pickle.load(f)
    print(f"[ML] Loaded pretrained model with {len(classifier.feature_names)} features")
else:
    print("[ML] No pretrained model found, using seed data")
    classifier = RiskClassifier()
cached_features = None
last_log_count = 0

def get_feature_dataframe():
    """
    CRITICAL: Single source of truth for all data
    
    FIX #8: Returns last N runs sorted by timestamp for live freshness
    
    Returns: pandas DataFrame with extracted features
    """
    global cached_features, last_log_count
    
    try:
        logs = load_all_logs("../logs")
        
        # FIX #8: Sort by timestamp to get latest runs
        if logs:
            try:
                # Try to sort by timestamp if available
                logs = sorted(logs, key=lambda x: x.get('start_ts', x.get('timestamp', 0)))
            except:
                pass  # If sorting fails, use original order
        
        # Cache invalidation - force refresh on every call for live updates
        # This ensures dashboard shows fresh data
        print(f"[Analytics] Extracting features from {len(logs)} logs...")
        cached_features = extract_features(logs)
        last_log_count = len(logs)
        
        # FIX #8: Return only last 50 runs for performance
        if len(cached_features) > 50:
            cached_features = cached_features.tail(50)
            
        # Train ML once when data changes
        if len(cached_features) > 0:
            print(f"[ML] Training on {len(cached_features)} samples...")
            classifier.train(cached_features)
        
        return cached_features if cached_features is not None else pd.DataFrame()
    
    except Exception as e:
        print(f"[ERROR] Feature extraction failed: {e}")
        traceback.print_exc()
        return pd.DataFrame()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/comparison')
def comparison():
    """Research comparison page (Phase 4)"""
    return render_template('comparison.html')

@app.route('/api/stats')
def stats():
    """
    CRASH-RESISTANT: Always returns valid JSON
    """
    try:
        # Get original logs for timeline data
        original_logs = load_all_logs("../logs")
        df = get_feature_dataframe()
        
        if df.empty:
            return jsonify({
                "total_runs": 0,
                "avg_cpu": 0,
                "avg_mem": 0,
                "violations": {},
                "runs": []
            })
        
        # Create a mapping of PID to original log (for timeline data)
        log_map = {log.get('pid'): log for log in original_logs}
        
        # Enrich with ML predictions (with SHAP) AND timeline
        enriched_runs = []
        for idx, row in df.head(50).iterrows():
            try:
                # STEP 2: Block ML if metrics are invalid (prevent fake confidence)
                runtime_ms = row.get('runtime_ms', 0)
                peak_cpu = row.get('peak_cpu', row.get('peak_cpu_percent', 0))
                
                if runtime_ms == 0 or peak_cpu == 0:
                    # Invalid data - skip ML prediction
                    run_data = row.to_dict()
                    run_data['prediction'] = 'Insufficient data'
                    run_data['confidence'] = 0.0
                    run_data['reason'] = 'Invalid metrics: runtime_ms or peak_cpu is zero'
                    print(f"  [WARNING] Skipping ML for run {idx}: runtime={runtime_ms}ms, cpu={peak_cpu}%")
                
                # FIX 1: BENIGN SHORT-RUN FILTER (Critical for credibility!)
                # Short-lived system utilities with minimal CPU are explicitly benign
                elif runtime_ms < 50 and peak_cpu < 5:
                    run_data = row.to_dict()
                    run_data['prediction'] = 'Benign'
                    run_data['confidence'] = 99.0
                    run_data['reason'] = 'Short-lived system utility (runtime<50ms, CPU<5%) - standard benign pattern'
                    print(f"  [BENIGN-FILTER] {row.get('program', 'unknown')}: runtime={runtime_ms}ms, cpu={peak_cpu}%")
                
                elif len(classifier.feature_names) == 0:
                    # Model not trained yet, skip prediction
                    run_data = row.to_dict()
                    run_data['prediction'] = 'Unknown'
                    run_data['confidence'] = 0
                    run_data['reason'] = 'Model not trained'
                else:
                    # FIX 2: Reject Out-of-Distribution Samples
                    # Check if feature vector has meaningful variance
                    feature_values = []
                    for fname in classifier.feature_names:
                        feature_values.append(row.get(fname, 0))
                    
                    import numpy as np
                    feature_std = np.std(feature_values) if feature_values else 0
                    
                    if feature_std < 0.01:  # epsilon = 0.01
                        # Out-of-distribution - reject
                        run_data = row.to_dict()
                        run_data['prediction'] = 'Unknown'
                        run_data['confidence'] = 0.0
                        run_data['reason'] = 'Out-of-distribution sample (feature variance too low)'
                        print(f"  [OOD-REJECT] {row.get('program', 'unknown')}: feature_std={feature_std:.4f}")
                    else:
                        # Valid data and trained model - use explainable prediction with SHAP values
                        ml_result = classifier.predict_with_explanation(row.to_dict())
                        run_data = row.to_dict()
                        run_data.update(ml_result)
                
                # Normalize for API compatibility (fixes zero metrics issue)
                run_data = normalize_for_api(run_data)
                
                # FIX #6: Wire policy enforcement to ML predictions
                # Map ML confidence to policy decision
                prediction = run_data.get('prediction', 'Unknown')
                confidence = run_data.get('confidence', 0)
                
                # Policy decision logic
                if prediction == 'Benign' or prediction == 'Insufficient data':
                    policy_mode = 'observe'
                    policy_reason = f"Low risk - {prediction}"
                    attempted_violations = 0
                    enforced_blocks = 0
                elif prediction == 'Malicious' and confidence >= 90:
                    policy_mode = 'block'
                    policy_reason = f"High confidence malicious ({confidence}%)"
                    attempted_violations = 1
                    enforced_blocks = 1
                elif prediction == 'Malicious' and confidence >= 70:
                    policy_mode = 'restrict'
                    policy_reason = f"Moderate confidence malicious ({confidence}%)"
                    attempted_violations = 1
                    enforced_blocks = 0  # Restrictive but not fully blocked
                elif prediction == 'Suspicious':
                    policy_mode = 'warn'
                    policy_reason = f"Suspicious but uncertain ({confidence}%)"
                    attempted_violations = 1
                    enforced_blocks = 0
                else:
                    policy_mode = 'observe'
                    policy_reason = 'Unknown risk level'
                    attempted_violations = 0
                    enforced_blocks = 0
                
                run_data['policy_decision'] = {
                    'mode': policy_mode,
                    'reason': policy_reason,
                    'attempted_violations': attempted_violations,
                    'enforced_blocks': enforced_blocks,
                    'confidence_threshold_met': confidence >= 70
                }
                
                # CRITICAL: Mark which metrics are actually available (prevent fake display)
                # Rule: If data not collected → do NOT display metric
                run_data['metrics_available'] = {
                    'syscall_data': bool(row.get('syscall_rate', 0) > 0 or row.get('total_syscalls', 0) > 0),
                    'network_data': bool(row.get('syscall_network_count', 0) > 0),
                    'cpu_data': bool(peak_cpu > 0),
                    'memory_data': bool(row.get('peak_memory_kb', 0) > 0),
                    'runtime_data': bool(runtime_ms > 0)
                }
                
                # If syscall data not available, explicitly mark it
                if not run_data['metrics_available']['syscall_data']:
                    run_data['syscall_note'] = 'Syscall telemetry unavailable in this run (eBPF not enabled)'
                
                if not run_data['metrics_available']['network_data']:
                    run_data['network_note'] = 'Network telemetry unavailable'
                
                # Add timeline from original log
                pid = row.get('pid', 0)
                if pid in log_map:
                    run_data['timeline'] = log_map[pid].get('timeline', {})
                else:
                    run_data['timeline'] = {'time_ms': [], 'cpu_percent': [], 'memory_kb': []}
                
                enriched_runs.append(run_data)
            except Exception as e:
                print(f"[WARNING] ML prediction failed for row {idx}: {e}")
                # Still include the row without ML
                run_data = row.to_dict()
                run_data['timeline'] = {'time_ms': [], 'cpu_percent': [], 'memory_kb': []}
                enriched_runs.append(run_data)
        
        # FIX #6: Calculate policy enforcement statistics
        total_violations_attempted = sum(r.get('policy_decision', {}).get('attempted_violations', 0) for r in enriched_runs)
        total_blocks_enforced = sum(r.get('policy_decision', {}).get('enforced_blocks', 0) for r in enriched_runs)
        
        result = {
            "total_runs": len(df),
            "avg_cpu": int(df['peak_cpu'].mean()) if 'peak_cpu' in df.columns else 0,
            "avg_mem": int(df['peak_memory_kb'].mean()) if 'peak_memory_kb' in df.columns else 0,
            "violations": df['exit_reason'].value_counts().to_dict() if 'exit_reason' in df.columns else {},
            "runs": enriched_runs,
            "ebpf_available": any(df['syscall_rate'] > 0) if 'syscall_rate' in df.columns else False,
            "avg_syscall_rate": int(df['syscall_rate'].mean()) if 'syscall_rate' in df.columns else 0,
            # Policy enforcement stats
            "policy_stats": {
                "total_violations_attempted": total_violations_attempted,
                "total_blocks_enforced": total_blocks_enforced,
                "enforcement_rate": round(total_blocks_enforced / max(1, total_violations_attempted) * 100, 1)
            }
        }
        
        return jsonify(result)
    
    except Exception as e:
        print(f"[ERROR] /api/stats crashed: {e}")
        traceback.print_exc()
        return jsonify({"error": "Stats generation failed", "total_runs": 0, "runs": []}), 200

@app.route('/api/analytics')
def analytics():
    """Comprehensive analytics endpoint"""
    try:
        df = get_feature_dataframe()
        
        if df.empty:
            return jsonify({
                "statistics": {"total_runs": 0},
                "syscall_frequency": {},
                "total_logs": 0
            })
        
        stats = compute_statistics(df)
        syscall_freq = get_syscall_frequency(df)
        
        result = {
            "statistics": stats,
            "syscall_frequency": syscall_freq,
            "total_logs": len(df)
        }
        return jsonify(result)
    
    except Exception as e:
        print(f"[ERROR] /api/analytics crashed: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e), "statistics": {}}), 200

@app.route('/api/ml')
def ml_predictions():
    """ML predictions for recent runs"""
    try:
        df = get_feature_dataframe()
        
        if df.empty:
            return jsonify({"predictions": [], "model_info": {"trained": False}})
        
        predictions = []
        for idx, row in df.head(20).iterrows():
            try:
                pred = classifier.predict(row.to_dict())
                pred['program'] = row.get('program', 'unknown')
                pred['profile'] = row.get('profile', 'unknown')
                predictions.append(pred)
            except Exception as e:
                print(f"[WARNING] Prediction failed for row {idx}: {e}")
        
        return jsonify({
            "predictions": predictions,
            "model_info": {
                "type": "RandomForest",
                "features": classifier.feature_names,
                "trained": classifier.is_trained
            }
        })
    
    except Exception as e:
        print(f"[ERROR] /api/ml crashed: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e), "predictions": []}), 200

@app.route('/api/ebpf')
def ebpf_stats():
    """eBPF syscall statistics (Phase 2)"""
    try:
        logs = load_all_logs("../logs")
        df = get_feature_dataframe()
        
        if df.empty:
            return jsonify({
                "ebpf_enabled": False,
                "syscall_stats": {},
                "top_syscalls": []
            })
        
        # Check if eBPF data exists
        ebpf_enabled = 'syscall_rate' in df.columns and any(df['syscall_rate'] > 0)
        
        # Get syscall statistics from logs
        syscall_df = get_syscall_stats(logs)
        
        top_syscalls = []
        if syscall_df is not None and not syscall_df.empty:
            # Aggregate across all programs
            top_syscalls = syscall_df.groupby('syscall_name')['count'].sum().sort_values(ascending=False).head(10).to_dict()
            top_syscalls = [{'name': k, 'count': int(v)} for k, v in top_syscalls.items()]
        
        result = {
            "ebpf_enabled": ebpf_enabled,
            "syscall_stats": {
                "avg_rate": float(df['syscall_rate'].mean()) if 'syscall_rate' in df.columns else 0,
                "avg_diversity": float(df['syscall_diversity'].mean()) if 'syscall_diversity' in df.columns else 0,
                "total_network_calls": int(df['syscall_network_count'].sum()) if 'syscall_network_count' in df.columns else 0
            },
            "top_syscalls": top_syscalls
        }
        
        return jsonify(result)
    
    except Exception as e:
        print(f"[ERROR] /api/ebpf crashed: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e), "ebpf_enabled": False}), 200

@app.route('/api/comparison_summary')
def comparison_summary():
    """
    Comparison dashboard API (Phase 4 - Fix #3)
    
    Reads benchmark CSVs and returns comparison data
    """
    try:
        # Look for benchmark results
        benchmark_files = glob.glob('../scripts/output/*.json') + glob.glob('../benchmark*.json')
        
        if not benchmark_files:
            return jsonify({
                "error": "No benchmark files found",
                "message": "Run 'sudo python3 scripts/benchmark_statistical.py' first"
            }), 404
        
        # Read the most recent benchmark
        latest_file = max(benchmark_files, key=os.path.getmtime)
        
        with open(latest_file, 'r') as f:
            data = json.load(f)
        
        return jsonify(data)
    
    except Exception as e:
        print(f"[ERROR] /api/comparison_summary crashed: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("[Flask] Starting OS Sandbox Analytics Dashboard...")
    print("[Flask] Initializing ML model with seed data...")
    print("[Flask] Server ready at http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)


