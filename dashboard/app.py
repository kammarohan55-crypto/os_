from flask import Flask, render_template, jsonify
import pandas as pd
import traceback
from ml_model import RiskClassifier
from analytics import load_all_logs, extract_features, compute_statistics, get_syscall_frequency

app = Flask(__name__)

# Global state (cached)
classifier = RiskClassifier()
cached_features = None
last_log_count = 0

def get_feature_dataframe():
    """
    CRITICAL: Single source of truth for all data
    
    Returns: pandas DataFrame with extracted features
    """
    global cached_features, last_log_count
    
    try:
        logs = load_all_logs("../logs")
        
        # Cache invalidation
        if len(logs) != last_log_count:
            print(f"[Analytics] Extracting features from {len(logs)} logs...")
            cached_features = extract_features(logs)
            last_log_count = len(logs)
            
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
    return render_template('index.html')

@app.route('/api/stats')
def stats():
    """
    CRASH-RESISTANT: Always returns valid JSON
    """
    try:
        df = get_feature_dataframe()
        
        if df.empty:
            return jsonify({
                "total_runs": 0,
                "avg_cpu": 0,
                "avg_mem": 0,
                "violations": {},
                "runs": []
            })
        
        # Enrich with ML predictions
        enriched_runs = []
        for idx, row in df.head(50).iterrows():
            try:
                ml_result = classifier.predict(row.to_dict())
                run_data = row.to_dict()
                run_data.update(ml_result)
                enriched_runs.append(run_data)
            except Exception as e:
                print(f"[WARNING] ML prediction failed for row {idx}: {e}")
                # Still include the row without ML
                enriched_runs.append(row.to_dict())
        
        result = {
            "total_runs": len(df),
            "avg_cpu": int(df['peak_cpu'].mean()) if 'peak_cpu' in df.columns else 0,
            "avg_mem": int(df['peak_memory_kb'].mean()) if 'peak_memory_kb' in df.columns else 0,
            "violations": df['exit_reason'].value_counts().to_dict() if 'exit_reason' in df.columns else {},
            "runs": enriched_runs
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
                "features": ["runtime_ms", "peak_cpu", "peak_memory_kb", "page_faults_minor", "page_faults_major"],
                "trained": classifier.is_trained
            }
        })
    
    except Exception as e:
        print(f"[ERROR] /api/ml crashed: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e), "predictions": []}), 200

if __name__ == '__main__':
    print("[Flask] Starting OS Sandbox Analytics Dashboard...")
    print("[Flask] Initializing ML model with seed data...")
    print("[Flask] Server ready at http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)


