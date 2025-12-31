from flask import Flask, render_template, jsonify
import os
import json
import glob
import pandas as pd
import time
from ml_model import RiskClassifier
from analytics import (load_all_logs, compute_statistics, 
                       get_syscall_frequency, get_memory_growth_rate)

app = Flask(__name__)

LOG_DIR = "../logs"
classifier = RiskClassifier()

def get_logs():
    """Load logs using analytics module"""
    return load_all_logs(LOG_DIR)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def stats():
    try:
        data = get_logs()
        
        # Train periodically
        if len(data) > 0:
            classifier.train(data)

        df = pd.DataFrame([log.get('summary', {}) for log in data])
        
        if df.empty:
            return jsonify({
                "total_runs": 0,
                "avg_cpu": 0,
                "avg_mem": 0,
                "violations": {},
                "runs": []
            })
            
        # Enrich data with ML predictions
        enriched_runs = []
        for run in data[:50]:
            ml_result = classifier.predict(run)
            # Flatten summary for backward compat
            run_flat = run.copy()
            run_flat.update(run.get('summary', {}))
            run_flat.update(ml_result)
            enriched_runs.append(run_flat)
            
        stats_result = {
            "total_runs": len(df),
            "avg_cpu": int(df['peak_cpu'].mean()) if 'peak_cpu' in df else 0,
            "avg_mem": int(df['peak_memory_kb'].mean()) if 'peak_memory_kb' in df else 0,
            "violations": df['exit_reason'].value_counts().to_dict() if 'exit_reason' in df else {},
            "runs": enriched_runs
        }
        return jsonify(stats_result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/analytics')
def analytics():
    """Comprehensive analytics endpoint"""
    try:
        logs = get_logs()
        stats = compute_statistics(logs)
        syscall_freq = get_syscall_frequency(logs)
        
        result = {
            "statistics": stats,
            "syscall_frequency": syscall_freq,
            "total_logs": len(logs)
        }
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

@app.route('/api/ml')
def ml_predictions():
    """ML predictions for all recent runs"""
    try:
        logs = get_logs()
        
        if len(logs) > 0:
            classifier.train(logs)
        
        predictions = []
        for log in logs[:20]:  # Last 20
            pred = classifier.predict(log)
            pred['program'] = log.get('program', 'unknown')
            pred['profile'] = log.get('profile', 'unknown')
            predictions.append(pred)
        
        return jsonify({
            "predictions": predictions,
            "model_info": {
                "type": "RandomForest",
                "features": ["runtime", "cpu", "memory", "faults_minor", "faults_major", "mem_growth", "cpu_variance"],
                "trained": classifier.is_trained
            }
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

