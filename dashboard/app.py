from flask import Flask, render_template, jsonify
import os
import json
import glob
import pandas as pd
import time
from ml_model import RiskClassifier

app = Flask(__name__)

LOG_DIR = "../logs"
classifier = RiskClassifier()

def get_logs():
    files = glob.glob(os.path.join(LOG_DIR, "*.json"))
    data = []
    for f in files:
        try:
            with open(f, 'r') as fh:
                entry = json.load(fh)
                entry['timestamp'] = os.path.getmtime(f)
                data.append(entry)
        except Exception as e:
            print(f"Error reading {f}: {e}")
    
    # Sort by timestamp desc
    data.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    return data

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def stats():
    try:
        data = get_logs()
        
        # Train periodically or on request (here on request for simplicity)
        if len(data) > 0:
            classifier.train(data)

        df = pd.DataFrame(data)
        
        if df.empty:
            return jsonify({
                "total_runs": 0,
                "avg_cpu": 0,
                "avg_mem": 0,
                "violations": {},
                "runs": []
            })
            
        # Enrich data with ML predictions
        start_time = time.time()
        enriched_runs = []
        for run in data[:50]: # Only process latest 50
            ml_result = classifier.predict(run)
            run.update(ml_result)
            enriched_runs.append(run)
            
        stats = {
            "total_runs": len(df),
            "avg_cpu": int(df['cpu_usage_percent'].mean()) if 'cpu_usage_percent' in df else 0,
            "avg_mem": int(df['memory_peak_kb'].mean()) if 'memory_peak_kb' in df else 0,
            "violations": df['exit_reason'].value_counts().to_dict(),
            "runs": enriched_runs
        }
        return jsonify(stats)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

