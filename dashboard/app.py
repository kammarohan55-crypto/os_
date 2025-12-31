from flask import Flask, render_template, jsonify
import os
import json
import glob
import pandas as pd
import time

app = Flask(__name__)

LOG_DIR = "../logs"

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
        df = pd.DataFrame(data)
        
        if df.empty:
            return jsonify({
                "total_runs": 0,
                "avg_cpu": 0,
                "avg_mem": 0,
                "violations": {},
                "runs": []
            })
            
        stats = {
            "total_runs": len(df),
            "avg_cpu": int(df['cpu_usage_percent'].mean()) if 'cpu_usage_percent' in df else 0,
            "avg_mem": int(df['memory_peak_kb'].mean()) if 'memory_peak_kb' in df else 0,
            "violations": df['exit_reason'].value_counts().to_dict(),
            "runs": data[:50] # Return latest 50
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
