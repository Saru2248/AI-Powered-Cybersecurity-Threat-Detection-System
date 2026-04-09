import os
import subprocess
import pandas as pd
from flask import Flask, render_template, jsonify, send_from_directory

app = Flask(__name__)

# Paths
BASE_DIR = os.path.dirname(__file__)
OUTPUTS_DIR = os.path.join(BASE_DIR, 'outputs')
RESULTS_CSV = os.path.join(OUTPUTS_DIR, 'live_detection.csv')
MAIN_RESULTS_CSV = os.path.join(OUTPUTS_DIR, 'detection_results.csv')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/run_pipeline', methods=['POST'])
def run_pipeline():
    try:
        # Run main.py full pipeline
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        process = subprocess.run(['python', 'main.py'], cwd=BASE_DIR, env=env, capture_output=True, text=True)
        
        # Also run generate_rf_plots.py to ensure Random Forest plots are explicitly generated
        subprocess.run(['python', 'generate_rf_plots.py'], cwd=BASE_DIR, env=env, capture_output=True, text=True)
        
        if process.returncode != 0:
            return jsonify({"error": "Pipeline failed", "details": process.stderr}), 500
            
        return jsonify({"success": True, "message": "Pipeline completed successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/run_detection', methods=['POST'])
def run_detection():
    try:
        # Run detect-only with 50 events
        env = os.environ.copy()
        env['PYTHONIOENCODING'] = 'utf-8'
        process = subprocess.run(['python', 'main.py', '--mode', 'detect', '--events', '50'], cwd=BASE_DIR, env=env, capture_output=True, text=True)
        
        if process.returncode != 0:
            return jsonify({"error": "Detection failed. Did you train the models first?", "details": process.stderr}), 500
            
        return jsonify({"success": True, "message": "Detection simulation completed!"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/results')
def get_results():
    # Try live_detection.csv first, fallback to detection_results.csv
    csv_to_load = RESULTS_CSV if os.path.exists(RESULTS_CSV) else MAIN_RESULTS_CSV
    
    if not os.path.exists(csv_to_load):
        return jsonify({
            "summary": {"total_events": 0, "threats_detected": 0, "normal_events": 0, "breakdown": {}},
            "alerts": []
        })
        
    try:
        df = pd.read_csv(csv_to_load)
        
        # Summary stats
        total_events = len(df)
        threats_detected = len(df[df['is_threat'] == True])
        normal_events = total_events - threats_detected
        
        # Breakdown
        breakdown = df[df['is_threat'] == True]['threat_type'].value_counts().to_dict()
        
        # Latest alerts
        latest_alerts = df.tail(50).fillna("").to_dict('records')
        
        return jsonify({
            "summary": {
                "total_events": total_events,
                "threats_detected": threats_detected,
                "normal_events": normal_events,
                "breakdown": breakdown
            },
            "alerts": latest_alerts
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/outputs/<path:filename>')
def custom_static(filename):
    return send_from_directory(OUTPUTS_DIR, filename)

if __name__ == '__main__':
    print("Starting AI Threat Detection Dashboard on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
