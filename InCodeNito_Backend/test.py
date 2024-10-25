from flask import Flask, request, jsonify, g
from flask_cors import CORS
from utils.analysis import run_bandit, run_pylint, analyze_files_with_ai
from utils.report_utils import generate_json_report
from utils.git_utils import clone_repository
from firebase_service import authenticate, save_report, get_reports, verify_google_token, get_or_create_user, db, update_user_company, get_report_by_id

app = Flask(__name__)
CORS(app)

@app.route('/login', methods=['POST'])
def login():
    id_token = request.json.get('id_token')
    
    if not id_token:
        return jsonify({"error": "ID token is required"}), 400
    
    try:
        decoded_token = verify_google_token(id_token)
        user_data, is_new_user = get_or_create_user(decoded_token)
        return jsonify({
            "message": "Login successful",
            "user": user_data,
            "is_new_user": is_new_user,
            "user_exists": not is_new_user
        }), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 401

@app.route('/update_company', methods=['POST'])
@authenticate
def update_company():
    company = request.json.get('company')
    
    if not company:
        return jsonify({"error": "Company name is required"}), 400
    
    try:
        update_user_company(g.user_id, company)
        return jsonify({"message": "Company name updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scan_repo', methods=['POST'])
@authenticate
def scan_repo():
    repo_url = request.json.get('repo_url')
    
    if not repo_url:
        return jsonify({"error": "Repository URL is required"}), 400
    
    try:
        repo_path = clone_repository(repo_url)
        
        bandit_results = run_bandit(repo_path)
        pylint_results = run_pylint(repo_path)
        ai_analysis_results = analyze_files_with_ai(repo_path)
        
        report = generate_json_report(bandit_results, pylint_results, ai_analysis_results)
        report['repo_url'] = repo_url
        
        report_id = save_report(g.user_id, report)
        
        return jsonify({
            "message": "Scan successful",
            "report_id": report_id,
            "report": report
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_reports', methods=['GET'])
@authenticate
def get_user_reports():
    try:
        reports = get_reports(g.user_id)  # Assuming g.user_id has the authenticated user's ID
        return jsonify({
            "reports": [
                {"id": report["id"], "repo_url": report["data"]["repo_url"]}
                for report in reports
            ]
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_report/<report_id>', methods=['GET'])
@authenticate
def get_specific_report(report_id):
    try:
        report = get_report_by_id(g.user_id, report_id)
        if report:
            return jsonify({"report": report}), 200
        else:
            return jsonify({"error": "Report not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)