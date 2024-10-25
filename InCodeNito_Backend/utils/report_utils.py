import json
import logging

logging.basicConfig(level=logging.INFO)

# Function to categorize Bandit results
def categorize_bandit_issues(bandit_results):
    bandit_data = json.loads(bandit_results)
    issue_counts = {"high": 0, "medium": 0, "low": 0}
    for issue in bandit_data.get("results", []):
        severity = issue["issue_severity"].lower()
        if severity in issue_counts:
            issue_counts[severity] += 1
    return issue_counts


def restructure_report(report_data):
    restructured_report = {
        "summary": report_data["summary"],
        "details": report_data["details"],
        "final_report": {}
    }

    # Create a dictionary to store vulnerable lines for each file
    vulnerable_lines = {}
    for result in report_data["details"]["bandit"]["results"]:
        file_name = result["filename"]
        if file_name not in vulnerable_lines:
            vulnerable_lines[file_name] = []
        vulnerable_lines[file_name].append({
            "line_number": result["line_number"],
            "code": result["code"],  # Use the entire code snippet
            "issue": result["issue_text"],
            "severity": result["issue_severity"]
        })

    # Create a mapping between file names and numerical IDs
    file_id_mapping = {file: f"{i+1}" for i, file in enumerate(set(file_analysis["file"] for file_analysis in report_data["details"]["ai_analysis"]))}

    # Process each file in the AI analysis
    for file_analysis in report_data["details"]["ai_analysis"]:
        file_name = file_analysis["file"]
        file_id = file_id_mapping[file_name]
        
        # Extract suggestions from both the 'suggestions' field and the 'analysis' text
        suggestions = file_analysis.get("suggestions", [])
        
        # If suggestions are empty, try to extract them from the analysis text
        if not suggestions:
            analysis_text = file_analysis["analysis"]
            suggestions_section = analysis_text.split("**2. Suggestions for Improvement:**")
            if len(suggestions_section) > 1:
                suggestions_text = suggestions_section[1]
                # Extract bullet points as suggestions
                suggestions = [s.strip().strip('*') for s in suggestions_text.split('\n') if s.strip().startswith('*')]

        # Check for vulnerable lines, add a message if none are detected
        if not vulnerable_lines.get(file_name):
            vulnerable_lines[file_name] = "No vulnerable code lines detected"

        restructured_report["final_report"][file_id] = {
            "file_name": file_name,
            "file_pylint_score": report_data["details"]["pylint"].get(file_name, "N/A"),
            "file_analysis": file_analysis["analysis"],
            "file_suggestions": suggestions,
            "vulnerable_lines_in_file": vulnerable_lines.get(file_name)
        }

    # Add file_id_mapping to the restructured report
    restructured_report["file_id_mapping"] = {v: k for k, v in file_id_mapping.items()}

    return restructured_report


def generate_json_report(bandit_results, pylint_results, ai_analysis_results):
    try:
        bandit_data = json.loads(bandit_results)
        bandit_summary = {
            "high": sum(1 for r in bandit_data.get("results", []) if r.get("issue_severity", "").lower() == "high"),
            "medium": sum(1 for r in bandit_data.get("results", []) if r.get("issue_severity", "").lower() == "medium"),
            "low": sum(1 for r in bandit_data.get("results", []) if r.get("issue_severity", "").lower() == "low")
        }
    except json.JSONDecodeError:
        logging.error("Error decoding Bandit results. Using empty summary.")
        bandit_summary = {"high": 0, "medium": 0, "low": 0}
        bandit_data = {"results": []}

    if not isinstance(pylint_results, dict):
        logging.warning("Pylint results are not in the expected format. Using empty dictionary.")
        pylint_results = {}

    pylint_scores = [score for score in pylint_results.values() if isinstance(score, (int, float))]
    pylint_average_score = sum(pylint_scores) / len(pylint_scores) if pylint_scores else 0.0
    
    if not isinstance(ai_analysis_results, list):
        logging.warning("AI analysis results are not in the expected format. Using empty list.")
        ai_analysis_results = []

    report_data = {
        "summary": {
            "bandit_issues": bandit_summary,
            "pylint_average_score": pylint_average_score,
            "ai_issues_found": len(ai_analysis_results)
        },
        "details": {
            "bandit": bandit_data,
            "pylint": pylint_results,
            "ai_analysis": ai_analysis_results
        }
    }
    
    # Call the restructure_report function to get the restructured report
    restructured_report = restructure_report(report_data)

    # Return the restructured report instead of writing to a file
    return restructured_report
