import os
import google.generativeai as genai
import glob
import subprocess
from pylint import lint
from pylint.reporters.text import TextReporter
from io import StringIO
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Retrieve the API key from the environment
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')


# Run Bandit security analysis with error handling
def run_bandit(repo_path):
    try:
        command = f"bandit -r {repo_path} -f json"
        result = subprocess.run(command.split(), capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running Bandit: {str(e)}")
    except FileNotFoundError as e:
        print(f"Bandit command not found: {str(e)}")
    except Exception as e:
        print(f"Unexpected error during Bandit analysis: {str(e)}")
    return None


# Run Pylint analysis with error handling
def run_pylint(repo_path):
    try:
        python_files = glob.glob(f"{repo_path}/**/*.py", recursive=True)
        pylint_scores = {}
        for file in python_files:
            try:
                pylint_output = StringIO()
                reporter = TextReporter(pylint_output)
                lint.Run([file], reporter=reporter, exit=False)
                output = pylint_output.getvalue()
                score_line = [line for line in output.split("\n") if line.startswith("Your code has been rated at")]
                if score_line:
                    score = float(score_line[0].split()[6].split("/")[0])
                    pylint_scores[file] = score
            except Exception as e:
                print(f"Error running Pylint on {file}: {str(e)}")
        return pylint_scores
    except Exception as e:
        print(f"Error during Pylint analysis: {str(e)}")
        return {}


# AI code analysis using Gemini API with error handling
def ai_code_analysis_gemini(code_snippet):
    genai.configure(api_key=GOOGLE_API_KEY)
    generation_config = {
        "temperature": 0.3,
        "max_output_tokens": 250,
        "response_mime_type": "text/plain",
    }
    
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        prompt = f"""
        Analyze the following code snippet and provide brief, point-wise suggestions for improvement:

        Code Snippet (limit to first 1024 characters):
        {code_snippet[:1024]}

        Please focus on the following:
        1. Highlight potential issues or vulnerabilities.
        2. Provide specific suggestions for improvement in a brief, point-wise format.

        Keep the analysis concise and avoid unnecessary details.
        """
        
        response = model.generate_content(
            prompt,
            generation_config=generation_config
        )
        
        if response and response.text:
            return response.text
        else:
            print("No valid response from Gemini API")
            return None
    except Exception as e:
        print(f"Failed to call Gemini API: {e}")
        return None


# Extract suggestions from AI analysis
def extract_suggestions_with_gemini(analysis):
    suggestions = []
    if analysis:
        suggestions = [line.strip() for line in analysis.split('\n') if line.strip() and line[0].isdigit()]
    return suggestions


# Analyze files with AI, with error handling for file access issues
def analyze_files_with_ai(repo_path):
    python_files = glob.glob(f"{repo_path}/**/*.py", recursive=True)
    ai_issues = []
    
    for file in python_files:
        try:
            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
                
                analysis = ai_code_analysis_gemini(code)
                if analysis:
                    suggestions = extract_suggestions_with_gemini(analysis)
                    ai_issues.append({
                        "file": file,
                        "analysis": analysis,
                        "suggestions": suggestions
                    })
        except (UnicodeDecodeError, FileNotFoundError) as e:
            print(f"Skipping file {file} due to read error: {str(e)}")
        except Exception as e:
            print(f"Unexpected error while analyzing {file}: {str(e)}")
    
    return ai_issues
