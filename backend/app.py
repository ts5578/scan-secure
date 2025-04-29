from flask import Flask, request, jsonify, session, redirect, url_for
from flask_cors import CORS
from werkzeug.utils import secure_filename
import os
import tempfile
import requests
from github import Github
import google.generativeai as genai
import torch
from transformers import RobertaTokenizer, RobertaForSequenceClassification
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

app.config.update(
    SECRET_KEY=os.getenv('FLASK_SECRET_KEY'),
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_HTTPONLY=True,
    PERMANENT_SESSION_LIFETIME=3600,
    SESSION_REFRESH_EACH_REQUEST=True
)

# Configuration
UPLOAD_FOLDER = tempfile.mkdtemp()
ALLOWED_EXTENSIONS = {'py', 'js', 'java', 'c', 'cpp', 'go', 'php', 'rb', 'ts','html'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# GitHub OAuth Config
GITHUB_CLIENT_ID = os.getenv('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.getenv('GITHUB_CLIENT_SECRET')
GITHUB_REDIRECT_URI = os.getenv('GITHUB_REDIRECT_URI')

# Gemini Config
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY')
genai.configure(api_key=GEMINI_API_KEY)
gemini_model = genai.GenerativeModel('models/gemini-1.5-flash-latest')

# Load CodeBERT model
model_path = './models/codebert_vuln_detector'
tokenizer = RobertaTokenizer.from_pretrained(model_path)
codebert_model = RobertaForSequenceClassification.from_pretrained(model_path)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def check_safe_with_gemini(code_snippet):
    prompt = f"""Analyze the following code snippet for vulnerabilities: buffer overflow, SQL injection, and cross-site scripting (XSS).
    If the code is safe, return 'SAFE'. Otherwise, return 'UNSAFE'.\n\n{code_snippet}"""

    try:
        response = gemini_model.generate_content(prompt)
        result = response.text.strip()
        return result
    except Exception as e:
        print(f"Error calling Gemini API: {e}")
        return "UNSAFE"

def predict_vulnerability_with_codebert(code_snippet):
    inputs = tokenizer(code_snippet, return_tensors="pt", padding=True, truncation=True)
    outputs = codebert_model(**inputs)
    prediction = torch.argmax(outputs.logits, dim=1).item()

    label_map = {0: "Cross-Site Scripting (XSS)", 1: "Buffer Overflow", 2: "SQL Injection"}
    return label_map.get(prediction, "Unknown Vulnerability")

@app.route('/analyze', methods=['POST'])
def analyze_code():
    if 'file' in request.files:
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            with open(filepath, 'r') as f:
                code_snippet = f.read()
            
            os.remove(filepath)
            return analyze_code_snippet(code_snippet)
    
    elif 'code' in request.json:
        code_snippet = request.json['code']
        return analyze_code_snippet(code_snippet)
    
    elif 'github_url' in request.json:
        if 'github_token' not in session:
            return jsonify({'error': 'Not authenticated with GitHub'}), 401
            
        try:
            g = Github(session['github_token'])
            repo_url = request.json['github_url']
            
            if not repo_url.startswith('https://github.com/'):
                return jsonify({'error': 'Invalid GitHub URL format'}), 400
                
            parts = repo_url.replace('https://github.com/', '').split('/')
            if len(parts) < 2:
                return jsonify({'error': 'Invalid repository path'}), 400
                
            repo = g.get_repo(f"{parts[0]}/{parts[1]}")
            results = []
            scanned_files = 0
            
            def scan_contents(contents):
                nonlocal scanned_files
                for content in contents:
                    try:
                        if content.type == "dir":
                            scan_contents(repo.get_contents(content.path))
                        else:
                            # Get file extension properly, even with multiple dots
                            filename_parts = content.name.split('.')
                            if len(filename_parts) > 1:
                                file_ext = filename_parts[-1].lower()
                                if file_ext in ALLOWED_EXTENSIONS:
                                    file_content = content.decoded_content.decode('utf-8')
                                    analysis = analyze_code_snippet(file_content).get_json()
                                    results.append({
                                        'file': content.path,
                                        'result': analysis['result'],
                                        'vulnerability': analysis.get('vulnerability'),
                                        'code_snippet': file_content[:500] + '...' if len(file_content) > 500 else file_content
                                    })
                                    scanned_files += 1
                    except Exception as e:
                        results.append({
                            'file': content.path if hasattr(content, 'path') else 'unknown',
                            'result': f"Error processing: {str(e)}",
                            'error': True
                        })
            
            scan_contents(repo.get_contents(""))
            
            if scanned_files == 0:
                return jsonify({'error': 'No supported files found in repository', 'details': f"Allowed extensions: {ALLOWED_EXTENSIONS}"}), 400
            
            return jsonify({
                'results': results,
                'summary': {
                    'total_files': scanned_files,
                    'vulnerable_files': len([r for r in results if 'vulnerability' in r]),
                    'scan_status': 'complete'
                }
            })
            
        except Exception as e:
            return jsonify({'error': f"Repository scan failed: {str(e)}"}), 500
    
    return jsonify({'error': 'No valid input provided'}), 400

def analyze_code_snippet(code_snippet):
    gemini_result = check_safe_with_gemini(code_snippet)
    
    if gemini_result == "SAFE":
        return jsonify({'result': 'Code is safe. No vulnerabilities detected.'})
    
    vulnerability = predict_vulnerability_with_codebert(code_snippet)
    return jsonify({
        'result': f"Potential Vulnerability Detected: {vulnerability}",
        'vulnerability': vulnerability,
        'code_snippet': code_snippet[:500] + '...' if len(code_snippet) > 500 else code_snippet
    })

# GitHub OAuth Routes
@app.route('/github/login')
def github_login():
    return redirect(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&redirect_uri={GITHUB_REDIRECT_URI}&scope=repo")

@app.route('/github/callback')
def github_callback():
    code = request.args.get('code')
    if not code:
        return jsonify({'error': 'Authorization failed: no code'}), 400

    try:
        response = requests.post(
            'https://github.com/login/oauth/access_token',
            json={
                'client_id': GITHUB_CLIENT_ID,
                'client_secret': GITHUB_CLIENT_SECRET,
                'code': code,
                'redirect_uri': GITHUB_REDIRECT_URI
            },
            headers={'Accept': 'application/json'},
            timeout=10
        )
        
        if response.status_code != 200:
            return jsonify({'error': 'GitHub token exchange failed'}), 401
            
        data = response.json()
        if 'access_token' not in data:
            return jsonify({'error': 'Missing access token'}), 401
        
        session.clear()
        session['github_token'] = data['access_token']
        session.permanent = True
        
        return redirect('http://localhost:3000')
        
    except Exception as e:
        return jsonify({'error': f"Auth error: {str(e)}"}), 500
    
@app.route('/github/repos', methods=['GET'])
def get_github_repos():
    if 'github_token' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        g = Github(session['github_token'])
        repos = [{
            'name': repo.name,
            'full_name': repo.full_name,
            'private': repo.private,
            'html_url': repo.html_url
        } for repo in g.get_user().get_repos()]
        
        return jsonify({'repos': repos})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/github/logout')
def github_logout():
    session.pop('github_token', None)
    return jsonify({'status': 'logged out'})

@app.route('/github/status')
def github_status():
    return jsonify({'authenticated': 'github_token' in session})

if __name__ == '__main__':
    app.run(debug=True, port=5000)