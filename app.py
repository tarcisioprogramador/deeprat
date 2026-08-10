from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import requests

from modules.password_analyzer import PasswordAnalyzer
from modules.command_generator import CommandGenerator
from modules.vuln_analyzer import VulnerabilityAnalyzer
from modules.exploitation import ExploitationModule
from modules.brute_force import BruteForceModule
from modules.web_scanner import WebScanner

app = Flask(__name__)
CORS(app)

HF_API_URL = "https://router.huggingface.co/v1"
HF_TOKEN = None

password_analyzer = PasswordAnalyzer()
command_generator = CommandGenerator()
vuln_analyzer = VulnerabilityAnalyzer()
exploitation_module = ExploitationModule()
brute_force = BruteForceModule()
web_scanner = WebScanner()

def authenticate(token):
    global HF_TOKEN
    HF_TOKEN = token
    return {"status": "ok", "message": "Conectado ao Hugging Face"}

def hf_chat(prompt):
    headers = {"Authorization": f"Bearer {HF_TOKEN}"}
    data = {
        "model": "DeepHat/DeepHat-V1-7B:featherless-ai",
        "messages": [
            {"role": "system", "content": "Você é DeepHat, um modelo de IA especializado em cibersegurança e DevOps. Responda em português."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 1024,
        "temperature": 0.7
    }
    response = requests.post(f"{HF_API_URL}/chat/completions", json=data, headers=headers)
    return response.json()

@app.route('/auth', methods=['POST'])
def auth():
    data = request.json
    token = data.get('api_key')
    if not token:
        return jsonify({'error': 'Token required'}), 400
    try:
        result = authenticate(token)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    prompt = data.get('prompt')
    if not prompt:
        return jsonify({'error': 'prompt required'}), 400
    if not HF_TOKEN:
        return jsonify({'error': 'Token não configurado. Use /auth primeiro.'}), 401
    try:
        result = hf_chat(prompt)
        if "choices" in result:
            response = result["choices"][0]["message"]["content"]
            return jsonify({'response': response})
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analyze/password', methods=['POST'])
def analyze_password():
    data = request.json
    password = data.get('password')
    if not password:
        return jsonify({'error': 'Password is required'}), 400
    result = password_analyzer.analyze_strength(password)
    return jsonify(result)

@app.route('/generate/wordlist', methods=['POST'])
def generate_wordlist():
    data = request.json
    base_word = data.get('base_word')
    modes = data.get('modes', ['leetspeak', 'case', 'append'])
    if not base_word:
        return jsonify({'error': 'base_word is required'}), 400
    wordlist = password_analyzer.generate_wordlist(base_word, modes)
    return jsonify({'base_word': base_word, 'total_words': len(wordlist), 'wordlist': wordlist})

@app.route('/generate/command', methods=['POST'])
def generate_command():
    data = request.json
    tool = data.get('tool')
    action = data.get('action')
    params = data.get('params', {})
    if not tool or not action:
        return jsonify({'error': 'tool and action are required'}), 400
    if tool == 'nmap':
        result = command_generator.generate_nmap(action, params.get('target'))
    elif tool == 'metasploit':
        result = command_generator.generate_metasploit(action, **params)
    elif tool == 'shell':
        result = command_generator.generate_shell(action, params.get('lhost'), params.get('lport'))
    elif tool == 'hydra':
        result = command_generator.generate_hydra(action, params.get('target'), params.get('username'), params.get('wordlist'))
    elif tool == 'sqlmap':
        result = command_generator.generate_sqlmap(action, params.get('url'), **params)
    else:
        return jsonify({'error': f'Tool not found: {tool}'}), 400
    return jsonify(result)

@app.route('/analyze/vulnerability', methods=['POST'])
def analyze_vulnerability():
    data = request.json
    action = data.get('action')
    if action == 'analyze_service':
        result = vuln_analyzer.analyze_service(data.get('port'), data.get('service'), data.get('version'))
    elif action == 'analyze_target':
        result = vuln_analyzer.analyze_target(data.get('target_info', {}))
    elif action == 'get_info':
        result = vuln_analyzer.get_vulnerability_info(data.get('vuln_name'))
    elif action == 'list':
        result = vuln_analyzer.list_vulnerabilities()
    else:
        return jsonify({'error': f'Action not found: {action}'}), 400
    return jsonify(result)

@app.route('/exploit/privilege-escalation', methods=['POST'])
def privilege_escalation():
    data = request.json
    os_type = data.get('os', 'linux')
    result = exploitation_module.get_priv_esc_techniques(os_type)
    return jsonify(result)

@app.route('/exploit/post-exploitation', methods=['POST'])
def post_exploitation():
    data = request.json
    phase = data.get('phase')
    os_type = data.get('os', 'linux')
    if not phase:
        return jsonify({'error': 'phase is required'}), 400
    result = exploitation_module.get_post_exploitation(phase, os_type)
    return jsonify({'techniques': result})

@app.route('/exploit/anti-forensics', methods=['POST'])
def anti_forensics():
    data = request.json
    os_type = data.get('os', 'linux')
    result = exploitation_module.get_anti_forensics(os_type)
    return jsonify({'techniques': result})

@app.route('/exploit/payload', methods=['POST'])
def generate_payload():
    data = request.json
    payload_type = data.get('payload_type')
    options = data.get('options', {})
    if not payload_type:
        return jsonify({'error': 'payload_type is required'}), 400
    result = exploitation_module.generate_payload(payload_type, options)
    return jsonify({'command': result})

@app.route('/brute/wordlist', methods=['POST'])
def generate_brute_wordlist():
    data = request.json
    base_words = data.get('base_words', ['admin', 'root', 'user'])
    modes = data.get('modes', ['numbers', 'symbols', 'years'])
    wordlist = brute_force.generate_wordlist(base_words, modes)
    return jsonify({'total': len(wordlist), 'wordlist': wordlist[:1000]})

@app.route('/brute/hydra', methods=['POST'])
def generate_hydra():
    data = request.json
    target = data.get('target')
    service = data.get('service')
    username = data.get('username')
    wordlist = data.get('wordlist')
    port = data.get('port')
    if not target or not service:
        return jsonify({'error': 'target and service required'}), 400
    result = brute_force.generate_hydra_command(target, service, username, wordlist, port)
    return jsonify(result)

@app.route('/brute/services', methods=['GET'])
def list_brute_services():
    return jsonify(brute_force.list_services())

@app.route('/scan/web', methods=['POST'])
def scan_web():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({'error': 'url required'}), 400
    result = web_scanner.scan(url)
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

@app.route('/')
def index():
    return send_file('index.html')

if __name__ == '__main__':
    print("Iniciando Pentest Tools API...")
    print("API rodando em http://localhost:5000")
    app.run(debug=True, host='0.0.0.0')
