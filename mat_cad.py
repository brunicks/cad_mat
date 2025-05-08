from flask import Flask, render_template, request, make_response, jsonify, send_file, redirect, session, url_for
import datetime
import csv
import io
import os
import pandas as pd
import requests
import logging
import base64
import json
import sys
from logging.handlers import RotatingFileHandler
from functools import wraps

# Configuração simplificada do sistema de logs
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
log_dir = os.path.join(BASE_DIR, 'logs')
os.makedirs(log_dir, exist_ok=True)

# Configurar um único logger para a aplicação
logger = logging.getLogger('mat_cad')
logger.setLevel(logging.DEBUG)

# Um único formato para todos os logs
log_format = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] - %(message)s')

# Arquivo de log único com rotação
file_handler = RotatingFileHandler(
    os.path.join(log_dir, 'application.log'),
    maxBytes=5*1024*1024,  # 5MB
    backupCount=5
)
file_handler.setFormatter(log_format)
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)

# Handler para console
console_handler = logging.StreamHandler()
console_handler.setFormatter(log_format)
console_handler.setLevel(logging.DEBUG)
logger.addHandler(console_handler)

# Evitar propagação para o logger raiz
logger.propagate = False

# Helper simples para serializar objetos JSON para logging
def safe_json_dumps(data):
    try:
        return json.dumps(data, default=lambda o: list(o) if isinstance(o, set) else str(o))
    except:
        return str(data)

# Configuração da aplicação Flask
app = Flask(__name__, static_folder='static')
app.secret_key = 'sysmex_material_cadastro_secret_key'

# Adicionar log de inicialização da aplicação
logger.info("=== Inicializando aplicação Sistema de Cadastro de Materiais ===")

# Constantes da API
SYSMEX_API_BASE_URL = "http://customer-API.qa.sysmexamerica.com/api"
APP_ID = "b51bc34c-52bd-4678-9e08-1580b58c1a79"

# Função para obter token da aplicação
def get_app_token():
    """Obtém token da aplicação via API"""
    try:
        logger.debug("Tentando obter token da aplicação")
        
        url = f"{SYSMEX_API_BASE_URL}/Usuario/TokenApp"
        headers = {'Content-Type': 'application/json-patch+json'}
        
        # Enviar apenas o app_id entre aspas como corpo da requisição
        data = f'"{APP_ID}"'
        
        logger.debug(f"Request para {url}")
        
        response = requests.post(url, data=data, headers=headers)
        
        logger.debug(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            if data.get('result') == True:
                logger.info("Token de aplicação obtido com sucesso")
                return data.get('token')
            else:
                logger.error(f"API retornou falha: {data}")
                return None
        else:
            logger.error(f"Erro ao obter token: Status {response.status_code}")
            return None
    except Exception as e:
        logger.exception(f"Erro ao obter token da aplicação: {str(e)}")
        return None

# Função para autenticar usuário
def authenticate_user(username, password):
    """Autentica usuário com Sysmex API"""
    try:
        logger.debug(f"Tentando autenticar usuário: {username}")
        
        # Gerar credenciais em base64
        credentials = f"{username}:{password}"
        credentials_bytes = credentials.encode('ascii')
        base64_credentials = base64.b64encode(credentials_bytes).decode('ascii')
        
        # Obter token da aplicação
        app_token = get_app_token()
        if not app_token:
            logger.error("Falha ao obter token de aplicação")
            return None, "Erro ao obter token da aplicação"
        
        # Request de login
        url = f"{SYSMEX_API_BASE_URL}/Usuario/Login"
        headers = {
            'Authorization': f"Bearer {app_token}",
            'Content-Type': 'application/json-patch+json'
        }
        
        data = f'"{base64_credentials}"'
        
        logger.debug(f"Request para {url}")
        
        response = requests.post(url, data=data, headers=headers)
        logger.debug(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            user_data = response.json()
            
            # Verificar se o resultado é verdadeiro
            if not user_data.get('result', False):
                logger.error("API retornou falha na autenticação")
                return None, "Falha na autenticação. Verifique suas credenciais."
            
            # Verificar se é um email Sysmex
            user_email = user_data.get('usuario', {}).get('email', '')
            if '@sysmex.com' not in user_email:
                logger.warning(f"Tentativa de login com email não autorizado: {user_email}")
                return None, "Usuário não autorizado. Apenas emails Sysmex são permitidos."
            
            # Estrutura correta do objeto de usuário 
            user_info = {
                'token': user_data.get('token'),
                'user': {
                    'email': user_email,
                    'nome': user_data.get('usuario', {}).get('nome', 'Usuário')
                }
            }
            
            logger.info(f"Usuário autenticado com sucesso: {user_email}")
            return user_info, None
        else:
            logger.error(f"Falha na autenticação: Status {response.status_code}")
            return None, "Credenciais inválidas"
    except Exception as e:
        logger.exception(f"Erro durante autenticação: {str(e)}")
        return None, f"Erro de autenticação: {str(e)}"

# Decorator para rotas protegidas            
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            logger.warning("Tentativa de acesso a rota protegida sem autenticação")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Rotas da aplicação
@app.route('/')
@login_required
def index():
    logger.debug("Acessando a página inicial")
    return render_template('index.html', user_name=session.get('user_name'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    logger.debug("Acessando a página de login")
    if 'user_email' in session:
        logger.debug("Usuário já autenticado, redirecionando para a página inicial")
        return redirect(url_for('index'))
        
    error = None
    if request.method == 'POST':
        logger.debug("Processando requisição de login")
        
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            logger.warning("Tentativa de login sem usuário ou senha")
            error = "Por favor, informe usuário e senha."
            return render_template('login.html', error=error)
        
        user_data, auth_error = authenticate_user(username, password)
        
        if user_data:
            # Salvar dados do usuário na sessão
            logger.info(f"Login bem-sucedido para {username}")
            session['user_token'] = user_data['token']
            session['user_name'] = user_data['user'].get('nome', 'Usuário')
            session['user_email'] = user_data['user'].get('email', '')
            
            # Redirecionar para a página solicitada ou para a página inicial
            next_page = request.args.get('next', url_for('index'))
            return redirect(next_page)
        else:
            logger.warning(f"Falha no login para {username}: {auth_error}")
            error = auth_error or "Erro de autenticação desconhecido."
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    logger.debug("Processando logout")
    session.clear()
    return redirect(url_for('login'))

@app.route('/check_auth')
def check_auth():
    if 'user_email' in session:
        logger.debug("Verificação de autenticação: usuário autenticado")
        return jsonify({'authenticated': True, 'user': session.get('user_name')})
    logger.debug("Verificação de autenticação: usuário não autenticado")
    return jsonify({'authenticated': False})

@app.route('/download_template', methods=['GET'])
@login_required
def download_template():
    try:
        logger.debug("Gerando template CSV para download")
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output, delimiter=';', quoting=csv.QUOTE_MINIMAL)
        
        # Write header with instructions
        writer.writerow(['INSTRUÇÕES:'])
        writer.writerow(['1. Preencha as colunas abaixo com os dados dos materiais'])
        writer.writerow(['2. Para marcar um material como bloqueado, escreva "X" na coluna "Bloqueio"'])
        writer.writerow(['3. Deixe a coluna "Bloqueio" vazia para materiais não bloqueados'])
        writer.writerow(['4. Não altere a ordem ou remova as colunas'])
        writer.writerow(['5. Salve o arquivo e faça o upload na plataforma'])
        writer.writerow([])  # Empty row for separation
        
        # Write actual template header
        writer.writerow(['Código Material', 'Descrição Material', 'Bloqueio'])
        
        # Write example row
        writer.writerow(['123456', 'Exemplo de Material', 'X'])
        writer.writerow(['789012', 'Exemplo sem bloqueio', ''])
        
        # Prepare response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename=template_materiais.csv'
        response.headers['Content-type'] = 'text/csv'
        
        logger.info("Template CSV gerado com sucesso")
        return response
    except Exception as e:
        logger.exception(f"Erro ao gerar template CSV: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/upload_csv', methods=['POST'])
@login_required
def upload_csv():
    try:
        logger.debug("Processando upload de CSV")
        
        if 'file' not in request.files:
            logger.warning("Upload CSV: nenhum arquivo enviado")
            return jsonify({'error': 'Nenhum arquivo enviado'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            logger.warning("Upload CSV: nome de arquivo vazio")
            return jsonify({'error': 'Nenhum arquivo selecionado'}), 400
            
        if not file.filename.endswith('.csv'):
            logger.warning("Upload CSV: tipo de arquivo inválido")
            return jsonify({'error': 'Arquivo deve ser do tipo CSV'}), 400
        
        # Read CSV file
        stream = io.StringIO(file.stream.read().decode('utf-8'))
        df = pd.read_csv(stream, delimiter=';', skiprows=7)  # Skip the instruction rows
        
        logger.debug(f"CSV lido com sucesso: {len(df)} linhas encontradas")
        
        # Process materials
        materials = []
        for _, row in df.iterrows():
            if pd.notna(row['Código Material']) and pd.notna(row['Descrição Material']):
                material = {
                    'code': str(row['Código Material']).strip(),
                    'description': str(row['Descrição Material']).strip(),
                    'blocked': str(row.get('Bloqueio', '')).strip().upper() == 'X'
                }
                materials.append(material)
        
        logger.info(f"CSV processado: {len(materials)} materiais válidos extraídos")
        return jsonify({'success': True, 'materials': materials, 'count': len(materials)})
    except Exception as e:
        logger.exception(f"Erro ao processar CSV: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/generate_csv', methods=['POST'])
@login_required
def generate_csv():
    try:
        logger.debug("Gerando CSV com materiais")
        
        # Get data from request
        data = request.json
        materials = data.get('materials', [])
        
        logger.debug(f"Gerando CSV com {len(materials)} materiais")
        
        # Create timestamp for filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"MAT_{timestamp}.csv"
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output, delimiter=';', quoting=csv.QUOTE_MINIMAL)
        
        # Write header
        writer.writerow([
            'Grupo Mat.', 'Descr.Grupo', 'Descr.SubG', 'Cód. Material',
            'Tipo Material', 'Unidade Medida', 'Descrição Material', 'Cód. Bloqueio'
        ])
        
        # Write materials
        for material in materials:
            writer.writerow([
                '0050000300',
                'Serviços de Manutenção',
                'Peças',
                material['code'],
                'FERT',
                'EA',
                material['description'],
                'X' if material['blocked'] else ''
            ])
        
        # Prepare response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Disposition'] = f'attachment; filename={filename}'
        response.headers['Content-type'] = 'text/csv'
        
        logger.info(f"CSV {filename} gerado com sucesso com {len(materials)} materiais")
        return response
    except Exception as e:
        logger.exception(f"Erro ao gerar CSV: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def page_not_found(e):
    logger.warning(f"Página não encontrada: {request.path}")
    return render_template('login.html', error="Página não encontrada"), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Erro interno do servidor: {str(e)}")
    return render_template('login.html', error="Erro interno do servidor"), 500

# Rota para criar o arquivo de template se não existir
@app.route('/create_template', methods=['GET'])
def create_template():
    try:
        # Create folders if they don't exist
        os.makedirs('templates', exist_ok=True)
        os.makedirs('static', exist_ok=True)
        os.makedirs('logs', exist_ok=True)
        
        logger.info("Diretórios criados/verificados com sucesso")
        
        # Copy the login.html template if it doesn't exist
        if not os.path.exists('templates/login.html'):
            with open('templates/login.html', 'w', encoding='utf-8') as f:
                f.write("""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Cadastro de materiais</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.2.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #0056b3;
            --secondary-color: #4a90e2;
            --accent-color: #28a745;
            --danger-color: #dc3545;
            --dark-color: #343a40;
            --light-color: #f8f9fa;
            --border-color: #dee2e6;
            --text-color: #333;
            --shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Roboto', sans-serif;
            background-color: #f4f7fa;
            color: var(--text-color);
            line-height: 1.6;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        
        .login-container {
            max-width: 420px;
            margin: auto;
            padding: 2rem;
            background-color: white;
            border-radius: 8px;
            box-shadow: var(--shadow);
        }
        
        .logo-container {
            text-align: center;
            margin-bottom: 2rem;
        }
        
        .logo {
            max-height: 120px;
            max-width: 100%;
        }
        
        h1 {
            text-align: center;
            color: var(--primary-color);
            margin-bottom: 1.5rem;
            font-weight: 500;
        }
        
        .form-group {
            margin-bottom: 1.2rem;
        }
        
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--dark-color);
        }
        
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 0.75rem;
            font-size: 1rem;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            transition: border-color 0.3s;
        }
        
        input[type="text"]:focus,
        input[type="password"]:focus {
            border-color: var(--secondary-color);
            outline: none;
            box-shadow: 0 0 0 3px rgba(74, 144, 226, 0.25);
        }
        
        .btn {
            display: block;
            width: 100%;
            font-weight: 500;
            text-align: center;
            white-space: nowrap;
            vertical-align: middle;
            user-select: none;
            border: 1px solid transparent;
            padding: 0.75rem 1.5rem;
            font-size: 1rem;
            line-height: 1.5;
            border-radius: 4px;
            transition: all 0.15s ease-in-out;
            cursor: pointer;
            background-color: var(--primary-color);
            color: white;
        }
        
        .btn:hover {
            background-color: #004494;
        }
        
        .error-message {
            color: var(--danger-color);
            background-color: rgba(220, 53, 69, 0.1);
            padding: 0.75rem;
            border-radius: 4px;
            margin-bottom: 1.2rem;
            font-size: 0.9rem;
        }
        
        footer {
            text-align: center;
            padding: 1rem 0;
            margin-top: auto;
            color: #6c757d;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo-container">
            <img src="/static/logo.png" alt="Logo da Sysmex" class="logo">
        </div>
        
        <h1>Cadastro de Materiais</h1>
        
        {% if error %}
        <div class="error-message">
            <i class="fas fa-exclamation-triangle"></i> {{ error }}
        </div>
        {% endif %}
        
        <form method="POST" action="{{ url_for('login') }}">
            <div class="form-group">
                <label for="username">Usuário</label>
                <input type="text" id="username" name="username" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Senha</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">
                <i class="fas fa-sign-in-alt"></i> Entrar
            </button>
        </form>
    </div>
    <footer>
        <p>&copy; 2025 Sysmex Brasil. Todos os direitos reservados.</p>
    </footer>
</body>
</html>""")
            logger.info("Template login.html criado")
        
        return jsonify({"success": True, "message": "Templates criados/verificados"})
        
    except Exception as e:
        logger.exception(f"Erro ao criar templates: {str(e)}")
        return jsonify({"success": False, "error": str(e)})

if __name__ == '__main__':
    # Garantir que os diretórios existam
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    logger.info("=== Iniciando servidor da aplicação ===")
    app.run(host='0.0.0.0', port=5000, debug=True)
