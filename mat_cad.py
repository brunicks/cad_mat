from flask import Flask, render_template, request, jsonify, redirect, session, url_for
import datetime
import os
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

# Novas constantes para API de materiais
MATERIAL_API_ENDPOINT = f"{SYSMEX_API_BASE_URL}/Material/AddOrUpdate"

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

@app.route('/api/submit_material', methods=['POST'])
@login_required
def submit_material():
    """Envia um material para a API do Sysmex"""
    try:
        logger.debug("Iniciando envio de material via API")
        
        # Verificar autenticação
        if 'user_token' not in session:
            logger.error("Token de usuário não encontrado na sessão")
            return jsonify({'success': False, 'error': 'Usuário não autenticado. Faça login novamente.'}), 401
        
        # Obter dados do material do request
        material_data = request.json
        
        if not material_data:
            logger.error("Dados de material não fornecidos")
            return jsonify({'success': False, 'error': 'Dados do material não fornecidos'}), 400
        
        # Completar o payload com valores padrão para a API
        complete_material = {
            "materialId": 0,  # auto increment
            "materialIdExt": material_data.get('materialIdExt', ''),
            "nome": material_data.get('nome', ''),
            "tipo": "FERT",  # valor padrão
            "matGrupoId": 7,  # valor padrão
            "uniMedida": "EA",  # valor padrão
            "ativo": True  # valor padrão
        }
        
        # Log do material que será enviado
        logger.debug(f"Enviando material: {safe_json_dumps(complete_material)}")
        
        # Configurar cabeçalhos com token de autenticação
        headers = {
            'Authorization': f"Bearer {session['user_token']}",
            'Content-Type': 'application/json'
        }
        
        # Enviar material para a API
        response = requests.post(
            MATERIAL_API_ENDPOINT, 
            json=complete_material, 
            headers=headers
        )
        
        logger.debug(f"Resposta da API: Status {response.status_code}")
        
        # Analisar resposta
        if response.status_code == 200:
            try:
                response_data = response.json()
                
                # Verificar se a API indica sucesso
                if response_data.get('result', False):
                    logger.info(f"Material {material_data.get('materialIdExt')} cadastrado com sucesso")
                    return jsonify({
                        'success': True,
                        'message': 'Material cadastrado com sucesso',
                        'data': response_data
                    })
                else:
                    error_msg = response_data.get('message', 'Erro não especificado pela API')
                    logger.error(f"Erro retornado pela API: {error_msg}")
                    return jsonify({
                        'success': False,
                        'error': error_msg,
                        'data': response_data
                    })
            except Exception as e:
                logger.exception(f"Erro ao processar resposta da API: {str(e)}")
                return jsonify({
                    'success': False,
                    'error': f"Erro ao processar resposta: {str(e)}"
                }), 500
        else:
            logger.error(f"Erro na requisição à API: Status {response.status_code}")
            error_msg = f"Erro na comunicação com a API: {response.status_code}"
            
            try:
                # Tentar obter mensagem de erro do corpo da resposta
                error_data = response.json()
                if error_data and 'message' in error_data:
                    error_msg = error_data['message']
            except:
                # Se falhar ao obter mensagem JSON, usar o texto da resposta
                if response.text:
                    error_msg = f"{error_msg} - {response.text[:200]}"
            
            return jsonify({
                'success': False,
                'error': error_msg
            }), 500
    except Exception as e:
        logger.exception(f"Exceção ao enviar material: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Exceção ao processar requisição: {str(e)}"
        }), 500

@app.errorhandler(404)
def page_not_found(e):
    logger.warning(f"Página não encontrada: {request.path}")
    return render_template('login.html', error="Página não encontrada"), 404

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Erro interno do servidor: {str(e)}")
    return render_template('login.html', error="Erro interno do servidor"), 500

if __name__ == '__main__':
    # Garantir que os diretórios existam
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    logger.info("=== Iniciando servidor da aplicação ===")
    app.run(host='0.0.0.0', port=5000, debug=True)
