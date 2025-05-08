"""
Analisador de logs do Sistema de Cadastro de Materiais

Este script analisa os logs de acesso e atividade do sistema de cadastro de materiais
e gera relatórios de atividades por usuário.
"""
import os
import re
import sys
import datetime
from collections import defaultdict

# Padrão para extrair informações dos logs
# Formato: timestamp [LEVEL] [module:line] [PID] - [EMAIL (NOME)] MESSAGE
LOG_PATTERN = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(\w+)\] \[[\w\.]+:\d+\] \[\d+\] - \[([^\]]+)\] (.+)'

# Padrão para extrair informações de materiais
MATERIAL_PATTERN = r'(CADASTRADO|ATUALIZADO|ENVIANDO): .*Código=([^,]+).*Nome=([^,]+)'

def parse_log_file(log_file_path):
    """
    Analisa o arquivo de log e extrai informações relevantes
    
    Args:
        log_file_path: Caminho do arquivo de log
        
    Returns:
        Um dicionário com as atividades de cada usuário
    """
    if not os.path.exists(log_file_path):
        print(f"ERRO: Arquivo de log não encontrado: {log_file_path}")
        return None
        
    # Estrutura para armazenar atividades por usuário
    user_activities = defaultdict(list)
    
    # Ler arquivo de log
    with open(log_file_path, 'r', encoding='utf-8') as file:
        for line in file:
            try:
                # Tentar fazer match com o padrão de log
                match = re.search(LOG_PATTERN, line)
                if match:
                    timestamp, level, email_name, message = match.groups()
                    
                    # Separar email e nome (se houver)
                    email = email_name.split(' ')[0]
                    
                    # Criar entrada para o evento
                    event = {
                        'timestamp': timestamp,
                        'level': level,
                        'message': message,
                        'raw': line.strip()
                    }
                    
                    # Detectar eventos específicos
                    if 'LOGIN BEM-SUCEDIDO' in message:
                        event['type'] = 'login'
                    elif 'LOGOUT' in message:
                        event['type'] = 'logout'
                    elif 'MATERIAL CADASTRADO' in message:
                        event['type'] = 'material_create'
                        # Extrair código e nome do material
                        mat_match = re.search(MATERIAL_PATTERN, message)
                        if mat_match:
                            _, code, name = mat_match.groups()
                            event['material_code'] = code
                            event['material_name'] = name
                    elif 'MATERIAL ATUALIZADO' in message:
                        event['type'] = 'material_update'
                        # Extrair código e nome do material
                        mat_match = re.search(MATERIAL_PATTERN, message)
                        if mat_match:
                            _, code, name = mat_match.groups()
                            event['material_code'] = code
                            event['material_name'] = name
                    elif 'PESQUISANDO MATERIAIS' in message:
                        event['type'] = 'material_search'
                        event['filters'] = message.split('PESQUISANDO MATERIAIS: ')[1].split(' (Página')[0]
                    else:
                        event['type'] = 'other'
                    
                    # Adicionar à lista de atividades do usuário
                    user_activities[email].append(event)
            except Exception as e:
                print(f"Erro ao processar linha: {line}")
                print(f"Erro: {str(e)}")
                continue
    
    return user_activities

def generate_user_activity_report(user_activities):
    """
    Gera um relatório de atividades por usuário
    
    Args:
        user_activities: Dicionário com atividades por usuário
        
    Returns:
        Uma string formatada com o relatório
    """
    if not user_activities:
        return "Nenhum dado de atividade encontrado."
        
    report = []
    report.append("=" * 80)
    report.append("RELATÓRIO DE ATIVIDADES POR USUÁRIO")
    report.append("=" * 80)
    
    # Data do relatório
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report.append(f"Gerado em: {now}")
    report.append("")
    
    # Para cada usuário
    for email, activities in sorted(user_activities.items()):
        if email == "Não autenticado":
            continue  # Pular eventos sem usuário
            
        report.append("-" * 80)
        report.append(f"USUÁRIO: {email}")
        report.append("-" * 80)
        
        # Contadores de atividades
        logins = 0
        logouts = 0
        materials_created = []
        materials_updated = []
        searches = 0
        
        # Datas
        first_activity = activities[0]['timestamp'] if activities else "N/A"
        last_activity = activities[-1]['timestamp'] if activities else "N/A"
        
        # Analisar atividades
        for event in activities:
            event_type = event.get('type')
            if event_type == 'login':
                logins += 1
            elif event_type == 'logout':
                logouts += 1
            elif event_type == 'material_create':
                code = event.get('material_code', 'N/A')
                name = event.get('material_name', 'N/A')
                materials_created.append(f"{code} ({name})")
            elif event_type == 'material_update':
                code = event.get('material_code', 'N/A')
                name = event.get('material_name', 'N/A')
                materials_updated.append(f"{code} ({name})")
            elif event_type == 'material_search':
                searches += 1
        
        # Adicionar estatísticas ao relatório
        report.append(f"Período de atividade: {first_activity} até {last_activity}")
        report.append(f"Total de logins: {logins}")
        report.append(f"Total de logouts: {logouts}")
        report.append(f"Materiais cadastrados: {len(materials_created)}")
        report.append(f"Materiais atualizados: {len(materials_updated)}")
        report.append(f"Pesquisas realizadas: {searches}")
        report.append("")
        
        # Detalhes dos materiais cadastrados
        if materials_created:
            report.append("MATERIAIS CADASTRADOS:")
            for i, material in enumerate(materials_created, 1):
                report.append(f"  {i}. {material}")
            report.append("")
        
        # Detalhes dos materiais atualizados
        if materials_updated:
            report.append("MATERIAIS ATUALIZADOS:")
            for i, material in enumerate(materials_updated, 1):
                report.append(f"  {i}. {material}")
            report.append("")
    
    return "\n".join(report)

def main(log_file=None):
    """
    Função principal
    
    Args:
        log_file: Caminho para o arquivo de log (opcional)
    """
    # Determinar o arquivo de log a ser analisado
    if log_file is None:
        log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
        log_file = os.path.join(log_dir, 'application.log')
    
    print(f"Analisando arquivo de log: {log_file}")
    
    # Analisar logs
    user_activities = parse_log_file(log_file)
    
    if user_activities:
        # Gerar relatório
        report = generate_user_activity_report(user_activities)
        
        # Determinar arquivo de saída
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"relatorio_atividades_{timestamp}.txt"
        
        # Salvar relatório
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(report)
        
        print(f"Relatório gerado com sucesso: {output_file}")
        print("")
        print(report)
    else:
        print("Não foi possível analisar os logs.")

if __name__ == "__main__":
    # Verificar se o arquivo de log foi especificado como argumento
    log_file = sys.argv[1] if len(sys.argv) > 1 else None
    main(log_file)
