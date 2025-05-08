# Sistema de Logs do Cadastro de Materiais

## Visão Geral

Este documento descreve o sistema de logs aprimorado para o Sistema de Cadastro de Materiais, que permite rastrear com clareza todas as ações realizadas pelos usuários, incluindo cadastro, atualização e consulta de materiais.

## Formato dos Logs

Os logs são gerados no seguinte formato:

```
YYYY-MM-DD HH:MM:SS [NÍVEL] [módulo:linha] [PID] - [EMAIL (NOME)] MENSAGEM
```

Onde:
- **YYYY-MM-DD HH:MM:SS**: Data e hora da ocorrência
- **NÍVEL**: Nível do log (INFO, WARNING, ERROR, DEBUG)
- **módulo:linha**: Arquivo e linha que gerou o log
- **PID**: ID do processo
- **EMAIL (NOME)**: Email e nome do usuário que realizou a ação
- **MENSAGEM**: Descrição detalhada da ação

## Categorias de Logs

### Autenticação
- `LOGIN BEM-SUCEDIDO`: Quando um usuário realiza login com sucesso
- `LOGOUT`: Quando um usuário encerra sua sessão
- `ACESSO NEGADO`: Tentativa de acesso não autorizado

### Materiais
- `ENVIANDO MATERIAL`: Início do processo de cadastro de material com detalhes
- `MATERIAL CADASTRADO`: Confirmação de cadastro bem-sucedido com detalhes
- `MATERIAL ATUALIZADO`: Confirmação de atualização bem-sucedida com detalhes
- `ATUALIZANDO MATERIAL`: Início do processo de atualização de material
- `FALHA NO CADASTRO`: Erro durante o cadastro de material
- `FALHA NA ATUALIZAÇÃO`: Erro durante a atualização de material

### Pesquisas
- `PESQUISANDO MATERIAIS`: Pesquisa de materiais com filtros aplicados
- `PESQUISA CONCLUÍDA`: Resultado da pesquisa com contagem de itens

## Ferramentas para Análise de Logs

### Teste de Logs (test_logs.py)

Este script executa uma série de ações para validar o sistema de logs:
1. Tenta realizar login
2. Cadastra um material de teste
3. Pesquisa materiais
4. Realiza logout

Para usar:
```bash
python test_logs.py
```

**Importante**: Edite o arquivo para inserir credenciais válidas antes de executar.

### Analisador de Logs (log_analyzer.py)

Esta ferramenta analisa os logs e gera um relatório de atividade por usuário, mostrando:
- Períodos de atividade
- Número de logins/logouts
- Materiais cadastrados e atualizados
- Pesquisas realizadas

Para usar:
```bash
python log_analyzer.py [caminho_do_arquivo_de_log]
```

Se o caminho não for especificado, o analisador usará o arquivo padrão em `logs/application.log`.

## Boas Práticas

1. **Verificação Regular**: Verifique os logs regularmente para identificar padrões de uso ou problemas
2. **Backup**: Mantenha backup dos arquivos de log antigos
3. **Análise Periódica**: Execute o log_analyzer.py periodicamente para gerar relatórios de atividade

## Exemplos de Logs

### Cadastro de Material
```
2025-05-08 10:15:32 [INFO] [mat_cad:218] [12345] - [usuario@sysmex.com (João Silva)] MATERIAL CADASTRADO: Código=ABC123, Nome=Reagente XYZ
```

### Erro de Autenticação
```
2025-05-08 09:47:15 [WARNING] [mat_cad:142] [12345] - API rejeitou credenciais: usuario.invalido@exemplo.com
```

### Pesquisa
```
2025-05-08 11:22:45 [INFO] [mat_cad:325] [12345] - [usuario@sysmex.com (João Silva)] PESQUISA CONCLUÍDA: 25 itens exibidos de um total de 142
```
