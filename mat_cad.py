from flask import Flask, render_template, request, make_response, jsonify, send_file
import datetime
import csv
import io
import os
import pandas as pd

# Specify static_folder when creating the app
app = Flask(__name__, static_folder='static')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/download_template', methods=['GET'])
def download_template():
    try:
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
        
        return response
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/upload_csv', methods=['POST'])
def upload_csv():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Nenhum arquivo enviado'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'Nenhum arquivo selecionado'}), 400
            
        if not file.filename.endswith('.csv'):
            return jsonify({'error': 'Arquivo deve ser do tipo CSV'}), 400
        
        # Read CSV file
        stream = io.StringIO(file.stream.read().decode('utf-8'))
        df = pd.read_csv(stream, delimiter=';', skiprows=7)  # Skip the instruction rows
        
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
        
        return jsonify({'success': True, 'materials': materials, 'count': len(materials)})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/generate_csv', methods=['POST'])
def generate_csv():
    try:
        # Get data from request
        data = request.json
        materials = data.get('materials', [])
        
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
        
        return response
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Create folders if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)
    
    # Create template file if it doesn't exist
    if not os.path.exists('templates/index.html'):
        with open('templates/index.html', 'w', encoding='utf-8') as f:
            f.write("""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cadastro de materiais</title>
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
        
        /* ...existing styles... */
        
        /* Tab styles */
        .tabs {
            display: flex;
            margin-bottom: 1.5rem;
        }
        
        .tab {
            padding: 0.75rem 1.5rem;
            cursor: pointer;
            border: 1px solid var(--border-color);
            background-color: #f8f9fa;
            transition: all 0.2s;
        }
        
        .tab:first-child {
            border-radius: 4px 0 0 4px;
        }
        
        .tab:last-child {
            border-radius: 0 4px 4px 0;
        }
        
        .tab.active {
            background-color: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        /* Upload area styles */
        .upload-area {
            border: 2px dashed var(--border-color);
            border-radius: 8px;
            padding: 2rem;
            text-align: center;
            cursor: pointer;
            margin-bottom: 1.5rem;
            transition: border-color 0.3s;
        }
        
        .upload-area:hover {
            border-color: var(--secondary-color);
        }
        
        .upload-icon {
            font-size: 2.5rem;
            color: var(--secondary-color);
            margin-bottom: 1rem;
        }
        
        .upload-text {
            margin-bottom: 1rem;
        }
        
        /* Processing overlay */
        .processing-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 1000;
        }
        
        .processing-content {
            background-color: white;
            padding: 2rem;
            border-radius: 8px;
            text-align: center;
            max-width: 80%;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid var(--primary-color);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            margin: 1rem auto;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <header>
        <div class="wrapper">
            <div class="logo-container">
                <img src="/static/logo.png" alt="Logo da Empresa" class="logo">
            </div>
        </div>
    </header>
    
    <div class="wrapper">
        <div class="container">
            <h1>Cadastro de Materiais</h1>
            
            <div class="tabs">
                <div class="tab active" data-tab="single">Cadastro Individual</div>
                <div class="tab" data-tab="batch">Upload em Lote</div>
            </div>
            
            <div id="singleTab" class="tab-content active">
                <div class="card">
                    <div class="form-group">
                        <label for="materialCode">Código do Material *</label>
                        <input type="text" id="materialCode" required>
                        <div id="codeError" class="error">O código do material é obrigatório.</div>
                    </div>
                    
                    <div class="form-group">
                        <label for="materialDescription">Descrição do Material *</label>
                        <input type="text" id="materialDescription" required>
                        <div id="descError" class="error">A descrição do material é obrigatória.</div>
                    </div>
                    
                    <div class="checkbox-group">
                        <input type="checkbox" id="blockMaterial">
                        <label for="blockMaterial">Aplicar bloqueio?</label>
                    </div>
                    
                    <div class="action-buttons">
                        <button id="addMaterial" class="btn btn-success">
                            <i class="fas fa-plus"></i> Adicionar Material
                        </button>
                    </div>
                </div>
            </div>
            
            <div id="batchTab" class="tab-content">
                <div class="card">
                    <h3>Upload de Materiais em Lote</h3>
                    <p>Faça o upload de um arquivo CSV contendo a lista de materiais.</p>
                    
                    <div class="form-group">
                        <button id="downloadTemplate" class="btn btn-primary">
                            <i class="fas fa-download"></i> Baixar Template
                        </button>
                    </div>
                    
                    <div id="uploadArea" class="upload-area">
                        <div class="upload-icon">
                            <i class="fas fa-cloud-upload-alt"></i>
                        </div>
                        <div class="upload-text">
                            Arraste e solte o arquivo CSV aqui ou clique para selecionar
                        </div>
                        <button class="btn btn-primary">
                            <i class="fas fa-file-upload"></i> Selecionar Arquivo
                        </button>
                    </div>
                    
                    <input type="file" id="csvFileInput" accept=".csv" style="display: none;">
                    
                    <div class="action-buttons">
                        <button id="processCSV" class="btn btn-success" disabled>
                            <i class="fas fa-cog"></i> Processar Arquivo
                        </button>
                    </div>
                </div>
            </div>
            
            <div id="materialsCounter" class="counter">
                <i class="fas fa-list"></i> Materiais adicionados: 0
            </div>
            
            <div class="table-container">
                <table id="materialsTable">
                    <thead>
                        <tr>
                            <th>Grupo Mat.</th>
                            <th>Descr.Grupo</th>
                            <th>Descr.SubG</th>
                            <th>Cód. Material</th>
                            <th>Tipo Material</th>
                            <th>Unidade Medida</th>
                            <th>Descrição Material</th>
                            <th>Cód. Bloqueio</th>
                            <th>Ações</th>
                        </tr>
                    </thead>
                    <tbody>
                        <!-- Materials will be added here dynamically -->
                    </tbody>
                </table>
            </div>
            
            <button id="generateCSV" class="btn btn-primary" disabled>
                <i class="fas fa-file-csv"></i> Gerar CSV
            </button>
        </div>
    </div>
    
    <div id="processingOverlay" class="processing-overlay">
        <div class="processing-content">
            <h3>Processando</h3>
            <div class="spinner"></div>
            <p id="processingMessage">Processando arquivo...</p>
        </div>
    </div>
    
    <footer>
        <div class="wrapper">
            <p>&copy; 2025 Sysmex Brasil. Todos os direitos reservados.</p>
        </div>
    </footer>

    <script>
        // ...existing JavaScript...
    </script>
</body>
</html>
""")
    
    app.run(host= '0.0.0.0', port=5000, debug=True)
