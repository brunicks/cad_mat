@echo off
setlocal

:: Definir pasta raiz do sistema
set ROOT_DIR=C:\mat_cad

:: Criar pasta de logs se não existir
if not exist "%ROOT_DIR%\logs" mkdir "%ROOT_DIR%\logs"

:: Registrar início da aplicação
echo ======================================== >> "%ROOT_DIR%\logs\modulo.log"
echo Iniciando mat cad - %date% %time% >> "%ROOT_DIR%\logs\modulo.log"
echo ======================================== >> "%ROOT_DIR%\logs\modulo.log"

:: Mudar para o diretório do sistema
cd /d "%ROOT_DIR%"
set PYTHONPATH=%ROOT_DIR%

:: Verificar se estamos no diretório correto
if not exist "%ROOT_DIR%\mat_cad.py" (
    echo ERRO: mat_cad.py não encontrado em %ROOT_DIR% - %date% %time% >> "%ROOT_DIR%\logs\modulo.log"
    goto :error
)

:: Iniciar a aplicação
echo Executando mat_cad.py >> "%ROOT_DIR%\logs\modulo.log"
python mat_cad.py >> "%ROOT_DIR%\logs\modulo.log" 2>&1

:: Se ocorrer erro, registrar
if errorlevel 1 (
    echo ERRO ao iniciar o modulo - %date% %time% - Código %errorlevel% >> "%ROOT_DIR%\logs\modulo.log"
    goto :error
)

echo Aplicação encerrada normalmente - %date% %time% >> "%ROOT_DIR%\logs\modulo.log"
goto :end

:error
exit /b %errorlevel%

:end
endlocal