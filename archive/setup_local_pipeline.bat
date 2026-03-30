@echo off
REM Setup script for Local Mutation Pipeline
REM Windows Batch Script

echo ========================================
echo LLMalMorph Local Pipeline Setup
echo ========================================
echo.

REM Check Python
echo [1/5] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found! Please install Python 3.8+
    pause
    exit /b 1
)
python --version
echo.

REM Check if in correct directory
echo [2/5] Checking directory...
if not exist "src" (
    echo ERROR: Please run this script from E:\LLMalMorph2 directory
    pause
    exit /b 1
)
echo Current directory: %CD%
echo.

REM Install dependencies
echo [3/5] Installing dependencies...
echo This may take a few minutes...
pip install -q mistralai requests tree-sitter tree-sitter-c tree-sitter-cpp rarfile
if errorlevel 1 (
    echo WARNING: Some packages failed to install
    echo Try: pip install -r requirements.txt
) else (
    echo Dependencies installed successfully
)
echo.

REM Check config file
echo [4/5] Checking configuration...
if not exist "local_config.json" (
    echo WARNING: local_config.json not found!
    echo Please ensure the config file exists
) else (
    echo Config file found: local_config.json
)
echo.

REM Check API key
echo [5/5] Checking API key...
if "%MISTRAL_API_KEY%"=="" (
    echo WARNING: MISTRAL_API_KEY environment variable not set!
    echo.
    echo Please set your API key:
    echo   PowerShell: $env:MISTRAL_API_KEY = "your-key"
    echo   CMD:        set MISTRAL_API_KEY=your-key
    echo.
    set /p SETUP_API_KEY="Would you like to set it now for this session? (y/n): "
    if /i "%SETUP_API_KEY%"=="y" (
        set /p API_KEY="Enter your Mistral API key: "
        set MISTRAL_API_KEY=!API_KEY!
        echo API key set for this session
    )
) else (
    echo API key is set
)
echo.

echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Next steps:
echo   1. Ensure your API key is set (see above)
echo   2. Review local_config.json settings
echo   3. Run pipeline:
echo      python test_local.py --stage all
echo.
echo Or open notebook:
echo   jupyter notebook test_local.ipynb
echo.
echo For help, see LOCAL_PIPELINE_README.md
echo.

pause





