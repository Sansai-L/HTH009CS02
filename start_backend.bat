@echo off
title VulnRankPro - FastAPI Nmap Scanning Server
echo ========================================================
echo   VulnRankPro - FastAPI & Nmap Vulnerability Engine
echo ========================================================
echo.
echo Installing / verifying dependencies...
python -m pip install -r requirements.txt
echo.
echo Starting server at http://localhost:8000
echo Access the dashboard: http://localhost:8000
echo API Documentation:   http://localhost:8000/docs
echo.
python main.py
pause
