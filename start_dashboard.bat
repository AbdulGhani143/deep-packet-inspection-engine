@echo off
title DPI Engine Visual Console
echo ========================================================
echo   Starting DPI Engine Visual Console & Bridge Server
echo ========================================================
echo.
echo Launching local server at http://localhost:8080 ...
echo (Press Ctrl+C in this terminal window to stop the server)
echo.

python bridge_server.py

pause
