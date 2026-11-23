@echo off
rem TEST live run: 20 attacks + 5 clean samples, about 5-20 minutes.
rem Usage: double-click, or from the project folder: scripts\run_live_test.bat [model]
cd /d "%~dp0.."
set MODEL=%1
if "%MODEL%"=="" set MODEL=qwen2.5:7b-instruct
.venv\Scripts\python.exe scripts\experiment_endtoend.py --ext ext --backend ollama --model %MODEL% --preset test --out docs\endtoend_real_test.json
pause
