@echo off
rem FULL live run: all scorable samples (~770 attacks + ~930 clean). Takes hours.
rem Safe to stop (Ctrl+C or close window): run again to resume where it stopped.
rem Usage: double-click, or from the project folder: scripts\run_live_full.bat [model]
cd /d "%~dp0.."
set MODEL=%1
if "%MODEL%"=="" set MODEL=qwen2.5:7b-instruct
.venv\Scripts\python.exe scripts\experiment_endtoend.py --ext ext --backend ollama --model %MODEL% --preset full --out docs\endtoend_real_full.json
pause
