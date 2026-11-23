@echo off
rem MAX live run: every sample (~1190 attacks + ~1190 clean), incl. attacks scored by an LLM judge.
rem Longest variant. Safe to stop and rerun: it resumes where it stopped.
rem Usage: double-click, or from the project folder: scripts\run_live_max.bat [model]
cd /d "%~dp0.."
set MODEL=%1
if "%MODEL%"=="" set MODEL=qwen2.5:7b-instruct
.venv\Scripts\python.exe scripts\experiment_endtoend.py --ext ext --backend ollama --model %MODEL% --preset max --out docs\endtoend_real_max.json
pause
