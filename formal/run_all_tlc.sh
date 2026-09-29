#!/usr/bin/env bash
# Runs every TLC job (F6, serve, then Semgate) and appends to results/tlc/run.log
cd "$(dirname "$0")"
PY=../.venv/Scripts/python.exe
$PY run_tlc.py --only MC_SemgateF6 --timeout 1800 --skip-done >> results/tlc/run.log 2>&1
$PY run_tlc.py --only SemgateServe --timeout 1800 --skip-done >> results/tlc/run.log 2>&1
$PY run_tlc.py --only MC_Semgate__ --timeout 2400 --skip-done >> results/tlc/run.log 2>&1
echo ALLDONE >> results/tlc/run.log
