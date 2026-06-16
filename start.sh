#!/bin/bash
cd /Users/andreyberestof/bugbounty-observer

pkill -f "bugbounty-observer" 2>/dev/null
pkill -f "python3 observers" 2>/dev/null
pkill -f "python3 ai" 2>/dev/null
pkill -f "go run" 2>/dev/null
sleep 3

go run main.go &
sleep 4

source venv/bin/activate
python3 observers/github_watcher.py &
sleep 1
python3 observers/multi_watcher.py &
sleep 1
python3 observers/hacker_tools_watcher.py &
sleep 1
python3 ai/redteam_mindset.py &
sleep 1
python3 ai/analyzer_loop.py &
sleep 1
python3 ai/correlator.py --loop &
sleep 1
python3 ai/attack_chains.py --loop &
sleep 1
python3 ai/forecast_engine.py --loop &
sleep 1
python3 ai/temporal_correlation.py --loop &

wait

# Company Scanner — еженедельно по воскресеньям в 10:00
# Запускается отдельно: python3 company_scanner.py <country> <count>

# Company Scanner — еженедельно по воскресеньям в 10:00
# Запускается отдельно: python3 company_scanner.py <country> <count>
