#!/bin/bash
# Red Team Mindset — Bash версия

OBSERVER_URL="http://localhost:8080/observer_feed"
FINDINGS_URL="http://localhost:8080/findings"
OPENROUTER_KEY="YOUR_OPENROUTER_API_KEY"
SHODAN_KEY="fhTJwwj0k5H7RMRkhUed1u8wHwJrmGl1"
DATA_DIR="$HOME/bugbounty-observer/data"
LOG_DIR="$HOME/bugbounty-observer/logs"

mkdir -p "$DATA_DIR" "$LOG_DIR"

send_to_observer() {
    local source="$1" hostname="$2" summary="$3" severity="${4:-YELLOW}"
    curl -s -X POST "$OBSERVER_URL" \
        -H "Content-Type: application/json" \
        -d "{\"source\":\"$source\",\"hostname\":\"$hostname\",\"summary\":\"$summary\",\"severity\":\"$severity\"}" \
        --connect-timeout 3 > /dev/null 2>&1
}

recon_passive() {
    echo "[RECON] DNS subdomain brute..."
    local targets_file="$HOME/bugbounty-observer/targets.txt"
    [ ! -f "$targets_file" ] && echo "  No targets.txt" && return
    
    local prefixes=(dev staging admin api vpn git jenkins)
    
    while read -r domain; do
        [ -z "$domain" ] && continue
        for prefix in "${prefixes[@]}"; do
            local sub="$prefix.$domain"
            local ip=$(dig +short "$sub" A 2>/dev/null | head -1)
            [ -n "$ip" ] && send_to_observer "recon_dns" "$sub" "Subdomain found: $sub -> $ip" "YELLOW"
        done
    done < "$targets_file"
}

scan_exposure() {
    echo "[SCAN] Exposed services..."
    local exposed=(
        "kibana port:5601|Kibana без auth|RED"
        "elasticsearch port:9200|ElasticSearch открытый|RED"
        "mongodb port:27017|MongoDB без пароля|RED"
        "redis port:6379|Redis без пароля|RED"
        "docker port:2375|Docker API открытый|RED"
    )
    
    for entry in "${exposed[@]}"; do
        IFS='|' read -r query desc severity <<< "$entry"
        local data=$(curl -s "https://api.shodan.io/shodan/host/count?key=$SHODAN_KEY&query=$query" --connect-timeout 10 2>/dev/null)
        if [ -n "$data" ]; then
            local count=$(echo "$data" | python3 -c "import json,sys; print(json.load(sys.stdin).get('total',0))" 2>/dev/null)
            [ "$count" -gt 0 ] 2>/dev/null && send_to_observer "scan_exposure" "$query" "$desc — $count открытых в интернете" "$severity"
        fi
        sleep 0.3
    done
}

ai_analyze() {
    echo "[ANALYZE] AI analysis..."
    local findings=$(curl -s "$FINDINGS_URL" --connect-timeout 10 2>/dev/null)
    [ -z "$findings" ] && echo "  No findings" && return
    
    echo "$findings" | python3 -c "
import json,sys
findings=json.load(sys.stdin)[-10:]
for f in findings:
    print(json.dumps(f))
" 2>/dev/null | while read -r finding_json; do
        local summary=$(echo "$finding_json" | python3 -c "import json,sys; print(json.loads(sys.stdin.read()).get('summary','')[:200])" 2>/dev/null)
        [ -z "$summary" ] && continue
        
        local hostname=$(echo "$finding_json" | python3 -c "import json,sys; print(json.loads(sys.stdin.read()).get('hostname','?'))" 2>/dev/null)
        
        local prompt="Red team AI. Analyze this finding. Return ONLY JSON: {\"attack_vector\":\"...\",\"impact\":\"...\",\"priority\":\"critical/high/medium/low\"}\n\nFinding: $summary"
        
        local ai_response=$(curl -s "https://openrouter.ai/api/v1/chat/completions" \
            -H "Authorization: Bearer $OPENROUTER_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"openai/gpt-oss-120b:free\",\"max_tokens\":200,\"messages\":[{\"role\":\"user\",\"content\":$(echo "$prompt" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))")}]}" \
            --connect-timeout 25 2>/dev/null)
        
        local analysis=$(echo "$ai_response" | python3 -c "
import json,sys,re
try:
    d=json.load(sys.stdin)
    content=d['choices'][0]['message']['content']
    m=re.search(r'{.*}', content, re.DOTALL)
    if m:
        a=json.loads(m.group())
        if a.get('priority') in ('critical','high'):
            print(f'{a[\"priority\"]}|{a.get(\"attack_vector\",\"?\")[:80]}')
except: pass
" 2>/dev/null)
        
        if [ -n "$analysis" ]; then
            IFS='|' read -r priority vector <<< "$analysis"
            send_to_observer "ai_redteam" "$hostname" "RedTeam [$priority]: $vector" "RED"
        fi
        sleep 2
    done
}

ai_prioritize() {
    echo "[PRIORITY] AI target selection..."
    local findings=$(curl -s "$FINDINGS_URL" --connect-timeout 10 2>/dev/null)
    [ -z "$findings" ] && echo "  No findings to prioritize" && return
    
    local findings_text=$(echo "$findings" | python3 -c "
import json,sys
findings=json.load(sys.stdin)[-20:]
for i,f in enumerate(findings,1):
    print(f'{i}. [{f.get(\"source\",\"?\")}] {f.get(\"summary\",\"\")[:80]}')
" 2>/dev/null)
    
    [ -z "$findings_text" ] && return
    
    local prompt="Red team AI. Choose the best target to attack first. Return JSON only: {\"top_target\":\"N\",\"reason\":\"...\",\"attack_chain\":\"...\"}\n\nFindings:\n$findings_text"
    
    local ai_response=$(curl -s "https://openrouter.ai/api/v1/chat/completions" \
        -H "Authorization: Bearer $OPENROUTER_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"openai/gpt-oss-120b:free\",\"max_tokens\":300,\"messages\":[{\"role\":\"user\",\"content\":$(echo "$prompt" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))")}]}" \
        --connect-timeout 30 2>/dev/null)
    
    local priority=$(echo "$ai_response" | python3 -c "
import json,sys,re
try:
    d=json.load(sys.stdin)
    content=d['choices'][0]['message']['content']
    m=re.search(r'{.*}', content, re.DOTALL)
    if m:
        p=json.loads(m.group())
        print(f'{p.get(\"top_target\",\"?\")}|{p.get(\"reason\",\"\")}|{p.get(\"attack_chain\",\"\")}')
except: pass
" 2>/dev/null)
    
    if [ -n "$priority" ]; then
        IFS='|' read -r target reason chain <<< "$priority"
        echo ""
        echo "  === RED TEAM PRIORITY ==="
        echo "  Target: #$target"
        echo "  Reason: $reason"
        echo "  Chain:  $chain"
        send_to_observer "ai_priority" "target-$target" "PRIORITY #$target: ${reason:0:150}" "RED"
    fi
}

echo "=== Red Team Mindset v2.0 (Bash) ==="
echo "=== Started: $(date) ==="
echo ""

scan_exposure
ai_analyze
ai_prioritize

while true; do
    sleep 600
    echo "[$(date '+%H:%M')] --- Cycle ---"
    scan_exposure
    ai_analyze
    ai_prioritize
done
