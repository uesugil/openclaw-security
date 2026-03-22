#!/bin/bash
# heartbeat-logger.sh — 独立于 agent 的心跳日志采集器
# 由系统 cron 触发，不依赖 agent 执行

SCANNER_DIR="$HOME/.openclaw/workspace/security-scanner"
LOG_DIR="$HOME/.openclaw/workspace/logs"
LOG_FILE="$LOG_DIR/heartbeat-log.jsonl"

mkdir -p "$LOG_DIR"
touch "$LOG_FILE"

# 读取真实数据
state_json=$(cat "$SCANNER_DIR/state.json" 2>/dev/null || echo "{}")
state=$(echo "$state_json" | grep -oE '"state":"[^"]*"' | cut -d'"' -f4)
repo=$(echo "$state_json" | grep -oE '"repo":"[^"]*"' | cut -d'"' -f4)
scanner_hb=$(echo "$state_json" | grep -oE '"heartbeat":[0-9]+' | cut -d: -f2)

scanned_total=$(wc -l < "$SCANNER_DIR/scanned.txt" 2>/dev/null | tr -d " ")
[ -z "$scanned_total" ] && scanned_total=0
findings_total=$(find "$SCANNER_DIR/findings/raw/" -size +20c 2>/dev/null | wc -l | tr -d " ")
[ -z "$findings_total" ] && findings_total=0

# 心跳编号 = 日志行数 + 1
current_lines=$(wc -l < "$LOG_FILE" | tr -d " ")
n=$((current_lines + 1))
ts=$(date -Iseconds)

# 判断模式
mode_idx=$((n % 12))
if [ "$mode_idx" -eq 0 ]; then
  mode="manager"
elif [ "$mode_idx" -eq 11 ]; then
  mode="reviewer"
else
  mode="executor"
fi

# 写日志
echo "{\"n\":$n,\"ts\":\"$ts\",\"mode\":\"$mode\",\"scanner_state\":\"${state:-UNKNOWN}\",\"repo\":\"${repo:-}\",\"scanner_hb\":${scanner_hb:-0},\"scanned_total\":$scanned_total,\"findings_total\":$findings_total}" >> "$LOG_FILE"
