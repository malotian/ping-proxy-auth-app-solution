#!/bin/bash

LOG_DIR="./logs"

echo "Stopping running applications..."

for PID_FILE in "$LOG_DIR"/*.pid; do
    if [[ -f "$PID_FILE" ]]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            echo "Stopping process $PID..."
            kill "$PID" && rm -f "$PID_FILE"
        else
            echo "Process $PID not found. Removing stale PID file."
            rm -f "$PID_FILE"
        fi
    fi
done

echo "All running applications stopped."
