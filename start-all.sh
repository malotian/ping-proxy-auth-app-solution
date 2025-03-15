#!/bin/bash

# Define directories for applications
AUTH_DIR="./auth"
PROXY_DIR="./proxy"
APP_DIR="./app"

# Define log directory
LOG_DIR="./logs"
mkdir -p "$LOG_DIR"

# Define PID files
AUTH_PID_FILE="$LOG_DIR/auth.pid"
PROXY_PID_FILE="$LOG_DIR/proxy.pid"
APP_PID_FILE="$LOG_DIR/app.pid"

# Function to check if an app is already running
is_running() {
    local PID_FILE=$1
    if [[ -f "$PID_FILE" ]]; then
        local PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            return 0  # Process is running
        else
            rm -f "$PID_FILE"  # Remove stale PID file
        fi
    fi
    return 1  # Process is not running
}

# Function to start an application
start_app() {
    local APP_DIR=$1
    local LOG_FILE=$2
    local PID_FILE=$3
    local APP_NAME=$4

    if is_running "$PID_FILE"; then
        echo "$APP_NAME is already running. Skipping..."
    else
        echo "Starting $APP_NAME..."
        cd "$APP_DIR" && npm start > "$LOG_FILE" 2>&1 & echo $! > "$PID_FILE"
        cd ..
        echo "$APP_NAME started."
    fi
}

# Start only non-running applications
start_app "$AUTH_DIR" "$LOG_DIR/auth.log" "$AUTH_PID_FILE" "Auth Service"
start_app "$PROXY_DIR" "$LOG_DIR/proxy.log" "$PROXY_PID_FILE" "Proxy Service"
start_app "$APP_DIR" "$LOG_DIR/app.log" "$APP_PID_FILE" "App Service"

echo "All applications checked. Running services will continue, non-running ones have been started."
