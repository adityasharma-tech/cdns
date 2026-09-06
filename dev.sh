#!/bin/bash

SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "Stopping server ($SERVER_PID)..."
        kill "$SERVER_PID"
        wait "$SERVER_PID" 2>/dev/null
    fi
}

trap cleanup EXIT INT TERM

# Initial build + start
make

if [ $? -eq 0 ]; then
    ./dist/server &
    SERVER_PID=$!
fi

# Watch src directory forever
while inotifywait -r -e close_write,move,create,delete src; do
    echo

    cleanup

    if make; then
        ./dist/server &
        SERVER_PID=$!
    else
        echo "failed to build"
    fi
done
