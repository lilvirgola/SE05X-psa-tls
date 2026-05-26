#!/bin/bash

counter=0

on_sigint() {
    echo
    echo "Received SIGINT. Counter: $counter"
    exit 0
}

trap on_sigint SIGINT

while true; do
    counter=$((counter + 1))
    MESSAGE="Hello, World! $(date) - Iteration: $counter"
    mosquitto_pub -h localhost -p 1883 -t 'portenta/sensor' -m "$MESSAGE"
    sleep 30
done