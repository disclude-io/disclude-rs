#!/bin/bash
# Clean bash script - no obfuscation
set -euo pipefail

NAME="World"
echo "Hello, $NAME!"

greet() {
    local who="$1"
    echo "Greetings, $who"
}

greet "Alice"
