# fixture: ifs_and_escapes.sh
# Masks: "/bin/nc -e /bin/sh"
# Using backslashes to break keywords
\b\i\n/\n\c -e /\b\i\n/s\h

# Using IFS to treat commas as spaces
IFS=,
cmd=/bin/bash,-c,whoami
$cmd
