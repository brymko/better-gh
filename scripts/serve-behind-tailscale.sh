#!/bin/sh
# Front a locally-running bgh-proxy (GHE mode, 127.0.0.1:PORT) with `tailscale serve`, giving
# it a real Let's Encrypt cert at https://<node>.<tailnet>.ts.net. Any tailnet client can then
# `gh auth login --hostname <that name>` with zero TLS-trust setup.
#
# One-time tailnet prerequisites (admin console, free):
#   - MagicDNS enabled
#   - HTTPS certificates enabled   https://login.tailscale.com/admin/dns
#   - Serve enabled                https://login.tailscale.com/f/serve
#
# Usage:  scripts/serve-behind-tailscale.sh [PORT] [PUBLIC_NAME]
#   PORT         loopback port the proxy listens on   (default 7843)
#   PUBLIC_NAME  this node's MagicDNS name             (default: auto-detected)
#
# Remember to set  external_url = "https://<PUBLIC_NAME>"  in the proxy config.
# Tear down with:  tailscale serve reset
set -eu

PORT="${1:-7843}"
NAME="${2:-}"

if [ -z "$NAME" ]; then
    # Self is the first node in `tailscale status --json`; grab its DNSName (strip trailing dot).
    NAME="$(tailscale status --json 2>/dev/null \
        | grep -m1 '"DNSName"' \
        | sed 's/.*"DNSName": *"\([^"]*\)\.".*/\1/')"
fi
if [ -z "$NAME" ]; then
    echo "could not auto-detect this node's MagicDNS name — pass it as the 2nd argument" >&2
    echo "  e.g. $0 $PORT vps.tailnet.ts.net" >&2
    exit 1
fi

echo "Fronting 127.0.0.1:$PORT as https://$NAME"
if ! tailscale serve --bg "https+insecure://127.0.0.1:$PORT" 2>serve.err; then
    echo "tailscale serve failed:" >&2
    sed 's/^/  /' serve.err >&2
    echo "  → enable Serve + HTTPS certs in the admin console (see header), then retry." >&2
    rm -f serve.err
    exit 1
fi
rm -f serve.err
tailscale serve status

cat <<EOF

Set in the proxy config:   external_url = "https://$NAME"
Then on any tailnet client:

    gh auth login --hostname $NAME

Tear down:   tailscale serve reset
EOF
