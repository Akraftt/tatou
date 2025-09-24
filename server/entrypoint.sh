#!/usr/bin/env bash
set -e

if [[ -z "${FLAG_2:-}" ]]; then
  echo "WARNING: FLAG_2 is not set"
fi

# Replace placeholder in /app/flag (if present)
if [[ -f "/app/flag" ]] && grep -q "REPLACE_THIS_STRING_WITH_SERVER_FLAG" "/app/flag"; then
  echo "Replacing placeholder in flag with $FLAG_2"
  sed -i "s/REPLACE_THIS_STRING_WITH_SERVER_FLAG/${FLAG_2}/g" /app/flag
fi

echo "Starting server..."
# ✅ chdir into /app/src so `server:app` imports cleanly
exec gunicorn -b 0.0.0.0:5000 server:app --chdir /app/src
