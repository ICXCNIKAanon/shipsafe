#!/bin/sh
# SHIPSAFE_HOOK
# ShipSafe pre-push hook — runs full scan before push

SHIPSAFE=$(command -v shipsafe 2>/dev/null)
if [ -z "$SHIPSAFE" ]; then
  SHIPSAFE="npx shipsafe"
fi

echo "ShipSafe: Running full scan before push..."
$SHIPSAFE scan --scope all

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "ShipSafe: Critical/high security issues found. Fix before pushing."
  echo "To bypass (not recommended): git push --no-verify"
  exit 1
fi

exit 0
