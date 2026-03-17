#!/bin/sh
# SHIPSAFE_HOOK
# ShipSafe pre-commit hook — scans staged files before commit

SHIPSAFE=$(command -v shipsafe 2>/dev/null)
if [ -z "$SHIPSAFE" ]; then
  SHIPSAFE="npx shipsafe"
fi

echo "ShipSafe: Scanning staged files..."
$SHIPSAFE scan --scope staged

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo ""
  echo "ShipSafe: Critical/high security issues found. Fix before committing."
  echo "To bypass (not recommended): git commit --no-verify"
  exit 1
fi

exit 0
