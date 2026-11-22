#!/usr/bin/env bash
# Fails the job on every creep exit code but 0 (ADR 0023). Exit 4, an
# incomplete run, fails exactly like a gate failure: the scanned
# repository's creep.yaml may lower its own budget, which turns a gate
# failure into exit 4 (ADR 0007), so a softer result for 4 would let a pull
# request pass the gate that judges it.
#
# Environment: EXIT_CODE (empty when the scan step did not run).
set -euo pipefail

case "${EXIT_CODE:-}" in
  0)
    echo "creep: nothing blocking (exit 0)"
    exit 0
    ;;
  1) echo "::error title=creep::gate exceeded (exit 1): a finding reaches the gate" ;;
  2) echo "::error title=creep::usage, configuration or consent error (exit 2)" ;;
  3) echo "::error title=creep::model, tool canary, calibration or sandbox error (exit 3)" ;;
  4) echo "::error title=creep::incomplete run (exit 4): not everything was evaluated, so the job fails as on a gate failure" ;;
  "") echo "::error title=creep::the scan did not run" ;;
  *) echo "::error title=creep::unexpected exit code from creep" ;;
esac
exit 1
