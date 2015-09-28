#!/usr/bin/env python
import subprocess
import sys

TAMARIN_PATH='tamarin-prover'
FALSIFIED=False

NOT_WELL_FORMED_MESSAGE='wellformedness check failed'
FALSIFIED_MESSAGE='falsified - found trace'

p = subprocess.Popen([TAMARIN_PATH, '--prove', sys.argv[1]],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT)
for l in p.stdout:
    print l,
    if (l.find(NOT_WELL_FORMED_MESSAGE) != -1):
        sys.exit(1)

    if (l.find(FALSIFIED_MESSAGE) != -1):
        FALSIFIED=True

if FALSIFIED:
    sys.exit(1)

p.wait()
if p.returncode != 0:
    sys.exit(p.returncode)


