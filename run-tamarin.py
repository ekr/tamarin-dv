#!/usr/bin/env python
import subprocess
import sys
import argparse

TAMARIN_PATH='tamarin-prover'
FALSIFIED=False

NOT_WELL_FORMED_MESSAGE='wellformedness check failed'
FALSIFIED_MESSAGE='falsified - found trace'


parser = argparse.ArgumentParser()
parser.add_argument("-a", "--allow_falsification",
                    action="store_true")
parser.add_argument("theory", 
                    help="the theory to prove")
args = parser.parse_args();

p = subprocess.Popen([TAMARIN_PATH, '--prove', args.theory],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT)
for l in p.stdout:
    print l,
    if (l.find(NOT_WELL_FORMED_MESSAGE) != -1):
        sys.exit(1)

    if (l.find(FALSIFIED_MESSAGE) != -1):
        FALSIFIED=True

if not args.allow_falsification:
    if FALSIFIED:
        sys.exit(1)

p.wait()
if p.returncode != 0:
    sys.exit(p.returncode)


