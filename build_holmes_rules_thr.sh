#!/usr/bin/env bash

set -e

V0=1
V1=$(git log --merges | grep "into 'master'" | wc -l) 
V=$(printf "%s.%s" $V0 $V1)
echo HOLMES RULES THR VERSION: $V
./dist/holmes-rules-pack --input configs/holmes/rules/holmes_rules.yaml --output ./dist/holmes-rules.thr --version "$V"