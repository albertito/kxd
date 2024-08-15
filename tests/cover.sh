#!/bin/bash

set -e

cd "$(realpath `dirname ${0}`)/../"

make GOFLAGS="-cover -covermode=count"

rm -rf .coverage/
mkdir -p .coverage
export GOCOVERDIR="${PWD}/.coverage"

tests/run_tests -b

go tool covdata textfmt -i "${GOCOVERDIR}" -o .cover-merged.out
go tool cover -func=.cover-merged.out | grep -i total
go tool cover -html=.cover-merged.out -o .cover-kxd.html

echo "file:///$PWD/.cover-kxd.html"
