#!/bin/bash

set -e

cd "$(realpath `dirname ${0}`)/../"

make GOFLAGS="-cover -covermode=count"

rm -rf .coverage/
mkdir -p .coverage/{go,sh,all}
export GOCOVERDIR="${PWD}/.coverage"

go test -covermode=count -coverpkg=./... ./... \
	-args -test.gocoverdir="${GOCOVERDIR}/go"

GOCOVERDIR="${GOCOVERDIR}/sh" tests/run_tests -b

go tool covdata merge -i "${GOCOVERDIR}/go,${GOCOVERDIR}/sh" -o "${GOCOVERDIR}/all"
go tool covdata textfmt -i "${GOCOVERDIR}/all" -o .cover-merged.out
go tool cover -func=.cover-merged.out | grep -i total
go tool cover -html=.cover-merged.out -o .cover-kxd.html

echo "file:///$PWD/.cover-kxd.html"
