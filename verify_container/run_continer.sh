#!/usr/bin/env bash
set -e

BIN=hello
IMAGE=hello-scratch

g++ -static -O2 hello.cpp -o ${BIN}
file ${BIN}

docker build -t ${IMAGE} .

docker run --rm --name test-scratch ${IMAGE}

echo "[✓] Done"