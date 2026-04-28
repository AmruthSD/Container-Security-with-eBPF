#!/usr/bin/env bash
set -e

IMAGE=hello-scratch

echo "[+] Building binaries..."

g++ -static -O2 hello.cpp -o hello
g++ -static -O2 test1.cpp -o test1
g++ -static -O2 test2.cpp -o test2

echo "[+] Checking binaries..."
file hello
file test1
file test2

echo "[+] Building Docker image..."
docker build -t ${IMAGE} .

echo "[+] Running container..."
docker run --rm --name test-scratch ${IMAGE}

echo "[✓] Done"