#!/usr/bin/env bash
set -e

IMAGE=hello-scratch

echo "[+] Building binaries..."

g++ -static -O2 hello.cpp -o hello

echo "[+] Checking binaries..."
file hello

echo "[+] Building Docker image..."
docker build -t ${IMAGE} .

echo "[+] Running container..."
docker run --rm --name test-scratch ${IMAGE}

echo "[✓] Done"