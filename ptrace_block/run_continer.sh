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
docker run --rm \
  --pid=host \
  --cap-add=SYS_PTRACE \
  --security-opt seccomp=unconfined \
  ${IMAGE}

echo "[✓] Done"