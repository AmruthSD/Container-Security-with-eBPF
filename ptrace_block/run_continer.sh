#!/usr/bin/env bash
set -e

ARGSIN=$1 

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
  --privileged \
  --userns=host \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  ${IMAGE} ${ARGSIN}

echo "[✓] Done"