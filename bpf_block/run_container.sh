#!/usr/bin/env bash
set -e

IMAGE=bpf-test

echo "[+] Building BPF syscall test container..."
docker build -t ${IMAGE} .

echo "[+] Running test container..."
docker run --rm \
  --privileged \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  ${IMAGE}

echo "[✓] Done"
