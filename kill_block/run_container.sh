#!/usr/bin/env bash
set -e

TARGET_PID="${1:-}"
IMAGE=kill-test

echo "[+] Building kill test container..."
docker build -t ${IMAGE} .

echo "[+] Running test container..."
docker run --rm \
  --pid=host \
  --privileged \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  ${IMAGE} ${TARGET_PID}

echo "[✓] Done"
