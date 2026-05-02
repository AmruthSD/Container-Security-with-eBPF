echo "[+] Running test container..."
docker build -t capset-test .

docker run --rm \
    --privileged \
    -v /sys/fs/bpf:/sys/fs/bpf \
    capset-test
