echo "Building and running container..."
docker build -t setuid-test .

docker run --rm \
    --privileged \
    -v /sys/fs/bpf:/sys/fs/bpf \
    setuid-test
