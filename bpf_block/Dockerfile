FROM ubuntu:22.04

RUN apt-get update && apt-get install -y build-essential

WORKDIR /app

COPY test_bpf.cpp .

RUN g++ -O2 -Wall -o test_bpf test_bpf.cpp

CMD ["./test_bpf"]
