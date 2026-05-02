FROM ubuntu:22.04

RUN apt update && apt install -y \
    g++ \
    libcap-dev

WORKDIR /app

COPY test_capset.cpp .

RUN g++ -O2 -Wall -o test_capset test_capset.cpp -lcap

CMD ["./test_capset"]
