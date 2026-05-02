FROM ubuntu:22.04

RUN apt update && apt install -y g++

WORKDIR /app

COPY test_setuid.cpp .

RUN g++ -O2 -Wall -o test_setuid test_setuid.cpp

CMD ["./test_setuid"]
