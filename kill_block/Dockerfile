FROM ubuntu:22.04

RUN apt-get update && apt-get install -y build-essential

WORKDIR /app

COPY test_kill.cpp .

RUN g++ -O2 -Wall -o test_kill test_kill.cpp

ENTRYPOINT ["./test_kill"]
