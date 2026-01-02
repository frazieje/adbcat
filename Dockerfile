FROM debian:12 AS builder

RUN apt-get update && apt-get install -y cmake \
    && apt-get install -y pkg-config libevent-dev libbsd-dev libssl-dev

COPY . /app
WORKDIR /app

RUN cmake . && make

FROM debian:12 AS runtime
COPY --from=builder /app/adbcat /usr/local/bin

RUN apt-get update \
    && apt-get install -y libevent-dev libbsd-dev

ENTRYPOINT ["adbcat"]
