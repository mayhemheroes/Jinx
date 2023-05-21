FROM debian:bookworm as builder
RUN apt update && apt install -y clang build-essential cmake

COPY . /jinx
WORKDIR /jinx
RUN cd fuzz && make

FROM debian:bookworm
COPY --from=builder /jinx/fuzz /