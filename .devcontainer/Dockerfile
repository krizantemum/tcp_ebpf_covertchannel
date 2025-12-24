# Dockerfile to build a "receiver" on Ubuntu 22.04
# Place this file at /Users/eonur/Development/liminal/tcp_ebpf_covertchannel/docker/Dockerfile
FROM ubuntu:22.04 
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates build-essential clang llvm libclang-dev clang-tools \
    libelf-dev libbpf-dev pkg-config git make golang-go iproute2  
RUN apt-get update &&  apt-get install -y libpcap0.8-dev  libpthread-stubs0-dev iperf3 libbpf-dev  
RUN rm -rf /var/lib/apt/lists/* && ln -s /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm 

WORKDIR /src
COPY .. /src

# Try common build paths:
# 1) make receiver
# 2) go build ./cmd/receiver
# 3) compile receiver.c (produces .o if eBPF C)
RUN make receiver && cp receiver /usr/local/bin/receiver && chmod +x /usr/local/bin/receiver || true
EXPOSE 5201/tcp
# Default entrypoint assumes an executable receiver is present.
#ENTRYPOINT ["/usr/local/bin/receiver"]