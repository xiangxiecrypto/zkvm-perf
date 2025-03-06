FROM nvidia/cuda:12.5.1-devel-ubuntu20.04

# Install system dependencies
RUN apt-get update && DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get install -y \
    curl \
    build-essential \
    protobuf-compiler \
    git \
    libssl-dev \
    pkg-config \
    python3 \
    python3-pip \
    build-essential \
    libc6 \
    gcc \
    g++ \
    docker.io \
    wget \
    llvm-dev \
    libclang-dev \
    clang \
    && rm -rf /var/lib/apt/lists/*

ENV LIBCLANG_PATH="/usr/lib/llvm-10/lib"

# Install Go 1.22
RUN wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz \
    && rm -rf /usr/local/go \
    && tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz \
    && rm go1.22.0.linux-amd64.tar.gz

# Add Go to PATH
ENV PATH="/usr/local/go/bin:${PATH}"

# Install Rust separately for better caching
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
ENV PS1="\u@\h:\w \$ "

# Copy just the install script first
COPY install.sh /install.sh
RUN chmod +x /install.sh && /install.sh

# Set the working directory
WORKDIR /usr/src/app

# Copy source code last since it changes most frequently
COPY . /usr/src/app

ENTRYPOINT ["/bin/bash", "-c"]