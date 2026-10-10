FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl build-essential pkg-config libssl-dev
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
COPY . /app
WORKDIR /app
CMD ["cargo", "test", "--test", "launch_handshake", "--", "--nocapture"]
