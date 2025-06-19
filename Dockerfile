# Build stage
FROM rust:1.75-slim as builder
WORKDIR /usr/src/aptotect
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
COPY --from=builder /usr/src/aptotect/target/release/aptotect /usr/local/bin/aptotect
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENTRYPOINT ["aptotect"] 