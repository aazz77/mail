FROM rust:1.85-slim AS backend
WORKDIR /build
# Frontend assets are prebuilt in ./frontend and embedded into the binary via rust-embed,
# so they must be present at compile time. No node build stage needed.
COPY Cargo.toml ./
COPY Cargo.lock* ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release || true
COPY src ./src
COPY migrations ./migrations
COPY frontend ./frontend
COPY Cargo.toml ./Cargo.toml
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=backend /build/target/release/cloud-mail-rust /usr/local/bin/cloud-mail-rust
ENV STORAGE_DIR=/data/storage
VOLUME ["/data"]
EXPOSE 8080
CMD ["cloud-mail-rust"]
