FROM rust:1.85-slim AS backend
WORKDIR /build
COPY mail-rust/Cargo.toml ./
COPY mail-rust/Cargo.lock* ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release || true
COPY mail-rust/src ./src
COPY mail-rust/migrations ./migrations
COPY mail-rust/Cargo.toml ./Cargo.toml
RUN touch src/main.rs && cargo build --release

FROM node:22-slim AS frontend
WORKDIR /build
COPY mail-vue/package.json ./
COPY mail-vue/pnpm-lock.yaml* ./
RUN corepack enable && pnpm install --frozen-lockfile || pnpm install
COPY mail-vue ./
RUN pnpm build --mode server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=backend /build/target/release/cloud-mail-rust /usr/local/bin/cloud-mail-rust
COPY --from=frontend /build/dist /app/frontend
ENV FRONTEND_DIR=/app/frontend STORAGE_DIR=/data/storage
VOLUME ["/data"]
EXPOSE 8080
CMD ["cloud-mail-rust"]
