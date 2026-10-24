# syntax=docker/dockerfile:1
#
# Statically linked (musl) server with the UI embedded, in an image that holds
# nothing else: no shell, no package manager, no libc. Next to the binary sits
# its CycloneDX SBOM.
#
#   docker build -t github-security-dashboard .
#   docker build --target sbom --output sbom .   # just the SBOM, into ./sbom

FROM node:26.12.0-alpine@sha256:6f08a523443ddedf52941874c203475b0ad503e859ad70cb26ab8be9a517dbd5 AS web
WORKDIR /src/web
RUN corepack enable
COPY web/package.json web/yarn.lock web/.yarnrc.yml ./
RUN --mount=type=cache,target=/root/.yarn/berry/cache \
    yarn install --immutable
COPY web/ ./
RUN yarn build

FROM rust:1.98.1-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS server
# C compilers for the bundled SQLite and aws-lc; certificates for the image.
RUN apk add --no-cache ca-certificates gcc make musl-dev
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install --locked cargo-cyclonedx@0.5.9
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY --from=web /src/web/build/ web/build/
ENV CARGO_PROFILE_RELEASE_STRIP=symbols
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin server \
    && mkdir -p /out/data \
    && cp target/release/server /out/server
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo cyclonedx --format json --spec-version 1.5 \
        --target "$(rustc -vV | sed -n 's/^host: //p')" \
        --manifest-path crates/server/Cargo.toml \
    && cp crates/server/server.cdx.json /out/server.cdx.json

FROM scratch AS sbom
COPY --from=server /out/server.cdx.json /

FROM scratch
COPY --from=server /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=server /out/server /out/server.cdx.json /
# Working directory for the default SQLite database, writable by the user.
COPY --from=server --chown=65532:65532 /out/data /data
USER 65532:65532
WORKDIR /data
ENV DASHBOARD_CONFIG=/config/config.toml
EXPOSE 8080
ENTRYPOINT ["/server"]
