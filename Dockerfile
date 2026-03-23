FROM rust:slim-trixie AS builder
RUN cargo install wit-deps-cli
WORKDIR /src
COPY . .
RUN wit-deps && cargo build --release

FROM gcr.io/distroless/cc-debian13:nonroot
COPY --from=builder /src/target/release/act /usr/local/bin/act
ENTRYPOINT ["act"]
