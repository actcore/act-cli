FROM scratch AS bins
COPY act-build-linux-x86_64-gnu /linux/amd64/act-build
COPY act-build-linux-aarch64-gnu /linux/arm64/act-build
COPY act-build-linux-riscv64-gnu /linux/riscv64/act-build

FROM gcr.io/distroless/cc-debian13:nonroot
ARG TARGETPLATFORM
COPY --from=bins /${TARGETPLATFORM}/act-build /usr/local/bin/act-build
ENTRYPOINT ["act-build"]
