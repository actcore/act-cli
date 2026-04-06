FROM scratch AS bins
COPY act-linux-x86_64-gnu /linux/amd64/act
COPY act-linux-aarch64-gnu /linux/arm64/act
COPY act-linux-riscv64-gnu /linux/riscv64/act

FROM gcr.io/distroless/cc-debian13:nonroot
ARG TARGETPLATFORM
COPY --from=bins /${TARGETPLATFORM}/act /usr/local/bin/act
ENTRYPOINT ["act"]
