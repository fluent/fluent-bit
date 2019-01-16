FROM debian:stretch as builder
ADD https://busybox.net/downloads/binaries/1.30.0-i686/busybox /bin/busybox
RUN chmod 555 /bin/busybox \
 && /bin/busybox --install

FROM fluent/fluent-bit:latest
COPY --from=builder /bin/ /bin/

