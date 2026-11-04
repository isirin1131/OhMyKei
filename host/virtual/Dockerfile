FROM python:3.12-bookworm@sha256:a5bab0ff300f91231c2e68bf73a8a8d60762ac39ce1c50eaf6803e4c38a9062b
RUN python -m pip install --no-cache-dir cmake==3.31.6 ninja==1.11.1.4 \
    fido2==2.0.0 cryptography==47.0.0 cffi==2.1.1 pycparser==3.12
WORKDIR /workspace
ENV ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1
