FROM node:24-bookworm@sha256:e7add2a490bb17d97b485b8641bd88455fff7839ade0f5eba493c3508124d413 AS node
FROM ohmykei-virtual:1
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN apt-get update && apt-get install -y --no-remove --no-install-recommends \
    libudev-dev libusb-1.0-0-dev libpcsclite-dev libbluetooth-dev \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libdrm2 libxkbcommon0 \
    libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 \
    libgtk-3-0 xvfb xauth
WORKDIR /opt/fido
COPY official-package.json package.json
COPY official-package-lock.json package-lock.json
RUN node /usr/local/lib/node_modules/npm/bin/npm-cli.js ci --omit=dev --no-audit --no-fund
RUN node node_modules/@electron/rebuild/lib/cli.js --version 41.7.0 --force
ENV NODE_PATH=/opt/fido/node_modules
WORKDIR /workspace
