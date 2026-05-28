FROM debian:bookworm-slim

LABEL maintainer="G2rayXCodeLeafy" \
      description="Made By CodeLeafy"

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash curl wget unzip ca-certificates sudo openssl uuid-runtime tmux tzdata \
        qrencode jq vnstat bc net-tools gnupg libcap2-bin iproute2 \
        nodejs npm \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN wget -qO xray.zip "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip" \
    && unzip -q xray.zip -d /tmp/xray-dir \
    && mv /tmp/xray-dir/xray /usr/local/bin/xray \
    && mv /tmp/xray-dir/*.dat /usr/local/bin/ \
    && chmod +x /usr/local/bin/xray \
    && rm -rf xray.zip /tmp/xray-dir

WORKDIR /workspaces

EXPOSE 8080 443
