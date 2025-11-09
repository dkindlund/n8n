ARG NODE_VERSION=22.21.0
ARG PYTHON_VERSION=3.13

# ==============================================================================
# STAGE 1: JavaScript runner (@n8n/task-runner) artifact from CI
# ==============================================================================
FROM node:${NODE_VERSION}-alpine AS javascript-runner-builder
COPY ./dist/task-runner-javascript /app/task-runner-javascript

WORKDIR /app/task-runner-javascript

RUN corepack enable pnpm

# Install extra runtime-only npm packages. Allow usage in the Code node via
# 'NODE_FUNCTION_ALLOW_EXTERNAL' env variable on n8n-task-runners.json.
RUN rm -f node_modules/.modules.yaml
RUN mv package.json package.json.bak
COPY docker/images/runners/package.json /app/task-runner-javascript/package.json
RUN pnpm install --prod --no-lockfile --silent
RUN mv package.json extras.json
RUN mv package.json.bak package.json

# ==============================================================================
# STAGE 2: Python runner build (@n8n/task-runner-python) with uv
# Produces a relocatable venv tied to the python version used
# ==============================================================================
FROM python:${PYTHON_VERSION}-alpine AS python-runner-builder
ARG TARGETPLATFORM
ARG UV_VERSION=0.8.14

RUN set -e; \
  case "$TARGETPLATFORM" in \
    "linux/amd64") UV_ARCH="x86_64-unknown-linux-musl" ;; \
    "linux/arm64") UV_ARCH="aarch64-unknown-linux-musl" ;; \
    *) echo "Unsupported platform: $TARGETPLATFORM" >&2; exit 1 ;; \
  esac; \
  mkdir -p /tmp/uv && cd /tmp/uv; \
  wget -q "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${UV_ARCH}.tar.gz"; \
  wget -q "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-${UV_ARCH}.tar.gz.sha256"; \
  sha256sum -c "uv-${UV_ARCH}.tar.gz.sha256"; \
	tar -xzf "uv-${UV_ARCH}.tar.gz"; \
  install -m 0755 "uv-${UV_ARCH}/uv" /usr/local/bin/uv; \
  cd / && rm -rf /tmp/uv

WORKDIR /app/task-runner-python

COPY packages/@n8n/task-runner-python/pyproject.toml \
     packages/@n8n/task-runner-python/uv.lock** \
     packages/@n8n/task-runner-python/.python-version** \
     ./

RUN uv venv
RUN uv sync \
			--frozen \
			--no-editable \
			--no-install-project \
			--no-dev \
			--all-extras

COPY packages/@n8n/task-runner-python/ ./
RUN uv sync \
      --frozen \
			--no-dev \
			--all-extras \
      --no-editable

# Install extra runtime-only Python packages. Allow usage in the Code node via
# 'N8N_RUNNERS_EXTERNAL_ALLOW' env variable on n8n-task-runners.json.
COPY docker/images/runners/extras.txt /app/task-runner-python/extras.txt
RUN uv pip install -r /app/task-runner-python/extras.txt

# ==============================================================================
# STAGE 3: Task Runner Launcher download
# ==============================================================================
FROM alpine:3.22.1 AS launcher-downloader
ARG TARGETPLATFORM
ARG LAUNCHER_VERSION=1.4.1

RUN set -e; \
    case "$TARGETPLATFORM" in \
        "linux/amd64") ARCH_NAME="amd64" ;; \
        "linux/arm64") ARCH_NAME="arm64" ;; \
        *) echo "Unsupported platform: $TARGETPLATFORM" && exit 1 ;; \
    esac; \
    mkdir /launcher-temp && cd /launcher-temp; \
    wget -q "https://github.com/n8n-io/task-runner-launcher/releases/download/${LAUNCHER_VERSION}/task-runner-launcher-${LAUNCHER_VERSION}-linux-${ARCH_NAME}.tar.gz"; \
    wget -q "https://github.com/n8n-io/task-runner-launcher/releases/download/${LAUNCHER_VERSION}/task-runner-launcher-${LAUNCHER_VERSION}-linux-${ARCH_NAME}.tar.gz.sha256"; \
    echo "$(cat task-runner-launcher-${LAUNCHER_VERSION}-linux-${ARCH_NAME}.tar.gz.sha256) task-runner-launcher-${LAUNCHER_VERSION}-linux-${ARCH_NAME}.tar.gz" > checksum.sha256; \
    sha256sum -c checksum.sha256; \
    mkdir -p /launcher-bin; \
    tar xzf task-runner-launcher-${LAUNCHER_VERSION}-linux-${ARCH_NAME}.tar.gz -C /launcher-bin; \
    cd / && rm -rf /launcher-temp

# ==============================================================================
# STAGE 4: Claude Code CLI installation
# ==============================================================================
FROM node:${NODE_VERSION}-alpine AS claude-code-installer

RUN npm install -g @anthropic-ai/claude-code

# ==============================================================================
# STAGE 5: Node alpine base for JS task runner
# ==============================================================================
FROM node:${NODE_VERSION}-alpine AS node-alpine

# ==============================================================================
# STAGE 6: Runtime
# ==============================================================================
FROM python:${PYTHON_VERSION}-alpine AS runtime
ARG N8N_VERSION=snapshot
ARG N8N_RELEASE_TYPE=dev

ENV NODE_ENV=production \
    N8N_RELEASE_TYPE=${N8N_RELEASE_TYPE} \
    SHELL=/bin/bash

# Bring `uv` over from python-runner-builder
COPY --from=python-runner-builder /usr/local/bin/uv /usr/local/bin/uv

# Bring node, npm, and supporting files from node-alpine
COPY --from=node-alpine /usr/local/bin/node /usr/local/bin/node
COPY --from=node-alpine /usr/local/bin/npm /usr/local/bin/npm
COPY --from=node-alpine /usr/local/bin/npx /usr/local/bin/npx
COPY --from=node-alpine /usr/local/lib/node_modules /usr/local/lib/node_modules

# libstdc++ is required by Node
# libc6-compat is required by task-runner-launcher
# git is required by Claude Code for repo operations
# bash is required by Claude Code for executing shell commands
# curl is required for downloading files and API calls
RUN apk add --no-cache ca-certificates tini libstdc++ libc6-compat git bash curl

RUN addgroup -g 1000 -S runner \
 && adduser  -u 1000 -S -G runner -h /home/runner -D runner

WORKDIR /home/runner

COPY --from=javascript-runner-builder --chown=root:root /app/task-runner-javascript /opt/runners/task-runner-javascript
COPY --from=python-runner-builder --chown=root:root /app/task-runner-python /opt/runners/task-runner-python
COPY --from=launcher-downloader /launcher-bin/* /usr/local/bin/
COPY --from=claude-code-installer /usr/local/lib/node_modules/@anthropic-ai/claude-code /usr/local/lib/node_modules/@anthropic-ai/claude-code
COPY --from=claude-code-installer /usr/local/bin/claude /usr/local/bin/claude
COPY --chown=root:root docker/images/runners/n8n-task-runners.json /etc/n8n-task-runners.json

# Ensure claude is executable and create config directory for runner user
RUN chmod +x /usr/local/bin/claude && \
    mkdir -p /home/runner/.config/claude && \
    chown -R runner:runner /home/runner/.config

USER runner

EXPOSE 5680/tcp
ENTRYPOINT ["tini", "--", "/usr/local/bin/task-runner-launcher"]
CMD ["javascript", "python"]

LABEL org.opencontainers.image.title="n8n task runners" \
      org.opencontainers.image.description="Sidecar image providing n8n task runners for JavaScript and Python code execution" \
      org.opencontainers.image.source="https://github.com/n8n-io/n8n" \
      org.opencontainers.image.url="https://n8n.io" \
      org.opencontainers.image.version="${N8N_VERSION}"
