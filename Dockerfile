FROM python:3.14-slim

# binutils provides the `strings` command used for binary string extraction
RUN apt-get update && apt-get install -y --no-install-recommends \
        binutils \
    && rm -rf /var/lib/apt/lists/*

# Install uv. Pinned to a release rather than :latest so image builds are
# reproducible and a new uv cannot silently change dependency resolution.
COPY --from=ghcr.io/astral-sh/uv:0.11.28 /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./

# Install dependencies (no dev extras, no editable install)
RUN uv sync --frozen --no-dev --no-install-project

# Copy application source
COPY shingan/ ./shingan/

# Install the project itself
RUN uv sync --frozen --no-dev

# Scan results and custom rules are stored under /data (mount as a volume)
ENV SHINGAN_HOME=/data

# Run as a non-root user. The container only needs to read the mounted artifact
# and write scan results under /data.
RUN groupadd --system --gid 1001 shingan \
    && useradd --system --uid 1001 --gid shingan shingan \
    && mkdir -p /data \
    && chown -R shingan:shingan /data /app
USER shingan

# Inside a container the server must listen on all interfaces to be reachable
# from the host; the CLI default is loopback. Publish the port deliberately
# (-p 127.0.0.1:8000:8000) and set SHINGAN_API_KEY if it is exposed beyond the
# host, since the API is otherwise unauthenticated.
ENV SHINGAN_HOST=0.0.0.0 \
    SHINGAN_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,os,sys; \
sys.exit(0) if urllib.request.urlopen(f\"http://127.0.0.1:{os.environ['SHINGAN_PORT']}/api/health\", timeout=3).status == 200 else sys.exit(1)"

# Default: start the web UI
# Override CMD for CLI use: docker run shingan scan /artifacts/MyApp.ipa
CMD ["sh", "-c", "uv run shingan serve --host \"$SHINGAN_HOST\" --port \"$SHINGAN_PORT\""]
