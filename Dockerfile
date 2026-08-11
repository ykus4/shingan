FROM python:3.14-slim

# binutils provides the `strings` command used for binary string extraction
RUN apt-get update && apt-get install -y --no-install-recommends \
        binutils \
    && rm -rf /var/lib/apt/lists/*

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

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
RUN mkdir -p /data

EXPOSE 8000

# Default: start the web UI
# Override CMD for CLI use: docker run shingan scan /artifacts/MyApp.ipa
CMD ["uv", "run", "shingan", "serve"]
