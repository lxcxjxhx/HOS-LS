FROM python:3.11-slim

LABEL maintainer="HOS Team <team@hos-ls.com>"
LABEL description="HOS-LS: AI Generated Code Security Scanner"
LABEL version="0.3.3.17"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOS_LS_HOME=/app
ENV HOS_LS_CACHE_DIR=/cache
ENV HOS_LS_OUTPUT_DIR=/output

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /output /cache

# Copy dependency files first for better caching
COPY requirements.txt pyproject.toml ./

# Copy source code and config
COPY src/ ./src/
COPY config/ ./config/
COPY prompts/ ./prompts/
COPY tests/ ./tests/

# Install all dependencies using pip (more reliable for complex dependencies)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -e .

VOLUME ["/output", "/cache"]

ENTRYPOINT ["python", "-m", "src.cli.main"]
CMD ["--help"]
