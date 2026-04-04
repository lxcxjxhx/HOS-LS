FROM python:3.11-slim

LABEL maintainer="HOS Team <team@hos-ls.com>"
LABEL description="HOS-LS: AI Generated Code Security Scanner"
LABEL version="3.0.0"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV HOS_LS_HOME=/app

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY pyproject.toml .
COPY src/ ./src/
COPY config/ ./config/

RUN pip install --no-cache-dir -e .

RUN mkdir -p /output /cache

ENV HOS_LS_CACHE_DIR=/cache
ENV HOS_LS_OUTPUT_DIR=/output

VOLUME ["/output", "/cache"]

ENTRYPOINT ["python", "-m", "src.cli.main"]
CMD ["--help"]
