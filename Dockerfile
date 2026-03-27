FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/JakobBartoschek/porthawk"
LABEL org.opencontainers.image.description="Async port scanner — authorized targets only"
LABEL org.opencontainers.image.licenses="MIT"

WORKDIR /app

# install runtime deps first so Docker cache survives code changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY porthawk/ ./porthawk/
COPY pyproject.toml .

RUN pip install --no-cache-dir -e . --no-deps

# SYN scan and raw socket features need root — running as root inside a container
# is acceptable here because the container itself is the isolation boundary.
# If you want non-root: drop --syn/--slow-low and add --user 1000 to docker run.

ENTRYPOINT ["porthawk"]
CMD ["--help"]
