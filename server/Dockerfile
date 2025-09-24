# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Copy project definition first so deps layer can cache
COPY pyproject.toml /app/pyproject.toml

# Install runtime dependencies (editable install is fine here)
RUN pip install --no-cache-dir -e .

# App files
COPY src /app/src
COPY flag /app/flag
COPY entrypoint.sh /app/entrypoint.sh

# ✅ Fix Windows line endings and make entrypoint executable
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

EXPOSE 5000

# ✅ Use ENTRYPOINT (your script already execs gunicorn)
ENTRYPOINT ["/app/entrypoint.sh"]
