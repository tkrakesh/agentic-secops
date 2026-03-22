FROM python:3.11-slim

WORKDIR /app

# Install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server code and fixture data
COPY server.py .
COPY data/ ./data/

# Cloud Run listens on PORT env var (default 8080)
ENV PORT=8080

CMD ["python", "server.py"]
