FROM python:3.12-slim

WORKDIR /app

# openssl für CA-Operationen
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Backend als Package ablegen (relative Imports benötigen ein Package)
COPY backend/ /app/backend/

EXPOSE 8080

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
