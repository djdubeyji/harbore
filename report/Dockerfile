FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi-dev build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN addgroup --system harbore && adduser --system --group harbore
USER harbore

ENV PORT=8091
EXPOSE 8091

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8091"]
