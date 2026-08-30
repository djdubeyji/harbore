FROM python:3.14-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN addgroup --system harbore && adduser --system --group harbore
USER harbore

ENV PORT=8090
EXPOSE 8090

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8090", "--workers", "2"]
