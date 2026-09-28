FROM python:3.11-slim

WORKDIR /edge

RUN pip install --no-cache-dir fastapi==0.115.* uvicorn==0.32.*

COPY app/ ./app/

EXPOSE 8090 8091 8099

CMD ["python", "-m", "app.run"]
