# The retired demo backend image already contains the pinned ML/CUDA runtime.
# Demo-2 keeps that vetted runtime and replaces only the isolated application.
FROM predictive-cyber-defence-demo-backend

WORKDIR /app
COPY app ./app
COPY config ./config

EXPOSE 8100
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]
