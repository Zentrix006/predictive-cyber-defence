# Startup script for Predictive Cyber Defence Platform (PowerShell)
# Run with: powershell -ExecutionPolicy Bypass -File start.ps1

$ErrorActionPreference = "Stop"

Write-Host "🚀 Starting Predictive Cyber Defence Platform..." -ForegroundColor Cyan

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

$docker = Get-Command docker -ErrorAction SilentlyContinue
$compose = Get-Command docker-compose -ErrorAction SilentlyContinue

if (-not $docker) {
    Write-Host "Docker is not installed. Please install Docker first." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

if (-not $compose) {
    Write-Host "Docker Compose is not installed. Please install Docker Compose first." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Prerequisites OK" -ForegroundColor Green

# Create .env file if it doesn't exist
if (-not (Test-Path ".env")) {
    Write-Host "Creating .env file..." -ForegroundColor Yellow
    @"
# Database
POSTGRES_PASSWORD=changeme123

# MinIO
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin123

# JWT
JWT_SECRET_KEY=your-super-secret-jwt-key-change-in-production
JWT_ALGORITHM=HS256

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws

# ML Engine (optional)
ML_MODEL_PATH=/models/world_model.onnx
"@ | Out-File -FilePath ".env" -Encoding utf8
    Write-Host ".env file created" -ForegroundColor Green
}

# Start infrastructure
Write-Host "Starting infrastructure (PostgreSQL, Redis, MinIO)..." -ForegroundColor Yellow
docker-compose up -d postgres redis minio

# Wait for services to be healthy
Write-Host "Waiting for services to be healthy..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Check if services are healthy
Write-Host "Checking PostgreSQL..." -ForegroundColor Yellow
for ($i = 1; $i -le 30; $i++) {
    try {
        $result = docker-compose exec -T postgres pg_isready -U cyber_defence -d cyber_defence
        if ($LASTEXITCODE -eq 0) {
            Write-Host "PostgreSQL is healthy" -ForegroundColor Green
            break
        }
    } catch {}
    Write-Host "Waiting for PostgreSQL... ($i/30)"
    Start-Sleep -Seconds 2
}

Write-Host "Checking Redis..." -ForegroundColor Yellow
for ($i = 1; $i -le 30; $i++) {
    try {
        $result = docker-compose exec -T redis redis-cli ping
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Redis is healthy" -ForegroundColor Green
            break
        }
    } catch {}
    Write-Host "Waiting for Redis... ($i/30)"
    Start-Sleep -Seconds 2
}

# Run backend migrations
Write-Host "Running database migrations..." -ForegroundColor Yellow
try {
    docker-compose exec -T backend alembic upgrade head
} catch {
    Write-Host "Migrations will run on first backend start" -ForegroundColor Yellow
}

# Start all services
Write-Host "Starting all services..." -ForegroundColor Yellow
docker-compose up -d

Write-Host ""
Write-Host "✅ Platform started successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Access Points:" -ForegroundColor Cyan
Write-Host "  🌐 Frontend:      http://localhost:3000"
Write-Host "  🔧 Backend API:   http://localhost:8000/api/v1"
Write-Host "  📚 API Docs:      http://localhost:8000/api/v1/docs"
Write-Host "  🔌 WebSocket:     ws://localhost:8000/ws"
Write-Host "  📊 Grafana:       http://localhost:3001 (admin/admin)"
Write-Host "  📈 Prometheus:    http://localhost:9090"
Write-Host "  🗄️  MinIO Console: http://localhost:9001 (minioadmin/minioadmin123)"
Write-Host ""
Write-Host "🛑 To stop: docker-compose down" -ForegroundColor Yellow
Write-Host "📋 To view logs: docker-compose logs -f" -ForegroundColor Yellow

Write-Host ""
Read-Host "Press Enter to exit"