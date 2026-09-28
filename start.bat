@echo off
REM ============================================================================
REM Predictive Cyber Defence Platform - Windows Startup Script
REM ============================================================================
REM Run: start.bat
REM ============================================================================

echo 🚀 Starting Predictive Cyber Defence Platform...

REM --------------------------------------------------------------------------
REM Check prerequisites
REM --------------------------------------------------------------------------
echo Checking prerequisites...

where docker >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

REM Check for docker compose (v2) or docker-compose (v1)
docker compose version >nul 2>&1
if %errorlevel% neq 0 (
    where docker-compose >nul 2>&1
    if %errorlevel% neq 0 (
        echo [ERROR] Docker Compose is not installed. Please install Docker Compose first.
        pause
        exit /b 1
    )
    set COMPOSE_CMD=docker-compose
) else (
    set COMPOSE_CMD=docker compose
)

echo [OK] Prerequisites OK

REM --------------------------------------------------------------------------
REM Stop any existing services first (releases .env lock)
REM --------------------------------------------------------------------------
echo Stopping any existing services...
%COMPOSE_CMD% down >nul 2>&1

REM --------------------------------------------------------------------------
REM Create .env file - using Python with proper escaping
REM --------------------------------------------------------------------------
if exist ".env" (
    echo [OK] .env file already exists
) else (
    echo Creating .env file...
    py -3.11 -c "open('.env','w').write('# Database\nPOSTGRES_PASSWORD=changeme123\n\n# MinIO\nMINIO_ROOT_USER=minioadmin\nMINIO_ROOT_PASSWORD=minioadmin123\n\n# JWT\nJWT_SECRET_KEY=your-super-secret-jwt-key-change-in-production\nJWT_ALGORITHM=HS256\n\n# Frontend\nNEXT_PUBLIC_API_URL=http://localhost:8000/api/v1\nNEXT_PUBLIC_WS_URL=ws://localhost:8000/ws\n\n# ML Engine (optional)\nML_MODEL_PATH=/models/world_model.onnx\n')"
    echo [OK] .env file created
)

REM Verify .env file
echo Verifying .env file...
type .env

REM --------------------------------------------------------------------------
REM Start CORE infrastructure only (PostgreSQL, Redis, MinIO)
REM --------------------------------------------------------------------------
echo Starting core infrastructure (PostgreSQL, Redis, MinIO)...
%COMPOSE_CMD% up -d postgres redis minio

REM Wait for services to be healthy
echo Waiting for services to be healthy...
timeout /t 15 /nobreak >nul

REM --------------------------------------------------------------------------
REM Check if services are healthy (using docker inspect instead of exec)
REM --------------------------------------------------------------------------
echo Checking PostgreSQL...
for /l %%i in (1,1,30) do (
    docker inspect --format='{{.State.Health.Status}}' predictive-cyber-defence-postgres-1 2>nul | find "healthy" >nul
    if not errorlevel 1 (
        echo [OK] PostgreSQL is healthy
        goto :redis_check
    )
    echo Waiting for PostgreSQL... (%%i/30)
    timeout /t 2 /nobreak >nul
)
echo [ERROR] PostgreSQL failed to start
echo Check logs: %COMPOSE_CMD% logs postgres
pause
exit /b 1

:redis_check
echo Checking Redis...
for /l %%i in (1,1,30) do (
    docker inspect --format='{{.State.Health.Status}}' predictive-cyber-defence-redis-1 2>nul | find "healthy" >nul
    if not errorlevel 1 (
        echo [OK] Redis is healthy
        goto :infra_ready
    )
    echo Waiting for Redis... (%%i/30)
    timeout /t 2 /nobreak >nul
)
echo [ERROR] Redis failed to start
echo Check logs: %COMPOSE_CMD% logs redis
pause
exit /b 1

:infra_ready
echo.
echo ===========================================
echo [OK] Core infrastructure is READY!
echo ===========================================
echo.
echo 📋 Core Services:
echo   🐘 PostgreSQL:  localhost:5432 (cyber_defence/changeme123)
echo   🔴 Redis:       localhost:6379
echo   🗄️  MinIO:       localhost:9000 (minioadmin/minioadmin123)
echo   📊 MinIO Console: http://localhost:9001
echo.
echo 📋 Next Steps (run in SEPARATE terminals):
echo   1. Backend:  cd backend && venv\Scripts\activate && uvicorn app.main:app --reload
echo   2. Frontend: cd frontend && npm run dev
echo   3. ML Engine: cd ml-engine && venv\Scripts\activate && python scripts/train.py
echo.
echo 🛑 To stop infrastructure: %COMPOSE_CMD% down
echo 📋 To view logs: %COMPOSE_CMD% logs -f
echo.
pause