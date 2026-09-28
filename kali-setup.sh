#!/bin/bash
# =============================================================================
# Predictive Cyber Defence Platform - Kali Linux Auto-Installer
# =============================================================================
# This script automatically installs all dependencies and starts the platform
# on Kali Linux. Run with: sudo bash kali-setup.sh
# =============================================================================

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
PROJECT_DIR="/opt/predictive-cyber-defence"
REPO_URL="https://github.com/your-org/predictive-cyber-defence.git"  # Update this
PYTHON_VERSION="3.11"
NODE_VERSION="20"

# Helper functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${CYAN}[STEP]${NC} $1"; }

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Detect OS and version
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
        log_info "Detected OS: $PRETTY_NAME"
    else
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    if [[ "$OS" != "kali" ]] && [[ "$OS" != "debian" ]] && [[ "$OS" != "ubuntu" ]]; then
        log_warn "This script is optimized for Kali/Debian/Ubuntu. Proceeding anyway..."
    fi
}

# Update package lists
update_packages() {
    log_step "Updating package lists..."
    apt-get update -qq
    log_success "Package lists updated"
}

# Install system dependencies
install_system_deps() {
    log_step "Installing system dependencies..."
    
    # Core build tools
    apt-get install -y -qq \
        build-essential \
        cmake \
        pkg-config \
        libssl-dev \
        libffi-dev \
        libpq-dev \
        libpcap-dev \
        libnetfilter-queue-dev \
        libnfnetlink-dev \
        libmnl-dev \
        libyaml-dev \
        libxml2-dev \
        libxslt-dev \
        zlib1g-dev \
        libjpeg-dev \
        libpng-dev \
        libfreetype6-dev \
        lcov \
        gcovr \
        valgrind \
        strace \
        lsof \
        net-tools \
        iproute2 \
        iptables \
        nmap \
        tcpdump \
        wireshark-common \
        tshark \
        curl \
        wget \
        git \
        unzip \
        jq \
        vim \
        htop \
        tmux \
        tree \
        netcat-openbsd \
        socat \
        dnsutils \
        whois \
        sslscan \
        nikto \
        gobuster \
        dirb \
        feroxbuster \
        ffuf \
        seclists \
        wordlists \
        exploitdb \
        metasploit-framework \
        bloodhound \
        neo4j \
        python3-neo4j \
        python3-pip \
        python3-venv \
        python3-dev \
        python3-setuptools \
        python3-wheel \
        python3-poetry \
        pipx \
        nodejs \
        npm \
        docker.io \
        docker-compose \
        docker-compose-v2 \
        postgresql \
        postgresql-contrib \
        redis-server \
        minio \
        prometheus \
        prometheus-node-exporter \
        prometheus-blackbox-exporter \
        grafana \
        loki \
        promtail \
        > /dev/null 2>&1
    
    log_success "System dependencies installed"
}

# Install Python and create virtual environment
setup_python() {
    log_step "Setting up Python $PYTHON_VERSION..."
    
    # Install specific Python version if not available
    if ! command -v python$PYTHON_VERSION &> /dev/null; then
        log_step "Installing Python $PYTHON_VERSION..."
        apt-get install -y -qq software-properties-common
        add-apt-repository -y ppa:deadsnakes/ppa
        apt-get update -qq
        apt-get install -y -qq python$PYTHON_VERSION python$PYTHON_VERSION-venv python$PYTHON_VERSION-dev
    fi
    
    log_success "Python $PYTHON_VERSION ready"
}

# Install Node.js
setup_nodejs() {
    log_step "Setting up Node.js $NODE_VERSION..."
    
    if ! command -v node &> /dev/null || [[ $(node -v | cut -d'v' -f2 | cut -d'.' -f1) -lt $NODE_VERSION ]]; then
        curl -fsSL https://deb.nodesource.com/setup_${NODE_VERSION}.x | bash -
        apt-get install -y -qq nodejs
    fi
    
    # Install pnpm for faster package management
    npm install -g pnpm > /dev/null 2>&1
    
    log_success "Node.js $(node -v) and pnpm ready"
}

# Configure Docker
setup_docker() {
    log_step "Configuring Docker..."
    
    # Add user to docker group
    usermod -aG docker $SUDO_USER 2>/dev/null || true
    
    # Enable and start Docker
    systemctl enable docker > /dev/null 2>&1
    systemctl start docker > /dev/null 2>&1
    
    # Configure Docker daemon for better performance
    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json << 'EOF'
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "max-concurrent-downloads": 10,
    "max-concurrent-uploads": 5
}
EOF
    
    systemctl daemon-reload
    systemctl restart docker
    
    log_success "Docker configured"
}

# Configure PostgreSQL
setup_postgresql() {
    log_step "Configuring PostgreSQL..."
    
    systemctl enable postgresql > /dev/null 2>&1
    systemctl start postgresql > /dev/null 2>&1
    
    # Create database and user
    sudo -u postgres psql -c "CREATE USER cyber_defence WITH PASSWORD 'changeme123';" 2>/dev/null || true
    sudo -u postgres psql -c "CREATE DATABASE cyber_defence OWNER cyber_defence;" 2>/dev/null || true
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE cyber_defence TO cyber_defence;" 2>/dev/null || true
    
    # Configure for remote connections
    PG_VERSION=$(psql --version | awk '{print $3}' | cut -d. -f1)
    PG_CONFIG="/etc/postgresql/$PG_VERSION/main"
    
    sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" $PG_CONFIG/postgresql.conf
    echo "host    all             all             0.0.0.0/0               md5" >> $PG_CONFIG/pg_hba.conf
    
    systemctl restart postgresql
    
    log_success "PostgreSQL configured"
}

# Configure Redis
setup_redis() {
    log_step "Configuring Redis..."
    
    systemctl enable redis-server > /dev/null 2>&1
    systemctl start redis-server > /dev/null 2>&1
    
    # Configure for persistence
    sed -i 's/^# maxmemory .*/maxmemory 256mb/' /etc/redis/redis.conf
    sed -i 's/^# maxmemory-policy .*/maxmemory-policy allkeys-lru/' /etc/redis/redis.conf
    
    systemctl restart redis-server
    
    log_success "Redis configured"
}

# Setup project directory and clone repo
setup_project() {
    log_step "Setting up project directory..."
    
    mkdir -p $PROJECT_DIR
    cd $PROJECT_DIR
    
    # If git repo exists, pull latest; otherwise create structure
    if [[ -d .git ]]; then
        git pull origin main
    else
        log_warn "No git repo found. Creating project structure..."
        create_project_structure
    fi
    
    log_success "Project directory ready at $PROJECT_DIR"
}

# Create project structure if no git repo
create_project_structure() {
    # Backend structure
    mkdir -p backend/app/{api/v1/endpoints,core,models,schemas,services,ws,db}
    mkdir -p backend/{alembic,tests,scripts,configs}
    
    # Frontend structure
    mkdir -p frontend/src/{app,components,hooks,store,types,utils,styles}
    mkdir -p frontend/public
    
    # ML Engine structure
    mkdir -p ml-engine/{models,training,inference,configs,scripts,data}
    
    # Shared
    mkdir -p shared
    
    # Docs
    mkdir -p docs
    
    # Configs
    mkdir -p config/{grafana/dashboards,grafana/datasources,prometheus,alertmanager}
    
    # Scripts
    mkdir -p scripts
}

# Setup backend
setup_backend() {
    log_step "Setting up backend..."
    
    cd $PROJECT_DIR/backend
    
    # Create virtual environment
    python$PYTHON_VERSION -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel > /dev/null 2>&1
    
    # Install requirements
    pip install -r requirements.txt > /dev/null 2>&1
    
    # Run migrations
    alembic upgrade head > /dev/null 2>&1 || log_warn "Migrations will run on first start"
    
    log_success "Backend ready"
}

# Setup frontend
setup_frontend() {
    log_step "Setting up frontend..."
    
    cd $PROJECT_DIR/frontend
    
    # Install dependencies
    pnpm install > /dev/null 2>&1
    
    # Build for production
    pnpm run build > /dev/null 2>&1
    
    log_success "Frontend ready"
}

# Setup ML Engine
setup_ml_engine() {
    log_step "Setting up ML Engine..."
    
    cd $PROJECT_DIR/ml-engine
    
    # Create virtual environment
    python$PYTHON_VERSION -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel > /dev/null 2>&1
    
    # Install ML requirements
    pip install -r requirements.txt > /dev/null 2>&1
    
    # Install PyTorch with CUDA support if available
    if command -v nvidia-smi &> /dev/null; then
        pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121 > /dev/null 2>&1
        pip install torch-scatter torch-sparse torch-cluster torch-spline-conv \
            -f https://data.pyg.org/whl/torch-2.4.0+cu121.html > /dev/null 2>&1
        log_success "PyTorch with CUDA support installed"
    else
        pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu > /dev/null 2>&1
        pip install torch-scatter torch-sparse torch-cluster torch-spline-conv \
            -f https://data.pyg.org/whl/torch-2.4.0+cpu.html > /dev/null 2>&1
        log_warn "CUDA not detected, using CPU-only PyTorch"
    fi
    
    log_success "ML Engine ready"
}

# Create configuration files
create_configs() {
    log_step "Creating configuration files..."
    
    cd $PROJECT_DIR
    
    # .env file
    cat > .env << 'EOF'
# Database
DATABASE_URL=postgresql+asyncpg://cyber_defence:changeme123@localhost:5432/cyber_defence
POSTGRES_PASSWORD=changeme123

# Redis
REDIS_URL=redis://localhost:6379/0

# MinIO
MINIO_ENDPOINT=localhost:9000
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=minioadmin123
MINIO_BUCKET=evidence
MINIO_SECURE=false

# JWT
JWT_SECRET_KEY=your-super-secret-jwt-key-change-in-production
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# API
API_V1_PREFIX=/api/v1
DEBUG=true
LOG_LEVEL=INFO

# ML
ML_MODEL_PATH=/opt/predictive-cyber-defence/ml-engine/models/world_model.onnx
ML_DEVICE=cuda
ML_BATCH_SIZE=1

# Frontend
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws

# CORS
CORS_ORIGINS=http://localhost:3000,http://localhost:8000
EOF
    
    # Docker Compose override for production
    cat > docker-compose.override.yml << 'EOF'
version: '3.8'

services:
  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    environment:
      - DATABASE_URL=postgresql+asyncpg://cyber_defence:changeme123@postgres:5432/cyber_defence
      - REDIS_URL=redis://redis:6379/0
      - MINIO_ENDPOINT=minio:9000
      - MINIO_ACCESS_KEY=minioadmin
      - MINIO_SECRET_KEY=minioadmin123
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
    volumes:
      - ./backend:/app
      - ./shared:/app/shared
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    ports:
      - "8000:8000"
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    environment:
      - NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
      - NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws
    volumes:
      - ./frontend:/app
      - /app/node_modules
      - /app/.next
    ports:
      - "3000:3000"
    command: npm run dev
    depends_on:
      - backend

  postgres:
    environment:
      POSTGRES_DB: cyber_defence
      POSTGRES_USER: cyber_defence
      POSTGRES_PASSWORD: changeme123
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U cyber_defence -d cyber_defence"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin123
    volumes:
      - minio_data:/data
    ports:
      - "9000:9000"
      - "9001:9001"

volumes:
  postgres_data:
  redis_data:
  minio_data:
EOF
    
    log_success "Configuration files created"
}

# Create systemd services for auto-start
create_systemd_services() {
    log_step "Creating systemd services..."
    
    # Backend service
    cat > /etc/systemd/system/predictive-cyber-backend.service << EOF
[Unit]
Description=Predictive Cyber Defence Backend
After=network.target postgresql.service redis.service
Requires=postgresql.service redis.service

[Service]
Type=exec
User=root
WorkingDirectory=$PROJECT_DIR/backend
Environment=PATH=$PROJECT_DIR/backend/venv/bin:/usr/bin:/bin
ExecStart=$PROJECT_DIR/backend/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Frontend service
    cat > /etc/systemd/system/predictive-cyber-frontend.service << EOF
[Unit]
Description=Predictive Cyber Defence Frontend
After=network.target predictive-cyber-backend.service
Requires=predictive-cyber-backend.service

[Service]
Type=exec
User=root
WorkingDirectory=$PROJECT_DIR/frontend
Environment=PATH=/usr/bin:/bin
ExecStart=/usr/bin/pnpm run dev
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # ML Engine service
    cat > /etc/systemd/system/predictive-cyber-ml.service << EOF
[Unit]
Description=Predictive Cyber Defence ML Engine
After=network.target
Requires=network.target

[Service]
Type=exec
User=root
WorkingDirectory=$PROJECT_DIR/ml-engine
Environment=PATH=$PROJECT_DIR/ml-engine/venv/bin:/usr/bin:/bin
ExecStart=$PROJECT_DIR/ml-engine/venv/bin/python -m scripts.serve_model
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable predictive-cyber-backend predictive-cyber-frontend predictive-cyber-ml > /dev/null 2>&1
    
    log_success "Systemd services created"
}

# Create startup script
create_startup_script() {
    log_step "Creating startup script..."
    
    cat > $PROJECT_DIR/start-platform.sh << 'EOF'
#!/bin/bash
# Quick start script for Predictive Cyber Defence Platform

set -e

PROJECT_DIR="/opt/predictive-cyber-defence"
cd $PROJECT_DIR

echo "🚀 Starting Predictive Cyber Defence Platform..."

# Start infrastructure
echo "Starting infrastructure..."
docker compose up -d postgres redis minio

# Wait for health
echo "Waiting for services..."
sleep 10

# Check health
for i in {1..30}; do
    docker compose exec postgres pg_isready -U cyber_defence -d cyber_defence >/dev/null 2>&1 && break
    echo "Waiting for PostgreSQL... ($i/30)"
    sleep 2
done

for i in {1..30}; do
    docker compose exec redis redis-cli ping >/dev/null 2>&1 && break
    echo "Waiting for Redis... ($i/30)"
    sleep 2
done

# Start application services
echo "Starting application services..."
docker compose up -d backend frontend

echo "✅ Platform started!"
echo "  Frontend: http://localhost:3000"
echo "  API: http://localhost:8000/api/v1"
echo "  Docs: http://localhost:8000/api/v1/docs"
echo "  MinIO: http://localhost:9001"
EOF
    
    chmod +x $PROJECT_DIR/start-platform.sh
    
    # Also create a stop script
    cat > $PROJECT_DIR/stop-platform.sh << 'EOF'
#!/bin/bash
cd /opt/predictive-cyber-defence
echo "🛑 Stopping Predictive Cyber Defence Platform..."
docker compose down
echo "✅ Platform stopped"
EOF
    chmod +x $PROJECT_DIR/stop-platform.sh
    
    log_success "Startup scripts created"
}

# Download datasets
download_datasets() {
    log_step "Downloading datasets..."
    
    mkdir -p $PROJECT_DIR/data/datasets
    
    cd $PROJECT_DIR/data/datasets
    
    # CESNET-TimeSeries24 (sample)
    if [[ ! -f "cesnet-timeseries24-sample.parquet" ]]; then
        log_info "Downloading CESNET-TimeSeries24 sample..."
        python3 -c "
from datasets import load_dataset
ds = load_dataset('Lystea/CESNET-TIMESERIES24-RAW', 'ip_addresses_sample', split='train')
ds.to_parquet('cesnet-timeseries24-sample.parquet')
print('CESNET sample downloaded')
" 2>/dev/null || log_warn "Could not download CESNET dataset"
    fi
    
    # UNSW-NB15
    if [[ ! -f "unsw-nb15-temporal.parquet" ]]; then
        log_info "Downloading UNSW-NB15..."
        python3 -c "
from datasets import load_dataset
ds = load_dataset('lacg030175/UNSW-NB15', 'temporal', split='train')
ds.to_parquet('unsw-nb15-temporal.parquet')
print('UNSW-NB15 downloaded')
" 2>/dev/null || log_warn "Could not download UNSW-NB15 dataset"
    fi
    
    # CICIDS2017
    if [[ ! -f "cicids2017-temporal.parquet" ]]; then
        log_info "Downloading CICIDS2017..."
        python3 -c "
from datasets import load_dataset
ds = load_dataset('lacg030175/CICIDS2017', 'temporal', split='train')
ds.to_parquet('cicids2017-temporal.parquet')
print('CICIDS2017 downloaded')
" 2>/dev/null || log_warn "Could not download CICIDS2017 dataset"
    fi
    
    log_success "Datasets downloaded"
}

# Main installation flow
main() {
    echo "============================================================================="
    echo "  Predictive Cyber Defence Platform - Kali Linux Auto-Installer"
    echo "============================================================================="
    echo ""
    
    check_root
    detect_os
    
    log_step "Starting installation..."
    
    update_packages
    install_system_deps
    setup_python
    setup_nodejs
    setup_docker
    setup_postgresql
    setup_redis
    setup_project
    create_configs
    setup_backend
    setup_frontend
    setup_ml_engine
    create_systemd_services
    create_startup_script
    download_datasets
    
    echo ""
    echo "============================================================================="
    log_success "Installation completed successfully!"
    echo "============================================================================="
    echo ""
    echo "📋 Next Steps:"
    echo "  1. cd /opt/predictive-cyber-defence"
    echo "  2. ./start-platform.sh"
    echo ""
    echo "📋 Access Points (after starting):"
    echo "  🌐 Frontend:      http://localhost:3000"
    echo "  🔧 Backend API:   http://localhost:8000/api/v1"
    echo "  📚 API Docs:      http://localhost:8000/api/v1/docs"
    echo "  🔌 WebSocket:     ws://localhost:8000/ws"
    echo "  📊 Grafana:       http://localhost:3001 (admin/admin)"
    echo "  📈 Prometheus:    http://localhost:9090"
    echo "  🗄️  MinIO Console: http://localhost:9001 (minioadmin/minioadmin123)"
    echo ""
    echo "🛑 To stop: ./stop-platform.sh"
    echo "📋 To view logs: docker compose logs -f"
    echo ""
}

# Run main
main "$@"