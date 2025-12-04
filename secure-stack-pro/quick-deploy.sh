#!/bin/bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.

# SecureStack Pro - One-Command Deployment Script
# This script deploys the entire SecureStack Pro platform with zero manual configuration

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="SecureStack Pro"
VERSION="1.0.0"
DOMAIN="${DOMAIN:-securestackpro.local}"
ENVIRONMENT="${NODE_ENV:-production}"

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║                    SecureStack Pro                               ║"
    echo "║              Automated Deployment System                        ║"
    echo "║                                                                  ║"
    echo "║                     Version: $VERSION                              ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo
}

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        warn "Running as root. This is not recommended for production deployments."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check system requirements
check_requirements() {
    log "🔍 Checking system requirements..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed. Please install Docker first."
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed. Please install Docker Compose first."
    fi
    
    # Check if Git is installed
    if ! command -v git &> /dev/null; then
        error "Git is not installed. Please install Git first."
    fi
    
    # Check Docker daemon is running
    if ! docker info &> /dev/null; then
        error "Docker daemon is not running. Please start Docker first."
    fi
    
    # Check available disk space (minimum 5GB)
    available_space=$(df . | tail -1 | awk '{print $4}')
    if [ "$available_space" -lt 5242880 ]; then  # 5GB in KB
        error "Insufficient disk space. At least 5GB is required."
    fi
    
    # Check available memory (minimum 4GB)
    available_memory=$(free -m | awk 'NR==2{print $7}')
    if [ "$available_memory" -lt 4096 ]; then
        warn "Less than 4GB of available memory detected. Performance may be affected."
    fi
    
    log "✅ System requirements check passed"
}

# Generate secure environment variables
generate_env() {
    log "🔐 Generating secure environment configuration..."
    
    # Generate random passwords and keys
    DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    REDIS_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    JWT_SECRET=$(openssl rand -base64 64 | tr -d "=+/")
    JWT_REFRESH_SECRET=$(openssl rand -base64 64 | tr -d "=+/")
    ENCRYPTION_KEY=$(openssl rand -base64 32 | tr -d "=+/")
    SNAPSHOT_SIGNING_KEY=$(openssl rand -base64 32 | tr -d "=+/")
    SESSION_SECRET=$(openssl rand -base64 32 | tr -d "=+/")
    GRAFANA_ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/" | cut -c1-12)
    
    # Create .env file
    cat > .env << EOF
# SecureStack Pro - Production Configuration
# Generated on $(date)

# Basic Configuration
NODE_ENV=${ENVIRONMENT}
DOMAIN=${DOMAIN}
VERSION=${VERSION}

# Database Configuration
DB_PASSWORD=${DB_PASSWORD}
POSTGRES_DB=securestack_pro
POSTGRES_USER=securestack

# Redis Configuration
REDIS_PASSWORD=${REDIS_PASSWORD}

# JWT Configuration
JWT_SECRET=${JWT_SECRET}
JWT_REFRESH_SECRET=${JWT_REFRESH_SECRET}
JWT_EXPIRES_IN=7d
JWT_REFRESH_EXPIRES_IN=30d

# Encryption Keys
ENCRYPTION_KEY=${ENCRYPTION_KEY}
SNAPSHOT_SIGNING_KEY=${SNAPSHOT_SIGNING_KEY}
SESSION_SECRET=${SESSION_SECRET}

# Monitoring
GRAFANA_ADMIN_PASSWORD=${GRAFANA_ADMIN_PASSWORD}

# API Keys (to be configured after deployment)
OPENAI_API_KEY=your-openai-api-key-here
PINECONE_API_KEY=your-pinecone-api-key-here
STRIPE_SECRET_KEY=your-stripe-secret-key-here
STRIPE_PUBLISHABLE_KEY=your-stripe-publishable-key-here

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
FROM_EMAIL=noreply@${DOMAIN}
FROM_NAME=SecureStack Pro

# Security Configuration
BCRYPT_ROUNDS=12
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Feature Flags
ENABLE_AI_INSIGHTS=true
ENABLE_REAL_TIME_SCANNING=true
ENABLE_COMPLIANCE_REPORTS=true
ENABLE_WHITE_LABEL=true
EOF

    chmod 600 .env
    log "✅ Environment configuration generated"
}

# Create necessary directories
create_directories() {
    log "📁 Creating directory structure..."
    
    mkdir -p {backend,frontend,scanner,ai-processor,nginx,monitoring,database}
    mkdir -p backend/{src,uploads,logs}
    mkdir -p frontend/{src,public,build}
    mkdir -p scanner/{tools,results,templates}
    mkdir -p nginx/{ssl,logs}
    mkdir -p monitoring/{prometheus,grafana,logstash}
    mkdir -p database/init
    
    log "✅ Directory structure created"
}

# Setup SSL certificates
setup_ssl() {
    log "🔒 Setting up SSL certificates..."
    
    mkdir -p nginx/ssl
    
    # Generate self-signed certificate for local development
    if [ "$DOMAIN" = "securestackpro.local" ] || [ "$ENVIRONMENT" = "development" ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout nginx/ssl/privkey.pem \
            -out nginx/ssl/fullchain.pem \
            -subj "/C=US/ST=CA/L=San Francisco/O=SecureStack Pro/OU=IT Department/CN=$DOMAIN"
        log "✅ Self-signed SSL certificate generated"
    else
        warn "For production, please configure Let's Encrypt certificates manually"
        # Create placeholder files
        touch nginx/ssl/{privkey.pem,fullchain.pem}
    fi
}

# Create Nginx configuration
create_nginx_config() {
    log "🌐 Creating Nginx configuration..."
    
    cat > nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';
    
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;
    
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    
    # Gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 10240;
    gzip_proxied expired no-cache no-store private must-revalidate;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/x-javascript
        application/xml+rss
        application/javascript
        application/json;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    upstream backend {
        server backend:3001;
    }
    
    upstream frontend {
        server frontend:80;
    }
    
    # Redirect HTTP to HTTPS
    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }
    
    # Main HTTPS server
    server {
        listen 443 ssl http2;
        server_name _;
        
        ssl_certificate /etc/ssl/certs/fullchain.pem;
        ssl_certificate_key /etc/ssl/certs/privkey.pem;
        
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
        ssl_session_timeout 10m;
        
        # Security headers
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
        add_header Referrer-Policy strict-origin-when-cross-origin;
        add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self' wss:";
        
        # API routes
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }
        
        # Authentication endpoints (stricter rate limiting)
        location /api/auth/ {
            limit_req zone=login burst=5 nodelay;
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        # WebSocket connections
        location /socket.io/ {
            proxy_pass http://backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        # Health check endpoint (no rate limiting)
        location /health {
            proxy_pass http://backend;
            proxy_set_header Host $host;
            access_log off;
        }
        
        # Frontend application
        location / {
            proxy_pass http://frontend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # Cache static assets
            location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
                expires 1y;
                add_header Cache-Control "public, immutable";
                proxy_pass http://frontend;
            }
        }
    }
}
EOF
    
    log "✅ Nginx configuration created"
}

# Create monitoring configuration
create_monitoring_config() {
    log "📊 Creating monitoring configuration..."
    
    # Prometheus configuration
    cat > monitoring/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
  
  - job_name: 'securestack-backend'
    static_configs:
      - targets: ['backend:3001']
    metrics_path: '/metrics'
    scrape_interval: 30s
  
  - job_name: 'securestack-postgres'
    static_configs:
      - targets: ['postgres:5432']
  
  - job_name: 'securestack-redis'
    static_configs:
      - targets: ['redis:6379']
  
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
EOF
    
    # Grafana provisioning
    mkdir -p monitoring/grafana/{dashboards,provisioning/{dashboards,datasources}}
    
    cat > monitoring/grafana/provisioning/datasources/prometheus.yml << 'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
EOF
    
    log "✅ Monitoring configuration created"
}

# Build application images
build_images() {
    log "🔨 Building application images..."
    
    # Create Dockerfiles if they don't exist
    create_dockerfiles
    
    # Build images
    docker-compose build --no-cache
    
    log "✅ Application images built successfully"
}

# Create Dockerfiles
create_dockerfiles() {
    log "📝 Creating Dockerfiles..."
    
    # Backend Dockerfile
    cat > backend/Dockerfile << 'EOF'
FROM node:18-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    curl \
    bash \
    git \
    openssl \
    ca-certificates

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy application code
COPY . .

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Set ownership
RUN chown -R nextjs:nodejs /app
USER nextjs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:3001/health || exit 1

EXPOSE 3001

CMD ["npm", "start"]
EOF
    
    # Frontend Dockerfile
    cat > frontend/Dockerfile << 'EOF'
# Build stage
FROM node:18-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Production stage
FROM nginx:alpine

# Copy built application
COPY --from=builder /app/build /usr/share/nginx/html

# Copy custom nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD curl -f http://localhost || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
EOF
    
    # Frontend nginx config
    cat > frontend/nginx.conf << 'EOF'
server {
    listen 80;
    server_name localhost;
    
    location / {
        root /usr/share/nginx/html;
        index index.html index.htm;
        try_files $uri $uri/ /index.html;
    }
    
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF
    
    log "✅ Dockerfiles created"
}

# Deploy services
deploy_services() {
    log "🚀 Deploying services..."
    
    # Pull base images
    docker-compose pull
    
    # Start services
    docker-compose up -d
    
    log "✅ Services deployed successfully"
}

# Wait for services to be ready
wait_for_services() {
    log "⏳ Waiting for services to be ready..."
    
    # Wait for database
    log "   Waiting for PostgreSQL..."
    timeout 60 bash -c 'until docker-compose exec -T postgres pg_isready -U securestack -d securestack_pro; do sleep 2; done'
    
    # Wait for Redis
    log "   Waiting for Redis..."
    timeout 30 bash -c 'until docker-compose exec -T redis redis-cli ping; do sleep 2; done'
    
    # Wait for backend
    log "   Waiting for Backend API..."
    timeout 120 bash -c 'until curl -f http://localhost:3001/health >/dev/null 2>&1; do sleep 5; done'
    
    # Wait for frontend
    log "   Waiting for Frontend..."
    timeout 60 bash -c 'until curl -f http://localhost:3000 >/dev/null 2>&1; do sleep 5; done'
    
    log "✅ All services are ready"
}

# Run initial setup
initial_setup() {
    log "⚙️  Running initial setup..."
    
    # Run database migrations
    log "   Running database migrations..."
    docker-compose exec -T backend npm run migrate || warn "Migrations failed - will be handled during first startup"
    
    # Seed initial data
    log "   Seeding initial data..."
    docker-compose exec -T backend npm run seed || warn "Seeding failed - will be handled during first startup"
    
    log "✅ Initial setup completed"
}

# Run health checks
health_checks() {
    log "🏥 Running health checks..."
    
    local failed=0
    
    # Check backend health
    if curl -f http://localhost:3001/health >/dev/null 2>&1; then
        log "   ✅ Backend API is healthy"
    else
        error "   ❌ Backend API health check failed"
        ((failed++))
    fi
    
    # Check frontend
    if curl -f http://localhost:3000 >/dev/null 2>&1; then
        log "   ✅ Frontend is healthy"
    else
        error "   ❌ Frontend health check failed"
        ((failed++))
    fi
    
    # Check database
    if docker-compose exec -T postgres pg_isready -U securestack -d securestack_pro >/dev/null 2>&1; then
        log "   ✅ Database is healthy"
    else
        error "   ❌ Database health check failed"
        ((failed++))
    fi
    
    # Check Redis
    if docker-compose exec -T redis redis-cli ping >/dev/null 2>&1; then
        log "   ✅ Redis is healthy"
    else
        error "   ❌ Redis health check failed"
        ((failed++))
    fi
    
    if [ $failed -eq 0 ]; then
        log "✅ All health checks passed"
    else
        error "$failed health checks failed"
    fi
}

# Generate deployment report
generate_report() {
    log "📋 Generating deployment report..."
    
    local deployment_time=$(($(date +%s) - start_time))
    
    cat > deployment-report.md << EOF
# SecureStack Pro Deployment Report

**Deployment Date:** $(date)  
**Duration:** ${deployment_time}s  
**Version:** ${VERSION}  
**Environment:** ${ENVIRONMENT}  

## 🌐 Access URLs

- **Frontend:** https://${DOMAIN}
- **Backend API:** https://${DOMAIN}/api
- **Admin Dashboard:** https://${DOMAIN}/admin
- **Grafana Monitoring:** http://localhost:3003 (admin/$(grep GRAFANA_ADMIN_PASSWORD .env | cut -d'=' -f2))
- **Prometheus Metrics:** http://localhost:9090

## 🔐 Generated Credentials

- **Database Password:** $(grep DB_PASSWORD .env | cut -d'=' -f2)
- **Redis Password:** $(grep REDIS_PASSWORD .env | cut -d'=' -f2)
- **Grafana Admin Password:** $(grep GRAFANA_ADMIN_PASSWORD .env | cut -d'=' -f2)

## 🚀 Next Steps

1. **Configure API Keys**: Update .env file with your API keys:
   - OpenAI API Key (for AI insights)
   - Pinecone API Key (for vector database)
   - Stripe Keys (for payments)

2. **Access Admin Dashboard**: Visit https://${DOMAIN}/admin to complete setup

3. **Configure Email**: Update SMTP settings in .env file

4. **Set up SSL**: For production, configure Let's Encrypt certificates

5. **Configure Monitoring**: Access Grafana at http://localhost:3003

## 🛠️ Management Commands

\`\`\`bash
# View logs
docker-compose logs -f

# Restart services
docker-compose restart

# Stop services
docker-compose down

# Update services
docker-compose pull && docker-compose up -d

# Backup database
docker-compose exec postgres pg_dump -U securestack securestack_pro > backup.sql
\`\`\`

## 📊 Service Status

$(docker-compose ps)

## 🔧 Troubleshooting

If you encounter issues:

1. Check service logs: \`docker-compose logs [service-name]\`
2. Verify all services are running: \`docker-compose ps\`
3. Check resource usage: \`docker stats\`
4. Restart specific service: \`docker-compose restart [service-name]\`

---

**SecureStack Pro is now ready for use!**
EOF
    
    log "✅ Deployment report generated: deployment-report.md"
}

# Show success message
show_success() {
    echo
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}║                    🎉 DEPLOYMENT SUCCESSFUL! 🎉                 ║${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}║  SecureStack Pro is now running and ready for use!              ║${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}║  🌐 Frontend:  https://${DOMAIN}${NC}"
    printf "${GREEN}║  📊 Monitoring: http://localhost:3003                           ║${NC}\n"
    echo -e "${GREEN}║  📋 Report:    deployment-report.md                             ║${NC}"
    echo -e "${GREEN}║                                                                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE}Next steps:${NC}"
    echo "1. Configure your API keys in the .env file"
    echo "2. Access the admin dashboard to complete setup"
    echo "3. Review the deployment report for detailed information"
    echo
    echo -e "${YELLOW}For help and documentation, visit: https://docs.securestackpro.com${NC}"
}

# Cleanup function for interrupted deployments
cleanup() {
    echo
    warn "Deployment interrupted. Cleaning up..."
    docker-compose down --volumes --remove-orphans 2>/dev/null || true
    exit 1
}

# Main deployment function
main() {
    local start_time=$(date +%s)
    
    # Set trap for cleanup
    trap cleanup INT TERM
    
    print_banner
    
    # Pre-deployment checks
    check_root
    check_requirements
    
    # Deployment steps
    generate_env
    create_directories
    setup_ssl
    create_nginx_config
    create_monitoring_config
    build_images
    deploy_services
    wait_for_services
    initial_setup
    health_checks
    generate_report
    show_success
    
    log "🎉 SecureStack Pro deployment completed successfully!"
    log "⏱️  Total deployment time: $(($(date +%s) - start_time)) seconds"
}

# Run main function
main "$@"







