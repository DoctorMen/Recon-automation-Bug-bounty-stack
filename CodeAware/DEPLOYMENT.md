<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# CodeAware Deployment Guide

This guide covers deploying CodeAware to production environments.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Environment Setup](#environment-setup)
- [Database Setup](#database-setup)
- [Backend Deployment](#backend-deployment)
- [Frontend Deployment](#frontend-deployment)
- [Docker Deployment](#docker-deployment)
- [Cloud Deployment](#cloud-deployment)
- [Monitoring & Maintenance](#monitoring--maintenance)

## Prerequisites

### Required Services
- PostgreSQL 15+
- Redis 7+
- Node.js 18+
- Python 3.11+
- Docker (optional but recommended)

### Cloud Requirements
- **Option 1**: AWS (EC2, RDS, ElastiCache, S3)
- **Option 2**: Google Cloud Platform (Compute Engine, Cloud SQL, Memorystore)
- **Option 3**: Azure (Virtual Machines, Database for PostgreSQL, Cache for Redis)
- **Option 4**: DigitalOcean (Droplets, Managed Databases)

## Environment Setup

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/codeaware.git
cd codeaware
```

### 2. Configure Environment Variables

#### Backend (.env)
```bash
cd backend
cp .env.example .env
```

**Required Variables:**
```env
# Application
PROJECT_NAME=CodeAware
DEBUG=false

# Security (CHANGE THESE!)
SECRET_KEY=<generate-secure-random-key>
ACCESS_TOKEN_EXPIRE_MINUTES=10080

# Database
DATABASE_URL=postgresql+asyncpg://user:password@host:5432/codeaware

# Redis
REDIS_URL=redis://host:6379/0
CELERY_BROKER_URL=redis://host:6379/1
CELERY_RESULT_BACKEND=redis://host:6379/2

# Stripe
STRIPE_SECRET_KEY=sk_live_your_key
STRIPE_PUBLIC_KEY=pk_live_your_key
STRIPE_WEBHOOK_SECRET=whsec_your_secret
```

**Generate Secure Keys:**
```bash
# Generate SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Database Setup

### PostgreSQL

#### Create Database
```sql
CREATE DATABASE codeaware;
CREATE USER codeaware WITH PASSWORD 'your-secure-password';
GRANT ALL PRIVILEGES ON DATABASE codeaware TO codeaware;
```

#### Run Migrations
```bash
cd backend
alembic upgrade head
```

### Redis Setup
```bash
# Install Redis
sudo apt-get install redis-server

# Start Redis
sudo systemctl start redis
sudo systemctl enable redis
```

## Backend Deployment

### Option 1: Docker (Recommended)

```bash
# Build image
docker build -t codeaware-backend ./backend

# Run container
docker run -d \
  --name codeaware-api \
  -p 8000:8000 \
  --env-file backend/.env \
  codeaware-backend
```

### Option 2: Systemd Service

Create `/etc/systemd/system/codeaware-api.service`:

```ini
[Unit]
Description=CodeAware API
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/codeaware/backend
Environment="PATH=/opt/codeaware/backend/venv/bin"
ExecStart=/opt/codeaware/backend/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable codeaware-api
sudo systemctl start codeaware-api
```

### Celery Worker Service

Create `/etc/systemd/system/codeaware-worker.service`:

```ini
[Unit]
Description=CodeAware Celery Worker
After=network.target redis.service

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/codeaware/backend
Environment="PATH=/opt/codeaware/backend/venv/bin"
ExecStart=/opt/codeaware/backend/venv/bin/celery -A app.celery_app worker --loglevel=info --concurrency=4

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Frontend Deployment

### Option 1: Static Build + Nginx

```bash
cd frontend

# Build production bundle
npm run build

# Copy to nginx directory
sudo cp -r dist/* /var/www/codeaware/
```

#### Nginx Configuration

Create `/etc/nginx/sites-available/codeaware`:

```nginx
server {
    listen 80;
    server_name codeaware.io www.codeaware.io;

    root /var/www/codeaware;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Enable gzip compression
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/x-javascript application/xml+rss application/javascript application/json;
}
```

Enable site:
```bash
sudo ln -s /etc/nginx/sites-available/codeaware /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Option 2: Docker

```bash
# Build image
docker build -t codeaware-frontend ./frontend

# Run container
docker run -d \
  --name codeaware-web \
  -p 3000:3000 \
  codeaware-frontend
```

## SSL/HTTPS Setup

### Using Let's Encrypt (Certbot)

```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d codeaware.io -d www.codeaware.io

# Auto-renewal
sudo certbot renew --dry-run
```

## Docker Compose Deployment

For full-stack deployment:

```bash
# Production docker-compose
docker-compose -f docker-compose.prod.yml up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

## Cloud Deployment

### AWS Deployment

#### 1. EC2 Instance Setup
```bash
# Launch Ubuntu 22.04 LTS instance (t3.medium or larger)
# Open ports: 80, 443, 22

# Connect and install dependencies
ssh ubuntu@your-instance-ip
sudo apt-get update
sudo apt-get install -y docker.io docker-compose nginx
```

#### 2. RDS PostgreSQL Setup
- Create RDS PostgreSQL 15 instance
- Configure security group to allow EC2 access
- Note connection string

#### 3. ElastiCache Redis Setup
- Create ElastiCache Redis cluster
- Configure security group
- Note connection endpoint

#### 4. Deploy Application
```bash
# Clone repo
git clone https://github.com/yourusername/codeaware.git
cd codeaware

# Configure environment
cp backend/.env.example backend/.env
# Edit with RDS and ElastiCache endpoints

# Deploy
docker-compose up -d
```

### Google Cloud Platform

```bash
# Create VM instance
gcloud compute instances create codeaware \
    --machine-type=n1-standard-2 \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --boot-disk-size=50GB

# Create Cloud SQL instance
gcloud sql instances create codeaware-db \
    --database-version=POSTGRES_15 \
    --tier=db-f1-micro \
    --region=us-central1

# Create Memorystore Redis
gcloud redis instances create codeaware-cache \
    --size=1 \
    --region=us-central1
```

## Monitoring & Maintenance

### Health Checks

```bash
# API health
curl http://localhost:8000/health

# Database connection
docker-compose exec backend python -c "from app.db.session import engine; print('OK')"
```

### Logging

#### Backend Logs
```bash
# Docker
docker-compose logs -f backend

# Systemd
sudo journalctl -u codeaware-api -f
```

#### Frontend Logs
```bash
docker-compose logs -f frontend
```

### Backup Strategy

#### Database Backup
```bash
# Automated daily backup
pg_dump -U codeaware -h localhost codeaware > backup_$(date +%Y%m%d).sql

# Restore
psql -U codeaware -h localhost codeaware < backup_20250104.sql
```

#### Cron Job
```bash
# Edit crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * /opt/codeaware/scripts/backup.sh
```

### Monitoring Tools

#### Sentry (Error Tracking)
```env
SENTRY_DSN=https://your-sentry-dsn
```

#### Prometheus + Grafana
```bash
docker-compose -f docker-compose.monitoring.yml up -d
```

### Scaling

#### Horizontal Scaling
```bash
# Backend: Add more API workers
docker-compose up -d --scale backend=3

# Celery: Add more workers
docker-compose up -d --scale celery-worker=5
```

#### Load Balancing (Nginx)
```nginx
upstream backend {
    server backend1:8000;
    server backend2:8000;
    server backend3:8000;
}

server {
    location /api {
        proxy_pass http://backend;
    }
}
```

## Performance Optimization

### Database
```sql
-- Add indexes
CREATE INDEX idx_analyses_user_id ON analyses(user_id);
CREATE INDEX idx_analyses_status ON analyses(status);
CREATE INDEX idx_repositories_owner_id ON repositories(owner_id);
```

### Redis Caching
```python
# Cache frequently accessed data
# Implement in backend code
```

### CDN Setup
- Use CloudFlare or AWS CloudFront for static assets
- Enable caching headers

## Security Checklist

- [ ] Change all default passwords
- [ ] Enable HTTPS with valid SSL certificate
- [ ] Configure firewall (only ports 80, 443 open)
- [ ] Set up regular backups
- [ ] Enable database encryption at rest
- [ ] Configure rate limiting
- [ ] Set up monitoring and alerting
- [ ] Implement IP whitelisting for admin panel
- [ ] Enable two-factor authentication
- [ ] Regular security updates

## Troubleshooting

### Common Issues

**Database Connection Failed**
```bash
# Check PostgreSQL is running
sudo systemctl status postgresql

# Verify connection string
psql $DATABASE_URL
```

**Redis Connection Failed**
```bash
# Check Redis
redis-cli ping

# Check connectivity
telnet localhost 6379
```

**Application Won't Start**
```bash
# Check logs
docker-compose logs backend

# Verify environment variables
docker-compose config
```

## Support

For deployment support:
- Email: devops@codeaware.io
- Docs: https://docs.codeaware.io/deployment
- Slack: codeaware.slack.com

---

**Remember to review and update this guide as the infrastructure evolves!**




