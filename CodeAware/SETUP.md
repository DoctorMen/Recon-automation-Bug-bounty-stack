<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# CodeAware Setup Guide

This guide will help you get CodeAware up and running quickly.

## Quick Start (5 minutes)

The fastest way to run CodeAware is using Docker Compose:

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/codeaware.git
cd codeaware

# 2. Set up environment variables
cp backend/.env.example backend/.env
# Edit backend/.env with your settings

# 3. Start all services
docker-compose up -d

# 4. Access the application
# Frontend: http://localhost:3000
# Backend API: http://localhost:8000
# API Docs: http://localhost:8000/api/docs
```

That's it! CodeAware is now running.

## What's Included

When you run `docker-compose up`, you get:

- **PostgreSQL**: Database for storing users, analyses, and subscriptions
- **Redis**: Cache and message queue
- **Backend API**: FastAPI server with code analysis engine
- **Celery Worker**: Background job processor for code analysis
- **Frontend**: React web application

## First Steps After Installation

### 1. Create Your Account

Visit http://localhost:3000 and click "Get Started" to create your account.

### 2. Add a Repository

1. Go to "Repositories" in the navigation
2. Click "Add Repository"
3. Fill in your repository details
4. Click "Run Analysis"

### 3. View Your Results

Once the analysis completes (usually 2-5 minutes), you'll see:
- Overall code quality score
- Security vulnerabilities
- Awareness metrics (Dunning-Kruger score)
- Detailed issue breakdown
- Personalized learning recommendations

## Detailed Setup Instructions

### Option 1: Docker (Recommended for Production)

See [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment instructions.

### Option 2: Local Development

#### Prerequisites
- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+

#### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/Mac:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env with your database credentials

# Run migrations
alembic upgrade head

# Start the server
uvicorn app.main:app --reload
```

Backend will be available at http://localhost:8000

#### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

Frontend will be available at http://localhost:3000

#### Start Celery Worker (for code analysis)

```bash
cd backend
celery -A app.celery_app worker --loglevel=info
```

## Configuration

### Environment Variables

The most important environment variables to configure:

#### Backend (.env)

```env
# Database
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/codeaware

# Security
SECRET_KEY=<generate-secure-key>

# Redis
REDIS_URL=redis://localhost:6379/0

# Optional: GitHub Integration
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Optional: Stripe (for payments)
STRIPE_SECRET_KEY=sk_test_your_key
```

### Generating Secure Keys

```bash
# Generate SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Supported Languages

CodeAware currently supports:
- ✅ Python
- ✅ JavaScript
- ✅ TypeScript
- 🔄 Java (coming soon)
- 🔄 Go (coming soon)
- 🔄 Ruby (coming soon)

## Troubleshooting

### "Database connection failed"

**Problem**: Cannot connect to PostgreSQL

**Solution**:
```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check logs
docker-compose logs postgres

# Restart PostgreSQL
docker-compose restart postgres
```

### "Redis connection failed"

**Problem**: Cannot connect to Redis

**Solution**:
```bash
# Check if Redis is running
docker-compose ps redis

# Test connection
redis-cli ping

# Restart Redis
docker-compose restart redis
```

### "Analysis stuck in 'pending' status"

**Problem**: Celery worker not running

**Solution**:
```bash
# Check worker status
docker-compose ps celery-worker

# View worker logs
docker-compose logs celery-worker

# Restart worker
docker-compose restart celery-worker
```

### "Frontend shows blank page"

**Problem**: Build or configuration issue

**Solution**:
```bash
# Check frontend logs
docker-compose logs frontend

# Rebuild frontend
cd frontend
npm run build

# Clear browser cache and reload
```

### "Cannot clone repository"

**Problem**: Git access or authentication issue

**Solution**:
- Ensure the repository URL is correct and accessible
- For private repositories, set up SSH keys or access tokens
- Check that the repository is not too large (default limit: 500MB)

## System Requirements

### Minimum
- **CPU**: 2 cores
- **RAM**: 4GB
- **Disk**: 20GB
- **OS**: Linux, macOS, or Windows with WSL2

### Recommended
- **CPU**: 4+ cores
- **RAM**: 8GB+
- **Disk**: 50GB+ SSD
- **OS**: Ubuntu 22.04 LTS

## Performance Tips

### For Large Repositories
```env
# Increase analysis timeout (backend/.env)
ANALYSIS_TIMEOUT_SECONDS=600

# Increase max repository size
MAX_REPO_SIZE_MB=1000
```

### For High Traffic
```bash
# Scale backend API
docker-compose up -d --scale backend=3

# Scale Celery workers
docker-compose up -d --scale celery-worker=5
```

## Security Checklist

Before deploying to production:

- [ ] Change default database passwords
- [ ] Generate secure SECRET_KEY
- [ ] Enable HTTPS with valid SSL certificate
- [ ] Set up firewall rules
- [ ] Configure CORS properly
- [ ] Set DEBUG=false
- [ ] Set up regular backups
- [ ] Review and restrict database access
- [ ] Enable rate limiting
- [ ] Configure Sentry or error tracking

## Updating CodeAware

```bash
# Pull latest changes
git pull origin main

# Update backend dependencies
cd backend
pip install -r requirements.txt
alembic upgrade head

# Update frontend dependencies
cd ../frontend
npm install

# Restart services
docker-compose restart
```

## Getting Help

### Documentation
- **Full Docs**: https://docs.codeaware.io
- **API Reference**: http://localhost:8000/api/docs (when running)

### Support
- **Email**: support@codeaware.io
- **GitHub Issues**: https://github.com/yourusername/codeaware/issues
- **Community**: https://community.codeaware.io

### Common Resources
- [Business Plan](BUSINESS_PLAN.md) - Understand the business model
- [Deployment Guide](DEPLOYMENT.md) - Production deployment
- [Marketing Strategy](MARKETING_STRATEGY.md) - Go-to-market approach
- [Sales Playbook](SALES_PLAYBOOK.md) - Sales process

## Next Steps

Now that you have CodeAware running:

1. **Try it out**: Analyze a few repositories
2. **Explore features**: Check awareness metrics, learning recommendations
3. **Customize**: Configure for your specific needs
4. **Deploy**: Move to production when ready
5. **Scale**: Grow your usage as needed

## License & Business

CodeAware is a commercial product. See [BUSINESS_PLAN.md](BUSINESS_PLAN.md) for pricing and licensing options.

For enterprise deployments, custom features, or white-label options, contact: sales@codeaware.io

---

**Welcome to CodeAware! Let's eliminate the Dunning-Kruger effect in coding together.**




