<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# CodeAware

**Know Your Code. Know Yourself.**

CodeAware is a SaaS platform that solves the Dunning-Kruger effect in software development by providing automated code quality assessment with awareness metrics.

## 🚀 The Problem We Solve

Traditional Dunning-Kruger in Coding:
1. Developers lack awareness to assess their code quality
2. They think their spaghetti code is acceptable
3. They ship buggy, insecure, non-scalable software
4. Reality catches up: apps break, security breaches occur, systems can't scale
5. Businesses lose money, reputation, and customer trust

## ✨ The Solution

CodeAware provides:

- **Automated Code Quality Analysis**: Real-time scanning for bugs, security issues, and anti-patterns
- **Awareness Metrics**: AI-powered assessment showing developers their actual skill level vs. perceived level
- **Skill Gap Identification**: Pinpoints exactly where developers have blind spots
- **Learning Pathways**: Customized training to address specific weaknesses
- **Business Intelligence**: Executive dashboards showing team-wide code quality and risk assessment
- **ROI Tracking**: Quantifiable metrics on code quality improvement over time

## 🏗️ Architecture

### Backend (FastAPI + Python)
- **API Server**: FastAPI with async support
- **Database**: PostgreSQL for data persistence
- **Cache**: Redis for caching and queue management
- **Task Queue**: Celery for background analysis jobs
- **Analysis Engine**: Multi-language code analyzer with ML-powered pattern detection

### Frontend (React + TypeScript)
- **UI Framework**: React 18 with TypeScript
- **Styling**: TailwindCSS
- **State Management**: Zustand + React Query
- **Charts**: Recharts for data visualization
- **Routing**: React Router v6

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Node.js 18+ (for local development)
- Python 3.11+ (for local development)

### Using Docker (Recommended)

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/codeaware.git
cd codeaware
```

2. **Set up environment variables**
```bash
cp backend/.env.example backend/.env
# Edit backend/.env with your configuration
```

3. **Start all services**
```bash
docker-compose up -d
```

4. **Access the application**
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/api/docs

### Local Development

#### Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment
cp .env.example .env

# Start PostgreSQL and Redis (using Docker)
docker-compose up -d postgres redis

# Run database migrations
alembic upgrade head

# Start development server
uvicorn app.main:app --reload
```

#### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

## 📊 Features

### For Developers
- ✅ Multi-language code analysis (Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#)
- ✅ Real-time quality, security, and complexity metrics
- ✅ Dunning-Kruger awareness scoring
- ✅ Personalized learning recommendations
- ✅ Progress tracking over time
- ✅ GitHub/GitLab/Bitbucket integration

### For Teams
- ✅ Team-wide code quality dashboards
- ✅ Comparative analytics
- ✅ Security vulnerability tracking
- ✅ Technical debt management
- ✅ Custom rules and policies

### For Businesses
- ✅ Executive reporting
- ✅ ROI metrics
- ✅ Compliance tracking
- ✅ Developer skill assessment
- ✅ Risk analysis

## 💰 Business Model

### Pricing Tiers

**Individual** - $29/month
- 10 repository scans per month
- Basic code quality analysis
- Personal awareness dashboard

**Professional** - $99/month
- 50 repository scans per month
- Advanced security scanning
- Custom learning paths
- API access

**Team** - $499/month
- Unlimited repository scans
- Team awareness dashboard
- Admin controls
- Integrations

**Enterprise** - Custom pricing
- On-premise deployment
- SSO/SAML integration
- Dedicated support
- Custom features

## 📖 API Documentation

Full API documentation is available at `/api/docs` when running the backend server.

### Key Endpoints

**Authentication**
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login and get access token

**Repositories**
- `GET /api/v1/repositories/` - List repositories
- `POST /api/v1/repositories/` - Add repository
- `GET /api/v1/repositories/{id}` - Get repository details

**Analyses**
- `POST /api/v1/analyses/` - Start new analysis
- `GET /api/v1/analyses/{id}` - Get analysis results
- `GET /api/v1/analyses/` - List analyses

**Subscriptions**
- `GET /api/v1/subscriptions/pricing` - Get pricing plans
- `POST /api/v1/subscriptions/` - Create subscription
- `GET /api/v1/subscriptions/me` - Get current subscription

## 🔒 Security

- All data encrypted at rest and in transit
- Code analyzed in isolated environments
- Source code never stored permanently
- SOC 2 Type II compliance (in progress)
- Regular security audits
- GDPR compliant

## 🧪 Testing

### Backend Tests
```bash
cd backend
pytest
```

### Frontend Tests
```bash
cd frontend
npm test
```

## 📈 Roadmap

### Q1 2025
- [x] MVP launch
- [x] Python and JavaScript support
- [x] Basic awareness metrics
- [ ] Beta program (50 users)

### Q2 2025
- [ ] Additional language support (Java, Go, Ruby)
- [ ] Advanced ML-based pattern detection
- [ ] Team collaboration features
- [ ] Mobile app

### Q3 2025
- [ ] Enterprise features (SSO, on-premise)
- [ ] IDE plugins (VSCode, JetBrains)
- [ ] Advanced reporting
- [ ] White-label option

### Q4 2025
- [ ] AI-powered code suggestions
- [ ] Automated refactoring recommendations
- [ ] Integration marketplace
- [ ] International expansion

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

Copyright © 2025 CodeAware. All rights reserved.

This is proprietary software. See [LICENSE](LICENSE) for details.

## 💬 Support

- **Email**: support@codeaware.io
- **Documentation**: https://docs.codeaware.io
- **Community**: https://community.codeaware.io
- **Twitter**: @codeaware_io

## 🎯 Target Market

- **Enterprise Dev Teams**: 10-500+ developers needing quality oversight
- **Software Agencies**: Delivering client projects with quality assurance
- **Individual Developers**: Career advancement and skill improvement
- **Coding Bootcamps**: Student assessment and placement success

## 📊 Market Opportunity

- Global software development market: $500B+
- Code quality tools market: $5B (15% YoY growth)
- 27M+ developers worldwide
- 67% of developers overestimate their code quality
- $2.08 trillion spent annually fixing bad code

## 🏆 Competitive Advantage

1. **Unique Focus**: Only platform addressing developer awareness and Dunning-Kruger effect
2. **Holistic Assessment**: Quality + Security + Awareness in one platform
3. **Actionable Intelligence**: Not just "what's wrong" but "how to fix it"
4. **Business ROI**: Clear metrics for leadership on team improvement
5. **Continuous Learning**: Integrated with learning resources

## 👥 Team

Built by experienced developers who've felt the pain of poor code awareness firsthand.

## 💼 For Investors

Interested in learning more? Contact us at investors@codeaware.io

---

**Built with ❤️ to make great code the standard**




