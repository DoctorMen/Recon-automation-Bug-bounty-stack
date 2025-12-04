<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Getting Started with CodeAware

## Welcome! 👋

CodeAware helps you understand your true code quality and eliminate blind spots. This guide will get you from zero to your first analysis in under 10 minutes.

## What You'll Learn

1. How to set up your account
2. How to connect your first repository
3. How to run your first analysis
4. How to interpret your results
5. How to improve based on recommendations

## Step 1: Create Your Account (2 minutes)

### Option A: Web Application

1. Visit http://localhost:3000 (or https://app.codeaware.io for cloud)
2. Click **"Get Started"** or **"Sign Up"**
3. Fill in your details:
   - Full Name
   - Email
   - Username
   - Password (minimum 8 characters)
4. Click **"Create Account"**
5. You're in! 🎉

### Option B: API (for automation)

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@example.com",
    "username": "yourusername",
    "password": "yourpassword",
    "full_name": "Your Name"
  }'
```

## Step 2: Connect Your First Repository (3 minutes)

### Via Web Interface

1. Click **"Repositories"** in the navigation
2. Click **"Add Repository"**
3. Fill in repository details:
   - **Name**: Your project name (e.g., "my-app")
   - **Full Name**: owner/repo format (e.g., "username/my-app")
   - **Provider**: GitHub, GitLab, or Bitbucket
   - **Repository URL**: Full HTTPS URL to your repo
   - **Default Branch**: Usually "main" or "master"
   - **Language**: Primary language (optional)
4. Click **"Add Repository"**

### Via API

```bash
curl -X POST http://localhost:8000/api/v1/repositories/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-app",
    "full_name": "username/my-app",
    "provider": "github",
    "provider_url": "https://github.com/username/my-app",
    "default_branch": "main",
    "language": "Python"
  }'
```

## Step 3: Run Your First Analysis (1 minute to start)

### Via Web Interface

1. Find your repository in the list
2. Click **"Run Analysis"**
3. Wait for analysis to complete (usually 2-5 minutes)
4. You'll see a progress indicator

### Via API

```bash
curl -X POST http://localhost:8000/api/v1/analyses/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "repository_id": 1,
    "branch": "main"
  }'
```

### What Happens During Analysis?

CodeAware:
1. ✅ Clones your repository (securely, temporarily)
2. ✅ Analyzes code structure and patterns
3. ✅ Checks for security vulnerabilities
4. ✅ Calculates complexity metrics
5. ✅ Detects code smells and anti-patterns
6. ✅ Computes awareness metrics
7. ✅ Generates personalized recommendations
8. ✅ Cleans up (your code is never stored permanently)

## Step 4: Understanding Your Results (5 minutes)

### Overall Score

Your **Overall Quality Score** (0-100) combines:
- **Quality**: Code structure, maintainability
- **Security**: Vulnerabilities and risks
- **Maintainability**: How easy to change
- **Scalability**: Architectural quality

**What's a Good Score?**
- 90-100: Excellent! 🟢
- 70-89: Good, room for improvement 🟡
- 50-69: Needs attention 🟠
- Below 50: Critical issues 🔴

### Awareness Metrics (The Secret Sauce!)

#### Dunning-Kruger Score
This shows whether you're **overconfident** about your code quality.

**Score Meaning:**
- **0-25**: Good self-awareness! You have a realistic view of your code.
- **25-50**: Moderate overconfidence. Some blind spots exist.
- **50-75**: High overconfidence. You're likely unaware of many issues.
- **75-100**: Severe Dunning-Kruger effect. Critical blind spots.

#### Awareness Gap
The difference between your perceived skill and actual measured quality.

- **Positive**: Overconfident (think you're better than you are)
- **Negative**: Underconfident (too hard on yourself)
- **Near Zero**: Well-calibrated (realistic self-assessment)

### Issue Breakdown

Issues are categorized by:

**Severity:**
- 🔴 **Critical**: Security vulnerabilities, major bugs
- 🟠 **High**: Important issues affecting quality
- 🟡 **Medium**: Code smells, moderate concerns
- 🟢 **Low**: Minor improvements, style issues

**Category:**
- 🔒 **Security**: Vulnerabilities, unsafe practices
- 🐛 **Bug**: Logic errors, potential failures
- 🔧 **Code Smell**: Maintainability issues
- 📊 **Complexity**: Overly complex code
- 📖 **Documentation**: Missing or poor docs

### Learning Recommendations

For each major issue category, you'll get:
- **What to learn**: Specific skill gap
- **Why it matters**: Business impact
- **How to improve**: Resource recommendations
- **Priority**: High/Medium/Low

## Step 5: Take Action (Ongoing)

### Immediate Actions

1. **Fix Critical Issues First**
   - Focus on security vulnerabilities
   - Address high-severity bugs
   - These have immediate business impact

2. **Review Awareness Gap**
   - If overconfident: Be more cautious
   - Study the learning recommendations
   - Get code reviews from senior developers

3. **Follow Learning Paths**
   - Start with high-priority recommendations
   - Dedicate 1-2 hours per week to learning
   - Track progress with re-analyses

### Ongoing Practices

**Weekly:**
- Run analysis on new branches
- Review new issues before merging
- Track improvement trends

**Monthly:**
- Review awareness metrics
- Complete 1-2 learning modules
- Compare scores month-over-month

**Quarterly:**
- Comprehensive skill assessment
- Team quality review (if Team plan)
- Adjust learning priorities

## Tips for Success

### 1. Don't Be Discouraged
Your first analysis might show many issues. **This is normal!** Most codebases have 50-200 issues. The goal is improvement, not perfection.

### 2. Celebrate Improvements
Track your progress. Even a 5-point improvement in quality score is meaningful and represents real skill growth.

### 3. Share with Your Team
If you're on a team plan, encourage others to use CodeAware. Team-wide quality improvement compounds.

### 4. Integrate into Workflow
- Run analysis before major releases
- Check quality on new features
- Use as part of code review process

### 5. Focus on Learning
The awareness metrics are most valuable when you act on them. Dedicate time to learning.

## Common Questions

### "Why is my score lower than expected?"
This is the Dunning-Kruger effect in action! Most developers overestimate their code quality by 20-40 points. Your score reflects objective measurement, not perceived skill.

### "How often should I run analyses?"
- **Development**: Before each merge/release
- **Learning**: Weekly to track improvement
- **Minimum**: Monthly to maintain visibility

### "Are the issues accurate?"
CodeAware uses industry-standard tools plus ML models. Accuracy is typically 85-95%. Some false positives are possible - use your judgment.

### "How long until I see improvement?"
Most developers see measurable improvement within 4-8 weeks of following learning recommendations.

### "Can I analyze private repositories?"
Yes! CodeAware analyzes code in isolated environments and never stores your source code permanently.

## Example Workflow

Here's how a typical developer uses CodeAware:

**Monday Morning:**
```
1. Start sprint
2. Run analysis on main branch (baseline)
3. Note current awareness gap
```

**During Development:**
```
4. Write code as normal
5. Before committing, run local quality checks
6. Address obvious issues
```

**Before Merge:**
```
7. Run analysis on feature branch
8. Compare to baseline
9. Fix any new critical/high issues
10. Merge confidently
```

**Friday Afternoon:**
```
11. Review week's analyses
12. Spend 30 minutes on learning recommendations
13. Plan next week's improvement focus
```

**Monthly Review:**
```
14. Compare this month vs. last month
15. Celebrate improvements
16. Adjust learning priorities
```

## Next Steps

Now that you've run your first analysis:

1. ✅ Review all critical and high issues
2. ✅ Read your learning recommendations
3. ✅ Set up weekly analysis schedule
4. ✅ Join our community for tips and support
5. ✅ Consider upgrading for more features

## Resources

- **Dashboard**: See all your analyses
- **API Docs**: http://localhost:8000/api/docs
- **Community**: https://community.codeaware.io
- **Support**: support@codeaware.io
- **Learning Hub**: https://learn.codeaware.io

## Need Help?

**Stuck?** We're here to help:
- 📧 Email: support@codeaware.io
- 💬 Community: community.codeaware.io
- 📖 Full Docs: docs.codeaware.io

## Pricing & Plans

### Free Features
- 5 analyses per month
- Basic quality metrics
- Learning recommendations

### Paid Plans
- **Individual**: $29/mo - 10 analyses, all features
- **Professional**: $99/mo - 50 analyses, API access
- **Team**: $499/mo - Unlimited, team dashboard
- **Enterprise**: Custom - On-premise, SSO, SLA

Start with free, upgrade when you need more!

---

**Welcome to better code quality and self-awareness! 🚀**

Questions? Email us at support@codeaware.io - we'd love to hear from you!




