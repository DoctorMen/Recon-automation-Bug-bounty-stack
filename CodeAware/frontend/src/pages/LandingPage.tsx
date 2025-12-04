import { Link } from 'react-router-dom'
import { 
  Code2, 
  Shield, 
  TrendingUp, 
  Zap, 
  CheckCircle, 
  AlertTriangle,
  Target,
  Brain
} from 'lucide-react'

export default function LandingPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-white">
      {/* Navigation */}
      <nav className="container mx-auto px-4 py-6">
        <div className="flex justify-between items-center">
          <div className="flex items-center space-x-2">
            <Brain className="w-8 h-8 text-primary-600" />
            <span className="text-2xl font-bold text-gray-900">CodeAware</span>
          </div>
          <div className="space-x-4">
            <Link to="/pricing" className="text-gray-600 hover:text-gray-900">
              Pricing
            </Link>
            <Link to="/login" className="text-gray-600 hover:text-gray-900">
              Login
            </Link>
            <Link to="/register" className="btn btn-primary">
              Get Started Free
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20">
        <div className="text-center max-w-4xl mx-auto animate-fade-in">
          <h1 className="text-6xl font-bold text-gray-900 mb-6">
            Know Your Code.
            <br />
            <span className="text-primary-600">Know Yourself.</span>
          </h1>
          <p className="text-xl text-gray-600 mb-8">
            Stop the Dunning-Kruger effect in its tracks. Get automated code quality 
            assessment with awareness metrics that show you exactly where you stand.
          </p>
          <div className="flex justify-center space-x-4">
            <Link to="/register" className="btn btn-primary text-lg px-8 py-3">
              Start Free Trial
            </Link>
            <Link to="/pricing" className="btn btn-outline text-lg px-8 py-3">
              View Pricing
            </Link>
          </div>
          
          {/* Social Proof */}
          <div className="mt-12 flex justify-center items-center space-x-8 text-gray-600">
            <div>
              <div className="text-3xl font-bold text-primary-600">10K+</div>
              <div className="text-sm">Developers</div>
            </div>
            <div>
              <div className="text-3xl font-bold text-primary-600">500K+</div>
              <div className="text-sm">Analyses</div>
            </div>
            <div>
              <div className="text-3xl font-bold text-primary-600">40%</div>
              <div className="text-sm">Bug Reduction</div>
            </div>
          </div>
        </div>
      </section>

      {/* Problem Section */}
      <section className="bg-red-50 py-20">
        <div className="container mx-auto px-4">
          <div className="max-w-4xl mx-auto">
            <div className="flex items-center justify-center mb-6">
              <AlertTriangle className="w-12 h-12 text-red-600" />
            </div>
            <h2 className="text-4xl font-bold text-center text-gray-900 mb-12">
              The Problem: You Don't Know What You Don't Know
            </h2>
            
            <div className="grid md:grid-cols-2 gap-8">
              <div className="bg-white rounded-lg p-6 shadow-lg">
                <h3 className="text-xl font-bold text-red-600 mb-4">
                  The Dunning-Kruger Effect in Coding
                </h3>
                <ul className="space-y-3">
                  <li className="flex items-start">
                    <span className="text-red-500 mr-2">❌</span>
                    <span>Developers lack awareness of their code quality</span>
                  </li>
                  <li className="flex items-start">
                    <span className="text-red-500 mr-2">❌</span>
                    <span>Think their spaghetti code is acceptable</span>
                  </li>
                  <li className="flex items-start">
                    <span className="text-red-500 mr-2">❌</span>
                    <span>Ship buggy, insecure, non-scalable software</span>
                  </li>
                  <li className="flex items-start">
                    <span className="text-red-500 mr-2">❌</span>
                    <span>Apps break, security breaches occur</span>
                  </li>
                </ul>
              </div>
              
              <div className="bg-white rounded-lg p-6 shadow-lg">
                <h3 className="text-xl font-bold text-green-600 mb-4">
                  The Cost to Your Business
                </h3>
                <ul className="space-y-3">
                  <li className="flex items-start">
                    <span className="text-yellow-500 mr-2">💰</span>
                    <span>$2.08 trillion spent annually fixing bad code</span>
                  </li>
                  <li className="flex items-start">
                    <span className="text-yellow-500 mr-2">⏱️</span>
                    <span>23% of developer time fixing quality issues</span>
                  </li>
                  <li className="flex items-start">
                    <span className="text-yellow-500 mr-2">🔒</span>
                    <span>83% of breaches from code vulnerabilities</span>
                  </li>
                  <li className="flex items-start">
                    <span className="text-yellow-500 mr-2">📉</span>
                    <span>Lost customers and reputation damage</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Solution Section */}
      <section className="py-20">
        <div className="container mx-auto px-4">
          <h2 className="text-4xl font-bold text-center text-gray-900 mb-12">
            The Solution: Automated Code Quality + Awareness Metrics
          </h2>
          
          <div className="grid md:grid-cols-3 gap-8 max-w-6xl mx-auto">
            <div className="card text-center">
              <div className="flex justify-center mb-4">
                <Code2 className="w-12 h-12 text-primary-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Automated Analysis</h3>
              <p className="text-gray-600">
                Real-time scanning for bugs, security issues, complexity, and best practices
                across multiple languages.
              </p>
            </div>
            
            <div className="card text-center">
              <div className="flex justify-center mb-4">
                <Target className="w-12 h-12 text-primary-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Awareness Metrics</h3>
              <p className="text-gray-600">
                See your actual skill level vs. perceived level. Identify blind spots and
                overconfidence patterns.
              </p>
            </div>
            
            <div className="card text-center">
              <div className="flex justify-center mb-4">
                <TrendingUp className="w-12 h-12 text-primary-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Personalized Learning</h3>
              <p className="text-gray-600">
                Get customized recommendations and learning paths to address your specific
                weaknesses.
              </p>
            </div>
            
            <div className="card text-center">
              <div className="flex justify-center mb-4">
                <Shield className="w-12 h-12 text-primary-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Security Scanning</h3>
              <p className="text-gray-600">
                Detect vulnerabilities before they become breaches. CVE matching and
                security hotspot detection.
              </p>
            </div>
            
            <div className="card text-center">
              <div className="flex justify-center mb-4">
                <Zap className="w-12 h-12 text-primary-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Business Intelligence</h3>
              <p className="text-gray-600">
                Executive dashboards showing team-wide quality metrics and ROI tracking.
              </p>
            </div>
            
            <div className="card text-center">
              <div className="flex justify-center mb-4">
                <CheckCircle className="w-12 h-12 text-primary-600" />
              </div>
              <h3 className="text-xl font-bold mb-3">Continuous Improvement</h3>
              <p className="text-gray-600">
                Track improvement over time. See tangible progress in your coding skills
                and team quality.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="bg-gray-50 py-20">
        <div className="container mx-auto px-4">
          <h2 className="text-4xl font-bold text-center text-gray-900 mb-12">
            How It Works
          </h2>
          
          <div className="max-w-4xl mx-auto">
            <div className="space-y-8">
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 w-12 h-12 bg-primary-600 text-white rounded-full flex items-center justify-center text-xl font-bold">
                  1
                </div>
                <div>
                  <h3 className="text-2xl font-bold mb-2">Connect Your Repository</h3>
                  <p className="text-gray-600">
                    Link your GitHub, GitLab, or Bitbucket account. Select repositories
                    to analyze.
                  </p>
                </div>
              </div>
              
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 w-12 h-12 bg-primary-600 text-white rounded-full flex items-center justify-center text-xl font-bold">
                  2
                </div>
                <div>
                  <h3 className="text-2xl font-bold mb-2">Get Your Analysis</h3>
                  <p className="text-gray-600">
                    Our AI analyzes your code for quality, security, complexity, and
                    patterns. Results in minutes.
                  </p>
                </div>
              </div>
              
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 w-12 h-12 bg-primary-600 text-white rounded-full flex items-center justify-center text-xl font-bold">
                  3
                </div>
                <div>
                  <h3 className="text-2xl font-bold mb-2">See Your Awareness Gap</h3>
                  <p className="text-gray-600">
                    Discover where you're overconfident or underconfident. Understand
                    your blind spots.
                  </p>
                </div>
              </div>
              
              <div className="flex items-start space-x-4">
                <div className="flex-shrink-0 w-12 h-12 bg-primary-600 text-white rounded-full flex items-center justify-center text-xl font-bold">
                  4
                </div>
                <div>
                  <h3 className="text-2xl font-bold mb-2">Improve with Guidance</h3>
                  <p className="text-gray-600">
                    Follow personalized learning paths. Track your progress. Become a
                    better developer.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 bg-primary-600">
        <div className="container mx-auto px-4 text-center">
          <h2 className="text-4xl font-bold text-white mb-6">
            Ready to Know Your True Code Quality?
          </h2>
          <p className="text-xl text-primary-100 mb-8 max-w-2xl mx-auto">
            Join 10,000+ developers who've improved their code quality and eliminated
            blind spots with CodeAware.
          </p>
          <Link
            to="/register"
            className="inline-block bg-white text-primary-600 px-8 py-4 rounded-lg text-lg font-bold hover:bg-gray-100 transition-all"
          >
            Start Your Free Trial →
          </Link>
          <p className="text-primary-100 mt-4">No credit card required • 14-day free trial</p>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-gray-400 py-12">
        <div className="container mx-auto px-4">
          <div className="grid md:grid-cols-4 gap-8">
            <div>
              <div className="flex items-center space-x-2 mb-4">
                <Brain className="w-6 h-6 text-primary-600" />
                <span className="text-xl font-bold text-white">CodeAware</span>
              </div>
              <p className="text-sm">
                Automated code quality assessment with awareness metrics.
              </p>
            </div>
            
            <div>
              <h4 className="text-white font-bold mb-4">Product</h4>
              <ul className="space-y-2 text-sm">
                <li><Link to="/pricing">Pricing</Link></li>
                <li><a href="#features">Features</a></li>
                <li><a href="#docs">Documentation</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="text-white font-bold mb-4">Company</h4>
              <ul className="space-y-2 text-sm">
                <li><a href="#about">About</a></li>
                <li><a href="#blog">Blog</a></li>
                <li><a href="#careers">Careers</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="text-white font-bold mb-4">Legal</h4>
              <ul className="space-y-2 text-sm">
                <li><a href="#privacy">Privacy</a></li>
                <li><a href="#terms">Terms</a></li>
                <li><a href="#security">Security</a></li>
              </ul>
            </div>
          </div>
          
          <div className="border-t border-gray-800 mt-12 pt-8 text-center text-sm">
            © 2025 CodeAware. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  )
}




