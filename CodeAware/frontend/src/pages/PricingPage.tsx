import { Link } from 'react-router-dom'
import { CheckCircle, Brain } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import api from '../lib/api'

export default function PricingPage() {
  const { data: pricingPlans } = useQuery({
    queryKey: ['pricing'],
    queryFn: async () => {
      const res = await api.get('/subscriptions/pricing')
      return res.data
    },
  })

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary-50 to-white">
      {/* Navigation */}
      <nav className="container mx-auto px-4 py-6">
        <div className="flex justify-between items-center">
          <Link to="/" className="flex items-center space-x-2">
            <Brain className="w-8 h-8 text-primary-600" />
            <span className="text-2xl font-bold text-gray-900">CodeAware</span>
          </Link>
          <div className="space-x-4">
            <Link to="/login" className="text-gray-600 hover:text-gray-900">
              Login
            </Link>
            <Link to="/register" className="btn btn-primary">
              Get Started
            </Link>
          </div>
        </div>
      </nav>

      {/* Header */}
      <section className="container mx-auto px-4 py-20 text-center">
        <h1 className="text-5xl font-bold text-gray-900 mb-4">
          Simple, Transparent Pricing
        </h1>
        <p className="text-xl text-gray-600 mb-8">
          Choose the plan that fits your needs. All plans include 14-day free trial.
        </p>
      </section>

      {/* Pricing Cards */}
      <section className="container mx-auto px-4 pb-20">
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8 max-w-7xl mx-auto">
          {pricingPlans?.map((plan: any) => (
            <div
              key={plan.tier}
              className={`card ${
                plan.tier === 'professional' ? 'ring-2 ring-primary-600' : ''
              }`}
            >
              {plan.tier === 'professional' && (
                <div className="absolute top-0 right-0 bg-primary-600 text-white text-xs px-3 py-1 rounded-bl-lg rounded-tr-lg">
                  POPULAR
                </div>
              )}
              
              <h3 className="text-2xl font-bold text-gray-900 mb-2">{plan.name}</h3>
              
              <div className="mb-6">
                <span className="text-4xl font-bold text-gray-900">
                  ${plan.monthly_price}
                </span>
                <span className="text-gray-600">/month</span>
                {plan.yearly_price && (
                  <div className="text-sm text-gray-600 mt-1">
                    or ${plan.yearly_price}/year (save ${(plan.monthly_price * 12 - plan.yearly_price).toFixed(0)})
                  </div>
                )}
              </div>

              <ul className="space-y-3 mb-8">
                {plan.features?.map((feature: string, idx: number) => (
                  <li key={idx} className="flex items-start">
                    <CheckCircle className="w-5 h-5 text-green-600 mr-2 flex-shrink-0 mt-0.5" />
                    <span className="text-sm text-gray-600">{feature}</span>
                  </li>
                ))}
              </ul>

              <Link
                to="/register"
                className={`block w-full text-center py-3 rounded-lg font-medium transition-all ${
                  plan.tier === 'professional'
                    ? 'bg-primary-600 text-white hover:bg-primary-700'
                    : 'bg-gray-100 text-gray-900 hover:bg-gray-200'
                }`}
              >
                Start Free Trial
              </Link>
            </div>
          ))}
        </div>
      </section>

      {/* Enterprise Section */}
      <section className="container mx-auto px-4 py-20">
        <div className="max-w-4xl mx-auto card text-center">
          <h2 className="text-3xl font-bold text-gray-900 mb-4">
            Need a Custom Solution?
          </h2>
          <p className="text-gray-600 mb-6">
            Our Enterprise plan offers custom features, on-premise deployment, dedicated support, 
            and more. Perfect for large teams and organizations.
          </p>
          <a href="mailto:sales@codeaware.io" className="btn btn-primary">
            Contact Sales
          </a>
        </div>
      </section>

      {/* FAQ Section */}
      <section className="container mx-auto px-4 py-20">
        <h2 className="text-3xl font-bold text-center text-gray-900 mb-12">
          Frequently Asked Questions
        </h2>
        
        <div className="max-w-3xl mx-auto space-y-6">
          <div className="card">
            <h3 className="text-lg font-bold text-gray-900 mb-2">
              What's included in the free trial?
            </h3>
            <p className="text-gray-600">
              All features of your chosen plan for 14 days. No credit card required. 
              Cancel anytime.
            </p>
          </div>

          <div className="card">
            <h3 className="text-lg font-bold text-gray-900 mb-2">
              Can I change plans later?
            </h3>
            <p className="text-gray-600">
              Yes! You can upgrade or downgrade your plan at any time. Changes take effect 
              immediately.
            </p>
          </div>

          <div className="card">
            <h3 className="text-lg font-bold text-gray-900 mb-2">
              What payment methods do you accept?
            </h3>
            <p className="text-gray-600">
              We accept all major credit cards (Visa, Mastercard, Amex) and offer annual 
              invoicing for Enterprise customers.
            </p>
          </div>

          <div className="card">
            <h3 className="text-lg font-bold text-gray-900 mb-2">
              Is my code secure?
            </h3>
            <p className="text-gray-600">
              Absolutely. We analyze your code in isolated environments and never store your 
              source code. All data is encrypted at rest and in transit.
            </p>
          </div>

          <div className="card">
            <h3 className="text-lg font-bold text-gray-900 mb-2">
              What languages do you support?
            </h3>
            <p className="text-gray-600">
              Currently: Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C#. We're 
              continuously adding more languages.
            </p>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="container mx-auto px-4 py-20 text-center">
        <h2 className="text-4xl font-bold text-gray-900 mb-6">
          Ready to Improve Your Code Quality?
        </h2>
        <Link to="/register" className="btn btn-primary text-lg px-8 py-3">
          Start Your Free Trial →
        </Link>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-gray-400 py-12">
        <div className="container mx-auto px-4 text-center">
          <div className="flex items-center justify-center space-x-2 mb-4">
            <Brain className="w-6 h-6 text-primary-600" />
            <span className="text-xl font-bold text-white">CodeAware</span>
          </div>
          <p className="text-sm">© 2025 CodeAware. All rights reserved.</p>
        </div>
      </footer>
    </div>
  )
}




