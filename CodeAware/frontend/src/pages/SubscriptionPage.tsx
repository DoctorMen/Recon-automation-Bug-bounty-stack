import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { CheckCircle, CreditCard } from 'lucide-react'
import api from '../lib/api'
import { Link } from 'react-router-dom'

export default function SubscriptionPage() {
  const queryClient = useQueryClient()

  const { data: subscription } = useQuery({
    queryKey: ['subscription'],
    queryFn: async () => {
      const res = await api.get('/subscriptions/me')
      return res.data
    },
  })

  const { data: pricingPlans } = useQuery({
    queryKey: ['pricing'],
    queryFn: async () => {
      const res = await api.get('/subscriptions/pricing')
      return res.data
    },
  })

  const createSubscription = useMutation({
    mutationFn: async (tier: string) => {
      const res = await api.post('/subscriptions/', {
        tier,
        billing_period: 'monthly'
      })
      return res.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['subscription'] })
    },
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Subscription</h1>
        <p className="text-gray-600">Manage your CodeAware subscription</p>
      </div>

      {/* Current Subscription */}
      {subscription && (
        <div className="card">
          <div className="flex items-start justify-between mb-6">
            <div>
              <h2 className="text-2xl font-bold text-gray-900 mb-2">
                Current Plan: {subscription.tier.charAt(0).toUpperCase() + subscription.tier.slice(1)}
              </h2>
              <p className="text-gray-600">
                Status: <span className={`font-medium ${
                  subscription.status === 'active' ? 'text-green-600' : 'text-orange-600'
                }`}>
                  {subscription.status.charAt(0).toUpperCase() + subscription.status.slice(1)}
                </span>
              </p>
            </div>
            <CreditCard className="w-12 h-12 text-primary-600" />
          </div>

          <div className="grid md:grid-cols-3 gap-6 mb-6">
            <div>
              <p className="text-sm text-gray-600 mb-1">Monthly Cost</p>
              <p className="text-2xl font-bold text-gray-900">
                ${subscription.amount}
                <span className="text-sm text-gray-600 font-normal">/month</span>
              </p>
            </div>

            <div>
              <p className="text-sm text-gray-600 mb-1">Scans This Month</p>
              <p className="text-2xl font-bold text-gray-900">
                {subscription.scans_used_this_month}
                {subscription.monthly_scan_limit > 0 && (
                  <span className="text-sm text-gray-600 font-normal">
                    / {subscription.monthly_scan_limit}
                  </span>
                )}
                {subscription.monthly_scan_limit === -1 && (
                  <span className="text-sm text-gray-600 font-normal"> / Unlimited</span>
                )}
              </p>
            </div>

            <div>
              <p className="text-sm text-gray-600 mb-1">Next Billing Date</p>
              <p className="text-lg font-medium text-gray-900">
                {subscription.current_period_end 
                  ? new Date(subscription.current_period_end).toLocaleDateString()
                  : 'N/A'}
              </p>
            </div>
          </div>

          {subscription.status === 'trialing' && subscription.trial_ends_at && (
            <div className="bg-blue-50 border-l-4 border-blue-500 p-4">
              <p className="text-blue-800">
                You're on a free trial until {new Date(subscription.trial_ends_at).toLocaleDateString()}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Available Plans */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900 mb-6">
          {subscription ? 'Upgrade Your Plan' : 'Choose a Plan'}
        </h2>
        
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {pricingPlans?.map((plan: any) => (
            <div
              key={plan.tier}
              className={`card ${
                subscription?.tier === plan.tier ? 'ring-2 ring-primary-600' : ''
              }`}
            >
              {subscription?.tier === plan.tier && (
                <div className="absolute top-0 right-0 bg-primary-600 text-white text-xs px-3 py-1 rounded-bl-lg rounded-tr-lg">
                  CURRENT
                </div>
              )}

              <h3 className="text-xl font-bold text-gray-900 mb-2">{plan.name}</h3>
              
              <div className="mb-4">
                <span className="text-3xl font-bold text-gray-900">
                  ${plan.monthly_price}
                </span>
                <span className="text-gray-600">/month</span>
              </div>

              <ul className="space-y-2 mb-6">
                {plan.features?.slice(0, 5).map((feature: string, idx: number) => (
                  <li key={idx} className="flex items-start text-sm">
                    <CheckCircle className="w-4 h-4 text-green-600 mr-2 flex-shrink-0 mt-0.5" />
                    <span className="text-gray-600">{feature}</span>
                  </li>
                ))}
              </ul>

              {subscription?.tier === plan.tier ? (
                <button disabled className="btn btn-secondary w-full">
                  Current Plan
                </button>
              ) : (
                <button
                  onClick={() => createSubscription.mutate(plan.tier)}
                  disabled={createSubscription.isPending}
                  className="btn btn-primary w-full"
                >
                  {subscription ? 'Upgrade' : 'Select Plan'}
                </button>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Billing Info */}
      <div className="card">
        <h2 className="text-xl font-bold text-gray-900 mb-4">Billing Information</h2>
        <p className="text-gray-600 mb-4">
          Manage your payment methods and billing history.
        </p>
        <button className="btn btn-outline">
          Update Payment Method
        </button>
      </div>

      {/* FAQ */}
      <div className="card">
        <h2 className="text-xl font-bold text-gray-900 mb-4">Subscription FAQ</h2>
        
        <div className="space-y-4">
          <div>
            <h3 className="font-medium text-gray-900 mb-2">
              Can I change my plan at any time?
            </h3>
            <p className="text-sm text-gray-600">
              Yes! You can upgrade or downgrade your plan at any time. Changes take effect 
              immediately, and we'll prorate any charges.
            </p>
          </div>

          <div>
            <h3 className="font-medium text-gray-900 mb-2">
              What happens if I exceed my scan limit?
            </h3>
            <p className="text-sm text-gray-600">
              You'll be prompted to upgrade your plan. Alternatively, your scans will be 
              queued until the next billing cycle.
            </p>
          </div>

          <div>
            <h3 className="font-medium text-gray-900 mb-2">
              Can I cancel my subscription?
            </h3>
            <p className="text-sm text-gray-600">
              Yes, you can cancel anytime. You'll retain access until the end of your 
              current billing period.
            </p>
          </div>
        </div>
      </div>

      {/* Need Help */}
      <div className="card bg-gray-50">
        <h2 className="text-xl font-bold text-gray-900 mb-2">Need Help?</h2>
        <p className="text-gray-600 mb-4">
          Have questions about your subscription? We're here to help.
        </p>
        <a href="mailto:support@codeaware.io" className="btn btn-primary">
          Contact Support
        </a>
      </div>
    </div>
  )
}




