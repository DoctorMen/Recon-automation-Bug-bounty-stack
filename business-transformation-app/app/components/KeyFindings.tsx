'use client'

import { motion } from 'framer-motion'
import { Target, CheckCircle2 } from 'lucide-react'
import { useStore } from '../store/useStore'

export default function KeyFindings() {
  const { transformation } = useStore()

  const findings = [
    {
      icon: <CheckCircle2 className="w-6 h-6" />,
      title: 'Personal Knowledge Base',
      from: `${transformation.knowledgeBaseScore}/10`,
      to: `Business System (${transformation.businessSystemScore}/10 uniqueness)`,
      highlight: transformation.businessSystemScore,
    },
    {
      icon: <CheckCircle2 className="w-6 h-6" />,
      title: 'Real competitive advantage',
      description: `${transformation.efficiencyMultiplier}x efficiency (not 50x)`,
      highlight: transformation.efficiencyMultiplier,
    },
    {
      icon: <CheckCircle2 className="w-6 h-6" />,
      title: 'Achievable revenue',
      from: `$${(transformation.year1RevenueMin / 1000).toFixed(0)}K-$${(transformation.year1RevenueMax / 1000).toFixed(0)}K Year 1`,
      to: `$${(transformation.year5RevenueMin / 1000).toFixed(0)}K-$${(transformation.year5RevenueMax / 1000).toFixed(0)}K Year 5`,
      highlight: transformation.year5RevenueMax,
    },
    {
      icon: <CheckCircle2 className="w-6 h-6" />,
      title: 'Exit potential',
      description: `$${(transformation.exitPotentialMin / 1000).toFixed(0)}K-$${(transformation.exitPotentialMax / 1000).toFixed(1)}M (${transformation.revenueMultiplier}-2x revenue at Year 5-7)`,
      highlight: transformation.exitPotentialMax,
    },
    {
      icon: <CheckCircle2 className="w-6 h-6" />,
      title: 'Market position',
      description: transformation.marketPosition,
      highlight: 'Top 10%',
    },
  ]

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-3 bg-primary-500/20 rounded-xl border border-primary-500/30">
          <Target className="w-8 h-8 text-primary-400" />
        </div>
        <h2 className="text-3xl font-bold gradient-text">Key Findings:</h2>
      </div>

      <div className="space-y-3">
        {findings.map((finding, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.1 }}
            className="card card-hover flex items-start gap-4"
          >
            <div className="flex-shrink-0 p-2 bg-green-500/20 rounded-lg border border-green-500/30">
              <div className="text-green-400">{finding.icon}</div>
            </div>
            
            <div className="flex-1">
              <div className="flex items-baseline gap-2 flex-wrap">
                <span className="font-semibold text-white">{finding.title}:</span>
                {finding.from && (
                  <>
                    <span className="text-dark-300">{finding.from}</span>
                    <span className="text-primary-400 font-bold">→</span>
                  </>
                )}
                {finding.to && (
                  <span className="text-white font-medium">{finding.to}</span>
                )}
                {finding.description && (
                  <span className="text-dark-200">{finding.description}</span>
                )}
              </div>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  )
}




