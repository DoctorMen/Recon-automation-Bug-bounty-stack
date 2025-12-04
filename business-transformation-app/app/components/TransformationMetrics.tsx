'use client'

import { motion } from 'framer-motion'
import { Brain, Building2, Sparkles, Zap } from 'lucide-react'
import { useStore } from '../store/useStore'

export default function TransformationMetrics() {
  const { transformation } = useStore()

  const metrics = [
    {
      icon: <Brain className="w-6 h-6" />,
      label: 'Knowledge Base',
      value: transformation.knowledgeBaseScore,
      max: 10,
      color: 'from-blue-500 to-cyan-500',
      bgColor: 'bg-blue-500/20',
      borderColor: 'border-blue-500/30',
    },
    {
      icon: <Building2 className="w-6 h-6" />,
      label: 'Business System',
      value: transformation.businessSystemScore,
      max: 10,
      color: 'from-green-500 to-emerald-500',
      bgColor: 'bg-green-500/20',
      borderColor: 'border-green-500/30',
    },
    {
      icon: <Sparkles className="w-6 h-6" />,
      label: 'Uniqueness',
      value: transformation.uniquenessScore,
      max: 10,
      color: 'from-purple-500 to-pink-500',
      bgColor: 'bg-purple-500/20',
      borderColor: 'border-purple-500/30',
    },
    {
      icon: <Zap className="w-6 h-6" />,
      label: 'Efficiency Multiplier',
      value: transformation.efficiencyMultiplier,
      max: 5,
      suffix: 'x',
      color: 'from-yellow-500 to-orange-500',
      bgColor: 'bg-yellow-500/20',
      borderColor: 'border-yellow-500/30',
    },
  ]

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {metrics.map((metric, index) => (
        <motion.div
          key={index}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: index * 0.1 }}
          className="stat-card card-hover"
        >
          <div className="flex items-start justify-between mb-4">
            <div className={`p-3 ${metric.bgColor} rounded-xl border ${metric.borderColor}`}>
              <div className={`bg-gradient-to-br ${metric.color} bg-clip-text text-transparent`}>
                {metric.icon}
              </div>
            </div>
            <div className="text-right">
              <div className={`text-3xl font-bold bg-gradient-to-br ${metric.color} bg-clip-text text-transparent`}>
                {metric.value}{metric.suffix || ''}
              </div>
              <div className="text-dark-400 text-xs">of {metric.max}</div>
            </div>
          </div>

          <div className="mb-3">
            <div className="text-sm font-medium text-dark-300 mb-2">{metric.label}</div>
            <div className="progress-bar">
              <motion.div
                className={`progress-fill bg-gradient-to-r ${metric.color}`}
                initial={{ width: 0 }}
                animate={{ width: `${(metric.value / metric.max) * 100}%` }}
                transition={{ delay: index * 0.1 + 0.2, duration: 0.8 }}
              />
            </div>
          </div>

          <div className="text-xs text-dark-400">
            {((metric.value / metric.max) * 100).toFixed(0)}% complete
          </div>
        </motion.div>
      ))}
    </div>
  )
}




