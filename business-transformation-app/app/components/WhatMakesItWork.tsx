'use client'

import { motion } from 'framer-motion'
import { Lightbulb, FileText, TrendingUp, Zap } from 'lucide-react'

export default function WhatMakesItWork() {
  const principles = [
    {
      icon: <FileText className="w-6 h-6" />,
      title: 'Executable documentation (not just notes)',
      description: 'Create actionable templates and systems you can use immediately, not passive information.',
      color: 'from-blue-500 to-cyan-500',
    },
    {
      icon: <TrendingUp className="w-6 h-6" />,
      title: 'Self-improving system (compound learning)',
      description: 'Every piece of knowledge builds on the last, creating exponential growth over time.',
      color: 'from-purple-500 to-pink-500',
    },
  ]

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-3 bg-yellow-500/20 rounded-xl border border-yellow-500/30">
          <Lightbulb className="w-8 h-8 text-yellow-400" />
        </div>
        <h2 className="text-3xl font-bold text-white">What Makes It Work:</h2>
      </div>

      <div className="grid md:grid-cols-2 gap-6">
        {principles.map((principle, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.15 }}
            className="card card-hover group relative overflow-hidden"
          >
            <div className={`absolute inset-0 bg-gradient-to-br ${principle.color} opacity-5 group-hover:opacity-10 transition-opacity`}></div>
            
            <div className="relative z-10">
              <div className="flex items-start gap-4">
                <div className={`p-3 bg-gradient-to-br ${principle.color} rounded-xl shadow-lg`}>
                  <div className="text-white">{principle.icon}</div>
                </div>
                
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-3">
                    <span className="text-2xl font-bold text-white">{index + 1}.</span>
                    <h3 className="text-lg font-bold text-white">{principle.title}</h3>
                  </div>
                  <p className="text-dark-300 leading-relaxed">{principle.description}</p>
                </div>
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ delay: 0.3 }}
        className="card bg-gradient-to-br from-primary-500/10 to-purple-500/10 border-primary-500/30"
      >
        <div className="flex items-start gap-4">
          <div className="p-3 bg-primary-500/20 rounded-xl">
            <Zap className="w-6 h-6 text-primary-400" />
          </div>
          <div>
            <h4 className="text-lg font-bold text-white mb-2">The Compound Effect</h4>
            <p className="text-dark-200 leading-relaxed">
              When you combine executable documentation with self-improving systems, you create a business 
              that becomes more valuable every day. Your knowledge doesn't just accumulate—it multiplies.
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  )
}




