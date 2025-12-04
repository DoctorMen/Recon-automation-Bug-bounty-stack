'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import Navigation from './components/Navigation'
import KeyFindings from './components/KeyFindings'
import WhatMakesItWork from './components/WhatMakesItWork'
import RevenueChart from './components/RevenueChart'
import TransformationMetrics from './components/TransformationMetrics'
import LearningSystem from './components/LearningSystem'
import DocumentationSystem from './components/DocumentationSystem'
import MilestonesTracker from './components/MilestonesTracker'
import SettingsPanel from './components/SettingsPanel'

export default function Home() {
  const [activeSection, setActiveSection] = useState('dashboard')

  const renderContent = () => {
    switch (activeSection) {
      case 'dashboard':
        return (
          <div className="space-y-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-8"
            >
              <h1 className="text-4xl md:text-5xl font-bold mb-3">
                <span className="gradient-text">Your Transformation</span>
              </h1>
              <p className="text-dark-400 text-lg">
                From personal knowledge to a thriving business system
              </p>
            </motion.div>

            <TransformationMetrics />
            <KeyFindings />
            <RevenueChart />
            <WhatMakesItWork />
          </div>
        )

      case 'transformation':
        return (
          <div className="space-y-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <h1 className="text-4xl font-bold mb-3 gradient-text">
                Business Transformation
              </h1>
              <p className="text-dark-400 text-lg">
                Track your journey from knowledge to market leadership
              </p>
            </motion.div>

            <TransformationMetrics />
            <RevenueChart />
          </div>
        )

      case 'learning':
        return (
          <div className="space-y-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <h1 className="text-4xl font-bold mb-3 gradient-text">
                Learning System
              </h1>
              <p className="text-dark-400 text-lg">
                Build compound knowledge that multiplies your value
              </p>
            </motion.div>

            <LearningSystem />
          </div>
        )

      case 'documentation':
        return (
          <div className="space-y-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <h1 className="text-4xl font-bold mb-3 gradient-text">
                Documentation Library
              </h1>
              <p className="text-dark-400 text-lg">
                Executable templates that drive real results
              </p>
            </motion.div>

            <DocumentationSystem />
          </div>
        )

      case 'milestones':
        return (
          <div className="space-y-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <h1 className="text-4xl font-bold mb-3 gradient-text">
                Milestones & Goals
              </h1>
              <p className="text-dark-400 text-lg">
                Track your progress toward business success
              </p>
            </motion.div>

            <MilestonesTracker />
          </div>
        )

      case 'settings':
        return (
          <div className="space-y-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
            >
              <h1 className="text-4xl font-bold mb-3 gradient-text">
                Settings
              </h1>
              <p className="text-dark-400 text-lg">
                Configure your transformation parameters
              </p>
            </motion.div>

            <SettingsPanel />
          </div>
        )

      default:
        return null
    }
  }

  return (
    <div className="flex min-h-screen bg-dark-950">
      <Navigation activeSection={activeSection} onSectionChange={setActiveSection} />
      
      <main className="flex-1 p-6 md:p-8 lg:p-12 overflow-auto">
        <div className="max-w-7xl mx-auto">
          <AnimatePresence mode="wait">
            <motion.div
              key={activeSection}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3 }}
            >
              {renderContent()}
            </motion.div>
          </AnimatePresence>
        </div>
      </main>
    </div>
  )
}




