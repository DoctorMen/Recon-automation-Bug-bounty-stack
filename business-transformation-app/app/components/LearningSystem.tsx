'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { BookOpen, Plus, Trash2, Edit2, TrendingUp, Calendar } from 'lucide-react'
import { useStore } from '../store/useStore'
import { format } from 'date-fns'

export default function LearningSystem() {
  const { learningEntries, addLearningEntry, deleteLearningEntry } = useStore()
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    category: '',
    impact: 'medium' as 'low' | 'medium' | 'high',
    compoundEffect: 1,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    addLearningEntry({
      ...formData,
      date: new Date(),
    })
    setFormData({
      title: '',
      description: '',
      category: '',
      impact: 'medium',
      compoundEffect: 1,
    })
    setShowForm(false)
  }

  const impactColors = {
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    high: 'bg-green-500/20 text-green-400 border-green-500/30',
  }

  const totalCompoundEffect = learningEntries.reduce((sum, entry) => sum + entry.compoundEffect, 0)

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-purple-500/20 rounded-xl border border-purple-500/30">
            <BookOpen className="w-8 h-8 text-purple-400" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">Self-Improving Learning System</h2>
            <p className="text-dark-400 text-sm">Track compound knowledge growth</p>
          </div>
        </div>
        
        <button
          onClick={() => setShowForm(!showForm)}
          className="btn-primary flex items-center gap-2"
        >
          <Plus className="w-5 h-5" />
          Add Learning
        </button>
      </div>

      {learningEntries.length > 0 && (
        <div className="mb-6 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">Total Entries</div>
            <div className="text-2xl font-bold text-white">{learningEntries.length}</div>
          </div>
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">Compound Effect</div>
            <div className="text-2xl font-bold gradient-text">{totalCompoundEffect.toFixed(1)}x</div>
          </div>
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">High Impact</div>
            <div className="text-2xl font-bold text-green-400">
              {learningEntries.filter(e => e.impact === 'high').length}
            </div>
          </div>
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">This Month</div>
            <div className="text-2xl font-bold text-blue-400">
              {learningEntries.filter(e => {
                const entryDate = new Date(e.date)
                const now = new Date()
                return entryDate.getMonth() === now.getMonth() && 
                       entryDate.getFullYear() === now.getFullYear()
              }).length}
            </div>
          </div>
        </div>
      )}

      <AnimatePresence>
        {showForm && (
          <motion.form
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            onSubmit={handleSubmit}
            className="mb-6 bg-dark-800 rounded-xl p-6 border border-dark-700"
          >
            <div className="grid md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Title *
                </label>
                <input
                  type="text"
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  className="input-field w-full"
                  required
                  placeholder="e.g., Learned React optimization"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Category
                </label>
                <input
                  type="text"
                  value={formData.category}
                  onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                  className="input-field w-full"
                  placeholder="e.g., Technical, Business, Marketing"
                />
              </div>
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-dark-300 mb-2">
                Description
              </label>
              <textarea
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="input-field w-full h-24 resize-none"
                placeholder="What did you learn and how will it compound?"
              />
            </div>

            <div className="grid md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Impact Level
                </label>
                <select
                  value={formData.impact}
                  onChange={(e) => setFormData({ ...formData, impact: e.target.value as any })}
                  className="input-field w-full"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Compound Effect (1-10x)
                </label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  step="0.1"
                  value={formData.compoundEffect}
                  onChange={(e) => setFormData({ ...formData, compoundEffect: parseFloat(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
            </div>

            <div className="flex gap-3">
              <button type="submit" className="btn-primary">
                Save Learning
              </button>
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="btn-secondary"
              >
                Cancel
              </button>
            </div>
          </motion.form>
        )}
      </AnimatePresence>

      <div className="space-y-3">
        {learningEntries.length === 0 ? (
          <div className="text-center py-12 text-dark-400">
            <BookOpen className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p className="text-lg">No learning entries yet</p>
            <p className="text-sm">Start tracking your compound knowledge growth</p>
          </div>
        ) : (
          learningEntries.map((entry) => (
            <motion.div
              key={entry.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="card card-hover"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-start gap-3 mb-2">
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-white mb-1">{entry.title}</h3>
                      {entry.description && (
                        <p className="text-dark-300 text-sm mb-2">{entry.description}</p>
                      )}
                      <div className="flex items-center gap-3 flex-wrap">
                        {entry.category && (
                          <span className="badge badge-info text-xs">
                            {entry.category}
                          </span>
                        )}
                        <span className={`badge text-xs ${impactColors[entry.impact]}`}>
                          {entry.impact.toUpperCase()} Impact
                        </span>
                        <span className="badge badge-success text-xs flex items-center gap-1">
                          <TrendingUp className="w-3 h-3" />
                          {entry.compoundEffect}x
                        </span>
                        <span className="text-dark-400 text-xs flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {format(new Date(entry.date), 'MMM d, yyyy')}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
                
                <button
                  onClick={() => deleteLearningEntry(entry.id)}
                  className="p-2 text-red-400 hover:bg-red-500/20 rounded-lg transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </motion.div>
          ))
        )}
      </div>
    </div>
  )
}




