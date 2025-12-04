'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Target, Plus, Trash2, CheckCircle2, Circle, Calendar } from 'lucide-react'
import { useStore } from '../store/useStore'
import { format, isBefore, isAfter } from 'date-fns'

export default function MilestonesTracker() {
  const { milestones, addMilestone, deleteMilestone, toggleMilestone } = useStore()
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    category: '',
    targetDate: '',
    completed: false,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    addMilestone({
      ...formData,
      targetDate: new Date(formData.targetDate),
    })
    setFormData({
      title: '',
      description: '',
      category: '',
      targetDate: '',
      completed: false,
    })
    setShowForm(false)
  }

  const completedCount = milestones.filter(m => m.completed).length
  const upcomingCount = milestones.filter(m => !m.completed && isAfter(new Date(m.targetDate), new Date())).length
  const overdueCount = milestones.filter(m => !m.completed && isBefore(new Date(m.targetDate), new Date())).length

  const sortedMilestones = [...milestones].sort((a, b) => {
    if (a.completed !== b.completed) return a.completed ? 1 : -1
    return new Date(a.targetDate).getTime() - new Date(b.targetDate).getTime()
  })

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-orange-500/20 rounded-xl border border-orange-500/30">
            <Target className="w-8 h-8 text-orange-400" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">Milestones & Goals</h2>
            <p className="text-dark-400 text-sm">Track your transformation journey</p>
          </div>
        </div>
        
        <button
          onClick={() => setShowForm(!showForm)}
          className="btn-primary flex items-center gap-2"
        >
          <Plus className="w-5 h-5" />
          Add Milestone
        </button>
      </div>

      {milestones.length > 0 && (
        <div className="mb-6 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">Total</div>
            <div className="text-2xl font-bold text-white">{milestones.length}</div>
          </div>
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">Completed</div>
            <div className="text-2xl font-bold text-green-400">{completedCount}</div>
          </div>
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">Upcoming</div>
            <div className="text-2xl font-bold text-blue-400">{upcomingCount}</div>
          </div>
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">Overdue</div>
            <div className="text-2xl font-bold text-red-400">{overdueCount}</div>
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
                  placeholder="e.g., Launch MVP"
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
                  placeholder="e.g., Product, Revenue, Marketing"
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
                placeholder="Describe this milestone..."
              />
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-dark-300 mb-2">
                Target Date *
              </label>
              <input
                type="date"
                value={formData.targetDate}
                onChange={(e) => setFormData({ ...formData, targetDate: e.target.value })}
                className="input-field w-full"
                required
              />
            </div>

            <div className="flex gap-3">
              <button type="submit" className="btn-primary">
                Save Milestone
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
        {sortedMilestones.length === 0 ? (
          <div className="text-center py-12 text-dark-400">
            <Target className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p className="text-lg">No milestones yet</p>
            <p className="text-sm">Set goals to track your transformation</p>
          </div>
        ) : (
          sortedMilestones.map((milestone) => {
            const isOverdue = !milestone.completed && isBefore(new Date(milestone.targetDate), new Date())
            
            return (
              <motion.div
                key={milestone.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                className={`card card-hover ${milestone.completed ? 'opacity-60' : ''}`}
              >
                <div className="flex items-start gap-4">
                  <button
                    onClick={() => toggleMilestone(milestone.id)}
                    className="flex-shrink-0 mt-1"
                  >
                    {milestone.completed ? (
                      <CheckCircle2 className="w-6 h-6 text-green-400" />
                    ) : (
                      <Circle className="w-6 h-6 text-dark-400 hover:text-primary-400 transition-colors" />
                    )}
                  </button>
                  
                  <div className="flex-1">
                    <h3 className={`text-lg font-semibold mb-1 ${milestone.completed ? 'line-through text-dark-400' : 'text-white'}`}>
                      {milestone.title}
                    </h3>
                    {milestone.description && (
                      <p className="text-dark-300 text-sm mb-2">{milestone.description}</p>
                    )}
                    <div className="flex items-center gap-3 flex-wrap text-xs">
                      {milestone.category && (
                        <span className="badge badge-info">
                          {milestone.category}
                        </span>
                      )}
                      <span className={`flex items-center gap-1 ${isOverdue ? 'text-red-400' : 'text-dark-400'}`}>
                        <Calendar className="w-3 h-3" />
                        {format(new Date(milestone.targetDate), 'MMM d, yyyy')}
                        {isOverdue && ' (Overdue)'}
                      </span>
                      {milestone.completed && milestone.completedDate && (
                        <span className="text-green-400">
                          ✓ Completed {format(new Date(milestone.completedDate), 'MMM d, yyyy')}
                        </span>
                      )}
                    </div>
                  </div>
                  
                  <button
                    onClick={() => deleteMilestone(milestone.id)}
                    className="p-2 text-red-400 hover:bg-red-500/20 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </motion.div>
            )
          })
        )}
      </div>
    </div>
  )
}




