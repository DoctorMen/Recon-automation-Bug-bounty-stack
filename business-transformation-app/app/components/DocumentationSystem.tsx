'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { FileText, Plus, Trash2, Play, Search, Filter } from 'lucide-react'
import { useStore } from '../store/useStore'
import { format } from 'date-fns'

export default function DocumentationSystem() {
  const { documents, addDocument, deleteDocument, incrementDocumentUsage } = useStore()
  const [showForm, setShowForm] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [filterCategory, setFilterCategory] = useState('all')
  const [formData, setFormData] = useState({
    title: '',
    category: '',
    content: '',
    isExecutable: true,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    addDocument(formData)
    setFormData({
      title: '',
      category: '',
      content: '',
      isExecutable: true,
    })
    setShowForm(false)
  }

  const categories = ['all', ...new Set(documents.map(d => d.category).filter(Boolean))]
  
  const filteredDocuments = documents.filter(doc => {
    const matchesSearch = doc.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         doc.content.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesCategory = filterCategory === 'all' || doc.category === filterCategory
    return matchesSearch && matchesCategory
  })

  const executableDocs = documents.filter(d => d.isExecutable).length

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-blue-500/20 rounded-xl border border-blue-500/30">
            <FileText className="w-8 h-8 text-blue-400" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">Executable Documentation</h2>
            <p className="text-dark-400 text-sm">Actionable templates, not just notes</p>
          </div>
        </div>
        
        <button
          onClick={() => setShowForm(!showForm)}
          className="btn-primary flex items-center gap-2"
        >
          <Plus className="w-5 h-5" />
          Add Document
        </button>
      </div>

      {documents.length > 0 && (
        <div className="mb-6 grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">Total Docs</div>
            <div className="text-2xl font-bold text-white">{documents.length}</div>
          </div>
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">Executable</div>
            <div className="text-2xl font-bold gradient-text">{executableDocs}</div>
          </div>
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">Most Used</div>
            <div className="text-2xl font-bold text-green-400">
              {Math.max(...documents.map(d => d.usageCount), 0)}
            </div>
          </div>
          <div className="bg-dark-800 rounded-lg p-4 border border-dark-700">
            <div className="text-dark-400 text-sm mb-1">Categories</div>
            <div className="text-2xl font-bold text-blue-400">
              {new Set(documents.map(d => d.category).filter(Boolean)).size}
            </div>
          </div>
        </div>
      )}

      {documents.length > 0 && (
        <div className="mb-6 flex gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-dark-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search documents..."
              className="input-field w-full pl-10"
            />
          </div>
          <select
            value={filterCategory}
            onChange={(e) => setFilterCategory(e.target.value)}
            className="input-field"
          >
            {categories.map(cat => (
              <option key={cat} value={cat}>
                {cat === 'all' ? 'All Categories' : cat}
              </option>
            ))}
          </select>
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
                  placeholder="e.g., Client Onboarding Checklist"
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
                  placeholder="e.g., Process, Template, Guide"
                />
              </div>
            </div>

            <div className="mb-4">
              <label className="block text-sm font-medium text-dark-300 mb-2">
                Content *
              </label>
              <textarea
                value={formData.content}
                onChange={(e) => setFormData({ ...formData, content: e.target.value })}
                className="input-field w-full h-32 resize-none"
                required
                placeholder="Add your executable documentation here..."
              />
            </div>

            <div className="mb-4">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.isExecutable}
                  onChange={(e) => setFormData({ ...formData, isExecutable: e.target.checked })}
                  className="w-4 h-4"
                />
                <span className="text-sm text-dark-300">
                  This is executable documentation (actionable template)
                </span>
              </label>
            </div>

            <div className="flex gap-3">
              <button type="submit" className="btn-primary">
                Save Document
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
        {filteredDocuments.length === 0 ? (
          <div className="text-center py-12 text-dark-400">
            <FileText className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p className="text-lg">
              {documents.length === 0 ? 'No documents yet' : 'No matching documents'}
            </p>
            <p className="text-sm">
              {documents.length === 0 
                ? 'Create executable documentation that drives results'
                : 'Try adjusting your search or filters'}
            </p>
          </div>
        ) : (
          filteredDocuments.map((doc) => (
            <motion.div
              key={doc.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              className="card card-hover"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-start gap-3 mb-2">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <h3 className="text-lg font-semibold text-white">{doc.title}</h3>
                        {doc.isExecutable && (
                          <span className="badge badge-success text-xs">
                            Executable
                          </span>
                        )}
                      </div>
                      <p className="text-dark-300 text-sm mb-3 line-clamp-2">{doc.content}</p>
                      <div className="flex items-center gap-3 flex-wrap text-xs">
                        {doc.category && (
                          <span className="badge badge-info">
                            {doc.category}
                          </span>
                        )}
                        <span className="text-dark-400">
                          Used {doc.usageCount} times
                        </span>
                        {doc.lastUsed && (
                          <span className="text-dark-400">
                            Last: {format(new Date(doc.lastUsed), 'MMM d, yyyy')}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="flex gap-2">
                  <button
                    onClick={() => incrementDocumentUsage(doc.id)}
                    className="p-2 text-green-400 hover:bg-green-500/20 rounded-lg transition-colors"
                    title="Mark as used"
                  >
                    <Play className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => deleteDocument(doc.id)}
                    className="p-2 text-red-400 hover:bg-red-500/20 rounded-lg transition-colors"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </motion.div>
          ))
        )}
      </div>
    </div>
  )
}




