'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { Settings, Download, Upload, Trash2, Save, AlertTriangle } from 'lucide-react'
import { useStore } from '../store/useStore'

export default function SettingsPanel() {
  const { transformation, updateTransformation, exportData, importData, resetData } = useStore()
  const [showResetConfirm, setShowResetConfirm] = useState(false)
  const [importError, setImportError] = useState('')

  const handleExport = () => {
    const data = exportData()
    const blob = new Blob([data], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `business-transformation-${new Date().toISOString().split('T')[0]}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleImport = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (event) => {
      try {
        const data = event.target?.result as string
        importData(data)
        setImportError('')
        alert('Data imported successfully!')
      } catch (error) {
        setImportError('Failed to import data. Please check the file format.')
      }
    }
    reader.readAsText(file)
  }

  const handleReset = () => {
    resetData()
    setShowResetConfirm(false)
    alert('All data has been reset to defaults.')
  }

  return (
    <div className="space-y-6">
      <div className="card">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-3 bg-gray-500/20 rounded-xl border border-gray-500/30">
            <Settings className="w-8 h-8 text-gray-400" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">Settings & Configuration</h2>
            <p className="text-dark-400 text-sm">Manage your business transformation data</p>
          </div>
        </div>

        <div className="space-y-6">
          {/* Transformation Metrics */}
          <div>
            <h3 className="text-lg font-semibold text-white mb-4">Transformation Metrics</h3>
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Knowledge Base Score (1-10)
                </label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={transformation.knowledgeBaseScore}
                  onChange={(e) => updateTransformation({ knowledgeBaseScore: parseInt(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Business System Score (1-10)
                </label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={transformation.businessSystemScore}
                  onChange={(e) => updateTransformation({ businessSystemScore: parseInt(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Uniqueness Score (1-10)
                </label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={transformation.uniquenessScore}
                  onChange={(e) => updateTransformation({ uniquenessScore: parseInt(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Efficiency Multiplier (1-10x)
                </label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  step="0.1"
                  value={transformation.efficiencyMultiplier}
                  onChange={(e) => updateTransformation({ efficiencyMultiplier: parseFloat(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
            </div>
          </div>

          {/* Revenue Projections */}
          <div>
            <h3 className="text-lg font-semibold text-white mb-4">Revenue Projections</h3>
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Year 1 Min Revenue ($)
                </label>
                <input
                  type="number"
                  value={transformation.year1RevenueMin}
                  onChange={(e) => updateTransformation({ year1RevenueMin: parseInt(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Year 1 Max Revenue ($)
                </label>
                <input
                  type="number"
                  value={transformation.year1RevenueMax}
                  onChange={(e) => updateTransformation({ year1RevenueMax: parseInt(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Year 5 Min Revenue ($)
                </label>
                <input
                  type="number"
                  value={transformation.year5RevenueMin}
                  onChange={(e) => updateTransformation({ year5RevenueMin: parseInt(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Year 5 Max Revenue ($)
                </label>
                <input
                  type="number"
                  value={transformation.year5RevenueMax}
                  onChange={(e) => updateTransformation({ year5RevenueMax: parseInt(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
            </div>
          </div>

          {/* Exit Strategy */}
          <div>
            <h3 className="text-lg font-semibold text-white mb-4">Exit Strategy</h3>
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Exit Potential Min ($)
                </label>
                <input
                  type="number"
                  value={transformation.exitPotentialMin}
                  onChange={(e) => updateTransformation({ exitPotentialMin: parseInt(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Exit Potential Max ($)
                </label>
                <input
                  type="number"
                  value={transformation.exitPotentialMax}
                  onChange={(e) => updateTransformation({ exitPotentialMax: parseInt(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Revenue Multiplier (1-3x)
                </label>
                <input
                  type="number"
                  min="1"
                  max="3"
                  step="0.1"
                  value={transformation.revenueMultiplier}
                  onChange={(e) => updateTransformation({ revenueMultiplier: parseFloat(e.target.value) })}
                  className="input-field w-full"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-2">
                  Market Position
                </label>
                <input
                  type="text"
                  value={transformation.marketPosition}
                  onChange={(e) => updateTransformation({ marketPosition: e.target.value })}
                  className="input-field w-full"
                />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Data Management */}
      <div className="card">
        <h3 className="text-lg font-semibold text-white mb-4">Data Management</h3>
        
        <div className="space-y-4">
          <div className="flex gap-3">
            <button
              onClick={handleExport}
              className="btn-primary flex items-center gap-2"
            >
              <Download className="w-5 h-5" />
              Export Data
            </button>
            
            <label className="btn-secondary flex items-center gap-2 cursor-pointer">
              <Upload className="w-5 h-5" />
              Import Data
              <input
                type="file"
                accept=".json"
                onChange={handleImport}
                className="hidden"
              />
            </label>
          </div>

          {importError && (
            <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-4 text-red-400 text-sm">
              {importError}
            </div>
          )}

          <div className="pt-4 border-t border-dark-800">
            {!showResetConfirm ? (
              <button
                onClick={() => setShowResetConfirm(true)}
                className="flex items-center gap-2 text-red-400 hover:text-red-300 transition-colors"
              >
                <Trash2 className="w-5 h-5" />
                Reset All Data
              </button>
            ) : (
              <div className="bg-red-500/20 border border-red-500/30 rounded-lg p-4">
                <div className="flex items-start gap-3 mb-4">
                  <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0" />
                  <div>
                    <h4 className="font-semibold text-red-400 mb-1">Are you sure?</h4>
                    <p className="text-sm text-red-300">
                      This will permanently delete all your data including learning entries, 
                      documents, milestones, and reset all settings to defaults.
                    </p>
                  </div>
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={handleReset}
                    className="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-lg font-semibold transition-colors"
                  >
                    Yes, Reset Everything
                  </button>
                  <button
                    onClick={() => setShowResetConfirm(false)}
                    className="btn-secondary"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}




