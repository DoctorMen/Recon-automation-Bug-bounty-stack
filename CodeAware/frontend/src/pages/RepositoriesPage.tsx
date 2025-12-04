import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, GitBranch, Play } from 'lucide-react'
import api from '../lib/api'

export default function RepositoriesPage() {
  const [showAddModal, setShowAddModal] = useState(false)
  const queryClient = useQueryClient()

  const { data: repositories, isLoading } = useQuery({
    queryKey: ['repositories'],
    queryFn: async () => {
      const res = await api.get('/repositories/')
      return res.data
    },
  })

  const analyzeMutation = useMutation({
    mutationFn: async (repositoryId: number) => {
      const res = await api.post('/analyses/', { repository_id: repositoryId })
      return res.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['analyses'] })
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary-600" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Repositories</h1>
          <p className="text-gray-600">Manage your code repositories and run analyses</p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="btn btn-primary flex items-center space-x-2"
        >
          <Plus className="w-5 h-5" />
          <span>Add Repository</span>
        </button>
      </div>

      {repositories && repositories.length > 0 ? (
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {repositories.map((repo: any) => (
            <div key={repo.id} className="card">
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <h3 className="text-lg font-bold text-gray-900">{repo.name}</h3>
                  <p className="text-sm text-gray-600">{repo.full_name}</p>
                </div>
                <span className="px-2 py-1 bg-primary-100 text-primary-600 rounded text-xs">
                  {repo.provider}
                </span>
              </div>

              {repo.description && (
                <p className="text-sm text-gray-600 mb-4">{repo.description}</p>
              )}

              <div className="flex items-center space-x-4 text-sm text-gray-600 mb-4">
                <div className="flex items-center">
                  <GitBranch className="w-4 h-4 mr-1" />
                  {repo.default_branch}
                </div>
                {repo.language && (
                  <div className="px-2 py-1 bg-gray-100 rounded">
                    {repo.language}
                  </div>
                )}
              </div>

              {repo.last_analyzed_at && (
                <p className="text-xs text-gray-500 mb-4">
                  Last analyzed: {new Date(repo.last_analyzed_at).toLocaleDateString()}
                </p>
              )}

              <button
                onClick={() => analyzeMutation.mutate(repo.id)}
                disabled={analyzeMutation.isPending}
                className="btn btn-primary w-full flex items-center justify-center space-x-2"
              >
                <Play className="w-4 h-4" />
                <span>
                  {analyzeMutation.isPending ? 'Starting...' : 'Run Analysis'}
                </span>
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="card text-center py-12">
          <GitBranch className="w-16 h-16 text-gray-300 mx-auto mb-4" />
          <h3 className="text-xl font-bold text-gray-900 mb-2">No repositories yet</h3>
          <p className="text-gray-600 mb-6">
            Add your first repository to start analyzing your code quality
          </p>
          <button
            onClick={() => setShowAddModal(true)}
            className="btn btn-primary"
          >
            Add Repository
          </button>
        </div>
      )}

      {/* Add Repository Modal */}
      {showAddModal && (
        <AddRepositoryModal onClose={() => setShowAddModal(false)} />
      )}
    </div>
  )
}

function AddRepositoryModal({ onClose }: { onClose: () => void }) {
  const [formData, setFormData] = useState({
    name: '',
    full_name: '',
    description: '',
    provider: 'github',
    provider_url: '',
    default_branch: 'main',
    language: ''
  })

  const queryClient = useQueryClient()

  const addMutation = useMutation({
    mutationFn: async (data: any) => {
      const res = await api.post('/repositories/', data)
      return res.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['repositories'] })
      onClose()
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    addMutation.mutate(formData)
  }

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-8 max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto">
        <h2 className="text-2xl font-bold text-gray-900 mb-6">Add Repository</h2>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Repository Name
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              className="input"
              placeholder="my-project"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Full Name (owner/repo)
            </label>
            <input
              type="text"
              value={formData.full_name}
              onChange={(e) => setFormData({ ...formData, full_name: e.target.value })}
              className="input"
              placeholder="username/my-project"
              required
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Provider
            </label>
            <select
              value={formData.provider}
              onChange={(e) => setFormData({ ...formData, provider: e.target.value })}
              className="input"
            >
              <option value="github">GitHub</option>
              <option value="gitlab">GitLab</option>
              <option value="bitbucket">Bitbucket</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Repository URL
            </label>
            <input
              type="url"
              value={formData.provider_url}
              onChange={(e) => setFormData({ ...formData, provider_url: e.target.value })}
              className="input"
              placeholder="https://github.com/username/my-project"
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Default Branch
              </label>
              <input
                type="text"
                value={formData.default_branch}
                onChange={(e) => setFormData({ ...formData, default_branch: e.target.value })}
                className="input"
                placeholder="main"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Primary Language
              </label>
              <input
                type="text"
                value={formData.language}
                onChange={(e) => setFormData({ ...formData, language: e.target.value })}
                className="input"
                placeholder="Python"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Description (optional)
            </label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="input"
              rows={3}
              placeholder="Describe your project..."
            />
          </div>

          {addMutation.isError && (
            <div className="bg-red-50 text-red-600 px-4 py-3 rounded-lg text-sm">
              Failed to add repository. Please try again.
            </div>
          )}

          <div className="flex space-x-4">
            <button
              type="submit"
              disabled={addMutation.isPending}
              className="btn btn-primary flex-1"
            >
              {addMutation.isPending ? 'Adding...' : 'Add Repository'}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="btn btn-secondary flex-1"
            >
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}




