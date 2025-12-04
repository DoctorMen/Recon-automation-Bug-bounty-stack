import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  ArrowLeft,
  AlertCircle,
  CheckCircle,
  Shield,
  Code2,
  TrendingUp,
  FileCode,
  AlertTriangle
} from 'lucide-react'
import api from '../lib/api'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell
} from 'recharts'

export default function AnalysisPage() {
  const { id } = useParams()

  const { data: analysis, isLoading } = useQuery({
    queryKey: ['analysis', id],
    queryFn: async () => {
      const res = await api.get(`/analyses/${id}`)
      return res.data
    },
    refetchInterval: (data) => {
      // Refetch every 5s if analysis is still running
      return data?.status === 'running' || data?.status === 'pending' ? 5000 : false
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary-600" />
      </div>
    )
  }

  if (!analysis) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-600">Analysis not found</p>
      </div>
    )
  }

  if (analysis.status === 'pending' || analysis.status === 'running') {
    return (
      <div className="text-center py-12">
        <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-primary-600 mx-auto mb-4" />
        <h2 className="text-2xl font-bold text-gray-900 mb-2">
          Analysis in Progress
        </h2>
        <p className="text-gray-600">
          This may take a few minutes. We're analyzing your code...
        </p>
      </div>
    )
  }

  if (analysis.status === 'failed') {
    return (
      <div className="text-center py-12">
        <AlertCircle className="w-16 h-16 text-red-600 mx-auto mb-4" />
        <h2 className="text-2xl font-bold text-gray-900 mb-2">
          Analysis Failed
        </h2>
        <p className="text-gray-600 mb-4">{analysis.error_message || 'Unknown error'}</p>
        <Link to="/repositories" className="btn btn-primary">
          Back to Repositories
        </Link>
      </div>
    )
  }

  const severityData = [
    { name: 'Critical', value: analysis.critical_issues, color: '#dc2626' },
    { name: 'High', value: analysis.high_issues, color: '#f97316' },
    { name: 'Medium', value: analysis.medium_issues, color: '#facc15' },
    { name: 'Low', value: analysis.low_issues, color: '#a3e635' },
  ]

  const scoreData = [
    { name: 'Quality', score: analysis.quality_score },
    { name: 'Security', score: analysis.security_score },
    { name: 'Maintainability', score: analysis.maintainability_score },
    { name: 'Scalability', score: analysis.scalability_score },
  ]

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <Link to="/dashboard" className="flex items-center text-gray-600 hover:text-gray-900 mb-4">
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Dashboard
        </Link>
        <h1 className="text-3xl font-bold text-gray-900">Analysis Results</h1>
        <p className="text-gray-600">
          Completed {new Date(analysis.completed_at).toLocaleString()}
        </p>
      </div>

      {/* Overall Score */}
      <div className="card bg-gradient-to-r from-primary-600 to-primary-700 text-white">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-primary-100 mb-2">Overall Code Quality Score</p>
            <p className="text-5xl font-bold">{analysis.overall_score.toFixed(1)}</p>
            <p className="text-primary-100 mt-2">out of 100</p>
          </div>
          <div className="text-right">
            <div className="text-3xl font-bold mb-2">
              {analysis.dunning_kruger_score.toFixed(0)}
            </div>
            <p className="text-primary-100">Dunning-Kruger Score</p>
            <p className="text-xs text-primary-200 mt-1">
              {analysis.dunning_kruger_score > 50 ? 'High Overconfidence' : 
               analysis.dunning_kruger_score > 25 ? 'Moderate Awareness' : 
               'Good Self-Awareness'}
            </p>
          </div>
        </div>
      </div>

      {/* Score Breakdown */}
      <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <Code2 className="w-8 h-8 text-blue-600" />
            <span className="text-2xl font-bold text-gray-900">
              {analysis.quality_score.toFixed(1)}
            </span>
          </div>
          <p className="text-sm text-gray-600">Quality Score</p>
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <Shield className="w-8 h-8 text-green-600" />
            <span className="text-2xl font-bold text-gray-900">
              {analysis.security_score.toFixed(1)}
            </span>
          </div>
          <p className="text-sm text-gray-600">Security Score</p>
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <TrendingUp className="w-8 h-8 text-purple-600" />
            <span className="text-2xl font-bold text-gray-900">
              {analysis.maintainability_score.toFixed(1)}
            </span>
          </div>
          <p className="text-sm text-gray-600">Maintainability</p>
        </div>

        <div className="card">
          <div className="flex items-center justify-between mb-2">
            <CheckCircle className="w-8 h-8 text-indigo-600" />
            <span className="text-2xl font-bold text-gray-900">
              {analysis.scalability_score.toFixed(1)}
            </span>
          </div>
          <p className="text-sm text-gray-600">Scalability</p>
        </div>
      </div>

      {/* Awareness Gap Alert */}
      {analysis.awareness_gap > 10 && (
        <div className="card bg-orange-50 border-l-4 border-orange-500">
          <div className="flex items-start space-x-4">
            <AlertTriangle className="w-6 h-6 text-orange-600 flex-shrink-0 mt-1" />
            <div>
              <h3 className="text-lg font-bold text-orange-900 mb-2">
                Overconfidence Detected
              </h3>
              <p className="text-orange-800 mb-2">
                Your awareness gap is {analysis.awareness_gap.toFixed(1)} points. This suggests 
                you may be overestimating your code quality.
              </p>
              <p className="text-orange-700 text-sm">
                This is common (Dunning-Kruger effect). Review the issues below and follow 
                the learning recommendations to improve.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Charts */}
      <div className="grid md:grid-cols-2 gap-6">
        <div className="card">
          <h3 className="text-xl font-bold text-gray-900 mb-4">Score Breakdown</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={scoreData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis domain={[0, 100]} />
              <Tooltip />
              <Bar dataKey="score" fill="#0ea5e9" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3 className="text-xl font-bold text-gray-900 mb-4">Issues by Severity</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, value }) => `${name}: ${value}`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Code Metrics */}
      <div className="card">
        <h3 className="text-xl font-bold text-gray-900 mb-4">Code Metrics</h3>
        <div className="grid md:grid-cols-4 gap-6">
          <div>
            <FileCode className="w-8 h-8 text-gray-400 mb-2" />
            <p className="text-2xl font-bold text-gray-900">{analysis.total_files}</p>
            <p className="text-sm text-gray-600">Total Files</p>
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900">
              {analysis.total_lines?.toLocaleString()}
            </p>
            <p className="text-sm text-gray-600">Total Lines</p>
          </div>
          <div>
            <p className="text-2xl font-bold text-gray-900">
              {analysis.average_complexity?.toFixed(1)}
            </p>
            <p className="text-sm text-gray-600">Avg Complexity</p>
          </div>
          <div>
            <p className="text-2xl font-bold text-red-600">
              {analysis.critical_issues + analysis.high_issues}
            </p>
            <p className="text-sm text-gray-600">Critical/High Issues</p>
          </div>
        </div>
      </div>

      {/* Issues Detail */}
      {analysis.issues_detail && analysis.issues_detail.length > 0 && (
        <div className="card">
          <h3 className="text-xl font-bold text-gray-900 mb-4">Issues Found</h3>
          <div className="space-y-4">
            {analysis.issues_detail.slice(0, 20).map((issue: any, idx: number) => (
              <div
                key={idx}
                className="border-l-4 pl-4 py-2"
                style={{
                  borderColor:
                    issue.severity === 'critical' ? '#dc2626' :
                    issue.severity === 'high' ? '#f97316' :
                    issue.severity === 'medium' ? '#facc15' : '#a3e635'
                }}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-2 mb-1">
                      <span className={`text-xs px-2 py-1 rounded-full ${
                        issue.severity === 'critical' ? 'bg-red-100 text-red-800' :
                        issue.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                        issue.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                        'bg-green-100 text-green-800'
                      }`}>
                        {issue.severity.toUpperCase()}
                      </span>
                      <span className="text-xs px-2 py-1 bg-gray-100 text-gray-800 rounded-full">
                        {issue.category}
                      </span>
                    </div>
                    <p className="text-sm font-medium text-gray-900">{issue.message}</p>
                    <p className="text-xs text-gray-600 mt-1">
                      {issue.file_path}:{issue.line_number}
                    </p>
                    {issue.recommendation && (
                      <p className="text-xs text-gray-500 mt-2 italic">
                        💡 {issue.recommendation}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            ))}
            {analysis.issues_detail.length > 20 && (
              <p className="text-sm text-gray-600 text-center">
                ...and {analysis.issues_detail.length - 20} more issues
              </p>
            )}
          </div>
        </div>
      )}

      {/* Learning Recommendations */}
      {analysis.learning_recommendations && analysis.learning_recommendations.length > 0 && (
        <div className="card">
          <h3 className="text-xl font-bold text-gray-900 mb-4">
            Personalized Learning Recommendations
          </h3>
          <div className="space-y-4">
            {analysis.learning_recommendations.map((rec: any, idx: number) => (
              <div key={idx} className="border border-gray-200 rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <h4 className="text-lg font-bold text-gray-900">{rec.title}</h4>
                  <span className={`text-xs px-2 py-1 rounded-full ${
                    rec.priority === 'high' ? 'bg-red-100 text-red-800' :
                    rec.priority === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                    'bg-green-100 text-green-800'
                  }`}>
                    {rec.priority} priority
                  </span>
                </div>
                <p className="text-gray-600 mb-3">{rec.description}</p>
                <div className="flex flex-wrap gap-2">
                  {rec.resources?.map((resource: string, ridx: number) => (
                    <span
                      key={ridx}
                      className="text-xs px-3 py-1 bg-primary-100 text-primary-800 rounded-full"
                    >
                      {resource}
                    </span>
                  ))}
                </div>
                <p className="text-xs text-gray-500 mt-2">
                  Found in {rec.issue_count} places in your code
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}




