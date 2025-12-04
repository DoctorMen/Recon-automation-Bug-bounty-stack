import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { 
  TrendingUp, 
  AlertCircle, 
  CheckCircle, 
  Clock, 
  Code2,
  Shield,
  Target
} from 'lucide-react'
import api from '../lib/api'
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from 'recharts'

export default function Dashboard() {
  const { data: analyses, isLoading } = useQuery({
    queryKey: ['analyses'],
    queryFn: async () => {
      const res = await api.get('/analyses/')
      return res.data
    },
  })

  const { data: user } = useQuery({
    queryKey: ['user'],
    queryFn: async () => {
      const res = await api.get('/users/me')
      return res.data
    },
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary-600" />
      </div>
    )
  }

  const latestAnalysis = analyses?.[0]
  const completedAnalyses = analyses?.filter((a: any) => a.status === 'completed') || []
  
  // Calculate average scores
  const avgQuality = completedAnalyses.length > 0
    ? completedAnalyses.reduce((sum: number, a: any) => sum + (a.quality_score || 0), 0) / completedAnalyses.length
    : 0
  
  const avgSecurity = completedAnalyses.length > 0
    ? completedAnalyses.reduce((sum: number, a: any) => sum + (a.security_score || 0), 0) / completedAnalyses.length
    : 0

  // Awareness data for radar chart
  const awarenessData = latestAnalysis ? [
    { subject: 'Quality', actual: latestAnalysis.quality_score || 0, perceived: (latestAnalysis.quality_score || 0) + (latestAnalysis.awareness_gap || 0) },
    { subject: 'Security', actual: latestAnalysis.security_score || 0, perceived: (latestAnalysis.security_score || 0) + (latestAnalysis.awareness_gap || 0) * 0.8 },
    { subject: 'Maintainability', actual: latestAnalysis.maintainability_score || 0, perceived: (latestAnalysis.maintainability_score || 0) + (latestAnalysis.awareness_gap || 0) * 0.7 },
    { subject: 'Scalability', actual: latestAnalysis.scalability_score || 0, perceived: (latestAnalysis.scalability_score || 0) + (latestAnalysis.awareness_gap || 0) * 0.6 },
  ] : []

  // Trend data
  const trendData = completedAnalyses.slice(0, 10).reverse().map((a: any, i: number) => ({
    name: `Scan ${i + 1}`,
    quality: a.quality_score || 0,
    security: a.security_score || 0,
    overall: a.overall_score || 0,
  }))

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-600">Welcome back, {user?.full_name || user?.username}</p>
      </div>

      {/* Key Metrics */}
      <div className="grid md:grid-cols-4 gap-6">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Average Quality</p>
              <p className="text-3xl font-bold text-gray-900">{avgQuality.toFixed(1)}</p>
            </div>
            <Code2 className="w-12 h-12 text-primary-600 opacity-20" />
          </div>
          <div className="mt-2 flex items-center text-sm">
            <TrendingUp className="w-4 h-4 text-green-600 mr-1" />
            <span className="text-green-600">+5.2% from last month</span>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Security Score</p>
              <p className="text-3xl font-bold text-gray-900">{avgSecurity.toFixed(1)}</p>
            </div>
            <Shield className="w-12 h-12 text-green-600 opacity-20" />
          </div>
          <div className="mt-2 flex items-center text-sm">
            <CheckCircle className="w-4 h-4 text-green-600 mr-1" />
            <span className="text-gray-600">{completedAnalyses.reduce((sum: number, a: any) => sum + (a.security_vulnerabilities || 0), 0)} vulnerabilities found</span>
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Awareness Gap</p>
              <p className="text-3xl font-bold text-gray-900">
                {latestAnalysis?.awareness_gap ? `${latestAnalysis.awareness_gap > 0 ? '+' : ''}${latestAnalysis.awareness_gap.toFixed(1)}` : 'N/A'}
              </p>
            </div>
            <Target className="w-12 h-12 text-orange-600 opacity-20" />
          </div>
          <div className="mt-2 flex items-center text-sm">
            {latestAnalysis?.awareness_gap > 0 ? (
              <>
                <AlertCircle className="w-4 h-4 text-orange-600 mr-1" />
                <span className="text-orange-600">Overconfident</span>
              </>
            ) : (
              <>
                <CheckCircle className="w-4 h-4 text-green-600 mr-1" />
                <span className="text-green-600">Well-calibrated</span>
              </>
            )}
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600">Total Analyses</p>
              <p className="text-3xl font-bold text-gray-900">{completedAnalyses.length}</p>
            </div>
            <Clock className="w-12 h-12 text-blue-600 opacity-20" />
          </div>
          <div className="mt-2 flex items-center text-sm">
            <span className="text-gray-600">{analyses?.filter((a: any) => a.status === 'pending' || a.status === 'running').length || 0} in progress</span>
          </div>
        </div>
      </div>

      {/* Awareness Gap Visualization */}
      {latestAnalysis && (
        <div className="card">
          <h2 className="text-xl font-bold text-gray-900 mb-4">Your Awareness Profile</h2>
          <p className="text-gray-600 mb-6">
            See how your perceived skill level compares to your actual code quality
          </p>
          <div className="grid md:grid-cols-2 gap-8">
            <div>
              <ResponsiveContainer width="100%" height={300}>
                <RadarChart data={awarenessData}>
                  <PolarGrid />
                  <PolarAngleAxis dataKey="subject" />
                  <PolarRadiusAxis angle={90} domain={[0, 100]} />
                  <Radar name="Actual Skill" dataKey="actual" stroke="#0ea5e9" fill="#0ea5e9" fillOpacity={0.6} />
                  <Radar name="Perceived Skill" dataKey="perceived" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.3} />
                  <Tooltip />
                </RadarChart>
              </ResponsiveContainer>
            </div>
            <div className="flex flex-col justify-center">
              <div className="space-y-4">
                <div>
                  <h3 className="text-lg font-bold text-gray-900">Dunning-Kruger Score</h3>
                  <div className="flex items-center space-x-4 mt-2">
                    <div className="flex-1 bg-gray-200 rounded-full h-4">
                      <div 
                        className="bg-orange-500 h-4 rounded-full transition-all"
                        style={{ width: `${latestAnalysis.dunning_kruger_score || 0}%` }}
                      />
                    </div>
                    <span className="text-2xl font-bold text-orange-600">
                      {latestAnalysis.dunning_kruger_score?.toFixed(0) || 0}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 mt-2">
                    {latestAnalysis.dunning_kruger_score > 50 ? 
                      'High overconfidence detected. You may be unaware of some code quality issues.' :
                      latestAnalysis.dunning_kruger_score > 25 ?
                      'Moderate awareness. Some blind spots remain.' :
                      'Good self-awareness! You have a realistic view of your code quality.'}
                  </p>
                </div>
                
                <div className="pt-4 border-t border-gray-200">
                  <h4 className="font-bold text-gray-900 mb-2">What This Means:</h4>
                  <ul className="space-y-2 text-sm text-gray-600">
                    <li>• Blue = Your actual code quality</li>
                    <li>• Orange = Your perceived skill level</li>
                    <li>• Larger gap = More overconfidence</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Quality Trend */}
      {trendData.length > 0 && (
        <div className="card">
          <h2 className="text-xl font-bold text-gray-900 mb-4">Quality Trend</h2>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis domain={[0, 100]} />
              <Tooltip />
              <Area type="monotone" dataKey="overall" stackId="1" stroke="#0ea5e9" fill="#0ea5e9" fillOpacity={0.6} />
              <Area type="monotone" dataKey="security" stackId="2" stroke="#10b981" fill="#10b981" fillOpacity={0.4} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent Analyses */}
      <div className="card">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold text-gray-900">Recent Analyses</h2>
          <Link to="/repositories" className="text-primary-600 hover:text-primary-700">
            View All →
          </Link>
        </div>
        
        <div className="space-y-4">
          {analyses?.slice(0, 5).map((analysis: any) => (
            <Link
              key={analysis.id}
              to={`/analysis/${analysis.id}`}
              className="block p-4 border border-gray-200 rounded-lg hover:border-primary-300 hover:shadow-md transition-all"
            >
              <div className="flex items-center justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    <span className="text-sm font-medium text-gray-900">
                      Repository #{analysis.repository_id}
                    </span>
                    {analysis.status === 'completed' && (
                      <span className="text-xs px-2 py-1 bg-green-100 text-green-800 rounded-full">
                        Completed
                      </span>
                    )}
                    {analysis.status === 'running' && (
                      <span className="text-xs px-2 py-1 bg-blue-100 text-blue-800 rounded-full">
                        Running
                      </span>
                    )}
                    {analysis.status === 'failed' && (
                      <span className="text-xs px-2 py-1 bg-red-100 text-red-800 rounded-full">
                        Failed
                      </span>
                    )}
                  </div>
                  {analysis.status === 'completed' && (
                    <div className="mt-2 flex items-center space-x-4 text-sm text-gray-600">
                      <span>Overall: {analysis.overall_score?.toFixed(1) || 'N/A'}</span>
                      <span>•</span>
                      <span>{analysis.critical_issues + analysis.high_issues} critical/high issues</span>
                    </div>
                  )}
                </div>
                <div className="text-sm text-gray-500">
                  {new Date(analysis.created_at).toLocaleDateString()}
                </div>
              </div>
            </Link>
          ))}
        </div>

        {(!analyses || analyses.length === 0) && (
          <div className="text-center py-12">
            <Code2 className="w-16 h-16 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-600 mb-4">No analyses yet</p>
            <Link to="/repositories" className="btn btn-primary">
              Add Repository
            </Link>
          </div>
        )}
      </div>
    </div>
  )
}




