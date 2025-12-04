'use client'

import { motion } from 'framer-motion'
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts'
import { TrendingUp, DollarSign } from 'lucide-react'
import { useStore } from '../store/useStore'

export default function RevenueChart() {
  const { transformation } = useStore()

  const generateProjection = () => {
    const years = [1, 2, 3, 4, 5]
    return years.map((year) => {
      const minGrowth = Math.pow(1.5, year - 1)
      const maxGrowth = Math.pow(1.7, year - 1)
      
      return {
        year: `Year ${year}`,
        min: Math.round(transformation.year1RevenueMin * minGrowth),
        projected: Math.round(
          (transformation.year1RevenueMin * minGrowth + transformation.year1RevenueMax * maxGrowth) / 2
        ),
        max: Math.round(transformation.year1RevenueMax * maxGrowth),
      }
    })
  }

  const data = generateProjection()

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-dark-800 border border-dark-700 rounded-lg p-4 shadow-xl">
          <p className="text-white font-semibold mb-2">{label}</p>
          <div className="space-y-1">
            <p className="text-green-400 text-sm">
              Min: ${(payload[0]?.value / 1000).toFixed(0)}K
            </p>
            <p className="text-primary-400 text-sm font-semibold">
              Projected: ${(payload[1]?.value / 1000).toFixed(0)}K
            </p>
            <p className="text-blue-400 text-sm">
              Max: ${(payload[2]?.value / 1000).toFixed(0)}K
            </p>
          </div>
        </div>
      )
    }
    return null
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="p-3 bg-green-500/20 rounded-xl border border-green-500/30">
            <TrendingUp className="w-8 h-8 text-green-400" />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white">Revenue Projection</h2>
            <p className="text-dark-400 text-sm">5-Year Growth Trajectory</p>
          </div>
        </div>
        
        <div className="text-right">
          <div className="text-sm text-dark-400">Year 5 Target</div>
          <div className="text-2xl font-bold gradient-text">
            ${(transformation.year5RevenueMax / 1000).toFixed(0)}K
          </div>
        </div>
      </div>

      <div className="h-80">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="colorMin" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#10b981" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#10b981" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorProjected" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
              </linearGradient>
              <linearGradient id="colorMax" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis 
              dataKey="year" 
              stroke="#94a3b8"
              style={{ fontSize: '14px' }}
            />
            <YAxis 
              stroke="#94a3b8"
              style={{ fontSize: '14px' }}
              tickFormatter={(value) => `$${(value / 1000).toFixed(0)}K`}
            />
            <Tooltip content={<CustomTooltip />} />
            <Legend 
              wrapperStyle={{ paddingTop: '20px' }}
              iconType="circle"
            />
            <Area 
              type="monotone" 
              dataKey="min" 
              stroke="#10b981" 
              fillOpacity={1} 
              fill="url(#colorMin)"
              name="Minimum"
            />
            <Area 
              type="monotone" 
              dataKey="projected" 
              stroke="#ef4444" 
              strokeWidth={3}
              fillOpacity={1} 
              fill="url(#colorProjected)"
              name="Projected"
            />
            <Area 
              type="monotone" 
              dataKey="max" 
              stroke="#3b82f6" 
              fillOpacity={1} 
              fill="url(#colorMax)"
              name="Maximum"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="grid grid-cols-3 gap-4 mt-6 pt-6 border-t border-dark-800">
        <div className="text-center">
          <div className="text-dark-400 text-sm mb-1">Year 1</div>
          <div className="text-lg font-bold text-white">
            ${(transformation.year1RevenueMin / 1000).toFixed(0)}K - ${(transformation.year1RevenueMax / 1000).toFixed(0)}K
          </div>
        </div>
        <div className="text-center">
          <div className="text-dark-400 text-sm mb-1">Year 5</div>
          <div className="text-lg font-bold gradient-text">
            ${(transformation.year5RevenueMin / 1000).toFixed(0)}K - ${(transformation.year5RevenueMax / 1000).toFixed(0)}K
          </div>
        </div>
        <div className="text-center">
          <div className="text-dark-400 text-sm mb-1">Exit Potential</div>
          <div className="text-lg font-bold text-green-400">
            ${(transformation.exitPotentialMin / 1000).toFixed(0)}K - ${(transformation.exitPotentialMax / 1000).toFixed(1)}M
          </div>
        </div>
      </div>
    </div>
  )
}




