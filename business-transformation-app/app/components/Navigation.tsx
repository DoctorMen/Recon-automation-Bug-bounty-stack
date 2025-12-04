'use client'

import { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  LayoutDashboard, 
  Target, 
  BookOpen, 
  FileText, 
  Settings, 
  Download, 
  Upload,
  BarChart3,
  Menu,
  X
} from 'lucide-react'

interface NavigationProps {
  activeSection: string
  onSectionChange: (section: string) => void
}

export default function Navigation({ activeSection, onSectionChange }: NavigationProps) {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard className="w-5 h-5" /> },
    { id: 'transformation', label: 'Transformation', icon: <BarChart3 className="w-5 h-5" /> },
    { id: 'learning', label: 'Learning', icon: <BookOpen className="w-5 h-5" /> },
    { id: 'documentation', label: 'Documentation', icon: <FileText className="w-5 h-5" /> },
    { id: 'milestones', label: 'Milestones', icon: <Target className="w-5 h-5" /> },
    { id: 'settings', label: 'Settings', icon: <Settings className="w-5 h-5" /> },
  ]

  const handleNavClick = (sectionId: string) => {
    onSectionChange(sectionId)
    setIsMobileMenuOpen(false)
  }

  return (
    <>
      {/* Mobile Menu Button */}
      <button
        onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
        className="lg:hidden fixed top-4 right-4 z-50 p-3 bg-dark-800 border border-dark-700 rounded-lg text-white"
      >
        {isMobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      {/* Sidebar */}
      <motion.nav
        initial={{ x: -300 }}
        animate={{ x: isMobileMenuOpen || window.innerWidth >= 1024 ? 0 : -300 }}
        className={`
          fixed lg:sticky top-0 left-0 h-screen w-64 bg-dark-900 border-r border-dark-800 p-6 z-40
          ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
          transition-transform duration-300 ease-in-out
        `}
      >
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-primary-500/20 rounded-lg">
              <Target className="w-6 h-6 text-primary-400" />
            </div>
            <h1 className="text-xl font-bold gradient-text">BizTransform</h1>
          </div>
          <p className="text-xs text-dark-400">Transform Knowledge into Business</p>
        </div>

        <div className="space-y-2">
          {navItems.map((item) => (
            <button
              key={item.id}
              onClick={() => handleNavClick(item.id)}
              className={`
                w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all
                ${activeSection === item.id
                  ? 'bg-primary-500/20 text-primary-400 border border-primary-500/30'
                  : 'text-dark-300 hover:bg-dark-800 hover:text-white'
                }
              `}
            >
              {item.icon}
              <span className="font-medium">{item.label}</span>
            </button>
          ))}
        </div>

        <div className="absolute bottom-6 left-6 right-6 pt-6 border-t border-dark-800">
          <div className="text-xs text-dark-400 text-center">
            Version 1.0.0
          </div>
        </div>
      </motion.nav>

      {/* Mobile Overlay */}
      {isMobileMenuOpen && (
        <div
          onClick={() => setIsMobileMenuOpen(false)}
          className="lg:hidden fixed inset-0 bg-black/50 z-30"
        />
      )}
    </>
  )
}




