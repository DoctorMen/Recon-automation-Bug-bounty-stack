import { Outlet, Link, useNavigate } from 'react-router-dom'
import { Brain, Home, GitBranch, CreditCard, LogOut, User } from 'lucide-react'
import { useAuthStore } from '../../store/auth'

export default function MainLayout() {
  const navigate = useNavigate()
  const { user, logout } = useAuthStore()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Top Navigation */}
      <nav className="bg-white border-b border-gray-200 sticky top-0 z-50">
        <div className="container mx-auto px-4">
          <div className="flex items-center justify-between h-16">
            <Link to="/dashboard" className="flex items-center space-x-2">
              <Brain className="w-8 h-8 text-primary-600" />
              <span className="text-xl font-bold text-gray-900">CodeAware</span>
            </Link>

            <div className="flex items-center space-x-6">
              <Link
                to="/dashboard"
                className="flex items-center space-x-2 text-gray-600 hover:text-gray-900"
              >
                <Home className="w-5 h-5" />
                <span>Dashboard</span>
              </Link>
              <Link
                to="/repositories"
                className="flex items-center space-x-2 text-gray-600 hover:text-gray-900"
              >
                <GitBranch className="w-5 h-5" />
                <span>Repositories</span>
              </Link>
              <Link
                to="/subscription"
                className="flex items-center space-x-2 text-gray-600 hover:text-gray-900"
              >
                <CreditCard className="w-5 h-5" />
                <span>Subscription</span>
              </Link>
            </div>

            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2 text-sm">
                <User className="w-4 h-4 text-gray-600" />
                <span className="text-gray-700">{user?.username}</span>
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center space-x-2 text-gray-600 hover:text-gray-900"
              >
                <LogOut className="w-5 h-5" />
                <span>Logout</span>
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 mt-20">
        <div className="container mx-auto px-4 py-8">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-2">
              <Brain className="w-6 h-6 text-primary-600" />
              <span className="text-sm text-gray-600">
                © 2025 CodeAware. All rights reserved.
              </span>
            </div>
            <div className="flex space-x-6 text-sm text-gray-600">
              <a href="#" className="hover:text-gray-900">Privacy</a>
              <a href="#" className="hover:text-gray-900">Terms</a>
              <a href="#" className="hover:text-gray-900">Support</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}




