import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './store/auth'

// Pages
import LandingPage from './pages/LandingPage'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import Dashboard from './pages/Dashboard'
import RepositoriesPage from './pages/RepositoriesPage'
import AnalysisPage from './pages/AnalysisPage'
import PricingPage from './pages/PricingPage'
import SubscriptionPage from './pages/SubscriptionPage'

// Layout
import MainLayout from './components/layout/MainLayout'
import AuthLayout from './components/layout/AuthLayout'

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore()
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />
}

function App() {
  return (
    <Routes>
      {/* Public Routes */}
      <Route path="/" element={<LandingPage />} />
      <Route path="/pricing" element={<PricingPage />} />
      
      {/* Auth Routes */}
      <Route element={<AuthLayout />}>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
      </Route>
      
      {/* Protected Routes */}
      <Route element={<MainLayout />}>
        <Route
          path="/dashboard"
          element={
            <PrivateRoute>
              <Dashboard />
            </PrivateRoute>
          }
        />
        <Route
          path="/repositories"
          element={
            <PrivateRoute>
              <RepositoriesPage />
            </PrivateRoute>
          }
        />
        <Route
          path="/analysis/:id"
          element={
            <PrivateRoute>
              <AnalysisPage />
            </PrivateRoute>
          }
        />
        <Route
          path="/subscription"
          element={
            <PrivateRoute>
              <SubscriptionPage />
            </PrivateRoute>
          }
        />
      </Route>
    </Routes>
  )
}

export default App




