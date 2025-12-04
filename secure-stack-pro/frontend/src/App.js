/**
 * Copyright © 2025 DoctorMen. All Rights Reserved.
 */
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { Toaster } from 'react-hot-toast';
import { motion, AnimatePresence } from 'framer-motion';

// Components
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import LoadingSpinner from './components/LoadingSpinner';

// Pages
import Dashboard from './pages/Dashboard';
import Scans from './pages/Scans';
import ScanDetails from './pages/ScanDetails';
import Snapshots from './pages/Snapshots';
import Compliance from './pages/Compliance';
import Settings from './pages/Settings';
import Login from './pages/Login';
import Register from './pages/Register';
import Landing from './pages/Landing';
import Pricing from './pages/Pricing';

// Hooks
import { useAuth } from './hooks/useAuth';
import { useTheme } from './hooks/useTheme';

// Contexts
import { AuthProvider } from './contexts/AuthContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { WebSocketProvider } from './contexts/WebSocketContext';

// Styles
import './App.css';

// React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 3,
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
      refetchOnWindowFocus: false,
    },
  },
});

// Protected Route Component
const ProtectedRoute = ({ children }) => {
  const { user, loading } = useAuth();
  
  if (loading) {
    return <LoadingSpinner />;
  }
  
  return user ? children : <Navigate to="/login" />;
};

// Main App Layout
const AppLayout = ({ children }) => {
  const { theme } = useTheme();
  
  return (
    <div className={`min-h-screen ${theme === 'dark' ? 'dark' : ''}`}>
      <div className="bg-gray-50 dark:bg-gray-900 min-h-screen">
        <Navbar />
        <div className="flex">
          <Sidebar />
          <main className="flex-1 ml-64">
            <div className="p-6">
              <AnimatePresence mode="wait">
                {children}
              </AnimatePresence>
            </div>
          </main>
        </div>
      </div>
    </div>
  );
};

// Public Layout (for landing, pricing, etc.)
const PublicLayout = ({ children }) => {
  return (
    <div className="min-h-screen bg-white">
      {children}
    </div>
  );
};

// Page Transition Wrapper
const PageTransition = ({ children }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      transition={{ duration: 0.3, ease: 'easeInOut' }}
    >
      {children}
    </motion.div>
  );
};

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AuthProvider>
          <WebSocketProvider>
            <Router>
              <div className="App">
                <Routes>
                  {/* Public Routes */}
                  <Route 
                    path="/" 
                    element={
                      <PublicLayout>
                        <PageTransition>
                          <Landing />
                        </PageTransition>
                      </PublicLayout>
                    } 
                  />
                  <Route 
                    path="/pricing" 
                    element={
                      <PublicLayout>
                        <PageTransition>
                          <Pricing />
                        </PageTransition>
                      </PublicLayout>
                    } 
                  />
                  <Route 
                    path="/login" 
                    element={
                      <PageTransition>
                        <Login />
                      </PageTransition>
                    } 
                  />
                  <Route 
                    path="/register" 
                    element={
                      <PageTransition>
                        <Register />
                      </PageTransition>
                    } 
                  />

                  {/* Protected Routes */}
                  <Route 
                    path="/dashboard" 
                    element={
                      <ProtectedRoute>
                        <AppLayout>
                          <PageTransition>
                            <Dashboard />
                          </PageTransition>
                        </AppLayout>
                      </ProtectedRoute>
                    } 
                  />
                  <Route 
                    path="/scans" 
                    element={
                      <ProtectedRoute>
                        <AppLayout>
                          <PageTransition>
                            <Scans />
                          </PageTransition>
                        </AppLayout>
                      </ProtectedRoute>
                    } 
                  />
                  <Route 
                    path="/scans/:id" 
                    element={
                      <ProtectedRoute>
                        <AppLayout>
                          <PageTransition>
                            <ScanDetails />
                          </PageTransition>
                        </AppLayout>
                      </ProtectedRoute>
                    } 
                  />
                  <Route 
                    path="/snapshots" 
                    element={
                      <ProtectedRoute>
                        <AppLayout>
                          <PageTransition>
                            <Snapshots />
                          </PageTransition>
                        </AppLayout>
                      </ProtectedRoute>
                    } 
                  />
                  <Route 
                    path="/compliance" 
                    element={
                      <ProtectedRoute>
                        <AppLayout>
                          <PageTransition>
                            <Compliance />
                          </PageTransition>
                        </AppLayout>
                      </ProtectedRoute>
                    } 
                  />
                  <Route 
                    path="/settings" 
                    element={
                      <ProtectedRoute>
                        <AppLayout>
                          <PageTransition>
                            <Settings />
                          </PageTransition>
                        </AppLayout>
                      </ProtectedRoute>
                    } 
                  />

                  {/* Redirect unknown routes */}
                  <Route path="*" element={<Navigate to="/" />} />
                </Routes>

                {/* Global Toast Notifications */}
                <Toaster
                  position="top-right"
                  toastOptions={{
                    duration: 4000,
                    style: {
                      background: '#363636',
                      color: '#fff',
                    },
                    success: {
                      iconTheme: {
                        primary: '#10B981',
                        secondary: '#fff',
                      },
                    },
                    error: {
                      iconTheme: {
                        primary: '#EF4444',
                        secondary: '#fff',
                      },
                    },
                  }}
                />
              </div>
            </Router>
          </WebSocketProvider>
        </AuthProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
