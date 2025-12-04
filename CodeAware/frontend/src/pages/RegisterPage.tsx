import { useForm } from 'react-hook-form'
import { Link, useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { Brain } from 'lucide-react'
import api from '../lib/api'

interface RegisterForm {
  email: string
  username: string
  password: string
  full_name: string
}

export default function RegisterPage() {
  const navigate = useNavigate()
  const { register, handleSubmit, formState: { errors } } = useForm<RegisterForm>()

  const registerMutation = useMutation({
    mutationFn: async (data: RegisterForm) => {
      const res = await api.post('/auth/register', data)
      return res.data
    },
    onSuccess: () => {
      navigate('/login')
    },
  })

  const onSubmit = (data: RegisterForm) => {
    registerMutation.mutate(data)
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-primary-50 to-white">
      <div className="card max-w-md w-full mx-4 animate-slide-up">
        <Link to="/" className="flex items-center justify-center space-x-2 mb-8">
          <Brain className="w-8 h-8 text-primary-600" />
          <span className="text-2xl font-bold text-gray-900">CodeAware</span>
        </Link>

        <h2 className="text-2xl font-bold text-gray-900 mb-6 text-center">
          Create Your Account
        </h2>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Full Name
            </label>
            <input
              type="text"
              {...register('full_name', { required: 'Full name is required' })}
              className="input"
              placeholder="Enter your full name"
            />
            {errors.full_name && (
              <p className="text-red-600 text-sm mt-1">{errors.full_name.message}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Email
            </label>
            <input
              type="email"
              {...register('email', {
                required: 'Email is required',
                pattern: {
                  value: /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i,
                  message: 'Invalid email address'
                }
              })}
              className="input"
              placeholder="you@example.com"
            />
            {errors.email && (
              <p className="text-red-600 text-sm mt-1">{errors.email.message}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Username
            </label>
            <input
              type="text"
              {...register('username', {
                required: 'Username is required',
                minLength: {
                  value: 3,
                  message: 'Username must be at least 3 characters'
                }
              })}
              className="input"
              placeholder="Choose a username"
            />
            {errors.username && (
              <p className="text-red-600 text-sm mt-1">{errors.username.message}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Password
            </label>
            <input
              type="password"
              {...register('password', {
                required: 'Password is required',
                minLength: {
                  value: 8,
                  message: 'Password must be at least 8 characters'
                }
              })}
              className="input"
              placeholder="Create a strong password"
            />
            {errors.password && (
              <p className="text-red-600 text-sm mt-1">{errors.password.message}</p>
            )}
          </div>

          {registerMutation.isError && (
            <div className="bg-red-50 text-red-600 px-4 py-3 rounded-lg text-sm">
              Registration failed. Please try again.
            </div>
          )}

          {registerMutation.isSuccess && (
            <div className="bg-green-50 text-green-600 px-4 py-3 rounded-lg text-sm">
              Account created! Redirecting to login...
            </div>
          )}

          <button
            type="submit"
            disabled={registerMutation.isPending}
            className="btn btn-primary w-full"
          >
            {registerMutation.isPending ? 'Creating account...' : 'Create Account'}
          </button>
        </form>

        <div className="mt-6 text-center text-sm text-gray-600">
          Already have an account?{' '}
          <Link to="/login" className="text-primary-600 hover:text-primary-700 font-medium">
            Login
          </Link>
        </div>

        <p className="text-xs text-gray-500 text-center mt-6">
          By creating an account, you agree to our Terms of Service and Privacy Policy
        </p>
      </div>
    </div>
  )
}




