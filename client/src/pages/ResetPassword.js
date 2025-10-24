import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';
import LoadingSpinner from '../components/LoadingSpinner';
import { FaEye, FaEyeSlash, FaSun, FaMoon, FaArrowLeft } from 'react-icons/fa';

const ResetPassword = () => {
  const [formData, setFormData] = useState({
    password: '',
    confirmPassword: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState('');
  
  const { resetPassword } = useAuth();
  const { darkMode, toggleDarkMode } = useTheme();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');

  useEffect(() => {
    if (!token) {
      navigate('/login', { replace: true });
    }
  }, [token, navigate]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ''
      }));
    }
  };

  const validateForm = () => {
    const newErrors = {};

    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }

    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Please confirm your password';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }

    setLoading(true);
    setError('');

    const result = await resetPassword(token, formData.password);
    
    if (result.success) {
      setSuccess(true);
      setTimeout(() => {
        navigate('/login', { replace: true });
      }, 2000);
    } else {
      setError(result.error);
    }
    
    setLoading(false);
  };

  if (success) {
    return (
      <div className={`min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 ${darkMode ? 'dark bg-gray-900' : 'bg-gray-50'}`}>
        <div className="max-w-md w-full space-y-8">
          <div className="text-center">
            <div className="flex justify-center items-center mb-6">
              <button
                onClick={toggleDarkMode}
                className="p-2 rounded-lg bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
              >
                {darkMode ? <FaSun className="w-5 h-5" /> : <FaMoon className="w-5 h-5" />}
              </button>
            </div>
            <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-green-100">
              <svg className="h-6 w-6 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"></path>
              </svg>
            </div>
            <h2 className="mt-6 text-3xl font-bold text-gray-900 dark:text-white">
              Password Reset Successfully
            </h2>
            <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
              Your password has been updated. You will be redirected to the login page.
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={`min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 ${darkMode ? 'dark bg-gray-900' : 'bg-gray-50'}`}>
      <div className="max-w-md w-full space-y-8">
        {/* Header */}
        <div className="text-center">
          <div className="flex justify-center items-center mb-6">
            <button
              onClick={toggleDarkMode}
              className="p-2 rounded-lg bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
            >
              {darkMode ? <FaSun className="w-5 h-5" /> : <FaMoon className="w-5 h-5" />}
            </button>
          </div>
          <h2 className="text-3xl font-bold text-gray-900 dark:text-white">
            Reset Password
          </h2>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
            Enter your new password below
          </p>
        </div>

        {/* Reset Password Form */}
        <div className={`${darkMode ? 'bg-gray-800' : 'bg-white'} shadow-xl rounded-lg p-8`}>
          <form className="space-y-6" onSubmit={handleSubmit}>
            <div>
              <label htmlFor="password" className="label">
                New Password
              </label>
              <div className="relative mt-1">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  required
                  value={formData.password}
                  onChange={handleChange}
                  className={`input pr-10 ${errors.password ? 'border-red-500' : ''}`}
                  placeholder="Enter your new password"
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? (
                    <FaEyeSlash className="h-4 w-4 text-gray-400" />
                  ) : (
                    <FaEye className="h-4 w-4 text-gray-400" />
                  )}
                </button>
              </div>
              {errors.password && (
                <p className="mt-1 text-sm text-red-600">{errors.password}</p>
              )}
            </div>

            <div>
              <label htmlFor="confirmPassword" className="label">
                Confirm New Password
              </label>
              <div className="relative mt-1">
                <input
                  id="confirmPassword"
                  name="confirmPassword"
                  type={showConfirmPassword ? 'text' : 'password'}
                  autoComplete="new-password"
                  required
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  className={`input pr-10 ${errors.confirmPassword ? 'border-red-500' : ''}`}
                  placeholder="Confirm your new password"
                />
                <button
                  type="button"
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                >
                  {showConfirmPassword ? (
                    <FaEyeSlash className="h-4 w-4 text-gray-400" />
                  ) : (
                    <FaEye className="h-4 w-4 text-gray-400" />
                  )}
                </button>
              </div>
              {errors.confirmPassword && (
                <p className="mt-1 text-sm text-red-600">{errors.confirmPassword}</p>
              )}
            </div>

            {error && (
              <div className="bg-red-50 border border-red-200 rounded-md p-4">
                <p className="text-sm text-red-600">{error}</p>
              </div>
            )}

            <div>
              <button
                type="submit"
                disabled={loading}
                className="btn btn-primary w-full btn-lg"
              >
                {loading ? (
                  <div className="flex items-center justify-center">
                    <LoadingSpinner size="sm" className="mr-2" />
                    Resetting...
                  </div>
                ) : (
                  'Reset Password'
                )}
              </button>
            </div>

            <div className="text-center">
              <Link
                to="/login"
                className="font-medium text-primary-600 hover:text-primary-500 flex items-center justify-center"
              >
                <FaArrowLeft className="mr-2" />
                Back to Login
              </Link>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default ResetPassword;
