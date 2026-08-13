import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { getBackendUrl } from '../utils/getBackendUrl';
import { useAuthStore } from '../store/authStore';
import PritrakLogo from '../assets/pritrak-logo.svg';

const CURRENT_YEAR = 2026;

export default function LoginPage() {
  const navigate = useNavigate();
  const { setToken, setUser } = useAuthStore();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const backendUrl = getBackendUrl();
      const response = await axios.post(
        `${backendUrl}/api/auth/login`,
        { email: username, password },
        {
          headers: { 'Content-Type': 'application/json' },
          timeout: 10000,
        }
      );

      if (response.data && response.data.token) {
        const user = response.data.user || {
          id: '1',
          email: username,
          name: username.split('@')[0],
          role: 'viewer' as const,
        };

        setToken(response.data.token, response.data.refreshToken);
        setUser(user);
        useAuthStore.setState({
          isAuthenticated: true,
          user: user,
          token: response.data.token,
          refreshToken: response.data.refreshToken || null,
        });
        localStorage.setItem('auth_token', response.data.token);
        setTimeout(() => navigate('/dashboard'), 100);
      } else {
        setError('Invalid response from server');
      }
    } catch (err: any) {
      let errorMessage = 'Login failed. Please try again.';
      if (err.response?.data) {
        errorMessage = err.response.data.message || err.response.data.error || errorMessage;
      } else if (err.request) {
        errorMessage = 'Unable to connect to server. Please check if the backend is running.';
      }
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-white flex items-center justify-center px-4 relative">
      {/* Copyright in bottom left */}
      <div className="absolute bottom-4 left-4">
        <p className="text-sm text-gray-600">
          Copyright © {CURRENT_YEAR} Pritrak
        </p>
      </div>

      {/* Login Card */}
      <div className="w-full max-w-md">
        <div className="bg-white border border-gray-200 rounded-xl shadow-lg p-8">
          {/* Logo */}
          <div className="text-center mb-8">
            <img src={PritrakLogo} alt="Pritrak" className="h-40 mx-auto mb-6" />
            <h1 className="text-2xl font-semibold text-gray-800">Security Center</h1>
            <p className="text-lg text-gray-600 mt-2">Enterprise DLP Solution</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Username */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                User name
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Internal or domain user"
                disabled={loading}
                className="w-full px-4 py-2.5 border border-gray-300 rounded-lg text-gray-800 placeholder-gray-400 focus:ring-2 focus:ring-[#fd382f] focus:border-[#fd382f] transition"
                required
              />
            </div>

            {/* Password */}
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password"
                disabled={loading}
                className="w-full px-4 py-2.5 border border-gray-300 rounded-lg text-gray-800 placeholder-gray-400 focus:ring-2 focus:ring-[#fd382f] focus:border-[#fd382f] transition"
                required
              />
            </div>

            {/* Remember Me */}
            <div className="flex items-center">
              <input
                type="checkbox"
                id="rememberMe"
                checked={rememberMe}
                onChange={(e) => setRememberMe(e.target.checked)}
                disabled={loading}
                className="w-4 h-4 text-[#fd382f] border-gray-300 rounded focus:ring-[#fd382f] focus:ring-2"
              />
              <label htmlFor="rememberMe" className="ml-2 text-sm text-gray-700 cursor-pointer">
                Remember me
              </label>
            </div>

            {/* Error Message */}
            {error && (
              <div className="bg-red-50 border border-red-200 rounded-lg p-3 text-red-700 text-sm">
                {error}
              </div>
            )}

            {/* Sign In Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-[#fd382f] hover:bg-[#e02f26] text-white font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        </div>

        {/* Privacy Links */}
        <div className="mt-6 text-center space-x-4">
          <a
            href="#"
            className="text-[#fd382f] hover:underline text-sm font-medium"
          >
            Privacy Policy
          </a>
          <span className="text-gray-400">|</span>
          <a
            href="#"
            className="text-[#fd382f] hover:underline text-sm font-medium"
          >
            Data Protection Policy
          </a>
        </div>
      </div>
    </div>
  );
}
