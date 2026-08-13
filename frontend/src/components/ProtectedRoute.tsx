import { Navigate, useLocation } from 'react-router-dom';
import { useAuthStore } from '../store/authStore';
import { useEffect } from 'react';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, token } = useAuthStore();
  const location = useLocation();

  // Check if token exists in localStorage as fallback
  const localStorageToken = localStorage.getItem('auth_token');
  const hasToken = token || localStorageToken;

  // Remove excessive logging - only log once on mount or path change
  useEffect(() => {
    console.log('🔐 ProtectedRoute:', { 
      authenticated: isAuthenticated, 
      path: location.pathname 
    });
  }, [location.pathname, isAuthenticated]); // Only log when path or auth state changes

  // If not authenticated, redirect to login
  if (!isAuthenticated && !hasToken) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // If we have a token but store isn't updated, try to restore from localStorage
  if (localStorageToken && !isAuthenticated) {
    // Try to restore auth state
    try {
      const authData = localStorage.getItem('auth-storage');
      if (authData) {
        const parsed = JSON.parse(authData);
        if (parsed.state) {
          useAuthStore.setState({
            token: parsed.state.token || localStorageToken,
            user: parsed.state.user || null,
            isAuthenticated: true,
          });
        }
      } else {
        // Fallback: just set the token
        useAuthStore.setState({
          token: localStorageToken,
          isAuthenticated: true,
        });
      }
    } catch (e) {
      console.error('Error restoring auth state:', e);
    }
  }

  // Render children if authenticated
  return <>{children}</>;
}
