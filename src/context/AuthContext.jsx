import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { authAPI, utils } from "../services/api";

const AuthContext = createContext();

// eslint-disable-next-line react-refresh/only-export-components
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Initialize auth state from local storage
  useEffect(() => {
    const initializeAuth = () => {
      const token = localStorage.getItem("token");
      const userData = utils.getCurrentUser();

      if (token && userData) {
        setUser(userData);
      }

      setLoading(false);
    };

    initializeAuth();
  }, []);

  // Login function
  const login = async (credentials) => {
    try {
      setError(null);
      setLoading(true);

      const response = await authAPI.login(credentials);

      if (response.token && response.role) {
        // Store token
        localStorage.setItem("token", response.token);

        // Create user object from the API response when available.
        const userData = {
          ...(response.user || {}),
          email: response.user?.email || credentials.email,
          role: response.role,
          loginTime: new Date().toISOString(),
        };

        // Store user data
        utils.setCurrentUser(userData);
        setUser(userData);

        return { success: true, data: response };
      } else {
        throw new Error("Invalid response from server");
      }
    } catch (err) {
      const errorMessage = err.message || "Login failed";
      setError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  };

  // Register function
  const register = async (userData) => {
    try {
      setError(null);
      setLoading(true);

      const response = await authAPI.register(userData);

      return { success: true, data: response };
    } catch (err) {
      const errorMessage = err.message || "Registration failed";
      setError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  };

  // Logout function
  const logout = () => {
    utils.logout();
    setUser(null);
    setError(null);
  };

  // Get user profile
  const getProfile = async () => {
    try {
      setError(null);
      const profileData = await authAPI.getProfile();

      if (profileData) {
        const updatedUser = { ...user, ...profileData };
        utils.setCurrentUser(updatedUser);
        setUser(updatedUser);
      }

      return { success: true, data: profileData };
    } catch (err) {
      const errorMessage = err.message || "Failed to fetch profile";
      setError(errorMessage);
      return { success: false, error: errorMessage };
    }
  };

  // Update user profile
  const updateProfile = async (profileData) => {
    try {
      setError(null);
      const response = await authAPI.updateProfile(profileData);

      if (response) {
        const updatedUser = { ...user, ...response };
        utils.setCurrentUser(updatedUser);
        setUser(updatedUser);
      }

      return { success: true, data: response };
    } catch (err) {
      const errorMessage = err.message || "Failed to update profile";
      setError(errorMessage);
      return { success: false, error: errorMessage };
    }
  };

  // Change password
  const changePassword = async (passwordData) => {
    try {
      setError(null);
      const response = await authAPI.changePassword(passwordData);
      return { success: true, data: response };
    } catch (err) {
      const errorMessage = err.message || "Failed to change password";
      setError(errorMessage);
      return { success: false, error: errorMessage };
    }
  };

  const getSettings = async () => {
    try {
      setError(null);
      const response = await authAPI.getSettings();
      return { success: true, data: response };
    } catch (err) {
      const errorMessage = err.message || "Failed to fetch settings";
      setError(errorMessage);
      return { success: false, error: errorMessage };
    }
  };

  const updateSettings = async (settingsData) => {
    try {
      setError(null);
      const response = await authAPI.updateSettings(settingsData);
      return { success: true, data: response };
    } catch (err) {
      const errorMessage = err.message || "Failed to update settings";
      setError(errorMessage);
      return { success: false, error: errorMessage };
    }
  };

  const deleteAccount = async () => {
    try {
      setError(null);
      const response = await authAPI.deleteAccount();
      utils.logout();
      setUser(null);
      return { success: true, data: response };
    } catch (err) {
      const errorMessage = err.message || "Failed to delete account";
      setError(errorMessage);
      return { success: false, error: errorMessage };
    }
  };

  const requestPasswordReset = async (payload) => {
    try {
      setError(null);
      const response = await authAPI.requestPasswordReset(payload);
      return { success: true, data: response };
    } catch (err) {
      const errorMessage = err.message || "Failed to request password reset";
      setError(errorMessage);
      return { success: false, error: errorMessage };
    }
  };

  const resetPassword = async (payload) => {
    try {
      setError(null);
      const response = await authAPI.resetPassword(payload);
      return { success: true, data: response };
    } catch (err) {
      const errorMessage = err.message || "Failed to reset password";
      setError(errorMessage);
      return { success: false, error: errorMessage };
    }
  };

  // Check if user has specific role
  const hasRole = (requiredRole) => {
    if (!user || !user.role) return false;

    const roleHierarchy = {
      user: 1,
      analyst: 2,
      manager: 3,
      admin: 4,
    };

    const userLevel = roleHierarchy[user.role] || 0;
    const requiredLevel = roleHierarchy[requiredRole] || 0;

    return userLevel >= requiredLevel;
  };

  // Check if user is authenticated
  const isAuthenticated = useMemo(() => {
    return utils.isAuthenticated() && user !== null;
  }, [user]);

  // Context value
  const contextValue = {
    // State
    user,
    loading,
    error,
    isAuthenticated,

    // Actions
    login,
    register,
    logout,
    getProfile,
    updateProfile,
    changePassword,
    getSettings,
    updateSettings,
    deleteAccount,
    requestPasswordReset,
    resetPassword,
    hasRole,

    // Utils
    clearError: () => setError(null),
  };

  return (
    <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>
  );
};
