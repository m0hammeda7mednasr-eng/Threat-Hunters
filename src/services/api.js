// Base API configuration
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "/api";

// Helper function to handle API responses
const handleResponse = async (response) => {
  const contentType = response.headers.get("content-type");

  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`;

    if (contentType && contentType.includes("application/json")) {
      try {
        const errorData = await response.json();
        errorMessage = errorData.message || errorMessage;
      } catch {
        // If can't parse JSON, use default message
      }
    }

    throw new Error(errorMessage);
  }

  if (contentType && contentType.includes("application/json")) {
    return await response.json();
  }

  return await response.text();
};

// Helper function to make API requests with authentication
const apiRequest = async (endpoint, options = {}) => {
  const token = localStorage.getItem("token");

  const config = {
    headers: {
      "Content-Type": "application/json",
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options.headers,
    },
    ...options,
  };

  if (config.body && typeof config.body === "object") {
    config.body = JSON.stringify(config.body);
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, config);
  return handleResponse(response);
};

// Authentication API calls
export const authAPI = {
  // Register new user
  register: async (userData) => {
    return apiRequest("/register", {
      method: "POST",
      body: userData,
    });
  },

  // Login user
  login: async (credentials) => {
    return apiRequest("/login", {
      method: "POST",
      body: credentials,
    });
  },

  // Get current user profile
  getProfile: async () => {
    return apiRequest("/user/profile");
  },

  // Update user profile
  updateProfile: async (profileData) => {
    return apiRequest("/user/profile", {
      method: "PUT",
      body: profileData,
    });
  },

  // Change password
  changePassword: async (passwordData) => {
    return apiRequest("/user/password", {
      method: "PUT",
      body: passwordData,
    });
  },

  // Request password reset
  requestPasswordReset: async (payload) => {
    return apiRequest("/password/forgot", {
      method: "POST",
      body: payload,
    });
  },

  // Confirm password reset
  resetPassword: async (payload) => {
    return apiRequest("/password/reset", {
      method: "POST",
      body: payload,
    });
  },
};

// Security API calls
export const securityAPI = {
  // Get latest CVEs
  getLatestCVEs: async () => {
    return apiRequest("/security/latest-cves");
  },

  // Get critical CVEs
  getCriticalCVEs: async () => {
    return apiRequest("/security/critical-cves");
  },

  // Get known exploited vulnerabilities (KEV)
  getKEV: async () => {
    return apiRequest("/security/kev");
  },

  // Get security news
  getSecurityNews: async () => {
    return apiRequest("/security/news");
  },
};

// Blog API calls
export const blogAPI = {
  // Get all blog posts
  getPosts: async () => {
    return apiRequest("/blog");
  },

  // Get single blog post
  getPost: async (id) => {
    return apiRequest(`/blog/${id}`);
  },

  // Create new blog post (requires authentication)
  createPost: async (postData) => {
    return apiRequest("/blog", {
      method: "POST",
      body: postData,
    });
  },

  // Update blog post (requires authentication)
  updatePost: async (id, postData) => {
    return apiRequest(`/blog/${id}`, {
      method: "PUT",
      body: postData,
    });
  },

  // Delete blog post (requires authentication)
  deletePost: async (id) => {
    return apiRequest(`/blog/${id}`, {
      method: "DELETE",
    });
  },

  // Toggle likes on a post
  toggleLike: async (id) => {
    return apiRequest(`/blog/${id}/like`, {
      method: "POST",
    });
  },

  // Track shares on a post
  sharePost: async (id) => {
    return apiRequest(`/blog/${id}/share`, {
      method: "POST",
    });
  },

  // Add a comment to a post
  addComment: async (id, commentData) => {
    return apiRequest(`/blog/${id}/comments`, {
      method: "POST",
      body: commentData,
    });
  },

  // Reply to an existing comment
  addReply: async (id, commentId, replyData) => {
    return apiRequest(`/blog/${id}/comments/${commentId}/replies`, {
      method: "POST",
      body: replyData,
    });
  },
};

// Dashboard/Analytics API calls
export const dashboardAPI = {
  // Get dashboard statistics
  getStats: async () => {
    return apiRequest("/dashboard/stats");
  },

  // Get recent activities
  getRecentActivities: async () => {
    return apiRequest("/dashboard/activities");
  },

  // Get security metrics
  getSecurityMetrics: async () => {
    return apiRequest("/dashboard/security-metrics");
  },
};

// Website content API calls
export const contentAPI = {
  getContent: async () => {
    return apiRequest("/web-content");
  },

  updateContent: async (page, content) => {
    return apiRequest(`/web-content/${page}`, {
      method: "PUT",
      body: content,
    });
  },
};

// User management API calls (admin only)
export const userAPI = {
  // Get all users
  getUsers: async (page = 1, limit = 10) => {
    return apiRequest(`/admin/users?page=${page}&limit=${limit}`);
  },

  // Get single user
  getUser: async (id) => {
    return apiRequest(`/admin/users/${id}`);
  },

  // Update user role/status
  updateUser: async (id, userData) => {
    return apiRequest(`/admin/users/${id}`, {
      method: "PUT",
      body: userData,
    });
  },

  // Delete user
  deleteUser: async (id) => {
    return apiRequest(`/admin/users/${id}`, {
      method: "DELETE",
    });
  },
};

// Utility functions
export const utils = {
  // Test API connection
  ping: async () => {
    try {
      const response = await fetch("/api/ping");
      return response.ok;
    } catch {
      return false;
    }
  },

  // Logout user (clear local storage)
  logout: () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    localStorage.removeItem("userRole");
  },

  // Get stored user data
  getCurrentUser: () => {
    try {
      const user = localStorage.getItem("user");
      return user ? JSON.parse(user) : null;
    } catch {
      return null;
    }
  },

  // Store user data
  setCurrentUser: (user) => {
    localStorage.setItem("user", JSON.stringify(user));
    if (user.role) {
      localStorage.setItem("userRole", user.role);
    }
  },

  // Check if user is authenticated
  isAuthenticated: () => {
    return !!localStorage.getItem("token");
  },

  // Get user role
  getUserRole: () => {
    return localStorage.getItem("userRole") || "user";
  },
};

// Export default API object
export default {
  auth: authAPI,
  security: securityAPI,
  blog: blogAPI,
  dashboard: dashboardAPI,
  content: contentAPI,
  user: userAPI,
  utils,
};
