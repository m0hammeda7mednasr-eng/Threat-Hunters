// Base API configuration
const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  (import.meta.env.DEV ? "http://localhost:5000/api" : "/api");

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

  // Verify email with OTP
  verifyEmail: async (payload) => {
    return apiRequest("/verify-email", {
      method: "POST",
      body: payload,
    });
  },

  // Resend verification OTP
  resendVerificationOtp: async (payload) => {
    return apiRequest("/verify-email/resend", {
      method: "POST",
      body: payload,
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

  // Get user console settings
  getSettings: async () => {
    return apiRequest("/user/settings");
  },

  // Update user console settings
  updateSettings: async (settingsData) => {
    return apiRequest("/user/settings", {
      method: "PUT",
      body: settingsData,
    });
  },

  // Delete current user account
  deleteAccount: async () => {
    return apiRequest("/user/account", {
      method: "DELETE",
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

  // Get security awareness learning content
  getAwarenessContent: async () => {
    return apiRequest("/security/awareness");
  },

  // Check password against Pwned Passwords
  checkPasswordBreach: async (payload) => {
    return apiRequest("/security/check-password", {
      method: "POST",
      body: payload,
    });
  },

  // Analyze password strength and exposure risk
  analyzePassword: async (payload) => {
    return apiRequest("/security/analyze-password", {
      method: "POST",
      body: payload,
    });
  },

  // Check email against HIBP breach data
  checkEmailBreach: async (payload) => {
    return apiRequest("/security/check-email", {
      method: "POST",
      body: payload,
    });
  },
};

// Blog API calls
export const blogAPI = {
  // Get all blog posts
  getPosts: async (options = {}) => {
    const params = new URLSearchParams();
    if (options.includeHidden) {
      params.set("include_hidden", "true");
    }

    const query = params.toString();
    return apiRequest(`/blogs${query ? `?${query}` : ""}`);
  },

  // Get single blog post
  getPost: async (id) => {
    return apiRequest(`/blogs/${id}`);
  },

  // Create new blog post (requires authentication)
  createPost: async (postData) => {
    return apiRequest("/blogs", {
      method: "POST",
      body: postData,
    });
  },

  // Update blog post (requires authentication)
  updatePost: async (id, postData) => {
    return apiRequest(`/blogs/${id}`, {
      method: "PUT",
      body: postData,
    });
  },

  // Delete blog post (requires authentication)
  deletePost: async (id) => {
    return apiRequest(`/blogs/${id}`, {
      method: "DELETE",
    });
  },

  // Hide or publish a post (admin only)
  setPostStatus: async (id, status) => {
    return apiRequest(`/blogs/${id}/status`, {
      method: "PATCH",
      body: { status },
    });
  },

  // Toggle likes on a post
  toggleLike: async (id) => {
    return apiRequest(`/blogs/${id}/like`, {
      method: "POST",
    });
  },

  // Track shares on a post
  sharePost: async (id) => {
    return apiRequest(`/blogs/${id}/share`, {
      method: "POST",
    });
  },

  // Add a comment to a post
  addComment: async (id, commentData) => {
    return apiRequest(`/blogs/${id}/comments`, {
      method: "POST",
      body: commentData,
    });
  },

  // Reply to an existing comment
  addReply: async (id, commentId, replyData) => {
    return apiRequest(`/blogs/${id}/comments/${commentId}/replies`, {
      method: "POST",
      body: replyData,
    });
  },

  // Get comments for a post
  getComments: async (id) => {
    return apiRequest(`/blogs/${id}/comments`);
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

// Scanner API calls
export const scannerAPI = {
  scanWebsite: async (payload) => {
    return apiRequest("/scanner/scan", {
      method: "POST",
      body: payload,
    });
  },
  getReports: async (limit = 12) => {
    return apiRequest(`/scanner/reports?limit=${limit}`);
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

  // Create user from admin dashboard
  createUser: async (userData) => {
    return apiRequest("/admin/users", {
      method: "POST",
      body: userData,
    });
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

// Admin workspace API calls
export const adminAPI = {
  getSettings: async () => {
    return apiRequest("/admin/settings");
  },

  updateSettings: async (settingsData) => {
    return apiRequest("/admin/settings", {
      method: "PUT",
      body: settingsData,
    });
  },

  getTeam: async () => {
    return apiRequest("/admin/team");
  },

  addTeamMember: async (memberData) => {
    return apiRequest("/admin/team", {
      method: "POST",
      body: memberData,
    });
  },

  updateTeamMember: async (id, memberData) => {
    return apiRequest(`/admin/team/${id}`, {
      method: "PUT",
      body: memberData,
    });
  },

  deleteTeamMember: async (id) => {
    return apiRequest(`/admin/team/${id}`, {
      method: "DELETE",
    });
  },

  getPricing: async () => {
    return apiRequest("/admin/pricing");
  },

  updatePricing: async (pricingData) => {
    return apiRequest("/admin/pricing", {
      method: "PUT",
      body: pricingData,
    });
  },

  addPricingPlan: async (planData) => {
    return apiRequest("/admin/pricing/plans", {
      method: "POST",
      body: planData,
    });
  },

  updatePricingPlan: async (id, planData) => {
    return apiRequest(`/admin/pricing/plans/${id}`, {
      method: "PUT",
      body: planData,
    });
  },

  deletePricingPlan: async (id) => {
    return apiRequest(`/admin/pricing/plans/${id}`, {
      method: "DELETE",
    });
  },

  getReports: async () => {
    return apiRequest("/admin/reports");
  },

  generateReport: async (reportData = {}) => {
    return apiRequest("/admin/reports", {
      method: "POST",
      body: reportData,
    });
  },

  recordReportDownload: async (id) => {
    return apiRequest(`/admin/reports/${id}/download`, {
      method: "POST",
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
    localStorage.removeItem("isLoggedIn");
    localStorage.removeItem("threatHuntersUserRole");
    localStorage.removeItem("threatHuntersUserEmail");
    localStorage.removeItem("threatHuntersScanReports");
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
      localStorage.setItem("threatHuntersUserRole", user.role);
    }
    if (user.email) {
      localStorage.setItem("threatHuntersUserEmail", user.email);
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
  admin: adminAPI,
  utils,
};
