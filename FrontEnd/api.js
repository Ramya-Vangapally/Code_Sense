/**
 * Frontend API Helper
 * 
 * Reusable API communication layer for Render backend.
 * Automatically handles:
 * - Session cookies (credentials: 'include')
 * - Environment-based API base URL
 * - JSON serialization/deserialization
 * - Error handling
 */

class API {
  /**
   * Get the base API URL from environment or use default
   * For Vercel: Set REACT_APP_API_BASE or VITE_API_BASE env var
   * For local dev: Checks if running on 127.0.0.1, uses localhost:5000
   */
  static getBaseURL() {
    // Check for environment variable first (Vercel)
    if (typeof process !== 'undefined' && process.env) {
      if (process.env.REACT_APP_API_BASE) return process.env.REACT_APP_API_BASE;
      if (process.env.VITE_API_BASE) return process.env.VITE_API_BASE;
    }

    // Browser-based detection for client-side apps
    if (typeof window !== 'undefined') {
      const hostname = window.location.hostname;
      
      // Local development
      if (hostname === '127.0.0.1' || hostname === 'localhost') {
        return 'http://127.0.0.1:5000';
      }
    }

    // Production (Render backend)
    return 'https://code-sense-bxqi.onrender.com';
  }

  /**
   * Generic fetch wrapper with credentials and error handling
   * @param {string} endpoint - API endpoint (e.g., '/login', '/me')
   * @param {object} options - fetch options (method, body, etc.)
   * @returns {Promise<object>} - JSON response
   */
  static async request(endpoint, options = {}) {
    const url = `${this.getBaseURL()}${endpoint}`;
    
    // Default options
    const fetchOptions = {
      credentials: 'include', // IMPORTANT: Include cookies for session
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      ...options
    };

    try {
      const response = await fetch(url, fetchOptions);

      // Handle non-JSON responses (e.g., 204 No Content)
      if (response.status === 204) {
        return { success: true };
      }

      const data = await response.json();

      // Check if response is successful
      if (!response.ok) {
        throw new Error(data.message || `HTTP ${response.status}: ${response.statusText}`);
      }

      return data;
    } catch (error) {
      console.error(`API Error [${options.method || 'GET'} ${endpoint}]:`, error.message);
      throw error;
    }
  }

  /**
   * GET request
   */
  static get(endpoint) {
    return this.request(endpoint, { method: 'GET' });
  }

  /**
   * POST request
   */
  static post(endpoint, body) {
    return this.request(endpoint, {
      method: 'POST',
      body: JSON.stringify(body)
    });
  }

  /**
   * PATCH request
   */
  static patch(endpoint, body) {
    return this.request(endpoint, {
      method: 'PATCH',
      body: JSON.stringify(body)
    });
  }

  /**
   * DELETE request
   */
  static delete(endpoint, body = null) {
    const options = { method: 'DELETE' };
    if (body) {
      options.body = JSON.stringify(body);
    }
    return this.request(endpoint, options);
  }
}

// ============================================================
// AUTHENTICATION API CALLS
// ============================================================

/**
 * Check current session (verify if user is logged in)
 * @returns {Promise<object>} - User data if logged in, null if not
 */
async function checkSession() {
  try {
    return await API.get('/me');
  } catch (error) {
    // Not logged in or session expired
    return null;
  }
}

/**
 * User login
 * @param {string} username - Username
 * @param {string} password - Password
 * @returns {Promise<object>} - { token, user data, role, etc. }
 */
async function login(username, password) {
  return API.post('/login', { username, password });
}

/**
 * Request OTP for signup
 * @param {string} email - Email address
 * @param {string} username - Desired username
 * @param {string} password - Password
 * @returns {Promise<object>} - { message: "OTP sent to your email..." }
 */
async function requestOTP(email, username, password) {
  return API.post('/register/request-otp', { email, username, password });
}

/**
 * Complete signup with OTP verification
 * @param {string} email - Email address
 * @param {string} username - Username
 * @param {string} otp - OTP received in email
 * @returns {Promise<object>} - { user data, role, etc. }
 */
async function verifyOTPAndSignup(email, username, otp) {
  return API.post('/register', { email, username, otp });
}

/**
 * Google OAuth login
 * @param {string} credential - Google JWT credential
 * @returns {Promise<object>} - { token, user data, role, etc. }
 */
async function loginWithGoogle(credential) {
  return API.post('/auth/google', { credential });
}

/**
 * User logout (destroy session)
 * @returns {Promise<object>} - { message: "Logged out" }
 */
async function logout() {
  return API.post('/logout', {});
}

// ============================================================
// USER SETTINGS
// ============================================================

/**
 * Get user settings
 * @returns {Promise<object>} - { username, email, displayName, preferredLanguage }
 */
async function getUserSettings() {
  return API.get('/user/settings');
}

/**
 * Update user settings
 * @param {object} settings - { displayName, preferredLanguage, newPassword }
 * @returns {Promise<object>} - Updated user data
 */
async function updateUserSettings(settings) {
  return API.patch('/user/settings', settings);
}

// ============================================================
// CODE EXPLANATION (NO SESSION REQUIRED)
// ============================================================

/**
 * Get code explanation from AI
 * @param {string} code - Code to explain
 * @param {string} language - Programming language
 * @returns {Promise<object>} - { explanation: "..." }
 */
async function explainCode(code, language) {
  return API.post('/api/explain', { code, language });
}

// ============================================================
// EXAMPLE USAGE (Uncomment to test)
// ============================================================

/*
// 1. Check if user is already logged in
const user = await checkSession();
if (user) {
  console.log('User logged in:', user);
} else {
  console.log('Not logged in');
}

// 2. Login
try {
  const response = await login('testuser', 'password123');
  console.log('Login successful:', response);
} catch (error) {
  console.error('Login failed:', error.message);
}

// 3. Request OTP for signup
try {
  const response = await requestOTP('test@example.com', 'newuser', 'password123');
  console.log('OTP sent:', response.message);
} catch (error) {
  console.error('OTP request failed:', error.message);
}

// 4. Verify OTP and complete signup
try {
  const response = await verifyOTPAndSignup('test@example.com', 'newuser', '123456');
  console.log('Signup successful:', response);
} catch (error) {
  console.error('Signup failed:', error.message);
}

// 5. Get user settings
try {
  const settings = await getUserSettings();
  console.log('User settings:', settings);
} catch (error) {
  console.error('Failed to get settings:', error.message);
}

// 6. Update settings
try {
  const updated = await updateUserSettings({
    displayName: 'New Name',
    preferredLanguage: 'Python'
  });
  console.log('Settings updated:', updated);
} catch (error) {
  console.error('Update failed:', error.message);
}

// 7. Get code explanation
try {
  const result = await explainCode('console.log("hello")', 'javascript');
  console.log('Explanation:', result.explanation);
} catch (error) {
  console.error('Explanation failed:', error.message);
}

// 8. Logout
try {
  await logout();
  console.log('Logged out successfully');
} catch (error) {
  console.error('Logout failed:', error.message);
}
*/

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    API,
    checkSession,
    login,
    requestOTP,
    verifyOTPAndSignup,
    loginWithGoogle,
    logout,
    getUserSettings,
    updateUserSettings,
    explainCode
  };
}
