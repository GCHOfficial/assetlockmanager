import axios from 'axios';

// Determine the API base URL from environment variables
// Fallback to localhost for development if not set
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Interceptor to add JWT token to requests
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('authToken'); // Or sessionStorage
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Placeholder functions - Implement actual API calls here

// Define expected User structure from backend
interface User {
  id: number;
  username: string;
  email: string;
  is_admin: boolean;
}

// Define expected Login response structure
interface LoginResponse {
  access_token: string;
}

// Define expected Lock structure from backend
interface Lock {
  id: number;
  asset_path: string;
  branch: string;
  comment: string | null;
  locked_by: string; // Username
  timestamp: string; // ISO date string
  // user: User; // Backend currently returns locked_by string, not full user object
}

// Define expected API response structure for confirmation requests
interface ConfirmationResponse {
  msg: string;
}

export const login = async (credentials: any) => {
  try {
    // Step 1: Authenticate and get the token
    const loginResponse = await apiClient.post<LoginResponse>('/login', credentials);
    const token = loginResponse.data.access_token;

    if (!token) {
      throw new Error('Login failed: No token received');
    }

    // Store token immediately so subsequent requests are authenticated
    localStorage.setItem('authToken', token);

    // Step 2: Fetch user details using the new token
    const userResponse = await apiClient.get<User>('/currentuser');
    const user = userResponse.data;

    if (!user) {
      throw new Error('Login succeeded but failed to fetch user details');
    }

    // Return both token and user data
    return { token, user };

  } catch (error) {
    // Clear token if login or user fetch fails
    localStorage.removeItem('authToken');
    console.error('Login process failed:', error);
    // Re-throw the error so the component can handle it
    throw error;
  }
};

export const logout = () => {
  // TODO: Implement actual logout logic if needed (e.g., call backend endpoint)
  localStorage.removeItem('authToken');
};

export const getLocks = async (): Promise<Lock[]> => {
  try {
    const response = await apiClient.get<Lock[]>('/locks');
    return response.data;
  } catch (error) {
    console.error('Failed to fetch locks:', error);
    // Return empty array or re-throw error based on how calling component should handle
    throw error; // Re-throw for now
  }
};

export const releaseLock = async (assetPath: string): Promise<void> => {
  try {
    // The backend expects the asset path in the URL, make sure it's properly encoded
    const encodedAssetPath = encodeURIComponent(assetPath);
    await apiClient.delete(`/locks/${encodedAssetPath}`);
  } catch (error) {
    console.error(`Failed to release lock for ${assetPath}:`, error);
    // Re-throw error for the component to handle
    throw error;
  }
};

// Define payload structure for changing password
interface ChangePasswordPayload {
  current_password: string;
  new_password: string;
}

export const changePasswordSelf = async (payload: ChangePasswordPayload): Promise<ConfirmationResponse> => {
  try {
    // Expect a response containing a 'msg' field
    const response = await apiClient.put<ConfirmationResponse>('/users/me/password', payload);
    return response.data;
  } catch (error) {
    console.error('Failed to change password:', error);
    throw error; // Re-throw for component handling
  }
};

// Define payload structure for changing email
interface ChangeEmailPayload {
  new_email: string;
  current_password: string; // Backend requires current password for email change
}

export const changeEmailSelf = async (payload: ChangeEmailPayload): Promise<ConfirmationResponse> => {
  try {
    // Expect a response containing a 'msg' field
    const response = await apiClient.put<ConfirmationResponse>('/users/me/email', payload);
    return response.data;
    // Note: The backend doesn't return the updated user object here.
    // The frontend might need to re-fetch user data or update context manually
    // if the email display needs to be updated immediately elsewhere.
  } catch (error) {
    console.error('Failed to change email:', error);
    throw error; // Re-throw for component handling
  }
};

// --- Notify Lock Holder API --- 
export const notifyLockHolder = async (assetPath: string): Promise<ConfirmationResponse> => {
    try {
        const encodedAssetPath = encodeURIComponent(assetPath.startsWith('/') ? assetPath.substring(1) : assetPath);
        const response = await apiClient.post<ConfirmationResponse>(`/locks/path/${encodedAssetPath}/notify`);
        return response.data;
    } catch (error) {
        console.error(`Failed to send notification for ${assetPath}:`, error);
        throw error;
    }
};

// --- Admin API Functions ---

// Re-using User interface defined earlier
// interface User { id: number; username: string; email: string; is_admin: boolean; }

export const adminListUsers = async (): Promise<User[]> => {
  try {
    const response = await apiClient.get<User[]>('/admin/users');
    return response.data;
  } catch (error) {
    console.error('Failed to list users:', error);
    throw error;
  }
};

interface AdminCreateUserPayload {
  username: string;
  email: string;
  password: string;
}

export const adminCreateUser = async (payload: AdminCreateUserPayload): Promise<User> => {
  try {
    const response = await apiClient.post<User>('/admin/users', payload);
    return response.data; // Backend returns the created user
  } catch (error) {
    console.error('Failed to create user:', error);
    throw error;
  }
};

interface AdminUpdateUserStatusPayload {
  is_admin: boolean;
}

export const adminUpdateUserStatus = async (userId: number, payload: AdminUpdateUserStatusPayload): Promise<void> => {
  try {
    await apiClient.put(`/admin/users/${userId}/status`, payload);
  } catch (error) {
    console.error(`Failed to update status for user ${userId}:`, error);
    throw error;
  }
};

interface AdminChangeUserPasswordPayload {
  new_password: string;
}

export const adminChangeUserPassword = async (userId: number, payload: AdminChangeUserPasswordPayload): Promise<void> => {
  try {
    await apiClient.put(`/admin/users/${userId}/password`, payload);
  } catch (error) {
    console.error(`Failed to change password for user ${userId}:`, error);
    throw error;
  }
};

interface AdminChangeUserEmailPayload {
  new_email: string;
}

export const adminChangeUserEmail = async (userId: number, payload: AdminChangeUserEmailPayload): Promise<void> => {
  try {
    await apiClient.put(`/admin/users/${userId}/email`, payload);
  } catch (error) { 
    console.error(`Failed to change email for user ${userId}:`, error);
    throw error;
  }
};

export const adminDeleteUser = async (userId: number): Promise<void> => {
  try {
    await apiClient.delete(`/admin/users/${userId}`);
  } catch (error) {
    console.error(`Failed to delete user ${userId}:`, error);
    throw error;
  }
};

// --- Admin Configuration API Functions ---

interface AdminConfig {
    jwt_expiry_enabled: boolean;
    jwt_expiry_minutes: number;
    auto_release_enabled: boolean;
    auto_release_hours: number;
    // Add other keys here to match backend response
}

export const getCurrentUser = async (): Promise<User> => {
  try {
    // Token is automatically added by the interceptor
    const response = await apiClient.get<User>('/currentuser');
    return response.data;
  } catch (error) {
    console.error('Failed to fetch current user:', error);
    // Re-throw so AuthContext can handle cleanup
    throw error;
  }
};

export const getAdminConfig = async (): Promise<AdminConfig> => {
  try {
    const response = await apiClient.get<AdminConfig>('/admin/config');
    return response.data;
  } catch (error) {
    console.error('Failed to fetch admin configuration:', error);
    throw error;
  }
};

// Use Partial<AdminConfig> as payload, since not all keys might be sent
export const updateAdminConfig = async (payload: Partial<AdminConfig>): Promise<void> => {
  try {
    await apiClient.put('/admin/config', payload);
  } catch (error) {
    console.error('Failed to update admin configuration:', error);
    throw error;
  }
};

export default apiClient;
