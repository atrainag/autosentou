import axios from 'axios'

// Create axios instance with base configuration
const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Add any auth tokens here if needed in the future
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor
api.interceptors.response.use(
  (response) => {
    return response
  },
  (error) => {
    // Handle global errors
    if (error.response) {
      console.error('API Error:', error.response.data)
    } else if (error.request) {
      console.error('Network Error:', error.message)
    }
    return Promise.reject(error)
  }
)

// API Methods
export const jobsApi = {
  // Start a new scan
  startScan: async (scanData) => {
    const response = await api.post('/start-scan', scanData)
    return response.data
  },

  // Get all jobs
  getJobs: async () => {
    const response = await api.get('/jobs')
    return response.data
  },

  // Get single job details
  getJob: async (jobId) => {
    const response = await api.get(`/job/${jobId}`)
    return response.data
  },

  // Delete a job (if backend supports it)
  deleteJob: async (jobId) => {
    const response = await api.delete(`/job/${jobId}`)
    return response.data
  },
}

export const wordlistsApi = {
  // Get all wordlists
  getWordlists: async () => {
    const response = await api.get('/wordlists')
    return response.data
  },

  // Upload a new wordlist
  uploadWordlist: async (formData) => {
    const response = await api.post('/upload-wordlist', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    })
    return response.data
  },

  // Delete a wordlist (if backend supports it)
  deleteWordlist: async (wordlistName) => {
    const response = await api.delete(`/wordlist/${wordlistName}`)
    return response.data
  },

  // Get wordlist content
  getWordlistContent: async (filename, limit = 1000) => {
    const response = await api.get(`/wordlists/${filename}`, {
      params: { limit },
    })
    return response.data
  },
}

export const reportsApi = {
  // Download report
  downloadReport: async (reportPath, format) => {
    const response = await api.get(`/report/${reportPath}`, {
      responseType: 'blob',
      params: { format },
    })
    return response.data
  },

  // Get report content (for preview)
  getReportContent: async (reportPath) => {
    const response = await api.get(`/report-content/${reportPath}`)
    return response.data
  },
}

export const healthApi = {
  // Health check
  healthCheck: async () => {
    const response = await api.get('/')
    return response.data
  },
}

export default api
