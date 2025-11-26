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

  // Get total findings count across all jobs
  getTotalFindingsCount: async () => {
    const response = await api.get('/findings/total-count')
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

export const knowledgeBaseApi = {
  // Get all vulnerabilities with pagination and filtering
  getVulnerabilities: async (params = {}) => {
    const response = await api.get('/knowledge-base/vulnerabilities/', { params })
    return response.data
  },

  // Get a single vulnerability by ID
  getVulnerability: async (id) => {
    const response = await api.get(`/knowledge-base/vulnerabilities/${id}`)
    return response.data
  },

  // Create a new vulnerability
  createVulnerability: async (data) => {
    const response = await api.post('/knowledge-base/vulnerabilities/', data)
    return response.data
  },

  // Update a vulnerability
  updateVulnerability: async (id, data) => {
    const response = await api.put(`/knowledge-base/vulnerabilities/${id}`, data)
    return response.data
  },

  // Delete a vulnerability
  deleteVulnerability: async (id) => {
    const response = await api.delete(`/knowledge-base/vulnerabilities/${id}`)
    return response.data
  },

  // Advanced search
  searchVulnerabilities: async (searchData) => {
    const response = await api.post('/knowledge-base/vulnerabilities/search', searchData)
    return response.data
  },

  // Test matching a finding to KB
  matchVulnerability: async (matchData) => {
    const response = await api.post('/knowledge-base/vulnerabilities/match', matchData)
    return response.data
  },

  // Import vulnerabilities
  importVulnerabilities: async (importData) => {
    const response = await api.post('/knowledge-base/vulnerabilities/import', importData)
    return response.data
  },

  // Export vulnerabilities
  exportVulnerabilities: async (format = 'json', params = {}) => {
    const response = await api.get('/knowledge-base/vulnerabilities/export', {
      params: { format, ...params },
      responseType: 'blob',
    })
    return response.data
  },

  // Link a finding to a KB entry
  linkFinding: async (findingId, kbId, similarityScore = null) => {
    const response = await api.post(`/knowledge-base/link-finding/${findingId}`, null, {
      params: { kb_id: kbId, similarity_score: similarityScore },
    })
    return response.data
  },

  // Get configuration value
  getConfig: async (key) => {
    const response = await api.get(`/knowledge-base/config/${key}`)
    return response.data
  },

  // Update configuration value
  updateConfig: async (key, value) => {
    const response = await api.put(`/knowledge-base/config/${key}`, { value })
    return response.data
  },

  // Get similarity threshold
  getSimilarityThreshold: async () => {
    const response = await api.get('/knowledge-base/config/similarity-threshold/value')
    return response.data
  },

  // Get KB statistics
  getStats: async () => {
    const response = await api.get('/knowledge-base/stats')
    return response.data
  },

  // Get uncategorized findings
  getUncategorizedFindings: async (params = {}) => {
    const response = await api.get('/knowledge-base/uncategorized-findings', { params })
    return response.data
  },

  // Get categorized findings
  getCategorizedFindings: async (params = {}) => {
    const response = await api.get('/knowledge-base/categorized-findings', { params })
    return response.data
  },

  // Get available categories
  getAvailableCategories: async () => {
    const response = await api.get('/knowledge-base/available-categories')
    return response.data
  },

  // Get available finding types
  getAvailableFindingTypes: async () => {
    const response = await api.get('/knowledge-base/available-finding-types')
    return response.data
  },
}

export default api
