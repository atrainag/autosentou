import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { knowledgeBaseApi } from '../services/api'

export const useKnowledgeBaseStore = defineStore('knowledgeBase', () => {
  // State
  const vulnerabilities = ref([])
  const currentVulnerability = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const pagination = ref({
    page: 1,
    limit: 20,
    total: 0,
    totalPages: 0,
  })
  const filters = ref({
    search: '',
    category: null,
    severity: null,
    is_active: true,
  })
  const stats = ref(null)
  const similarityThreshold = ref(0.85)

  // Getters
  const activeVulnerabilities = computed(() =>
    vulnerabilities.value.filter((v) => v.is_active)
  )

  const vulnerabilitiesByCategory = computed(() => {
    const grouped = {}
    vulnerabilities.value.forEach((v) => {
      const category = v.category || 'Uncategorized'
      if (!grouped[category]) {
        grouped[category] = []
      }
      grouped[category].push(v)
    })
    return grouped
  })

  const vulnerabilitiesBySeverity = computed(() => {
    const grouped = {}
    vulnerabilities.value.forEach((v) => {
      const severity = v.severity || 'Unknown'
      if (!grouped[severity]) {
        grouped[severity] = []
      }
      grouped[severity].push(v)
    })
    return grouped
  })

  const categorizedFindings = computed(() => {
    return stats.value?.linked_findings || 0
  })

  const uncategorizedFindings = computed(() => {
    return stats.value?.uncategorized_findings || 0
  })

  // Actions
  const fetchVulnerabilities = async (params = {}) => {
    loading.value = true
    error.value = null
    try {
      const queryParams = {
        page: pagination.value.page,
        limit: pagination.value.limit,
        ...filters.value,
        ...params,
      }

      const data = await knowledgeBaseApi.getVulnerabilities(queryParams)
      vulnerabilities.value = data.vulnerabilities
      pagination.value = {
        page: data.page,
        limit: data.limit,
        total: data.total,
        totalPages: data.total_pages,
      }
    } catch (err) {
      error.value = err.message || 'Failed to fetch vulnerabilities'
      console.error('Error fetching vulnerabilities:', err)
    } finally {
      loading.value = false
    }
  }

  const fetchVulnerability = async (id) => {
    loading.value = true
    error.value = null
    try {
      const data = await knowledgeBaseApi.getVulnerability(id)
      currentVulnerability.value = data
      return data
    } catch (err) {
      error.value = err.message || 'Failed to fetch vulnerability'
      console.error('Error fetching vulnerability:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const createVulnerability = async (vulnerabilityData) => {
    loading.value = true
    error.value = null
    try {
      const data = await knowledgeBaseApi.createVulnerability(vulnerabilityData)
      // Refresh the list
      await fetchVulnerabilities()
      return data
    } catch (err) {
      error.value = err.response?.data?.detail || err.message || 'Failed to create vulnerability'
      console.error('Error creating vulnerability:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const updateVulnerability = async (id, vulnerabilityData) => {
    loading.value = true
    error.value = null
    try {
      const data = await knowledgeBaseApi.updateVulnerability(id, vulnerabilityData)
      // Update in list
      const index = vulnerabilities.value.findIndex((v) => v.id === id)
      if (index !== -1) {
        vulnerabilities.value[index] = data
      }
      if (currentVulnerability.value?.id === id) {
        currentVulnerability.value = data
      }
      return data
    } catch (err) {
      error.value = err.response?.data?.detail || err.message || 'Failed to update vulnerability'
      console.error('Error updating vulnerability:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const deleteVulnerability = async (id) => {
    loading.value = true
    error.value = null
    try {
      await knowledgeBaseApi.deleteVulnerability(id)
      // Remove from list
      vulnerabilities.value = vulnerabilities.value.filter((v) => v.id !== id)
      if (currentVulnerability.value?.id === id) {
        currentVulnerability.value = null
      }
    } catch (err) {
      error.value = err.message || 'Failed to delete vulnerability'
      console.error('Error deleting vulnerability:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const searchVulnerabilities = async (searchData) => {
    loading.value = true
    error.value = null
    try {
      const data = await knowledgeBaseApi.searchVulnerabilities(searchData)
      vulnerabilities.value = data.vulnerabilities
      pagination.value = {
        page: data.page,
        limit: data.limit,
        total: data.total,
        totalPages: data.total_pages,
      }
    } catch (err) {
      error.value = err.message || 'Failed to search vulnerabilities'
      console.error('Error searching vulnerabilities:', err)
    } finally {
      loading.value = false
    }
  }

  const matchVulnerability = async (matchData) => {
    loading.value = true
    error.value = null
    try {
      const data = await knowledgeBaseApi.matchVulnerability(matchData)
      return data
    } catch (err) {
      error.value = err.message || 'Failed to match vulnerability'
      console.error('Error matching vulnerability:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const importVulnerabilities = async (importData) => {
    loading.value = true
    error.value = null
    try {
      const data = await knowledgeBaseApi.importVulnerabilities(importData)
      // Refresh the list
      await fetchVulnerabilities()
      return data
    } catch (err) {
      error.value = err.message || 'Failed to import vulnerabilities'
      console.error('Error importing vulnerabilities:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const exportVulnerabilities = async (format = 'json', params = {}) => {
    loading.value = true
    error.value = null
    try {
      const blob = await knowledgeBaseApi.exportVulnerabilities(format, params)
      // Create download link
      const url = window.URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `knowledge_base_vulnerabilities.${format}`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      window.URL.revokeObjectURL(url)
    } catch (err) {
      error.value = err.message || 'Failed to export vulnerabilities'
      console.error('Error exporting vulnerabilities:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const linkFinding = async (findingId, kbId, similarityScore = null) => {
    loading.value = true
    error.value = null
    try {
      await knowledgeBaseApi.linkFinding(findingId, kbId, similarityScore)
      // Refresh stats
      await fetchStats()
    } catch (err) {
      error.value = err.message || 'Failed to link finding'
      console.error('Error linking finding:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const fetchStats = async () => {
    try {
      const data = await knowledgeBaseApi.getStats()
      stats.value = data
    } catch (err) {
      console.error('Error fetching stats:', err)
    }
  }

  const fetchSimilarityThreshold = async () => {
    try {
      const data = await knowledgeBaseApi.getSimilarityThreshold()
      similarityThreshold.value = parseFloat(data.value)
    } catch (err) {
      console.error('Error fetching similarity threshold:', err)
    }
  }

  const updateSimilarityThreshold = async (value) => {
    try {
      await knowledgeBaseApi.updateConfig('rag_similarity_threshold', String(value))
      similarityThreshold.value = value
    } catch (err) {
      error.value = err.message || 'Failed to update similarity threshold'
      console.error('Error updating similarity threshold:', err)
      throw err
    }
  }

  const setPage = (page) => {
    pagination.value.page = page
    fetchVulnerabilities()
  }

  const setFilters = (newFilters) => {
    filters.value = { ...filters.value, ...newFilters }
    pagination.value.page = 1 // Reset to first page
    fetchVulnerabilities()
  }

  const clearFilters = () => {
    filters.value = {
      search: '',
      category: null,
      severity: null,
      is_active: true,
    }
    pagination.value.page = 1
    fetchVulnerabilities()
  }

  const clearError = () => {
    error.value = null
  }

  // Uncategorized findings management
  const uncategorizedFindingsList = ref([])
  const uncategorizedPagination = ref({
    page: 1,
    limit: 20,
    total: 0,
    totalPages: 0,
  })
  const uncategorizedFilters = ref({
    search: '',
    severity: null,
    finding_type: null,
    job_id: null,
    sort_by: 'created_at',
    sort_order: 'desc',
  })

  const fetchUncategorizedFindings = async (params = {}) => {
    loading.value = true
    error.value = null
    try {
      const queryParams = {
        page: uncategorizedPagination.value.page,
        limit: uncategorizedPagination.value.limit,
        ...uncategorizedFilters.value,
        ...params,
      }

      const data = await knowledgeBaseApi.getUncategorizedFindings(queryParams)
      uncategorizedFindingsList.value = data.findings
      uncategorizedPagination.value = {
        page: data.page,
        limit: data.limit,
        total: data.total,
        totalPages: data.total_pages,
      }
    } catch (err) {
      error.value = err.message || 'Failed to fetch uncategorized findings'
      console.error('Error fetching uncategorized findings:', err)
    } finally {
      loading.value = false
    }
  }

  const setUncategorizedPage = (page) => {
    uncategorizedPagination.value.page = page
    fetchUncategorizedFindings()
  }

  const setUncategorizedFilters = (newFilters) => {
    uncategorizedFilters.value = { ...uncategorizedFilters.value, ...newFilters }
    uncategorizedPagination.value.page = 1 // Reset to first page
    fetchUncategorizedFindings()
  }

  const clearUncategorizedFilters = () => {
    uncategorizedFilters.value = {
      search: '',
      severity: null,
      finding_type: null,
      job_id: null,
      sort_by: 'created_at',
      sort_order: 'desc',
    }
    uncategorizedPagination.value.page = 1
    fetchUncategorizedFindings()
  }

  return {
    // State
    vulnerabilities,
    currentVulnerability,
    loading,
    error,
    pagination,
    filters,
    stats,
    similarityThreshold,
    uncategorizedFindingsList,
    uncategorizedPagination,
    uncategorizedFilters,

    // Getters
    activeVulnerabilities,
    vulnerabilitiesByCategory,
    vulnerabilitiesBySeverity,
    categorizedFindings,
    uncategorizedFindings,

    // Actions
    fetchVulnerabilities,
    fetchVulnerability,
    createVulnerability,
    updateVulnerability,
    deleteVulnerability,
    searchVulnerabilities,
    matchVulnerability,
    importVulnerabilities,
    exportVulnerabilities,
    linkFinding,
    fetchStats,
    fetchSimilarityThreshold,
    updateSimilarityThreshold,
    setPage,
    setFilters,
    clearFilters,
    clearError,
    fetchUncategorizedFindings,
    setUncategorizedPage,
    setUncategorizedFilters,
    clearUncategorizedFilters,
  }
})
