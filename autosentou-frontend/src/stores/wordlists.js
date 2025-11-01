import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { wordlistsApi } from '../services/api'

export const useWordlistsStore = defineStore('wordlists', () => {
  // State
  const wordlists = ref([])
  const loading = ref(false)
  const error = ref(null)
  const uploadProgress = ref(0)
  const previewData = ref(null)
  const isLoadingPreview = ref(false)
  const previewError = ref(null)

  // Getters
  const defaultWordlists = computed(() =>
    wordlists.value.filter(w => w.type === 'default')
  )

  const customWordlists = computed(() =>
    wordlists.value.filter(w => w.type === 'custom')
  )

  const wordlistOptions = computed(() =>
    wordlists.value.map(w => ({
      label: w.name,
      value: w.path,
      type: w.type,
      size: w.size,
      lines: w.line_count,
    }))
  )

  // Actions
  const fetchWordlists = async () => {
    loading.value = true
    error.value = null
    try {
      const data = await wordlistsApi.getWordlists()
      wordlists.value = data
    } catch (err) {
      error.value = err.message || 'Failed to fetch wordlists'
      console.error('Error fetching wordlists:', err)
    } finally {
      loading.value = false
    }
  }

  const uploadWordlist = async (file) => {
    loading.value = true
    error.value = null
    uploadProgress.value = 0

    try {
      const formData = new FormData()
      formData.append('file', file)

      const data = await wordlistsApi.uploadWordlist(formData)

      // Refresh wordlists after upload
      await fetchWordlists()

      uploadProgress.value = 100
      return data
    } catch (err) {
      error.value = err.response?.data?.detail || err.message || 'Failed to upload wordlist'
      console.error('Error uploading wordlist:', err)
      throw err
    } finally {
      loading.value = false
      setTimeout(() => {
        uploadProgress.value = 0
      }, 2000)
    }
  }

  const deleteWordlist = async (wordlistName) => {
    loading.value = true
    error.value = null
    try {
      await wordlistsApi.deleteWordlist(wordlistName)

      // Remove from list
      wordlists.value = wordlists.value.filter(w => w.name !== wordlistName)
    } catch (err) {
      error.value = err.message || 'Failed to delete wordlist'
      console.error('Error deleting wordlist:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const fetchWordlistPreview = async (filename, limit = 1000) => {
    isLoadingPreview.value = true
    previewError.value = null
    try {
      const data = await wordlistsApi.getWordlistContent(filename, limit)
      previewData.value = data
    } catch (err) {
      previewError.value = err.message || 'Failed to fetch wordlist preview'
      console.error('Error fetching wordlist preview:', err)
    } finally {
      isLoadingPreview.value = false
    }
  }

  const clearPreview = () => {
    previewData.value = null
    previewError.value = null
    isLoadingPreview.value = false
  }

  return {
    // State
    wordlists,
    loading,
    error,
    uploadProgress,
    previewData,
    isLoadingPreview,
    previewError,

    // Getters
    defaultWordlists,
    customWordlists,
    wordlistOptions,

    // Actions
    fetchWordlists,
    uploadWordlist,
    deleteWordlist,
    fetchWordlistPreview,
    clearPreview,
  }
})
