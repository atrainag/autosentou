import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { jobsApi } from '../services/api'

export const useJobsStore = defineStore('jobs', () => {
  // State
  const jobs = ref([])
  const currentJob = ref(null)
  const loading = ref(false)
  const error = ref(null)
  const pollingInterval = ref(null)

  // Getters
  const activeJobs = computed(() =>
    jobs.value.filter(job => job.status === 'running' || job.status === 'pending')
  )

  const completedJobs = computed(() =>
    jobs.value.filter(job => job.status === 'completed')
  )

  const failedJobs = computed(() =>
    jobs.value.filter(job => job.status === 'failed')
  )

  const totalFindings = ref(0)

  // Actions
  const fetchJobs = async () => {
    loading.value = true
    error.value = null
    try {
      const data = await jobsApi.getJobs()
      jobs.value = data
    } catch (err) {
      error.value = err.message || 'Failed to fetch jobs'
      console.error('Error fetching jobs:', err)
    } finally {
      loading.value = false
    }
  }

  const fetchJob = async (jobId) => {
    loading.value = true
    error.value = null
    try {
      const data = await jobsApi.getJob(jobId)
      currentJob.value = data

      // Update job in jobs list if it exists
      const index = jobs.value.findIndex(j => j.id === jobId)
      if (index !== -1) {
        jobs.value[index] = data
      }

      return data
    } catch (err) {
      error.value = err.message || 'Failed to fetch job'
      console.error('Error fetching job:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const startScan = async (scanData) => {
    loading.value = true
    error.value = null
    try {
      const data = await jobsApi.startScan(scanData)

      // Add new job to the list
      if (data.job_id) {
        await fetchJobs() // Refresh the list
      }

      return data
    } catch (err) {
      error.value = err.response?.data?.detail || err.message || 'Failed to start scan'
      console.error('Error starting scan:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const deleteJob = async (jobId) => {
    loading.value = true
    error.value = null
    try {
      await jobsApi.deleteJob(jobId)

      // Remove from list
      jobs.value = jobs.value.filter(j => j.id !== jobId)

      if (currentJob.value?.id === jobId) {
        currentJob.value = null
      }
    } catch (err) {
      error.value = err.message || 'Failed to delete job'
      console.error('Error deleting job:', err)
      throw err
    } finally {
      loading.value = false
    }
  }

  const fetchTotalFindings = async () => {
    try {
      const data = await jobsApi.getTotalFindingsCount()
      totalFindings.value = data.total_findings
    } catch (err) {
      console.error('Error fetching total findings:', err)
      totalFindings.value = 0
    }
  }

  // Start polling for job updates (for active jobs)
  const startPolling = (jobId, interval = 3000) => {
    stopPolling() // Clear any existing polling

    pollingInterval.value = setInterval(async () => {
      try {
        await fetchJob(jobId)

        // Stop polling if job is completed or failed
        if (currentJob.value &&
            (currentJob.value.status === 'completed' || currentJob.value.status === 'failed')) {
          stopPolling()
        }
      } catch (err) {
        console.error('Polling error:', err)
      }
    }, interval)
  }

  const stopPolling = () => {
    if (pollingInterval.value) {
      clearInterval(pollingInterval.value)
      pollingInterval.value = null
    }
  }

  const clearCurrentJob = () => {
    currentJob.value = null
    stopPolling()
  }

  return {
    // State
    jobs,
    currentJob,
    loading,
    error,
    totalFindings,

    // Getters
    activeJobs,
    completedJobs,
    failedJobs,

    // Actions
    fetchJobs,
    fetchJob,
    startScan,
    deleteJob,
    fetchTotalFindings,
    startPolling,
    stopPolling,
    clearCurrentJob,
  }
})
