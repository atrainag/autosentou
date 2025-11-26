<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold text-white">📋 All Jobs</h1>
        <p class="text-gray-400 mt-1">Manage and monitor your scan jobs</p>
      </div>
      <router-link to="/scan/create" class="btn-primary">
        Start New Scan
      </router-link>
    </div>

    <!-- Filters -->
    <div class="card p-4">
      <div class="flex flex-wrap items-center gap-4">
        <div class="flex-1 min-w-[200px]">
          <input
            v-model="searchQuery"
            type="text"
            class="input-field"
            placeholder="Search by target..."
          />
        </div>
        <div class="flex items-center space-x-2">
          <button
            v-for="filter in statusFilters"
            :key="filter.value"
            @click="selectedStatus = filter.value"
            :class="[
              'px-4 py-2 rounded-lg font-medium text-sm transition-colors',
              selectedStatus === filter.value
                ? 'bg-cyber-cyan text-white'
                : 'bg-cyber-dark text-gray-400 hover:text-white'
            ]"
          >
            {{ filter.label }}
          </button>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <LoadingSpinner v-if="jobsStore.loading" text="Loading jobs..." />

    <!-- Empty State -->
    <EmptyState
      v-else-if="filteredJobs.length === 0"
      icon="📭"
      title="No jobs found"
      description="Start a new scan or adjust your filters"
    >
      <template #action>
        <router-link to="/scan/create" class="btn-primary">
          Start New Scan
        </router-link>
      </template>
    </EmptyState>

    <!-- Jobs Table -->
    <div v-else class="card overflow-hidden">
      <div class="overflow-x-auto">
        <table class="w-full">
          <thead class="bg-cyber-dark">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Status
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Target
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Description
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Phase
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Created
              </th>
              <th class="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-800">
            <tr
              v-for="job in paginatedJobs"
              :key="job.id"
              class="table-row"
            >
              <td class="px-6 py-4 whitespace-nowrap">
                <StatusBadge :status="job.status" />
              </td>
              <td class="px-6 py-4">
                <div class="text-sm font-medium text-white">{{ job.original_target || job.target }}</div>
                <div v-if="job.original_target && job.target !== job.original_target" class="text-xs text-gray-500">
                  Scanning: {{ job.target }}
                </div>
              </td>
              <td class="px-6 py-4">
                <div class="text-sm text-gray-300 max-w-xs truncate">
                  {{ job.description || 'No description' }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-sm text-gray-400">
                  {{ job.phase ? formatPhaseName(job.phase) : 'N/A' }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="text-sm text-gray-400">
                  {{ formatRelativeTime(job.created_at) }}
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                <div class="flex items-center justify-end space-x-2">
                  <button
                    @click="viewJob(job.id)"
                    class="text-cyber-cyan hover:text-cyan-400"
                    title="View Details"
                  >
                    <EyeIcon class="h-5 w-5" />
                  </button>
                  <button
                    v-if="job.report_generated"
                    @click="viewReport(job.id)"
                    class="text-green-500 hover:text-green-400"
                    title="View Report"
                  >
                    <DocumentTextIcon class="h-5 w-5" />
                  </button>
                  <button
                    @click="openConfirmDialog(job)"
                    class="text-red-500 hover:text-red-400"
                    title="Delete Job"
                  >
                    <TrashIcon class="h-5 w-5" />
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div v-if="totalPages > 1" class="px-6 py-4 border-t border-gray-800 flex items-center justify-between">
        <div class="text-sm text-gray-400">
          Showing {{ (currentPage - 1) * itemsPerPage + 1 }} to
          {{ Math.min(currentPage * itemsPerPage, filteredJobs.length) }} of
          {{ filteredJobs.length }} jobs
        </div>
        <div class="flex space-x-2">
          <button
            @click="currentPage--"
            :disabled="currentPage === 1"
            class="px-3 py-1 rounded bg-cyber-dark text-gray-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Previous
          </button>
          <button
            @click="currentPage++"
            :disabled="currentPage === totalPages"
            class="px-3 py-1 rounded bg-cyber-dark text-gray-400 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
          >
            Next
          </button>
        </div>
      </div>
    </div>

    <!-- Confirmation Dialog -->
    <ConfirmDialog
      :is-open="isConfirmOpen"
      title="Delete Scan Job"
      :message="`Are you sure you want to delete the scan for '${jobToDelete?.target}'? This action cannot be undone.`"
      confirm-text="Delete"
      cancel-text="Cancel"
      variant="danger"
      @confirm="handleDeleteJob"
      @close="closeConfirmDialog"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useJobsStore } from '../stores/jobs'
import StatusBadge from '../components/common/StatusBadge.vue'
import LoadingSpinner from '../components/common/LoadingSpinner.vue'
import EmptyState from '../components/common/EmptyState.vue'
import { formatRelativeTime, formatPhaseName } from '../utils/formatters'
import { EyeIcon, DocumentTextIcon, TrashIcon } from '@heroicons/vue/24/outline'
import ConfirmDialog from '../components/common/ConfirmDialog.vue'
import { useAppStore } from '../stores/app'

const router = useRouter()
const jobsStore = useJobsStore()
const appStore = useAppStore()

const isConfirmOpen = ref(false)
const jobToDelete = ref(null)

const searchQuery = ref('')
const selectedStatus = ref('all')
const currentPage = ref(1)
const itemsPerPage = 10

const statusFilters = [
  { label: 'All', value: 'all' },
  { label: 'Running', value: 'running' },
  { label: 'Completed', value: 'completed' },
  { label: 'Failed', value: 'failed' },
]

const filteredJobs = computed(() => {
  let jobs = [...jobsStore.jobs]

  // Filter by status
  if (selectedStatus.value !== 'all') {
    jobs = jobs.filter(job => job.status === selectedStatus.value)
  }

  // Filter by search query
  if (searchQuery.value) {
    const query = searchQuery.value.toLowerCase()
    jobs = jobs.filter(job =>
      job.target.toLowerCase().includes(query) ||
      (job.description && job.description.toLowerCase().includes(query))
    )
  }

  // Sort by created_at (newest first)
  return jobs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
})

const totalPages = computed(() =>
  Math.ceil(filteredJobs.value.length / itemsPerPage)
)

const paginatedJobs = computed(() => {
  const start = (currentPage.value - 1) * itemsPerPage
  const end = start + itemsPerPage
  return filteredJobs.value.slice(start, end)
})

const viewJob = (jobId) => {
  router.push(`/job/${jobId}`)
}

const viewReport = (jobId) => {
  router.push(`/report/${jobId}`)
}

const openConfirmDialog = (job) => {
  jobToDelete.value = job
  isConfirmOpen.value = true
}

const closeConfirmDialog = () => {
  jobToDelete.value = null
  isConfirmOpen.value = false
}

const handleDeleteJob = async () => {
  if (!jobToDelete.value) return

  try {
    await jobsStore.deleteJob(jobToDelete.value.id)
    appStore.showToast({ message: `Job for '${jobToDelete.value.target}' deleted.`, type: 'success' })
  } catch (error) {
    appStore.showToast({ message: 'Failed to delete job.', type: 'error' })
  }

  closeConfirmDialog()
}

onMounted(async () => {
  await jobsStore.fetchJobs()
})
</script>
