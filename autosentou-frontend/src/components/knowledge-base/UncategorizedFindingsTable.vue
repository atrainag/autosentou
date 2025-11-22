<template>
  <div class="space-y-4">
    <!-- Search and Filters -->
    <div class="card p-6">
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <!-- Search -->
        <div class="md:col-span-2">
          <label class="block text-sm font-medium text-gray-300 mb-2">
            🔍 Search
          </label>
          <input
            v-model="searchQuery"
            @input="debouncedSearch"
            type="text"
            placeholder="Search by title, description, CVE..."
            class="input-field"
          />
        </div>

        <!-- Severity Filter -->
        <div>
          <label class="block text-sm font-medium text-gray-300 mb-2">
            ⚠️ Severity
          </label>
          <select v-model="severityFilter" @change="handleFilterChange" class="input-field">
            <option :value="null">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Informational">Informational</option>
          </select>
        </div>

        <!-- Finding Type Filter -->
        <div>
          <label class="block text-sm font-medium text-gray-300 mb-2">
            📂 Type
          </label>
          <select v-model="typeFilter" @change="handleFilterChange" class="input-field">
            <option :value="null">All Types</option>
            <option value="cve">CVE</option>
            <option value="sqli">SQL Injection</option>
            <option value="auth">Authentication</option>
            <option value="web_exposure">Web Exposure</option>
          </select>
        </div>
      </div>

      <!-- Active Filters Display -->
      <div v-if="hasActiveFilters" class="mt-4 flex items-center space-x-2">
        <span class="text-sm text-gray-400">Active filters:</span>
        <span v-if="searchQuery" class="badge-info">
          Search: {{ searchQuery }}
          <button @click="clearSearch" class="ml-1 hover:text-white">×</button>
        </span>
        <span v-if="severityFilter" class="badge-info">
          Severity: {{ severityFilter }}
          <button @click="severityFilter = null; handleFilterChange()" class="ml-1 hover:text-white">×</button>
        </span>
        <span v-if="typeFilter" class="badge-info">
          Type: {{ typeFilter }}
          <button @click="typeFilter = null; handleFilterChange()" class="ml-1 hover:text-white">×</button>
        </span>
        <button @click="clearAllFilters" class="text-xs text-cyber-cyan hover:underline ml-2">
          Clear all
        </button>
      </div>
    </div>

    <!-- Findings Table -->
    <div class="card">
      <div class="p-6 border-b border-gray-800">
        <div class="flex items-center justify-between">
          <h2 class="text-xl font-semibold text-white">
            Uncategorized Findings
            <span class="text-sm text-gray-400 font-normal ml-2">
              ({{ kbStore.uncategorizedPagination.total }} total)
            </span>
          </h2>
          <div class="flex items-center space-x-3">
            <button
              v-if="kbStore.uncategorizedPagination.total > 0 && !recategorizing"
              @click="handleRecategorizeAll"
              class="btn-primary flex items-center space-x-2"
            >
              🤖 AI Re-categorize All
            </button>
            <div v-if="recategorizing" class="flex items-center space-x-3">
              <span class="text-gray-300">
                ⏳ Processing {{ recategorizeProgress.current }}/{{ recategorizeProgress.total }}...
              </span>
              <button
                @click="handleCancelRecategorization"
                class="btn-danger flex items-center space-x-2"
                :disabled="cancelling"
              >
                <span v-if="!cancelling">⏹️ Cancel</span>
                <span v-else>Cancelling...</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Loading State -->
      <LoadingSpinner v-if="kbStore.loading" />

      <!-- Empty State -->
      <div v-else-if="kbStore.uncategorizedFindingsList.length === 0" class="p-6">
        <EmptyState
          icon="✅"
          title="No uncategorized findings"
          description="All findings have been categorized! Great work."
        />
      </div>

      <!-- Table -->
      <div v-else class="overflow-x-auto">
        <table class="w-full">
          <thead class="bg-cyber-dark border-b border-gray-800">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Title
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Type
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Severity
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                OWASP
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                CVE / CWE
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Service / URL
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-800">
            <tr
              v-for="finding in kbStore.uncategorizedFindingsList"
              :key="finding.id"
              class="hover:bg-cyber-dark transition-colors"
            >
              <td class="px-6 py-4">
                <div class="text-white font-medium">{{ finding.title }}</div>
                <div class="text-sm text-gray-400 truncate max-w-md">
                  {{ finding.description }}
                </div>
              </td>
              <td class="px-6 py-4">
                <span v-if="finding.finding_type" class="badge-secondary">
                  {{ finding.finding_type }}
                </span>
                <span v-else class="text-gray-500 text-sm">-</span>
              </td>
              <td class="px-6 py-4">
                <SeverityBadge :severity="finding.severity" />
              </td>
              <td class="px-6 py-4">
                <span v-if="finding.owasp_category" class="text-xs text-gray-300 bg-gray-800 px-2 py-1 rounded">
                  {{ finding.owasp_category }}
                </span>
                <span v-else class="text-gray-500 text-sm">-</span>
              </td>
              <td class="px-6 py-4">
                <div class="text-xs space-y-1">
                  <div v-if="finding.cve_id">
                    <span class="text-gray-400">CVE:</span>
                    <span class="text-cyber-cyan ml-1">{{ finding.cve_id }}</span>
                  </div>
                  <div v-if="finding.evidence && typeof finding.evidence === 'object' && finding.evidence.cwe_id">
                    <span class="text-gray-400">CWE:</span>
                    <span class="text-purple-400 ml-1">{{ finding.evidence.cwe_id }}</span>
                  </div>
                  <span v-if="!finding.cve_id && (!finding.evidence || !finding.evidence.cwe_id)" class="text-gray-500">-</span>
                </div>
              </td>
              <td class="px-6 py-4">
                <div class="text-sm">
                  <div v-if="finding.service" class="text-white">
                    {{ finding.service }}
                    <span v-if="finding.port" class="text-gray-400">:{{ finding.port }}</span>
                  </div>
                  <div v-if="finding.url" class="text-cyber-cyan truncate max-w-xs">
                    {{ finding.url }}
                  </div>
                  <span v-if="!finding.service && !finding.url" class="text-gray-500">-</span>
                </div>
              </td>
              <td class="px-6 py-4">
                <div class="flex items-center space-x-2">
                  <button
                    @click="handleView(finding)"
                    class="text-cyber-cyan hover:text-cyan-300 text-sm"
                    title="View Details"
                  >
                    👁️
                  </button>
                  <button
                    @click="handleLink(finding)"
                    class="text-green-400 hover:text-green-300 text-sm"
                    title="Link to KB"
                  >
                    🔗
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div v-if="kbStore.uncategorizedPagination.totalPages > 1" class="p-6 border-t border-gray-800">
        <div class="flex items-center justify-between">
          <div class="text-sm text-gray-400">
            Showing {{ (kbStore.uncategorizedPagination.page - 1) * kbStore.uncategorizedPagination.limit + 1 }} to
            {{ Math.min(kbStore.uncategorizedPagination.page * kbStore.uncategorizedPagination.limit, kbStore.uncategorizedPagination.total) }} of
            {{ kbStore.uncategorizedPagination.total }} results
          </div>
          <div class="flex items-center space-x-2">
            <button
              @click="kbStore.setUncategorizedPage(kbStore.uncategorizedPagination.page - 1)"
              :disabled="kbStore.uncategorizedPagination.page === 1"
              class="btn-secondary px-3 py-1 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              ← Previous
            </button>
            <span class="text-white">
              Page {{ kbStore.uncategorizedPagination.page }} of {{ kbStore.uncategorizedPagination.totalPages }}
            </span>
            <button
              @click="kbStore.setUncategorizedPage(kbStore.uncategorizedPagination.page + 1)"
              :disabled="kbStore.uncategorizedPagination.page === kbStore.uncategorizedPagination.totalPages"
              class="btn-secondary px-3 py-1 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next →
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- View Details Modal -->
    <FindingDetailsModal
      v-if="showDetailsModal"
      :finding="selectedFinding"
      @close="showDetailsModal = false"
      @link="handleLink(selectedFinding)"
    />

    <!-- Link to KB Modal -->
    <LinkFindingModal
      v-if="showLinkModal"
      :finding="selectedFinding"
      @close="showLinkModal = false"
      @linked="handleLinked"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useKnowledgeBaseStore } from '../../stores/knowledgeBase'
import { useAppStore } from '../../stores/app'
import LoadingSpinner from '../common/LoadingSpinner.vue'
import EmptyState from '../common/EmptyState.vue'
import SeverityBadge from '../common/SeverityBadge.vue'
import FindingDetailsModal from './FindingDetailsModal.vue'
import LinkFindingModal from './LinkFindingModal.vue'

const kbStore = useKnowledgeBaseStore()
const appStore = useAppStore()

// State
const searchQuery = ref('')
const severityFilter = ref(null)
const typeFilter = ref(null)
const showDetailsModal = ref(false)
const showLinkModal = ref(false)
const selectedFinding = ref(null)
const recategorizing = ref(false)
const cancelling = ref(false)
const recategorizeProgress = ref({ current: 0, total: 0 })

// Computed
const hasActiveFilters = computed(() => {
  return searchQuery.value || severityFilter.value || typeFilter.value
})

// Debounce search
let searchTimeout = null
const debouncedSearch = () => {
  clearTimeout(searchTimeout)
  searchTimeout = setTimeout(() => {
    handleFilterChange()
  }, 500)
}

// Methods
const handleFilterChange = () => {
  kbStore.setUncategorizedFilters({
    search: searchQuery.value,
    severity: severityFilter.value,
    finding_type: typeFilter.value,
  })
}

const clearSearch = () => {
  searchQuery.value = ''
  handleFilterChange()
}

const clearAllFilters = () => {
  searchQuery.value = ''
  severityFilter.value = null
  typeFilter.value = null
  kbStore.clearUncategorizedFilters()
}

const handleView = (finding) => {
  selectedFinding.value = finding
  showDetailsModal.value = true
}

const handleLink = (finding) => {
  selectedFinding.value = finding
  showDetailsModal.value = false
  showLinkModal.value = true
}

const handleLinked = async () => {
  showLinkModal.value = false
  selectedFinding.value = null
  // Refresh the list and stats
  await Promise.all([
    kbStore.fetchUncategorizedFindings(),
    kbStore.fetchStats()
  ])
}

const handleRecategorizeAll = async () => {
  const total = kbStore.uncategorizedPagination.total

  if (!confirm(
    `This will re-categorize ${total} uncategorized findings using AI.\n\n` +
    `⏱ Estimated time: ~${Math.ceil(total / 10)} minutes (due to API rate limits)\n\n` +
    `The process will run in the background. Continue?`
  )) {
    return
  }

  recategorizing.value = true
  recategorizeProgress.value = { current: 0, total }

  try {
    const response = await fetch(
      `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/knowledge-base/recategorize-uncategorized`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      }
    )

    if (!response.ok) {
      throw new Error('Failed to start re-categorization')
    }

    const result = await response.json()

    appStore.showToast({
      message: `✓ Re-categorization complete!\n${result.successful} successful, ${result.failed} failed`,
      type: 'success'
    })

    // Refresh the list and stats
    await Promise.all([
      kbStore.fetchUncategorizedFindings(),
      kbStore.fetchStats()
    ])

  } catch (error) {
    console.error('Error re-categorizing findings:', error)
    appStore.showToast({
      message: 'Failed to re-categorize findings. Check logs for details.',
      type: 'error'
    })
  } finally {
    recategorizing.value = false
    cancelling.value = false
    recategorizeProgress.value = { current: 0, total: 0 }
  }
}

const handleCancelRecategorization = async () => {
  if (!confirm('Are you sure you want to cancel the re-categorization?\n\nProgress will be saved up to the current finding.')) {
    return
  }

  cancelling.value = true

  try {
    const response = await fetch(
      `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/knowledge-base/cancel-recategorization`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      }
    )

    if (!response.ok) {
      throw new Error('Failed to cancel re-categorization')
    }

    appStore.showToast({
      message: 'Cancellation requested - stopping after current finding...',
      type: 'info'
    })

  } catch (error) {
    console.error('Error cancelling re-categorization:', error)
    appStore.showToast({
      message: 'Failed to request cancellation',
      type: 'error'
    })
    cancelling.value = false
  }
}

// Lifecycle
onMounted(async () => {
  await kbStore.fetchUncategorizedFindings()
})
</script>

<style scoped>
.badge-info {
  @apply inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-blue-900/50 text-blue-300 border border-blue-700;
}

.badge-secondary {
  @apply inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-gray-700 text-gray-300;
}
</style>
