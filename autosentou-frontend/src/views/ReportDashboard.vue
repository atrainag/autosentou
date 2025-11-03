<template>
  <div class="space-y-6">
    <!-- Loading State -->
    <LoadingSpinner v-if="loading" text="Loading findings..." />

    <template v-else-if="summary">
      <!-- Header -->
      <div class="flex items-start justify-between">
        <div>
          <button
            @click="$router.back()"
            class="text-gray-400 hover:text-white mb-3"
          >
            ← Back
          </button>
          <h1 class="text-3xl font-bold text-white">Interactive Findings Dashboard</h1>
          <p class="text-gray-400 mt-1">{{ route.params.jobId }}</p>
        </div>
        <div class="flex space-x-3">
          <button
            @click="showExportModal = true"
            class="btn-primary"
          >
            Export Findings
          </button>
          <router-link
            :to="`/job/${route.params.jobId}`"
            class="btn-secondary"
          >
            View Job Details
          </router-link>
        </div>
      </div>

      <!-- Summary Statistics -->
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div class="card p-6 text-center">
          <div class="text-4xl font-bold text-white">{{ summary.total_findings }}</div>
          <div class="text-gray-400 text-sm mt-2">Total Findings</div>
        </div>
        <div class="card p-6 text-center border-l-4 border-severity-critical">
          <div class="text-4xl font-bold text-severity-critical">{{ summary.critical_findings }}</div>
          <div class="text-gray-400 text-sm mt-2">Critical</div>
        </div>
        <div class="card p-6 text-center border-l-4 border-severity-high">
          <div class="text-4xl font-bold text-severity-high">{{ summary.high_findings }}</div>
          <div class="text-gray-400 text-sm mt-2">High</div>
        </div>
        <div class="card p-6 text-center border-l-4 border-severity-medium">
          <div class="text-4xl font-bold text-severity-medium">{{ summary.medium_findings }}</div>
          <div class="text-gray-400 text-sm mt-2">Medium</div>
        </div>
      </div>

      <!-- OWASP Top 10 Distribution -->
      <div class="card p-6" v-if="Object.keys(summary.by_owasp_category).length > 0">
        <h3 class="text-xl font-semibold text-white mb-4">OWASP Top 10 2021 Distribution</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div
            v-for="(count, category) in summary.by_owasp_category"
            :key="category"
            class="p-4 bg-cyber-dark rounded-lg flex justify-between items-center"
          >
            <span class="text-gray-300 text-sm">{{ category }}</span>
            <span class="badge bg-cyber-cyan">{{ count }}</span>
          </div>
        </div>
      </div>

      <!-- Filters and Search -->
      <div class="card p-6">
        <h3 class="text-xl font-semibold text-white mb-4">Filter Findings</h3>
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
          <!-- Search -->
          <div class="md:col-span-2">
            <label class="block text-sm font-medium text-gray-400 mb-2">Search</label>
            <input
              v-model="filters.search"
              type="text"
              placeholder="Search by title, description, CVE..."
              class="w-full px-4 py-2 bg-cyber-dark text-white rounded-lg border border-gray-700 focus:border-cyber-cyan focus:outline-none"
              @input="debouncedSearch"
            />
          </div>

          <!-- Severity Filter -->
          <div>
            <label class="block text-sm font-medium text-gray-400 mb-2">Severity</label>
            <select
              v-model="filters.severity"
              @change="fetchFindings"
              class="w-full px-4 py-2 bg-cyber-dark text-white rounded-lg border border-gray-700 focus:border-cyber-cyan focus:outline-none"
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          <!-- OWASP Category Filter -->
          <div>
            <label class="block text-sm font-medium text-gray-400 mb-2">OWASP Category</label>
            <select
              v-model="filters.owasp_category"
              @change="fetchFindings"
              class="w-full px-4 py-2 bg-cyber-dark text-white rounded-lg border border-gray-700 focus:border-cyber-cyan focus:outline-none"
            >
              <option value="">All Categories</option>
              <option v-for="(count, category) in summary.by_owasp_category" :key="category" :value="category">
                {{ category }}
              </option>
            </select>
          </div>
        </div>

        <!-- Active Filters Display -->
        <div v-if="hasActiveFilters" class="mt-4 flex items-center space-x-2">
          <span class="text-gray-400 text-sm">Active filters:</span>
          <span v-if="filters.search" class="badge bg-gray-700">Search: {{ filters.search }}</span>
          <span v-if="filters.severity" class="badge bg-gray-700">Severity: {{ filters.severity }}</span>
          <span v-if="filters.owasp_category" class="badge bg-gray-700">OWASP: {{ filters.owasp_category }}</span>
          <button @click="clearFilters" class="text-cyber-cyan text-sm hover:underline">Clear all</button>
        </div>
      </div>

      <!-- Findings Table -->
      <div class="card">
        <div class="p-6 border-b border-gray-800">
          <div class="flex justify-between items-center">
            <h3 class="text-xl font-semibold text-white">
              Findings ({{ findingsData?.total || 0 }} total)
            </h3>
            <div class="text-sm text-gray-400">
              Page {{ findingsData?.page || 1 }} of {{ findingsData?.total_pages || 1 }}
            </div>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full">
            <thead class="bg-cyber-dark">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Title
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Severity
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  OWASP Category
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Type
                </th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-800">
              <tr
                v-for="finding in findingsData?.findings || []"
                :key="finding.id"
                class="hover:bg-cyber-dark cursor-pointer transition-colors"
                @click="viewFindingDetails(finding)"
              >
                <td class="px-6 py-4">
                  <div class="text-white font-medium">{{ finding.title }}</div>
                  <div v-if="finding.description" class="text-sm text-gray-400 mt-1 truncate max-w-md">
                    {{ finding.description }}
                  </div>
                </td>
                <td class="px-6 py-4">
                  <SeverityBadge :severity="finding.severity" />
                </td>
                <td class="px-6 py-4">
                  <span v-if="finding.owasp_category" class="text-sm text-gray-300">
                    {{ finding.owasp_category }}
                  </span>
                  <span v-else class="text-sm text-gray-500">N/A</span>
                </td>
                <td class="px-6 py-4">
                  <span class="badge bg-gray-700 text-xs">{{ formatFindingType(finding.finding_type) }}</span>
                </td>
                <td class="px-6 py-4">
                  <button
                    @click.stop="viewFindingDetails(finding)"
                    class="text-cyber-cyan hover:underline text-sm"
                  >
                    View Details
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        <div v-if="findingsData && findingsData.total_pages > 1" class="p-6 border-t border-gray-800">
          <div class="flex justify-between items-center">
            <button
              @click="changePage(findingsData.page - 1)"
              :disabled="findingsData.page <= 1"
              class="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <div class="text-sm text-gray-400">
              Page {{ findingsData.page }} of {{ findingsData.total_pages }}
            </div>
            <button
              @click="changePage(findingsData.page + 1)"
              :disabled="findingsData.page >= findingsData.total_pages"
              class="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        </div>

        <!-- Empty State -->
        <div v-if="!findingsData || findingsData.findings.length === 0" class="p-12">
          <EmptyState
            icon="🔍"
            title="No findings match your filters"
            description="Try adjusting your search criteria or clearing filters"
          >
            <template #action>
              <button v-if="hasActiveFilters" @click="clearFilters" class="btn-primary">
                Clear Filters
              </button>
            </template>
          </EmptyState>
        </div>
      </div>

      <!-- Finding Details Modal -->
      <div v-if="selectedFinding" class="fixed inset-0 z-50 overflow-y-auto" @click.self="selectedFinding = null">
        <div class="flex items-center justify-center min-h-screen px-4">
          <div class="fixed inset-0 bg-black opacity-75"></div>

          <div class="relative bg-cyber-card rounded-lg max-w-4xl w-full p-8 border border-gray-800">
            <!-- Modal Header -->
            <div class="flex justify-between items-start mb-6">
              <div>
                <h2 class="text-2xl font-bold text-white">{{ selectedFinding.title }}</h2>
                <div class="flex items-center space-x-3 mt-2">
                  <SeverityBadge :severity="selectedFinding.severity" />
                  <span v-if="selectedFinding.owasp_category" class="badge bg-gray-700">
                    {{ selectedFinding.owasp_category }}
                  </span>
                  <span class="badge bg-gray-700">{{ formatFindingType(selectedFinding.finding_type) }}</span>
                </div>
              </div>
              <button @click="selectedFinding = null" class="text-gray-400 hover:text-white">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                </svg>
              </button>
            </div>

            <!-- Modal Content -->
            <div class="space-y-6">
              <!-- Description -->
              <div v-if="selectedFinding.description">
                <h3 class="text-lg font-semibold text-white mb-2">Description</h3>
                <p class="text-gray-300">{{ selectedFinding.description }}</p>
              </div>

              <!-- Technical Details -->
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div v-if="selectedFinding.service">
                  <h4 class="text-sm font-medium text-gray-400">Service</h4>
                  <p class="text-white">{{ selectedFinding.service }}:{{ selectedFinding.port }}</p>
                </div>
                <div v-if="selectedFinding.url">
                  <h4 class="text-sm font-medium text-gray-400">URL</h4>
                  <p class="text-white font-mono text-sm break-all">{{ selectedFinding.url }}</p>
                </div>
                <div v-if="selectedFinding.cve_id">
                  <h4 class="text-sm font-medium text-gray-400">CVE ID</h4>
                  <p class="text-white">{{ selectedFinding.cve_id }}</p>
                </div>
                <div v-if="selectedFinding.cvss_score">
                  <h4 class="text-sm font-medium text-gray-400">CVSS Score</h4>
                  <p class="text-white">{{ selectedFinding.cvss_score }}</p>
                </div>
              </div>

              <!-- Remediation -->
              <div v-if="selectedFinding.remediation" class="p-4 bg-blue-900 bg-opacity-20 border border-blue-700 rounded-lg">
                <h3 class="text-lg font-semibold text-white mb-2">Remediation</h3>
                <p class="text-gray-300">{{ selectedFinding.remediation }}</p>
              </div>

              <!-- Proof of Concept -->
              <div v-if="selectedFinding.poc" class="p-4 bg-cyber-dark rounded-lg">
                <h3 class="text-lg font-semibold text-white mb-2">Proof of Concept</h3>
                <pre class="text-gray-300 text-sm overflow-x-auto">{{ selectedFinding.poc }}</pre>
              </div>

              <!-- Evidence -->
              <div v-if="selectedFinding.evidence" class="p-4 bg-cyber-dark rounded-lg">
                <h3 class="text-lg font-semibold text-white mb-2">Additional Evidence</h3>
                <pre class="text-gray-300 text-sm overflow-x-auto">{{ JSON.stringify(selectedFinding.evidence, null, 2) }}</pre>
              </div>
            </div>

            <!-- Modal Footer -->
            <div class="mt-8 flex justify-end space-x-3">
              <button @click="selectedFinding = null" class="btn-secondary">
                Close
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Export Modal -->
      <div v-if="showExportModal" class="fixed inset-0 z-50 overflow-y-auto" @click.self="showExportModal = false">
        <div class="flex items-center justify-center min-h-screen px-4">
          <div class="fixed inset-0 bg-black opacity-75"></div>

          <div class="relative bg-cyber-card rounded-lg max-w-md w-full p-8 border border-gray-800">
            <h2 class="text-2xl font-bold text-white mb-6">Export Findings</h2>

            <div class="space-y-4">
              <div>
                <label class="block text-sm font-medium text-gray-400 mb-2">Export Format</label>
                <select
                  v-model="exportFormat"
                  class="w-full px-4 py-2 bg-cyber-dark text-white rounded-lg border border-gray-700 focus:border-cyber-cyan focus:outline-none"
                >
                  <option value="pdf">PDF</option>
                  <option value="csv">CSV</option>
                  <option value="json">JSON</option>
                </select>
              </div>

              <div class="p-4 bg-blue-900 bg-opacity-20 border border-blue-700 rounded-lg">
                <p class="text-sm text-gray-300">
                  Current filters will be applied to the export:
                </p>
                <ul class="mt-2 space-y-1 text-sm text-gray-400">
                  <li v-if="filters.search">Search: "{{ filters.search }}"</li>
                  <li v-if="filters.severity">Severity: {{ filters.severity }}</li>
                  <li v-if="filters.owasp_category">OWASP: {{ filters.owasp_category }}</li>
                  <li v-if="!hasActiveFilters">No filters (all findings)</li>
                </ul>
              </div>
            </div>

            <div class="mt-6 flex justify-end space-x-3">
              <button @click="showExportModal = false" class="btn-secondary">
                Cancel
              </button>
              <button @click="exportFindings" class="btn-primary">
                Export
              </button>
            </div>
          </div>
        </div>
      </div>
    </template>

    <!-- Error State -->
    <EmptyState
      v-else
      icon="❌"
      title="Failed to load findings"
      description="Unable to load findings for this job"
    >
      <template #action>
        <button @click="fetchData" class="btn-primary">
          Retry
        </button>
      </template>
    </EmptyState>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useAppStore } from '../stores/app'
import LoadingSpinner from '../components/common/LoadingSpinner.vue'
import EmptyState from '../components/common/EmptyState.vue'
import SeverityBadge from '../components/common/SeverityBadge.vue'

const route = useRoute()
const appStore = useAppStore()

const loading = ref(true)
const summary = ref(null)
const findingsData = ref(null)
const selectedFinding = ref(null)
const showExportModal = ref(false)
const exportFormat = ref('pdf')

const filters = ref({
  search: '',
  severity: '',
  owasp_category: '',
  page: 1,
  limit: 50
})

const hasActiveFilters = computed(() => {
  return filters.value.search || filters.value.severity || filters.value.owasp_category
})

const fetchData = async () => {
  await Promise.all([fetchSummary(), fetchFindings()])
}

const fetchSummary = async () => {
  try {
    const response = await fetch(
      `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/job/${route.params.jobId}/summary`
    )
    if (!response.ok) throw new Error('Failed to fetch summary')
    summary.value = await response.json()
  } catch (error) {
    console.error('Error fetching summary:', error)
    appStore.showError('Failed to load findings summary')
  }
}

const fetchFindings = async () => {
  try {
    const params = new URLSearchParams()
    params.append('page', filters.value.page)
    params.append('limit', filters.value.limit)
    if (filters.value.search) params.append('search', filters.value.search)
    if (filters.value.severity) params.append('severity', filters.value.severity)
    if (filters.value.owasp_category) params.append('owasp_category', filters.value.owasp_category)

    const response = await fetch(
      `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/job/${route.params.jobId}/findings?${params}`
    )
    if (!response.ok) throw new Error('Failed to fetch findings')
    findingsData.value = await response.json()
  } catch (error) {
    console.error('Error fetching findings:', error)
    appStore.showError('Failed to load findings')
  }
}

let searchTimeout
const debouncedSearch = () => {
  clearTimeout(searchTimeout)
  searchTimeout = setTimeout(() => {
    filters.value.page = 1
    fetchFindings()
  }, 500)
}

const clearFilters = () => {
  filters.value.search = ''
  filters.value.severity = ''
  filters.value.owasp_category = ''
  filters.value.page = 1
  fetchFindings()
}

const changePage = (page) => {
  filters.value.page = page
  fetchFindings()
  window.scrollTo({ top: 0, behavior: 'smooth' })
}

const viewFindingDetails = (finding) => {
  selectedFinding.value = finding
}

const formatFindingType = (type) => {
  const types = {
    'cve': 'CVE',
    'sqli': 'SQL Injection',
    'authentication': 'Authentication',
    'web_exposure': 'Web Exposure'
  }
  return types[type] || type
}

const exportFindings = async () => {
  try {
    const exportData = {
      format: exportFormat.value,
      search: filters.value.search || null,
      severity: filters.value.severity || null,
      owasp_category: filters.value.owasp_category || null
    }

    const response = await fetch(
      `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/job/${route.params.jobId}/export`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(exportData)
      }
    )

    if (!response.ok) throw new Error('Export failed')

    // Trigger download
    const blob = await response.blob()
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `findings_export.${exportFormat.value}`
    document.body.appendChild(a)
    a.click()
    window.URL.revokeObjectURL(url)
    document.body.removeChild(a)

    appStore.showSuccess('Export completed successfully')
    showExportModal.value = false
  } catch (error) {
    console.error('Error exporting findings:', error)
    appStore.showError('Failed to export findings')
  }
}

onMounted(async () => {
  await fetchData()
  loading.value = false
})
</script>
