<template>
  <div class="space-y-4">
    <!-- Search and Filters -->
    <div class="card p-6">
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <!-- Search -->
        <div class="md:col-span-2">
          <label class="block text-sm font-medium text-gray-300 mb-2 flex items-center space-x-2">
            <MagnifyingGlassIcon class="w-4 h-4" />
            <span>Search</span>
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
          <label class="block text-sm font-medium text-gray-300 mb-2 flex items-center space-x-2">
            <ShieldExclamationIcon class="w-4 h-4" />
            <span>Severity</span>
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
          <label class="block text-sm font-medium text-gray-300 mb-2 flex items-center space-x-2">
            <FolderIcon class="w-4 h-4" />
            <span>Type</span>
          </label>
          <select v-model="typeFilter" @change="handleFilterChange" class="input-field">
            <option :value="null">All Types</option>
            <option v-for="type in kbStore.availableFindingTypes" :key="type" :value="type">
              {{ type }}
            </option>
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
            Categorized Findings
            <span class="text-sm text-gray-400 font-normal ml-2">
              ({{ kbStore.categorizedPagination.total }} total)
            </span>
          </h2>
        </div>
      </div>

      <!-- Loading State -->
      <LoadingSpinner v-if="kbStore.loading" />

      <!-- Empty State -->
      <div v-else-if="kbStore.categorizedFindingsList.length === 0" class="p-6">
        <EmptyState
          title="No categorized findings"
          description="Findings that are linked to KB entries will appear here."
        >
          <template #icon>
            <CheckCircleIcon class="w-16 h-16 mx-auto text-gray-600" />
          </template>
        </EmptyState>
      </div>

      <!-- Table -->
      <div v-else class="overflow-x-auto">
        <table class="w-full table-fixed">
          <thead class="bg-cyber-dark border-b border-gray-800">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider w-1/4">
                <SortableTableHeader
                  label="Title"
                  column="title"
                  :current-sort="sortBy"
                  :current-order="sortOrder"
                  @sort="handleSort"
                />
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider w-24">
                <SortableTableHeader
                  label="Type"
                  column="finding_type"
                  :current-sort="sortBy"
                  :current-order="sortOrder"
                  @sort="handleSort"
                />
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider w-28">
                <SortableTableHeader
                  label="Severity"
                  column="severity"
                  :current-sort="sortBy"
                  :current-order="sortOrder"
                  @sort="handleSort"
                />
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider w-1/5">
                Linked KB Entry
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider w-24">
                Similarity
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider w-32">
                <SortableTableHeader
                  label="Linked At"
                  column="linked_at"
                  :current-sort="sortBy"
                  :current-order="sortOrder"
                  @sort="handleSort"
                />
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider w-20">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-800">
            <tr
              v-for="finding in kbStore.categorizedFindingsList"
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
                <div v-if="finding.kb_link" class="space-y-1">
                  <div class="text-white font-medium">{{ finding.kb_link.name }}</div>
                  <div class="text-xs text-gray-400">
                    <span v-if="finding.kb_link.category" class="badge-secondary mr-1">
                      {{ finding.kb_link.category }}
                    </span>
                    <span v-if="finding.kb_link.cve_id" class="text-cyber-cyan">
                      {{ finding.kb_link.cve_id }}
                    </span>
                  </div>
                </div>
                <span v-else class="text-gray-500 text-sm">Not linked</span>
              </td>
              <td class="px-6 py-4">
                <div v-if="finding.kb_link && finding.kb_link.similarity_score" class="flex items-center space-x-2">
                  <div class="w-12 bg-gray-700 rounded-full h-2">
                    <div
                      class="bg-green-500 h-2 rounded-full"
                      :style="{ width: `${finding.kb_link.similarity_score * 100}%` }"
                    ></div>
                  </div>
                  <span class="text-xs text-gray-400">
                    {{ (finding.kb_link.similarity_score * 100).toFixed(0) }}%
                  </span>
                </div>
                <span v-else class="text-gray-500 text-sm">Manual</span>
              </td>
              <td class="px-6 py-4">
                <span v-if="finding.kb_link && finding.kb_link.linked_at" class="text-xs text-gray-400">
                  {{ formatRelativeTime(finding.kb_link.linked_at) }}
                </span>
                <span v-else class="text-gray-500 text-sm">-</span>
              </td>
              <td class="px-6 py-4">
                <div class="flex items-center space-x-2">
                  <button
                    @click="handleView(finding)"
                    class="text-cyber-cyan hover:text-cyan-300"
                    title="View Details"
                  >
                    <EyeIcon class="w-5 h-5" />
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div v-if="kbStore.categorizedPagination.totalPages > 1" class="p-6 border-t border-gray-800">
        <div class="flex items-center justify-between">
          <div class="text-sm text-gray-400">
            Showing {{ (kbStore.categorizedPagination.page - 1) * kbStore.categorizedPagination.limit + 1 }} to
            {{ Math.min(kbStore.categorizedPagination.page * kbStore.categorizedPagination.limit, kbStore.categorizedPagination.total) }} of
            {{ kbStore.categorizedPagination.total }} results
          </div>
          <div class="flex items-center space-x-2">
            <button
              @click="kbStore.setCategorizedPage(kbStore.categorizedPagination.page - 1)"
              :disabled="kbStore.categorizedPagination.page === 1"
              class="btn-secondary px-3 py-1 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              ← Previous
            </button>
            <span class="text-white">
              Page {{ kbStore.categorizedPagination.page }} of {{ kbStore.categorizedPagination.totalPages }}
            </span>
            <button
              @click="kbStore.setCategorizedPage(kbStore.categorizedPagination.page + 1)"
              :disabled="kbStore.categorizedPagination.page === kbStore.categorizedPagination.totalPages"
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
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useKnowledgeBaseStore } from '../../stores/knowledgeBase'
import LoadingSpinner from '../common/LoadingSpinner.vue'
import EmptyState from '../common/EmptyState.vue'
import SeverityBadge from '../common/SeverityBadge.vue'
import SortableTableHeader from '../common/SortableTableHeader.vue'
import FindingDetailsModal from './FindingDetailsModal.vue'
import { formatRelativeTime } from '../../utils/formatters'
import {
  MagnifyingGlassIcon,
  ShieldExclamationIcon,
  FolderIcon,
  CheckCircleIcon,
  EyeIcon
} from '@heroicons/vue/24/outline'

const kbStore = useKnowledgeBaseStore()

// State
const searchQuery = ref('')
const severityFilter = ref(null)
const typeFilter = ref(null)
const showDetailsModal = ref(false)
const selectedFinding = ref(null)
const sortBy = ref('linked_at')
const sortOrder = ref('desc')

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
const handleSort = (column) => {
  if (sortBy.value === column) {
    // Toggle sort order
    sortOrder.value = sortOrder.value === 'asc' ? 'desc' : 'asc'
  } else {
    // New column, default to descending
    sortBy.value = column
    sortOrder.value = 'desc'
  }

  kbStore.setCategorizedFilters({
    search: searchQuery.value,
    severity: severityFilter.value,
    finding_type: typeFilter.value,
    sort_by: sortBy.value,
    sort_order: sortOrder.value,
  })
}

const handleFilterChange = () => {
  kbStore.setCategorizedFilters({
    search: searchQuery.value,
    severity: severityFilter.value,
    finding_type: typeFilter.value,
    sort_by: sortBy.value,
    sort_order: sortOrder.value,
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
  kbStore.clearCategorizedFilters()
}

const handleView = (finding) => {
  selectedFinding.value = finding
  showDetailsModal.value = true
}

// Lifecycle
onMounted(async () => {
  await Promise.all([
    kbStore.fetchCategorizedFindings(),
    kbStore.fetchAvailableFindingTypes(),
  ])
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
