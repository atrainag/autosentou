<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold text-white">🧠 Knowledge Base</h1>
        <p class="text-gray-400 mt-1">Manage vulnerability knowledge for intelligent categorization</p>
      </div>
      <div class="flex items-center space-x-3">
        <button @click="handleExport" class="btn-secondary" :disabled="kbStore.loading">
          📤 Export
        </button>
        <button @click="showAddModal = true" class="btn-primary">
          ➕ Add Vulnerability
        </button>
      </div>
    </div>

    <!-- Statistics Cards -->
    <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
      <StatCard
        icon="📊"
        :value="kbStore.stats?.total_active_vulnerabilities || 0"
        label="Total Vulnerabilities"
        color="cyan"
      />
      <StatCard
        icon="✅"
        :value="kbStore.stats?.linked_findings || 0"
        label="Categorized Findings"
        color="green"
      />
      <StatCard
        icon="❓"
        :value="kbStore.stats?.uncategorized_findings || 0"
        label="Uncategorized Findings"
        color="yellow"
      />
      <StatCard
        icon="⚙️"
        :value="(kbStore.similarityThreshold * 100).toFixed(0) + '%'"
        label="Match Threshold"
        color="purple"
      />
    </div>

    <!-- Tabs -->
    <div class="card">
      <div class="flex border-b border-gray-800">
        <button
          @click="activeTab = 'vulnerabilities'"
          :class="[
            'px-6 py-4 font-medium transition-colors',
            activeTab === 'vulnerabilities'
              ? 'text-cyber-cyan border-b-2 border-cyber-cyan'
              : 'text-gray-400 hover:text-white'
          ]"
        >
          📚 Vulnerabilities
          <span class="ml-2 text-sm">({{ kbStore.pagination.total }})</span>
        </button>
        <button
          @click="activeTab = 'uncategorized'"
          :class="[
            'px-6 py-4 font-medium transition-colors',
            activeTab === 'uncategorized'
              ? 'text-cyber-cyan border-b-2 border-cyber-cyan'
              : 'text-gray-400 hover:text-white'
          ]"
        >
          ❓ Uncategorized Findings
          <span
            v-if="kbStore.uncategorizedFindings > 0"
            class="ml-2 text-sm bg-yellow-900/50 text-yellow-300 px-2 py-0.5 rounded"
          >
            {{ kbStore.uncategorizedFindings }}
          </span>
          <span v-else class="ml-2 text-sm">(0)</span>
        </button>
      </div>
    </div>

    <!-- Vulnerabilities Tab Content -->
    <div v-show="activeTab === 'vulnerabilities'">
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
            placeholder="Search by name, description, CVE, CWE..."
            class="input-field"
          />
        </div>

        <!-- Category Filter -->
        <div>
          <label class="block text-sm font-medium text-gray-300 mb-2">
            📂 Category
          </label>
          <select v-model="categoryFilter" @change="handleFilterChange" class="input-field">
            <option :value="null">All Categories</option>
            <option value="Web">Web</option>
            <option value="Network">Network</option>
            <option value="Auth">Authentication</option>
            <option value="API">API</option>
            <option value="Mobile">Mobile</option>
          </select>
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
      </div>

      <!-- Active Filters Display -->
      <div v-if="hasActiveFilters" class="mt-4 flex items-center space-x-2">
        <span class="text-sm text-gray-400">Active filters:</span>
        <span v-if="searchQuery" class="badge-info">
          Search: {{ searchQuery }}
          <button @click="clearSearch" class="ml-1 hover:text-white">×</button>
        </span>
        <span v-if="categoryFilter" class="badge-info">
          Category: {{ categoryFilter }}
          <button @click="categoryFilter = null; handleFilterChange()" class="ml-1 hover:text-white">×</button>
        </span>
        <span v-if="severityFilter" class="badge-info">
          Severity: {{ severityFilter }}
          <button @click="severityFilter = null; handleFilterChange()" class="ml-1 hover:text-white">×</button>
        </span>
        <button @click="clearAllFilters" class="text-xs text-cyber-cyan hover:underline ml-2">
          Clear all
        </button>
      </div>
    </div>

    <!-- Vulnerabilities Table -->
    <div class="card">
      <div class="p-6 border-b border-gray-800">
        <div class="flex items-center justify-between">
          <h2 class="text-xl font-semibold text-white">
            Vulnerabilities
            <span class="text-sm text-gray-400 font-normal ml-2">
              ({{ kbStore.pagination.total }} total)
            </span>
          </h2>
        </div>
      </div>

      <!-- Loading State -->
      <LoadingSpinner v-if="kbStore.loading" />

      <!-- Empty State -->
      <div v-else-if="kbStore.vulnerabilities.length === 0" class="p-6">
        <EmptyState
          icon="🧠"
          title="No vulnerabilities found"
          description="Add your first vulnerability to the knowledge base or adjust your filters"
        />
      </div>

      <!-- Table -->
      <div v-else class="overflow-x-auto">
        <table class="w-full">
          <thead class="bg-cyber-dark border-b border-gray-800">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Name
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Category
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Severity
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                CVE / CWE
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Priority
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-800">
            <tr
              v-for="vuln in kbStore.vulnerabilities"
              :key="vuln.id"
              class="hover:bg-cyber-dark transition-colors"
            >
              <td class="px-6 py-4">
                <div class="text-white font-medium">{{ vuln.name }}</div>
                <div class="text-sm text-gray-400 truncate max-w-md">
                  {{ vuln.description }}
                </div>
              </td>
              <td class="px-6 py-4">
                <span v-if="vuln.category" class="badge-secondary">
                  {{ vuln.category }}
                </span>
                <span v-else class="text-gray-500 text-sm">-</span>
              </td>
              <td class="px-6 py-4">
                <SeverityBadge :severity="vuln.severity" />
              </td>
              <td class="px-6 py-4">
                <div class="space-y-1">
                  <div v-if="vuln.cve_id" class="text-xs">
                    <span class="text-gray-400">CVE:</span>
                    <span class="text-cyber-cyan ml-1">{{ vuln.cve_id }}</span>
                  </div>
                  <div v-if="vuln.cwe_id" class="text-xs">
                    <span class="text-gray-400">CWE:</span>
                    <span class="text-cyber-cyan ml-1">{{ vuln.cwe_id }}</span>
                  </div>
                  <span v-if="!vuln.cve_id && !vuln.cwe_id" class="text-gray-500 text-sm">-</span>
                </div>
              </td>
              <td class="px-6 py-4">
                <div class="flex items-center space-x-1">
                  <div class="w-12 bg-gray-700 rounded-full h-2">
                    <div
                      class="bg-cyber-cyan h-2 rounded-full"
                      :style="{ width: `${vuln.priority}%` }"
                    ></div>
                  </div>
                  <span class="text-xs text-gray-400">{{ vuln.priority }}</span>
                </div>
              </td>
              <td class="px-6 py-4">
                <div class="flex items-center space-x-2">
                  <button
                    @click="handleView(vuln)"
                    class="text-cyber-cyan hover:text-cyan-300 text-sm"
                    title="View Details"
                  >
                    👁️
                  </button>
                  <button
                    @click="handleEdit(vuln)"
                    class="text-blue-400 hover:text-blue-300 text-sm"
                    title="Edit"
                  >
                    ✏️
                  </button>
                  <button
                    @click="handleDelete(vuln)"
                    class="text-red-400 hover:text-red-300 text-sm"
                    title="Delete"
                  >
                    🗑️
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div v-if="kbStore.pagination.totalPages > 1" class="p-6 border-t border-gray-800">
        <div class="flex items-center justify-between">
          <div class="text-sm text-gray-400">
            Showing {{ (kbStore.pagination.page - 1) * kbStore.pagination.limit + 1 }} to
            {{ Math.min(kbStore.pagination.page * kbStore.pagination.limit, kbStore.pagination.total) }} of
            {{ kbStore.pagination.total }} results
          </div>
          <div class="flex items-center space-x-2">
            <button
              @click="kbStore.setPage(kbStore.pagination.page - 1)"
              :disabled="kbStore.pagination.page === 1"
              class="btn-secondary px-3 py-1 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              ← Previous
            </button>
            <span class="text-white">
              Page {{ kbStore.pagination.page }} of {{ kbStore.pagination.totalPages }}
            </span>
            <button
              @click="kbStore.setPage(kbStore.pagination.page + 1)"
              :disabled="kbStore.pagination.page === kbStore.pagination.totalPages"
              class="btn-secondary px-3 py-1 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next →
            </button>
          </div>
        </div>
      </div>
    </div>
    </div>

    <!-- Uncategorized Findings Tab Content -->
    <div v-show="activeTab === 'uncategorized'">
      <UncategorizedFindingsTable />
    </div>

    <!-- Add/Edit Modal -->
    <VulnerabilityFormModal
      v-if="showAddModal || showEditModal"
      :vulnerability="editingVulnerability"
      :is-edit="showEditModal"
      @close="closeModals"
      @save="handleSave"
    />

    <!-- Delete Confirmation -->
    <ConfirmDialog
      v-if="showDeleteConfirm"
      title="Delete Vulnerability"
      :message="`Are you sure you want to delete '${deletingVulnerability?.name}'? This action cannot be undone.`"
      confirm-text="Delete"
      confirm-class="bg-red-600 hover:bg-red-700"
      @confirm="confirmDelete"
      @cancel="showDeleteConfirm = false"
    />

    <!-- Notification Toast -->
    <NotificationToast
      v-if="notification.show"
      :type="notification.type"
      :message="notification.message"
      @close="notification.show = false"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useKnowledgeBaseStore } from '../stores/knowledgeBase'
import LoadingSpinner from '../components/common/LoadingSpinner.vue'
import EmptyState from '../components/common/EmptyState.vue'
import StatCard from '../components/dashboard/StatCard.vue'
import SeverityBadge from '../components/common/SeverityBadge.vue'
import VulnerabilityFormModal from '../components/knowledge-base/VulnerabilityFormModal.vue'
import UncategorizedFindingsTable from '../components/knowledge-base/UncategorizedFindingsTable.vue'
import ConfirmDialog from '../components/common/ConfirmDialog.vue'
import NotificationToast from '../components/common/NotificationToast.vue'

const route = useRoute()
const kbStore = useKnowledgeBaseStore()

// State - check query param for initial tab
const activeTab = ref(route.query.tab === 'uncategorized' ? 'uncategorized' : 'vulnerabilities')
const searchQuery = ref('')
const categoryFilter = ref(null)
const severityFilter = ref(null)
const showAddModal = ref(false)
const showEditModal = ref(false)
const showDeleteConfirm = ref(false)
const editingVulnerability = ref(null)
const deletingVulnerability = ref(null)
const notification = ref({ show: false, type: 'success', message: '' })

// Computed
const hasActiveFilters = computed(() => {
  return searchQuery.value || categoryFilter.value || severityFilter.value
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
  kbStore.setFilters({
    search: searchQuery.value,
    category: categoryFilter.value,
    severity: severityFilter.value,
  })
}

const clearSearch = () => {
  searchQuery.value = ''
  handleFilterChange()
}

const clearAllFilters = () => {
  searchQuery.value = ''
  categoryFilter.value = null
  severityFilter.value = null
  kbStore.clearFilters()
}

const handleView = (vuln) => {
  editingVulnerability.value = vuln
  showEditModal.value = true
}

const handleEdit = (vuln) => {
  editingVulnerability.value = vuln
  showEditModal.value = true
}

const handleDelete = (vuln) => {
  deletingVulnerability.value = vuln
  showDeleteConfirm.value = true
}

const confirmDelete = async () => {
  try {
    await kbStore.deleteVulnerability(deletingVulnerability.value.id)
    showNotification('success', 'Vulnerability deleted successfully')
    showDeleteConfirm.value = false
    deletingVulnerability.value = null
  } catch (error) {
    showNotification('error', error.message || 'Failed to delete vulnerability')
  }
}

const handleSave = async (data) => {
  try {
    if (showEditModal.value) {
      await kbStore.updateVulnerability(editingVulnerability.value.id, data)
      showNotification('success', 'Vulnerability updated successfully')
    } else {
      await kbStore.createVulnerability(data)
      showNotification('success', 'Vulnerability created successfully')
    }
    closeModals()
  } catch (error) {
    showNotification('error', error.message || 'Failed to save vulnerability')
  }
}

const handleExport = async () => {
  try {
    await kbStore.exportVulnerabilities('json')
    showNotification('success', 'Knowledge base exported successfully')
  } catch (error) {
    showNotification('error', error.message || 'Failed to export knowledge base')
  }
}

const closeModals = () => {
  showAddModal.value = false
  showEditModal.value = false
  editingVulnerability.value = null
}

const showNotification = (type, message) => {
  notification.value = { show: true, type, message }
  setTimeout(() => {
    notification.value.show = false
  }, 5000)
}

// Lifecycle
onMounted(async () => {
  await Promise.all([
    kbStore.fetchVulnerabilities(),
    kbStore.fetchStats(),
    kbStore.fetchSimilarityThreshold(),
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
