<template>
  <div class="fixed inset-0 z-50 overflow-y-auto">
    <div class="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
      <!-- Background overlay -->
      <div class="fixed inset-0 transition-opacity bg-gray-900 bg-opacity-75" @click="handleClose"></div>

      <!-- Modal panel -->
      <div
        class="inline-block align-bottom bg-cyber-dark rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-4xl sm:w-full border border-gray-800"
      >
        <!-- Header -->
        <div class="bg-cyber-darker px-6 py-4 border-b border-gray-800">
          <div class="flex items-center justify-between">
            <h3 class="text-xl font-semibold text-white">
              Link Finding to Knowledge Base
            </h3>
            <button
              @click="handleClose"
              class="text-gray-400 hover:text-white transition-colors"
            >
              <XMarkIcon class="w-6 h-6" />
            </button>
          </div>
        </div>

        <!-- Body -->
        <div class="px-6 py-6 space-y-6 max-h-[70vh] overflow-y-auto">
          <!-- Finding Summary -->
          <div class="bg-cyber-darker p-4 rounded-lg border border-gray-800">
            <div class="flex items-start justify-between">
              <div class="flex-1">
                <h4 class="text-lg font-medium text-white mb-1">{{ finding.title }}</h4>
                <p class="text-sm text-gray-400">{{ finding.description?.substring(0, 200) }}...</p>
              </div>
              <SeverityBadge :severity="finding.severity" />
            </div>
          </div>

          <!-- AI Matching Section -->
          <div class="space-y-3">
            <div class="flex items-center justify-between">
              <h5 class="text-sm font-medium text-gray-300 flex items-center space-x-2">
                <CpuChipIcon class="w-5 h-5 text-cyber-cyan" />
                <span>AI-Powered Matching</span>
              </h5>
              <button
                @click="testMatch"
                :disabled="testing"
                class="btn-secondary text-sm"
              >
                {{ testing ? 'Testing...' : 'Test Match' }}
              </button>
            </div>

            <!-- Match Results -->
            <div v-if="matchResult" class="bg-cyber-darker p-4 rounded-lg border border-gray-800">
              <div v-if="matchResult.matched" class="space-y-3">
                <div class="flex items-center space-x-2">
                  <CheckCircleIcon class="w-5 h-5 text-green-400" />
                  <span class="text-green-400">Match Found</span>
                  <span class="text-sm text-gray-400">
                    ({{ (matchResult.similarity_score * 100).toFixed(1) }}% similarity)
                  </span>
                </div>
                <div class="border-t border-gray-700 pt-3">
                  <div class="text-white font-medium">{{ matchResult.kb_entry.name }}</div>
                  <div class="text-sm text-gray-400 mt-1">{{ matchResult.kb_entry.description }}</div>
                  <div class="flex items-center space-x-2 mt-2">
                    <SeverityBadge :severity="matchResult.kb_entry.severity" />
                    <span v-if="matchResult.kb_entry.cve_id" class="text-cyber-cyan text-sm">
                      {{ matchResult.kb_entry.cve_id }}
                    </span>
                  </div>
                  <button
                    @click="selectKbEntry(matchResult.kb_entry, matchResult.similarity_score)"
                    class="btn-primary text-sm mt-3"
                  >
                    Use This Match
                  </button>
                </div>
              </div>
              <div v-else class="flex items-center space-x-2 text-yellow-400">
                <ExclamationTriangleIcon class="w-5 h-5" />
                <span>No automatic match found. Search manually below.</span>
              </div>
            </div>
          </div>

          <!-- Manual Search Section -->
          <div class="space-y-3">
            <h5 class="text-sm font-medium text-gray-300 flex items-center space-x-2">
              <MagnifyingGlassIcon class="w-5 h-5" />
              <span>Manual Search</span>
            </h5>
            <div class="flex space-x-2">
              <input
                v-model="searchQuery"
                @input="debouncedSearch"
                type="text"
                placeholder="Search vulnerabilities by name, CVE, description..."
                class="input-field flex-1"
              />
              <select v-model="categoryFilter" @change="handleSearch" class="input-field w-40">
                <option :value="null">All Categories</option>
                <option value="Web">Web</option>
                <option value="Network">Network</option>
                <option value="Auth">Auth</option>
                <option value="API">API</option>
              </select>
            </div>
          </div>

          <!-- Search Results -->
          <div v-if="searching" class="text-center py-8">
            <LoadingSpinner text="Searching..." />
          </div>

          <div v-else-if="searchResults.length > 0" class="space-y-2">
            <div
              v-for="vuln in searchResults"
              :key="vuln.id"
              @click="selectKbEntry(vuln, null)"
              class="p-4 border border-gray-700 rounded-lg hover:border-cyber-cyan cursor-pointer transition-colors"
              :class="{ 'border-cyber-cyan bg-cyber-darker': selectedKb?.id === vuln.id }"
            >
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <div class="text-white font-medium">{{ vuln.name }}</div>
                  <div class="text-sm text-gray-400 mt-1">{{ vuln.description }}</div>
                  <div class="flex items-center space-x-2 mt-2">
                    <SeverityBadge :severity="vuln.severity" />
                    <span v-if="vuln.category" class="badge-secondary">{{ vuln.category }}</span>
                    <span v-if="vuln.cve_id" class="text-cyber-cyan text-sm">{{ vuln.cve_id }}</span>
                  </div>
                </div>
                <div v-if="selectedKb?.id === vuln.id">
                  <CheckCircleIcon class="w-6 h-6 text-cyber-cyan" />
                </div>
              </div>
            </div>
          </div>

          <div v-else-if="searchQuery && !searching" class="text-center py-8 text-gray-400">
            No vulnerabilities found. Try a different search term.
          </div>
        </div>

        <!-- Footer -->
        <div class="bg-cyber-darker px-6 py-4 border-t border-gray-800 flex justify-between">
          <button @click="handleClose" class="btn-secondary">
            Cancel
          </button>
          <button
            @click="handleLink"
            :disabled="!selectedKb || linking"
            class="btn-primary disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {{ linking ? 'Linking...' : 'Link Finding' }}
          </button>
        </div>

        <!-- Error Message -->
        <div v-if="error" class="px-6 pb-4">
          <div class="bg-red-900/20 border border-red-700 rounded-lg p-3 text-red-300 text-sm">
            {{ error }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useKnowledgeBaseStore } from '../../stores/knowledgeBase'
import LoadingSpinner from '../common/LoadingSpinner.vue'
import SeverityBadge from '../common/SeverityBadge.vue'
import {
  XMarkIcon,
  CpuChipIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  MagnifyingGlassIcon
} from '@heroicons/vue/24/outline'

const props = defineProps({
  finding: {
    type: Object,
    required: true
  }
})

const emit = defineEmits(['close', 'linked'])

const kbStore = useKnowledgeBaseStore()

// State
const searchQuery = ref('')
const categoryFilter = ref(null)
const searchResults = ref([])
const selectedKb = ref(null)
const selectedSimilarity = ref(null)
const testing = ref(false)
const searching = ref(false)
const linking = ref(false)
const matchResult = ref(null)
const error = ref(null)

// Methods
let searchTimeout = null
const debouncedSearch = () => {
  clearTimeout(searchTimeout)
  searchTimeout = setTimeout(() => {
    handleSearch()
  }, 500)
}

const handleSearch = async () => {
  if (!searchQuery.value && !categoryFilter.value) {
    searchResults.value = []
    return
  }

  searching.value = true
  error.value = null
  try {
    const result = await kbStore.searchVulnerabilities({
      query: searchQuery.value,
      category: categoryFilter.value,
      is_active: true,
      page: 1,
      limit: 10
    })
    searchResults.value = result.vulnerabilities || []
  } catch (err) {
    error.value = err.message || 'Failed to search vulnerabilities'
    console.error('Search error:', err)
  } finally {
    searching.value = false
  }
}

const testMatch = async () => {
  testing.value = true
  error.value = null
  try {
    const result = await kbStore.matchVulnerability({
      finding_description: props.finding.description,
      finding_title: props.finding.title,
      threshold: 0.85
    })
    matchResult.value = result
  } catch (err) {
    error.value = err.message || 'Failed to test match'
    console.error('Match test error:', err)
  } finally {
    testing.value = false
  }
}

const selectKbEntry = (vuln, similarityScore) => {
  selectedKb.value = vuln
  selectedSimilarity.value = similarityScore
}

const handleLink = async () => {
  if (!selectedKb.value) return

  linking.value = true
  error.value = null
  try {
    await kbStore.linkFinding(
      props.finding.id,
      selectedKb.value.id,
      selectedSimilarity.value
    )
    emit('linked')
  } catch (err) {
    error.value = err.message || 'Failed to link finding'
    console.error('Link error:', err)
  } finally {
    linking.value = false
  }
}

const handleClose = () => {
  if (!linking.value) {
    emit('close')
  }
}
</script>

<style scoped>
.badge-secondary {
  @apply inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-gray-700 text-gray-300;
}
</style>
