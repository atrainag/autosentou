<template>
  <div class="fixed inset-0 z-50 overflow-y-auto">
    <div class="flex items-center justify-center min-h-screen px-4 pt-4 pb-20 text-center sm:block sm:p-0">
      <!-- Background overlay -->
      <div class="fixed inset-0 transition-opacity bg-gray-900 bg-opacity-75" @click="$emit('close')"></div>

      <!-- Modal panel -->
      <div
        class="inline-block align-bottom bg-cyber-dark rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-3xl sm:w-full border border-gray-800"
      >
        <!-- Header -->
        <div class="bg-cyber-darker px-6 py-4 border-b border-gray-800">
          <div class="flex items-center justify-between">
            <h3 class="text-xl font-semibold text-white">
              Finding Details
            </h3>
            <button
              @click="$emit('close')"
              class="text-gray-400 hover:text-white transition-colors"
            >
              ✕
            </button>
          </div>
        </div>

        <!-- Body -->
        <div class="px-6 py-6 space-y-6 max-h-[70vh] overflow-y-auto">
          <!-- Title and Severity -->
          <div class="space-y-2">
            <div class="flex items-start justify-between">
              <div class="flex-1">
                <h4 class="text-lg font-semibold text-white">{{ finding.title }}</h4>
                <div class="flex items-center space-x-2 mt-2">
                  <SeverityBadge :severity="finding.severity" />
                  <span v-if="finding.finding_type" class="badge-secondary">
                    {{ finding.finding_type }}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <!-- Description -->
          <div>
            <label class="block text-sm font-medium text-gray-400 mb-2">Description</label>
            <div class="bg-cyber-darker p-4 rounded-lg border border-gray-800 text-gray-300 whitespace-pre-wrap">
              {{ finding.description || 'No description provided' }}
            </div>
          </div>

          <!-- Technical Details Grid -->
          <div class="grid grid-cols-2 gap-4">
            <!-- Service -->
            <div v-if="finding.service">
              <label class="block text-sm font-medium text-gray-400 mb-2">Service</label>
              <div class="text-white">
                {{ finding.service }}
                <span v-if="finding.port" class="text-gray-400">:{{ finding.port }}</span>
              </div>
            </div>

            <!-- CVE ID -->
            <div v-if="finding.cve_id">
              <label class="block text-sm font-medium text-gray-400 mb-2">CVE ID</label>
              <div class="text-cyber-cyan">{{ finding.cve_id }}</div>
            </div>

            <!-- CVSS Score -->
            <div v-if="finding.cvss_score">
              <label class="block text-sm font-medium text-gray-400 mb-2">CVSS Score</label>
              <div class="text-white">{{ finding.cvss_score }}</div>
            </div>

            <!-- OWASP Category -->
            <div v-if="finding.owasp_category">
              <label class="block text-sm font-medium text-gray-400 mb-2">OWASP Category</label>
              <div class="text-white">{{ finding.owasp_category }}</div>
            </div>

            <!-- Job ID -->
            <div v-if="finding.job_id">
              <label class="block text-sm font-medium text-gray-400 mb-2">Job ID</label>
              <div class="text-cyber-cyan font-mono text-sm">{{ finding.job_id }}</div>
            </div>

            <!-- Created At -->
            <div v-if="finding.created_at">
              <label class="block text-sm font-medium text-gray-400 mb-2">Discovered</label>
              <div class="text-white">{{ formatDate(finding.created_at) }}</div>
            </div>
          </div>

          <!-- URL -->
          <div v-if="finding.url">
            <label class="block text-sm font-medium text-gray-400 mb-2">URL</label>
            <div class="bg-cyber-darker p-3 rounded border border-gray-800 text-cyber-cyan break-all font-mono text-sm">
              {{ finding.url }}
            </div>
          </div>

          <!-- Remediation -->
          <div v-if="finding.remediation">
            <label class="block text-sm font-medium text-gray-400 mb-2">Remediation</label>
            <div class="bg-cyber-darker p-4 rounded-lg border border-gray-800 text-gray-300 whitespace-pre-wrap">
              {{ finding.remediation }}
            </div>
          </div>

          <!-- Proof of Concept -->
          <div v-if="finding.poc">
            <label class="block text-sm font-medium text-gray-400 mb-2">Proof of Concept</label>
            <div class="bg-cyber-darker p-4 rounded-lg border border-gray-800 text-gray-300 whitespace-pre-wrap font-mono text-sm">
              {{ finding.poc }}
            </div>
          </div>

          <!-- Evidence -->
          <div v-if="finding.evidence && Object.keys(finding.evidence).length > 0">
            <label class="block text-sm font-medium text-gray-400 mb-2">Evidence</label>
            <div class="bg-cyber-darker p-4 rounded-lg border border-gray-800">
              <pre class="text-gray-300 text-xs overflow-x-auto">{{ JSON.stringify(finding.evidence, null, 2) }}</pre>
            </div>
          </div>
        </div>

        <!-- Footer -->
        <div class="bg-cyber-darker px-6 py-4 border-t border-gray-800 flex justify-between">
          <button @click="$emit('close')" class="btn-secondary">
            Close
          </button>
          <button @click="$emit('link')" class="btn-primary">
            🔗 Link to Knowledge Base
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import SeverityBadge from '../common/SeverityBadge.vue'

defineProps({
  finding: {
    type: Object,
    required: true
  }
})

defineEmits(['close', 'link'])

const formatDate = (dateString) => {
  if (!dateString) return 'N/A'
  const date = new Date(dateString)
  return date.toLocaleString()
}
</script>

<style scoped>
.badge-secondary {
  @apply inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium bg-gray-700 text-gray-300;
}
</style>
