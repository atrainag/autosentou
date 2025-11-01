<template>
  <div class="card p-6">
    <h2 class="text-xl font-semibold text-white mb-6">Scan Progress</h2>

    <div class="space-y-4">
      <div
        v-for="(phase, index) in phases"
        :key="phase.phase_name"
        class="relative"
      >
        <!-- Progress Line -->
        <div
          v-if="index < phases.length - 1"
          :class="[
            'absolute left-6 top-12 w-0.5 h-8',
            getLineColor(phase.status)
          ]"
        ></div>

        <!-- Phase Row -->
        <div class="flex items-start space-x-4">
          <!-- Icon/Status -->
          <div
            :class="[
              'flex-shrink-0 w-12 h-12 rounded-full flex items-center justify-center text-xl',
              getPhaseColor(phase.status)
            ]"
          >
            <span v-if="phase.status === 'running'" class="animate-spin">⚙️</span>
            <span v-else-if="phase.status === 'completed'">✅</span>
            <span v-else-if="phase.status === 'failed'">❌</span>
            <span v-else>{{ getPhaseIcon(phase.phase_name) }}</span>
          </div>

          <!-- Phase Info -->
          <div class="flex-1 min-w-0">
            <div class="flex items-center justify-between">
              <h3 class="text-lg font-medium text-white">
                {{ formatPhaseName(phase.phase_name) }}
              </h3>
              <StatusBadge v-if="phase.status" :status="phase.status" />
            </div>
            <p class="text-sm text-gray-400 mt-1">
              {{ phase.description || getPhaseDescription(phase.phase_name) }}
            </p>
            <div v-if="phase.updated_at" class="text-xs text-gray-500 mt-2">
              {{ formatRelativeTime(phase.updated_at) }}
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import StatusBadge from '../common/StatusBadge.vue'
import { formatPhaseName, getPhaseIcon, formatRelativeTime } from '../../utils/formatters'

defineProps({
  phases: {
    type: Array,
    required: true,
  },
})

const getPhaseColor = (status) => {
  const colors = {
    running: 'bg-blue-600 text-white',
    completed: 'bg-green-600 text-white',
    failed: 'bg-red-600 text-white',
    pending: 'bg-gray-700 text-gray-400',
  }
  return colors[status] || 'bg-gray-700 text-gray-400'
}

const getLineColor = (status) => {
  return status === 'completed' ? 'bg-green-600' : 'bg-gray-700'
}

const getPhaseDescription = (phaseName) => {
  const descriptions = {
    'Information Gathering': 'Port scanning and service detection',
    'Web Enumeration': 'Directory brute-forcing and web crawling',
    'Vulnerability Analysis': 'CVE lookup and exploit search',
    'SQL Injection Testing': 'SQL injection vulnerability testing',
    'Authentication Testing': 'Username enumeration and auth testing',
    'Report Generation': 'Generating comprehensive pentest report',
  }
console.log(phaseName)
  return descriptions[phaseName] || 'Processing...'
}
</script>
