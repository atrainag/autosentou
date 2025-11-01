<template>
  <div class="card">
    <div class="p-6 border-b border-gray-800">
      <h2 class="text-xl font-semibold text-white">Recent Scans</h2>
    </div>
    <div v-if="jobs.length === 0" class="p-6">
      <EmptyState
        icon="📋"
        title="No scans yet"
        description="Start your first penetration test to see results here"
      >
        <template #action>
          <router-link to="/scan/create" class="btn-primary">
            Start New Scan
          </router-link>
        </template>
      </EmptyState>
    </div>
    <div v-else class="divide-y divide-gray-800">
      <div
        v-for="job in jobs"
        :key="job.id"
        class="p-4 hover:bg-cyber-dark transition-colors cursor-pointer"
        @click="navigateToJob(job.id)"
      >
        <div class="flex items-center justify-between">
          <div class="flex-1 min-w-0">
            <div class="flex items-center space-x-3">
              <StatusBadge :status="job.status" />
              <h3 class="text-sm font-medium text-white truncate">
                {{ job.target }}
              </h3>
            </div>
            <p class="text-xs text-gray-400 mt-1 truncate">
              {{ job.description || 'No description' }}
            </p>
            <div class="flex items-center space-x-4 mt-2 text-xs text-gray-500">
              <span>{{ formatRelativeTime(job.created_at) }}</span>
              <span v-if="job.phase">Phase: {{ formatPhaseName(job.phase) }}</span>
            </div>
          </div>
          <div class="ml-4">
            <ChevronRightIcon class="h-5 w-5 text-gray-500" />
          </div>
        </div>
      </div>
    </div>
    <div v-if="jobs.length > 0" class="p-4 border-t border-gray-800">
      <router-link
        to="/jobs"
        class="text-sm text-cyber-cyan hover:text-cyan-400 flex items-center justify-center"
      >
        View All Jobs
        <ArrowRightIcon class="h-4 w-4 ml-1" />
      </router-link>
    </div>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'
import { ChevronRightIcon, ArrowRightIcon } from '@heroicons/vue/24/outline'
import StatusBadge from '../common/StatusBadge.vue'
import EmptyState from '../common/EmptyState.vue'
import { formatRelativeTime, formatPhaseName } from '../../utils/formatters'

defineProps({
  jobs: {
    type: Array,
    required: true,
  },
})

const router = useRouter()

const navigateToJob = (jobId) => {
  router.push(`/job/${jobId}`)
}
</script>
