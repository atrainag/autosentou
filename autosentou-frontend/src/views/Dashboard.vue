<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold text-white neon-glow">Dashboard</h1>
        <p class="text-gray-400 mt-1">Automated Penetration Testing Platform</p>
      </div>
      <router-link to="/scan/create" class="btn-primary">
        🚀 Start New Scan
      </router-link>
    </div>

    <!-- Loading State -->
    <LoadingSpinner v-if="jobsStore.loading" text="Loading dashboard..." />

    <!-- Stats Grid -->
    <div v-else class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      <StatCard
        label="Total Scans"
        :value="jobsStore.jobs.length"
        icon="📊"
        iconColor="text-cyber-cyan"
      />
      <StatCard
        label="Active Scans"
        :value="jobsStore.activeJobs.length"
        icon="🔄"
        iconColor="text-blue-500"
        :subtitle="jobsStore.activeJobs.length > 0 ? 'In Progress' : 'No active scans'"
      />
      <StatCard
        label="Completed"
        :value="jobsStore.completedJobs.length"
        icon="✅"
        iconColor="text-green-500"
      />
      <StatCard
        label="Vulnerabilities"
        :value="jobsStore.totalVulnerabilities"
        icon="⚠️"
        iconColor="text-red-500"
        subtitle="Total found"
      />
    </div>

    <!-- Recent Scans -->
    <RecentScans :jobs="recentJobs" />

    <!-- Quick Actions -->
    <div class="card p-6">
      <h2 class="text-xl font-semibold text-white mb-4">Quick Actions</h2>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <router-link
          to="/scan/create"
          class="p-4 border border-gray-700 rounded-lg hover:border-cyber-cyan transition-colors"
        >
          <div class="text-3xl mb-2">🚀</div>
          <h3 class="font-semibold text-white mb-1">New Scan</h3>
          <p class="text-sm text-gray-400">Start a new penetration test</p>
        </router-link>

        <router-link
          to="/jobs"
          class="p-4 border border-gray-700 rounded-lg hover:border-cyber-cyan transition-colors"
        >
          <div class="text-3xl mb-2">📋</div>
          <h3 class="font-semibold text-white mb-1">View All Jobs</h3>
          <p class="text-sm text-gray-400">Browse all scan jobs</p>
        </router-link>

        <router-link
          to="/wordlists"
          class="p-4 border border-gray-700 rounded-lg hover:border-cyber-cyan transition-colors"
        >
          <div class="text-3xl mb-2">📝</div>
          <h3 class="font-semibold text-white mb-1">Wordlists</h3>
          <p class="text-sm text-gray-400">Manage custom wordlists</p>
        </router-link>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, computed } from 'vue'
import { useJobsStore } from '../stores/jobs'
import StatCard from '../components/dashboard/StatCard.vue'
import RecentScans from '../components/dashboard/RecentScans.vue'
import LoadingSpinner from '../components/common/LoadingSpinner.vue'

const jobsStore = useJobsStore()

// Get recent 5 jobs
const recentJobs = computed(() => {
  return [...jobsStore.jobs]
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 5)
})

onMounted(async () => {
  await jobsStore.fetchJobs()
})
</script>
