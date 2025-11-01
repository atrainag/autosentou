<template>
  <div class="min-h-screen bg-cyber-darker">
    <!-- Sidebar -->
    <div
      :class="[
        'fixed inset-y-0 left-0 z-50 w-64 bg-cyber-dark border-r border-gray-800 transform transition-transform duration-300',
        appStore.sidebarOpen ? 'translate-x-0' : '-translate-x-full'
      ]"
    >
      <!-- Logo/Brand -->
      <div class="p-6 border-b border-gray-800">
        <div class="flex items-center space-x-3">
          <div class="text-3xl">🛡️</div>
          <div>
            <h1 class="text-xl font-bold text-white neon-glow">Autosentou</h1>
            <p class="text-xs text-gray-400">Automated Pentesting</p>
          </div>
        </div>
      </div>

      <!-- Navigation -->
      <nav class="p-4 space-y-2">
        <router-link
          v-for="route in mainRoutes"
          :key="route.path"
          :to="route.path"
          v-slot="{ isActive }"
          custom
        >
          <a
            @click="navigateTo(route.path)"
            :class="[
              'flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors cursor-pointer',
              isActive
                ? 'bg-cyber-cyan text-white'
                : 'text-gray-400 hover:text-white hover:bg-cyber-darker'
            ]"
          >
            <span class="text-xl">{{ route.meta.icon }}</span>
            <span class="font-medium">{{ route.meta.title }}</span>
          </a>
        </router-link>
      </nav>

      <!-- Backend Status -->
      <div class="absolute bottom-0 left-0 right-0 p-4 border-t border-gray-800">
        <div class="flex items-center space-x-2 text-sm">
          <div
            :class="[
              'w-2 h-2 rounded-full',
              appStore.backendConnected ? 'bg-green-500' : 'bg-red-500'
            ]"
          ></div>
          <span class="text-gray-400">
            {{ appStore.backendConnected ? 'Connected' : 'Disconnected' }}
          </span>
        </div>
      </div>
    </div>

    <!-- Mobile Overlay -->
    <div
      v-if="appStore.sidebarOpen"
      @click="appStore.toggleSidebar"
      class="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden"
    ></div>

    <!-- Main Content -->
    <div
      :class="[
        'transition-all duration-300',
        appStore.sidebarOpen ? 'lg:ml-64' : ''
      ]"
    >
      <!-- Top Bar -->
      <header class="bg-cyber-dark border-b border-gray-800 sticky top-0 z-30">
        <div class="px-6 py-4 flex items-center justify-between">
          <button
            @click="appStore.toggleSidebar"
            class="text-gray-400 hover:text-white"
          >
            <Bars3Icon class="h-6 w-6" />
          </button>

          <div class="flex items-center space-x-4">
            <!-- Active Jobs Indicator -->
            <router-link
              v-if="jobsStore.activeJobs.length > 0"
              to="/jobs"
              class="flex items-center space-x-2 px-3 py-2 rounded-lg bg-blue-600/20 text-blue-400 hover:bg-blue-600/30"
            >
              <div class="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
              <span class="text-sm font-medium">{{ jobsStore.activeJobs.length }} Active Scans</span>
            </router-link>
          </div>
        </div>
      </header>

      <!-- Page Content -->
      <main class="p-6">
        <router-view />
      </main>
    </div>

    <!-- Notification Toasts -->
    <NotificationToast />
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAppStore } from './stores/app'
import { useJobsStore } from './stores/jobs'
import { healthApi } from './services/api'
import NotificationToast from './components/common/NotificationToast.vue'
import { Bars3Icon } from '@heroicons/vue/24/outline'

const router = useRouter()
const appStore = useAppStore()
const jobsStore = useJobsStore()

// Main navigation routes
const mainRoutes = [
  { path: '/', meta: { title: 'Dashboard', icon: '📊' } },
  { path: '/scan/create', meta: { title: 'New Scan', icon: '🚀' } },
  { path: '/jobs', meta: { title: 'Jobs', icon: '📋' } },
  { path: '/wordlists', meta: { title: 'Wordlists', icon: '📝' } },
]

const navigateTo = (path) => {
  router.push(path)
  // Close sidebar on mobile after navigation
  if (window.innerWidth < 1024) {
    appStore.toggleSidebar()
  }
}

// Check backend connection
const checkBackendConnection = async () => {
  try {
    await healthApi.healthCheck()
    appStore.setBackendConnected(true)
  } catch (error) {
    appStore.setBackendConnected(false)
  }
}

onMounted(async () => {
  await checkBackendConnection()

  // Open sidebar by default on desktop
  if (window.innerWidth >= 1024 && !appStore.sidebarOpen) {
    appStore.toggleSidebar()
  }

  // Check connection periodically
  setInterval(checkBackendConnection, 30000)
})
</script>
