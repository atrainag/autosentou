import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useAppStore = defineStore('app', () => {
  // State
  const sidebarOpen = ref(true)
  const notifications = ref([])
  const backendConnected = ref(false)

  // Actions
  const toggleSidebar = () => {
    sidebarOpen.value = !sidebarOpen.value
  }

  const addNotification = (notification) => {
    const id = Date.now()
    notifications.value.push({
      id,
      ...notification,
      timestamp: new Date(),
    })

    // Auto-remove after 5 seconds
    setTimeout(() => {
      removeNotification(id)
    }, 5000)
  }

  const removeNotification = (id) => {
    notifications.value = notifications.value.filter(n => n.id !== id)
  }

  const showSuccess = (message) => {
    addNotification({
      type: 'success',
      message,
    })
  }

  const showError = (message) => {
    addNotification({
      type: 'error',
      message,
    })
  }

  const showInfo = (message) => {
    addNotification({
      type: 'info',
      message,
    })
  }

  const showWarning = (message) => {
    addNotification({
      type: 'warning',
      message,
    })
  }

  const setBackendConnected = (status) => {
    backendConnected.value = status
  }

  return {
    // State
    sidebarOpen,
    notifications,
    backendConnected,

    // Actions
    toggleSidebar,
    addNotification,
    removeNotification,
    showSuccess,
    showError,
    showInfo,
    showWarning,
    setBackendConnected,
  }
})
