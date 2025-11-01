<template>
  <div class="fixed top-4 right-4 z-50 space-y-2 max-w-md">
    <TransitionGroup
      name="toast"
      tag="div"
      class="space-y-2"
    >
      <div
        v-for="notification in notifications"
        :key="notification.id"
        :class="['card p-4 flex items-start space-x-3', getNotificationClass(notification.type)]"
      >
        <div class="flex-shrink-0">
          <component :is="getIcon(notification.type)" class="h-6 w-6" />
        </div>
        <div class="flex-1">
          <p class="text-sm font-medium text-white">{{ notification.message }}</p>
        </div>
        <button
          @click="removeNotification(notification.id)"
          class="flex-shrink-0 text-gray-400 hover:text-white"
        >
          <XMarkIcon class="h-5 w-5" />
        </button>
      </div>
    </TransitionGroup>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import { useAppStore } from '../../stores/app'
import {
  CheckCircleIcon,
  XCircleIcon,
  InformationCircleIcon,
  ExclamationTriangleIcon,
  XMarkIcon,
} from '@heroicons/vue/24/outline'

const appStore = useAppStore()

const notifications = computed(() => appStore.notifications)

const getNotificationClass = (type) => {
  const classes = {
    success: 'border-l-4 border-green-500',
    error: 'border-l-4 border-red-500',
    warning: 'border-l-4 border-yellow-500',
    info: 'border-l-4 border-blue-500',
  }
  return classes[type] || classes.info
}

const getIcon = (type) => {
  const icons = {
    success: CheckCircleIcon,
    error: XCircleIcon,
    warning: ExclamationTriangleIcon,
    info: InformationCircleIcon,
  }
  return icons[type] || InformationCircleIcon
}

const removeNotification = (id) => {
  appStore.removeNotification(id)
}
</script>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition: all 0.3s ease;
}

.toast-enter-from {
  opacity: 0;
  transform: translateX(100%);
}

.toast-leave-to {
  opacity: 0;
  transform: translateX(100%);
}
</style>
