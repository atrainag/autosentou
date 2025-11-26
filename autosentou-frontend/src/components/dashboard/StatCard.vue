<template>
  <div class="card p-6">
    <div class="flex items-center justify-between">
      <div class="flex-1">
        <p class="text-sm text-gray-400 mb-1">{{ label }}</p>
        <p class="text-3xl font-bold text-white">{{ value }}</p>
        <p v-if="subtitle" class="text-xs text-gray-500 mt-1">{{ subtitle }}</p>
      </div>
      <component :is="iconComponent" :class="['w-12 h-12', iconColor]" />
    </div>
    <div v-if="trend" class="mt-4 flex items-center text-sm">
      <span :class="[trendColor]">{{ trend }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import {
  ChartBarIcon,
  ArrowPathIcon,
  CheckCircleIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  BoltIcon,
  ClockIcon,
  DocumentTextIcon
} from '@heroicons/vue/24/outline'

const props = defineProps({
  label: {
    type: String,
    required: true,
  },
  value: {
    type: [String, Number],
    required: true,
  },
  icon: {
    type: String,
    default: 'chart-bar',
  },
  iconColor: {
    type: String,
    default: 'text-cyber-cyan',
  },
  subtitle: {
    type: String,
    default: '',
  },
  trend: {
    type: String,
    default: '',
  },
})

const iconMap = {
  'chart-bar': ChartBarIcon,
  'arrow-path': ArrowPathIcon,
  'check-circle': CheckCircleIcon,
  'exclamation-triangle': ExclamationTriangleIcon,
  'shield-check': ShieldCheckIcon,
  'bolt': BoltIcon,
  'clock': ClockIcon,
  'document-text': DocumentTextIcon
}

const iconComponent = computed(() => {
  return iconMap[props.icon] || ChartBarIcon
})

const trendColor = computed(() => {
  if (props.trend.includes('+')) return 'text-green-500'
  if (props.trend.includes('-')) return 'text-red-500'
  return 'text-gray-400'
})
</script>
