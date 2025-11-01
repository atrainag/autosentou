<template>
  <div class="card p-6">
    <div class="flex items-center justify-between">
      <div class="flex-1">
        <p class="text-sm text-gray-400 mb-1">{{ label }}</p>
        <p class="text-3xl font-bold text-white">{{ value }}</p>
        <p v-if="subtitle" class="text-xs text-gray-500 mt-1">{{ subtitle }}</p>
      </div>
      <div :class="['text-4xl', iconColor]">
        {{ icon }}
      </div>
    </div>
    <div v-if="trend" class="mt-4 flex items-center text-sm">
      <span :class="[trendColor]">{{ trend }}</span>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

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
    default: '📊',
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

const trendColor = computed(() => {
  if (props.trend.includes('+')) return 'text-green-500'
  if (props.trend.includes('-')) return 'text-red-500'
  return 'text-gray-400'
})
</script>
