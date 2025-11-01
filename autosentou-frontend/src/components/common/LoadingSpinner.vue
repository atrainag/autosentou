<template>
  <div class="flex items-center justify-center" :class="containerClass">
    <div class="relative" :class="sizeClass">
      <div class="absolute inset-0 border-4 border-gray-700 rounded-full"></div>
      <div
        class="absolute inset-0 border-4 border-transparent border-t-cyber-cyan rounded-full animate-spin"
      ></div>
    </div>
    <span v-if="text" class="ml-3 text-gray-300">{{ text }}</span>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  size: {
    type: String,
    default: 'md',
    validator: (value) => ['sm', 'md', 'lg'].includes(value),
  },
  text: {
    type: String,
    default: '',
  },
  fullScreen: {
    type: Boolean,
    default: false,
  },
})

const sizeClass = computed(() => {
  const sizes = {
    sm: 'w-6 h-6',
    md: 'w-12 h-12',
    lg: 'w-16 h-16',
  }
  return sizes[props.size]
})

const containerClass = computed(() => {
  return props.fullScreen ? 'min-h-screen' : 'py-8'
})
</script>
