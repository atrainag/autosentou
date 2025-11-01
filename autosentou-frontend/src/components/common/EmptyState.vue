<template>
  <div class="flex flex-col items-center justify-center py-12 px-4">
    <div class="text-6xl mb-4">{{ icon }}</div>
    <h3 class="text-xl font-semibold text-white mb-2">{{ title }}</h3>
    <p class="text-gray-400 text-center mb-6 max-w-md">{{ description }}</p>
    <slot name="action"></slot>
  </div>
</template>

<script setup>
defineProps({
  icon: {
    type: String,
    default: '📭',
  },
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
})
</script>
