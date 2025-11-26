<template>
  <button
    @click="$emit('sort', column)"
    class="flex items-center space-x-1 hover:text-white transition-colors"
  >
    <span>{{ label }}</span>
    <component :is="icon" class="w-4 h-4" />
  </button>
</template>

<script setup>
import { computed } from 'vue'
import {
  ChevronUpIcon,
  ChevronDownIcon,
  Bars3Icon
} from '@heroicons/vue/24/outline'

const props = defineProps({
  label: {
    type: String,
    required: true
  },
  column: {
    type: String,
    required: true
  },
  currentSort: {
    type: String,
    default: null
  },
  currentOrder: {
    type: String,
    default: 'desc',
    validator: (value) => ['asc', 'desc'].includes(value)
  }
})

defineEmits(['sort'])

const icon = computed(() => {
  if (props.currentSort !== props.column) {
    return Bars3Icon
  }
  return props.currentOrder === 'asc' ? ChevronUpIcon : ChevronDownIcon
})
</script>
