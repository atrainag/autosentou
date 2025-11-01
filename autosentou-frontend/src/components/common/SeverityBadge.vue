<template>
  <span :class="['badge', colorClass]">
    {{ severity.toUpperCase() }}
  </span>
</template>

<script setup>
import { computed } from 'vue'
import { getSeverityColor } from '../../utils/formatters'

const props = defineProps({
  severity: {
    type: String,
    required: true,
    validator: (value) => ['critical', 'high', 'medium', 'low', 'info'].includes(value.toLowerCase()),
  },
})

const colorClass = computed(() => getSeverityColor(props.severity))
</script>
