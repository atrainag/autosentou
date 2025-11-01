<template>
  <span :class="['badge', colorClass]">
    {{ displayText }}
  </span>
</template>

<script setup>
import { computed } from 'vue'
import { getStatusColor, getStatusText } from '../../utils/formatters'

const props = defineProps({
  status: {
    type: String,
    required: true,
  },
})

const colorClass = computed(() => getStatusColor(props.status))
const displayText = computed(() => getStatusText(props.status))
</script>
