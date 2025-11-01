<template>
  <TransitionRoot appear :show="isOpen" as="template">
    <Dialog as="div" @close="closeModal" class="relative z-50">
      <TransitionChild
        as="template"
        enter="duration-300 ease-out"
        enter-from="opacity-0"
        enter-to="opacity-100"
        leave="duration-200 ease-in"
        leave-from="opacity-100"
        leave-to="opacity-0"
      >
        <div class="fixed inset-0 bg-black bg-opacity-75" />
      </TransitionChild>

      <div class="fixed inset-0 overflow-y-auto">
        <div class="flex min-h-full items-center justify-center p-4 text-center">
          <TransitionChild
            as="template"
            enter="duration-300 ease-out"
            enter-from="opacity-0 scale-95"
            enter-to="opacity-100 scale-100"
            leave="duration-200 ease-in"
            leave-from="opacity-100 scale-100"
            leave-to="opacity-0 scale-95"
          >
            <DialogPanel
              class="w-full max-w-4xl transform overflow-hidden rounded-lg card p-6 text-left align-middle shadow-xl transition-all"
            >
              <!-- Header -->
              <div class="flex items-start justify-between">
                <div class="flex-1">
                  <DialogTitle as="h3" class="text-xl font-medium leading-6 text-white flex items-center">
                    <DocumentTextIcon class="w-6 h-6 mr-2 text-cyan-400" />
                    Wordlist Preview: {{ wordlistName }}
                  </DialogTitle>

                  <!-- Metadata -->
                  <div class="mt-3 flex items-center space-x-4 text-sm">
                    <span
                      :class="typeBadgeClass"
                      class="badge"
                    >
                      {{ type.toUpperCase() }}
                    </span>
                    <span class="text-gray-400 flex items-center">
                      <span class="text-gray-500 mr-1">Total Lines:</span>
                      <span class="text-white font-semibold">{{ formatNumber(lineCount) }}</span>
                    </span>
                    <span class="text-gray-400 flex items-center">
                      <span class="text-gray-500 mr-1">Size:</span>
                      <span class="text-white font-semibold">{{ formatFileSize(size) }}</span>
                    </span>
                  </div>
                </div>

                <button
                  @click="closeModal"
                  class="text-gray-400 hover:text-gray-200 transition-colors"
                  aria-label="Close"
                >
                  <XMarkIcon class="w-6 h-6" />
                </button>
              </div>

              <!-- Content Area -->
              <div class="mt-6">
                <div
                  v-if="loading"
                  class="flex items-center justify-center py-12"
                >
                  <LoadingSpinner size="md" text="Loading wordlist content..." />
                </div>

                <div
                  v-else
                  class="relative border border-cyan-500/20 rounded-lg bg-gray-900 overflow-hidden"
                >
                  <!-- Scrollable Content -->
                  <div
                    class="overflow-auto font-mono text-sm"
                    style="max-height: 60vh;"
                  >
                    <pre class="p-4 m-0"><code><div
                      v-for="(line, index) in content"
                      :key="index"
                      class="flex hover:bg-gray-800/50 transition-colors"
                    ><span class="inline-block w-16 text-right pr-4 text-gray-500 select-none border-r border-gray-700 mr-4">{{ index + 1 }}</span><span class="text-gray-100 flex-1">{{ line || ' ' }}</span></div></code></pre>
                  </div>

                  <!-- Line count indicator at bottom -->
                  <div class="bg-gray-800/50 border-t border-cyan-500/20 px-4 py-2 text-xs text-gray-400">
                    Showing {{ content.length }} of {{ formatNumber(lineCount) }} lines
                  </div>
                </div>
              </div>

              <!-- Footer -->
              <div class="mt-6 flex justify-end">
                <button
                  type="button"
                  class="btn-secondary"
                  @click="closeModal"
                >
                  Close
                </button>
              </div>
            </DialogPanel>
          </TransitionChild>
        </div>
      </div>
    </Dialog>
  </TransitionRoot>
</template>

<script setup>
import { computed } from 'vue'
import { TransitionRoot, TransitionChild, Dialog, DialogPanel, DialogTitle } from '@headlessui/vue'
import { XMarkIcon, DocumentTextIcon } from '@heroicons/vue/24/outline'
import LoadingSpinner from '@/components/common/LoadingSpinner.vue'
import { formatFileSize, formatNumber } from '@/utils/formatters'

const props = defineProps({
  isOpen: {
    type: Boolean,
    required: true,
  },
  wordlistName: {
    type: String,
    required: true,
  },
  content: {
    type: Array,
    required: true,
  },
  lineCount: {
    type: Number,
    required: true,
  },
  size: {
    type: Number,
    required: true,
  },
  type: {
    type: String,
    required: true,
    validator: (value) => ['default', 'custom'].includes(value),
  },
  loading: {
    type: Boolean,
    default: false,
  },
})

const emit = defineEmits(['close'])

const typeBadgeClass = computed(() => {
  return props.type === 'default'
    ? 'bg-cyan-600 text-white'
    : 'bg-blue-600 text-white'
})

const closeModal = () => {
  emit('close')
}
</script>

<style scoped>
/* Ensure proper spacing and styling for code preview */
pre {
  margin: 0;
  padding: 0;
}

code {
  display: block;
  background: transparent;
  padding: 0;
}

/* Custom scrollbar styling for the content area */
.overflow-auto::-webkit-scrollbar {
  width: 10px;
  height: 10px;
}

.overflow-auto::-webkit-scrollbar-track {
  background: #1a1a2e;
}

.overflow-auto::-webkit-scrollbar-thumb {
  background: #1e3a8a;
  border-radius: 4px;
}

.overflow-auto::-webkit-scrollbar-thumb:hover {
  background: #2563eb;
}
</style>
