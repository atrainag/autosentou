<template>
  <div class="max-w-4xl mx-auto space-y-6">
    <!-- Header -->
    <div>
      <h1 class="text-3xl font-bold text-white">🚀 Start New Scan</h1>
      <p class="text-gray-400 mt-1">Configure and launch an automated penetration test</p>
    </div>

    <!-- Form -->
    <form @submit.prevent="handleSubmit" class="card p-6 space-y-6">
      <!-- Target -->
      <div>
        <label class="input-label">
          Target <span class="text-red-500">*</span>
        </label>
        <input
          v-model="formData.target"
          type="text"
          class="input-field"
          :class="{ 'border-red-500': errors.target }"
          placeholder="192.168.1.1 or example.com"
          @blur="validateTarget"
        />
        <p v-if="errors.target" class="text-red-500 text-sm mt-1">{{ errors.target }}</p>
        <p class="text-gray-500 text-xs mt-1">Enter IP address, domain name, or URL</p>
      </div>

      <!-- Description -->
      <div>
        <label class="input-label">Description</label>
        <textarea
          v-model="formData.description"
          class="input-field"
          rows="3"
          placeholder="Optional description for this scan..."
        ></textarea>
      </div>

      <!-- Custom Wordlist -->
      <div>
        <label class="input-label">Custom Wordlist (Optional)</label>
        <Listbox v-model="formData.custom_wordlist">
          <div class="relative">
            <ListboxButton
              class="input-field flex items-center justify-between cursor-pointer"
            >
              <span>{{ selectedWordlistLabel }}</span>
              <ChevronUpDownIcon class="h-5 w-5 text-gray-400" />
            </ListboxButton>
            <transition
              leave-active-class="transition duration-100 ease-in"
              leave-from-class="opacity-100"
              leave-to-class="opacity-0"
            >
              <ListboxOptions
                class="absolute z-10 mt-1 w-full card max-h-60 overflow-auto py-1"
              >
                <ListboxOption
                  v-slot="{ active, selected }"
                  :value="null"
                  as="template"
                >
                  <li
                    :class="[
                      active ? 'bg-cyber-blue text-white' : 'text-gray-300',
                      'cursor-pointer select-none relative py-2 pl-10 pr-4',
                    ]"
                  >
                    <span :class="[selected ? 'font-medium' : 'font-normal', 'block truncate']">
                      Default Wordlist
                    </span>
                    <span
                      v-if="selected"
                      class="absolute inset-y-0 left-0 flex items-center pl-3 text-cyber-cyan"
                    >
                      <CheckIcon class="h-5 w-5" />
                    </span>
                  </li>
                </ListboxOption>
                <ListboxOption
                  v-for="wordlist in wordlistsStore.wordlistOptions"
                  :key="wordlist.value"
                  v-slot="{ active, selected }"
                  :value="wordlist.value"
                  as="template"
                >
                  <li
                    :class="[
                      active ? 'bg-cyber-blue text-white' : 'text-gray-300',
                      'cursor-pointer select-none relative py-2 pl-10 pr-4',
                    ]"
                  >
                    <span :class="[selected ? 'font-medium' : 'font-normal', 'block truncate']">
                      {{ wordlist.label }}
                      <span class="text-xs text-gray-500 ml-2">({{ wordlist.type }})</span>
                    </span>
                    <span
                      v-if="selected"
                      class="absolute inset-y-0 left-0 flex items-center pl-3 text-cyber-cyan"
                    >
                      <CheckIcon class="h-5 w-5" />
                    </span>
                  </li>
                </ListboxOption>
              </ListboxOptions>
            </transition>
          </div>
        </Listbox>
        <p class="text-gray-500 text-xs mt-1">
          Select a custom wordlist or leave default
        </p>
      </div>

      <!-- Error Message -->
      <div v-if="jobsStore.error" class="p-4 bg-red-900/50 border border-red-500 rounded-lg">
        <p class="text-red-300 text-sm">{{ jobsStore.error }}</p>
      </div>

      <!-- Actions -->
      <div class="flex justify-end space-x-3 pt-4 border-t border-gray-800">
        <router-link to="/" class="btn-secondary">Cancel</router-link>
        <button
          type="submit"
          class="btn-primary"
          :disabled="jobsStore.loading"
        >
          <span v-if="jobsStore.loading" class="flex items-center space-x-2">
            <svg class="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
              <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Checking connectivity...</span>
          </span>
          <span v-else>Start Scan</span>
        </button>
      </div>
    </form>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useJobsStore } from '../stores/jobs'
import { useWordlistsStore } from '../stores/wordlists'
import { useAppStore } from '../stores/app'
import { isValidTarget } from '../utils/validators'
import {
  Listbox,
  ListboxButton,
  ListboxOptions,
  ListboxOption,
} from '@headlessui/vue'
import { CheckIcon, ChevronUpDownIcon } from '@heroicons/vue/24/outline'

const router = useRouter()
const jobsStore = useJobsStore()
const wordlistsStore = useWordlistsStore()
const appStore = useAppStore()

const formData = ref({
  target: '',
  description: '',
  custom_wordlist: null,
})

const errors = ref({
  target: '',
})

const selectedWordlistLabel = computed(() => {
  if (!formData.value.custom_wordlist) return 'Default Wordlist'
  const wordlist = wordlistsStore.wordlistOptions.find(
    w => w.value === formData.value.custom_wordlist
  )
  return wordlist ? wordlist.label : 'Default Wordlist'
})

const validateTarget = () => {
  if (!formData.value.target) {
    errors.value.target = 'Target is required'
    return false
  }
  if (!isValidTarget(formData.value.target)) {
    errors.value.target = 'Invalid target format. Use IP, domain, or URL'
    return false
  }
  errors.value.target = ''
  return true
}

const handleSubmit = async () => {
  // Validate
  if (!validateTarget()) {
    return
  }

  try {
    const result = await jobsStore.startScan(formData.value)

    if (result.job_id) {
      appStore.showSuccess('Scan started successfully!')
      router.push(`/job/${result.job_id}`)
    }
  } catch (error) {
    // Show detailed error message from backend if available
    const errorMessage = error.response?.data?.detail || 'Failed to start scan'
    appStore.showError(errorMessage)

    // If it's a connectivity error, show in form error too
    if (errorMessage.includes('not responding') || errorMessage.includes('DNS resolution failed')) {
      errors.value.target = errorMessage
    }
  }
}

onMounted(async () => {
  await wordlistsStore.fetchWordlists()
})
</script>
