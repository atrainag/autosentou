<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold text-white">📝 Wordlist Manager</h1>
        <p class="text-gray-400 mt-1">Manage wordlists for directory enumeration</p>
      </div>
    </div>

    <!-- Upload Section -->
    <div class="card p-6">
      <h2 class="text-xl font-semibold text-white mb-4">Upload Custom Wordlist</h2>
      <div
        @drop.prevent="handleDrop"
        @dragover.prevent="dragOver = true"
        @dragleave.prevent="dragOver = false"
        :class="[
          'border-2 border-dashed rounded-lg p-8 text-center transition-colors',
          dragOver ? 'border-cyber-cyan bg-cyber-blue/10' : 'border-gray-700'
        ]"
      >
        <input
          ref="fileInput"
          type="file"
          accept=".txt,.lst,.wordlist"
          class="hidden"
          @change="handleFileSelect"
        />
        <div class="text-4xl mb-3">📁</div>
        <p class="text-white mb-2">Drag and drop a wordlist file here</p>
        <p class="text-sm text-gray-400 mb-4">or</p>
        <button
          @click="$refs.fileInput.click()"
          class="btn-primary"
        >
          Choose File
        </button>
        <p class="text-xs text-gray-500 mt-4">
          Supported formats: .txt, .lst, .wordlist (Max 50MB)
        </p>
      </div>

      <!-- Upload Progress -->
      <div v-if="wordlistsStore.uploadProgress > 0 && wordlistsStore.uploadProgress < 100" class="mt-4">
        <div class="flex items-center justify-between mb-2">
          <span class="text-sm text-gray-400">Uploading...</span>
          <span class="text-sm text-cyber-cyan">{{ wordlistsStore.uploadProgress }}%</span>
        </div>
        <div class="w-full bg-gray-700 rounded-full h-2">
          <div
            class="bg-cyber-cyan h-2 rounded-full transition-all"
            :style="{ width: `${wordlistsStore.uploadProgress}%` }"
          ></div>
        </div>
      </div>

      <!-- Upload Error -->
      <div v-if="uploadError" class="mt-4 p-4 bg-red-900/50 border border-red-500 rounded-lg">
        <p class="text-red-300 text-sm">{{ uploadError }}</p>
      </div>
    </div>

    <!-- Wordlists Lists -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <!-- Default Wordlists -->
      <div class="card">
        <div class="p-6 border-b border-gray-800">
          <h2 class="text-xl font-semibold text-white">Default Wordlists</h2>
        </div>
        <LoadingSpinner v-if="wordlistsStore.loading" />
        <div v-else-if="wordlistsStore.defaultWordlists.length === 0" class="p-6">
          <EmptyState
            icon="📝"
            title="No default wordlists"
            description="No default wordlists available"
          />
        </div>
        <div v-else class="divide-y divide-gray-800">
          <div
            v-for="wordlist in wordlistsStore.defaultWordlists"
            :key="wordlist.path"
            class="p-4 hover:bg-cyber-dark transition-colors"
          >
            <div class="flex items-start justify-between">
              <div class="flex-1">
                <h3 class="text-white font-medium">{{ wordlist.name }}</h3>
                <div class="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                  <span>{{ formatFileSize(wordlist.size) }}</span>
                  <span>{{ formatNumber(wordlist.line_count) }} lines</span>
                </div>
              </div>
              <div class="flex items-center space-x-2">
                <button
                  @click="handlePreview(wordlist)"
                  class="btn-primary text-xs py-1 px-3"
                  title="Preview"
                >
                  <EyeIcon class="h-4 w-4 inline mr-1" />
                  Preview
                </button>
                <span class="badge bg-blue-600">Default</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Custom Wordlists -->
      <div class="card">
        <div class="p-6 border-b border-gray-800">
          <h2 class="text-xl font-semibold text-white">Custom Wordlists</h2>
        </div>
        <LoadingSpinner v-if="wordlistsStore.loading" />
        <div v-else-if="wordlistsStore.customWordlists.length === 0" class="p-6">
          <EmptyState
            icon="📝"
            title="No custom wordlists"
            description="Upload your first custom wordlist to get started"
          />
        </div>
        <div v-else class="divide-y divide-gray-800">
          <div
            v-for="wordlist in wordlistsStore.customWordlists"
            :key="wordlist.path"
            class="p-4 hover:bg-cyber-dark transition-colors"
          >
            <div class="flex items-start justify-between">
              <div class="flex-1">
                <h3 class="text-white font-medium">{{ wordlist.name }}</h3>
                <div class="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                  <span>{{ formatFileSize(wordlist.size) }}</span>
                  <span>{{ formatNumber(wordlist.line_count) }} lines</span>
                </div>
              </div>
              <div class="flex items-center space-x-2">
                <button
                  @click="handlePreview(wordlist)"
                  class="btn-primary text-xs py-1 px-3"
                  title="Preview"
                >
                  <EyeIcon class="h-4 w-4 inline mr-1" />
                  Preview
                </button>
                <span class="badge bg-cyber-cyan">Custom</span>
                <button
                  @click="confirmDelete(wordlist)"
                  class="text-red-500 hover:text-red-400"
                  title="Delete"
                >
                  <TrashIcon class="h-5 w-5" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Delete Confirmation Dialog -->
    <ConfirmDialog
      :isOpen="showDeleteDialog"
      title="Delete Wordlist"
      :message="`Are you sure you want to delete '${wordlistToDelete?.name}'? This action cannot be undone.`"
      confirmText="Delete"
      cancelText="Cancel"
      variant="danger"
      @close="showDeleteDialog = false"
      @confirm="handleDelete"
    />

    <!-- Wordlist Preview Modal -->
    <WordlistPreviewModal
      :is-open="isPreviewOpen"
      :wordlist-name="selectedWordlist?.name || ''"
      :content="wordlistsStore.previewData?.content || []"
      :line-count="selectedWordlist?.line_count || 0"
      :size="selectedWordlist?.size || 0"
      :type="selectedWordlist?.type || 'default'"
      :loading="wordlistsStore.isLoadingPreview"
      @close="handleClosePreview"
    />
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useWordlistsStore } from '../stores/wordlists'
import { useAppStore } from '../stores/app'
import LoadingSpinner from '../components/common/LoadingSpinner.vue'
import EmptyState from '../components/common/EmptyState.vue'
import ConfirmDialog from '../components/common/ConfirmDialog.vue'
import WordlistPreviewModal from '@/components/wordlist/WordlistPreviewModal.vue'
import { TrashIcon, EyeIcon } from '@heroicons/vue/24/outline'
import { formatFileSize, formatNumber } from '../utils/formatters'
import { isValidWordlist } from '../utils/validators'

const wordlistsStore = useWordlistsStore()
const appStore = useAppStore()

const fileInput = ref(null)
const dragOver = ref(false)
const uploadError = ref('')
const showDeleteDialog = ref(false)
const wordlistToDelete = ref(null)
const isPreviewOpen = ref(false)
const selectedWordlist = ref(null)

const handleFileSelect = async (event) => {
  const file = event.target.files[0]
  if (file) {
    await uploadFile(file)
  }
  event.target.value = '' // Reset input
}

const handleDrop = async (event) => {
  dragOver.value = false
  const file = event.dataTransfer.files[0]
  if (file) {
    await uploadFile(file)
  }
}

const uploadFile = async (file) => {
  uploadError.value = ''

  // Validate file
  const validation = isValidWordlist(file)
  if (!validation.valid) {
    uploadError.value = validation.error
    return
  }

  try {
    await wordlistsStore.uploadWordlist(file)
    appStore.showSuccess(`Wordlist '${file.name}' uploaded successfully`)
  } catch (error) {
    uploadError.value = error.response?.data?.detail || error.message || 'Failed to upload wordlist'
    appStore.showError('Failed to upload wordlist')
  }
}

const confirmDelete = (wordlist) => {
  wordlistToDelete.value = wordlist
  showDeleteDialog.value = true
}

const handleDelete = async () => {
  if (!wordlistToDelete.value) return

  try {
    await wordlistsStore.deleteWordlist(wordlistToDelete.value.name)
    appStore.showSuccess(`Wordlist '${wordlistToDelete.value.name}' deleted`)
  } catch (error) {
    appStore.showError('Failed to delete wordlist')
  } finally {
    wordlistToDelete.value = null
  }
}

const handlePreview = async (wordlist) => {
  selectedWordlist.value = wordlist
  isPreviewOpen.value = true
  await wordlistsStore.fetchWordlistPreview(wordlist.name)
}

const handleClosePreview = () => {
  isPreviewOpen.value = false
  wordlistsStore.clearPreview()
  selectedWordlist.value = null
}

onMounted(async () => {
  await wordlistsStore.fetchWordlists()
})
</script>
