<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-3xl font-bold text-white neon-glow">🧪 Phase Testing</h1>
        <p class="text-gray-400 mt-1">Test individual phases with custom inputs</p>
      </div>
    </div>

    <!-- Phase Selection -->
    <div class="flex gap-2 flex-wrap">
      <button
        v-for="phase in phases"
        :key="phase.id"
        @click="selectedPhase = phase.id"
        :class="[
          'px-4 py-3 rounded-lg transition-all font-semibold',
          selectedPhase === phase.id
            ? 'bg-cyber-cyan text-white'
            : 'bg-cyber-dark text-gray-400 border border-gray-700 hover:border-cyber-cyan hover:text-white'
        ]"
      >
        {{ phase.icon }} {{ phase.name }}
      </button>
    </div>

    <!-- Phase Testing Forms -->
    <div class="card p-6">
      <!-- Phase 1: Info Gathering -->
      <div v-if="selectedPhase === 1">
        <h2 class="text-2xl font-bold text-white mb-2">Phase 1: Information Gathering</h2>
        <p class="text-gray-400 mb-6">Run nmap scan and gather target information</p>

        <div class="space-y-4">
          <div>
            <label class="input-label">Target (IP or Domain)</label>
            <input
              v-model="phase1Input.target"
              type="text"
              placeholder="e.g., scanme.nmap.org or 192.168.1.1"
              class="input-field"
            />
          </div>

          <button @click="runPhase1" :disabled="loading" class="btn-primary">
            {{ loading ? '⏳ Running...' : '▶️ Run Phase 1' }}
          </button>
        </div>
      </div>

      <!-- Phase 2: Web Enumeration -->
      <div v-else-if="selectedPhase === 2">
        <h2 class="text-2xl font-bold text-white mb-2">Phase 2: Web Enumeration</h2>
        <p class="text-gray-400 mb-6">Enumerate web paths (requires Phase 1 data)</p>

        <div class="space-y-4">
          <div>
            <label class="input-label">Select Job (with Phase 1 data)</label>
            <select v-model="phase2Input.job_id" class="input-field">
              <option value="">-- Select a job --</option>
              <option v-for="job in availableJobs" :key="job.id" :value="job.id">
                {{ job.target }} ({{ job.id }})
              </option>
            </select>
          </div>

          <div>
            <label class="input-label">Custom Wordlist (optional)</label>
            <input
              v-model="phase2Input.custom_wordlist"
              type="text"
              placeholder="Path to custom wordlist"
              class="input-field"
            />
          </div>

          <button @click="runPhase2" :disabled="loading || !phase2Input.job_id" class="btn-primary">
            {{ loading ? '⏳ Running...' : '▶️ Run Phase 2' }}
          </button>
        </div>
      </div>

      <!-- Phase 3: Vulnerability Analysis -->
      <div v-else-if="selectedPhase === 3">
        <h2 class="text-2xl font-bold text-white mb-2">Phase 3: Vulnerability Analysis</h2>
        <p class="text-gray-400 mb-6">Analyze vulnerabilities (requires Phase 1 data)</p>

        <div class="space-y-4">
          <div>
            <label class="input-label">Select Job (with Phase 1 data)</label>
            <select v-model="phase3Input.job_id" class="input-field">
              <option value="">-- Select a job --</option>
              <option v-for="job in availableJobs" :key="job.id" :value="job.id">
                {{ job.target }} ({{ job.id }})
              </option>
            </select>
          </div>

          <button @click="runPhase3" :disabled="loading || !phase3Input.job_id" class="btn-primary">
            {{ loading ? '⏳ Running...' : '▶️ Run Phase 3' }}
          </button>
        </div>
      </div>

      <!-- Phase 4: SQLi Testing -->
      <div v-else-if="selectedPhase === 4">
        <h2 class="text-2xl font-bold text-white mb-2">Phase 4: SQL Injection Testing</h2>
        <p class="text-gray-400 mb-6">Test for SQL injection (requires Phase 2 data)</p>

        <div class="space-y-4">
          <div>
            <label class="input-label">Select Job (with Phase 2 data)</label>
            <select v-model="phase4Input.job_id" class="input-field">
              <option value="">-- Select a job --</option>
              <option v-for="job in availableJobs" :key="job.id" :value="job.id">
                {{ job.target }} ({{ job.id }})
              </option>
            </select>
          </div>

          <button @click="runPhase4" :disabled="loading || !phase4Input.job_id" class="btn-primary">
            {{ loading ? '⏳ Running...' : '▶️ Run Phase 4' }}
          </button>
        </div>
      </div>

      <!-- Phase 5: Auth Testing -->
      <div v-else-if="selectedPhase === 5">
        <h2 class="text-2xl font-bold text-white mb-2">Phase 5: Authentication Testing</h2>
        <p class="text-gray-400 mb-6">Test authentication mechanisms (requires Phase 2 data)</p>

        <div class="space-y-4">
          <div>
            <label class="input-label">Select Job (with Phase 2 data)</label>
            <select v-model="phase5Input.job_id" class="input-field">
              <option value="">-- Select a job --</option>
              <option v-for="job in availableJobs" :key="job.id" :value="job.id">
                {{ job.target }} ({{ job.id }})
              </option>
            </select>
          </div>

          <button @click="runPhase5" :disabled="loading || !phase5Input.job_id" class="btn-primary">
            {{ loading ? '⏳ Running...' : '▶️ Run Phase 5' }}
          </button>
        </div>
      </div>

      <!-- Phase 6: Web Analysis -->
      <div v-else-if="selectedPhase === 6">
        <h2 class="text-2xl font-bold text-white mb-2">
          <span class="text-cyber-neon">Phase 2.5: Web Analysis (NEW)</span>
        </h2>
        <p class="text-gray-400 mb-6">Deep analysis with Playwright + LLM (requires Phase 2 data)</p>

        <div class="space-y-4">
          <div>
            <label class="input-label">Select Job (with Phase 2 data)</label>
            <select v-model="phase6Input.job_id" class="input-field">
              <option value="">-- Select a job --</option>
              <option v-for="job in availableJobs" :key="job.id" :value="job.id">
                {{ job.target }} ({{ job.id }})
              </option>
            </select>
          </div>

          <div>
            <label class="input-label">Max Pages to Analyze</label>
            <input
              v-model.number="phase6Input.max_pages"
              type="number"
              min="1"
              max="200"
              class="input-field"
            />
            <p class="text-sm text-gray-500 mt-1">Recommended: 50-100 pages</p>
          </div>

          <button @click="runPhase6" :disabled="loading || !phase6Input.job_id" class="btn-primary">
            {{ loading ? '⏳ Running...' : '▶️ Run Phase 2.5' }}
          </button>
        </div>
      </div>

      <!-- Phase 7: Report Generation -->
      <div v-else-if="selectedPhase === 7">
        <h2 class="text-2xl font-bold text-white mb-2">
          <span class="text-green-400">📄 Report Generation</span>
        </h2>
        <p class="text-gray-400 mb-6">Generate final pentest report from existing phase data</p>

        <div class="space-y-4">
          <div>
            <label class="input-label">Select Job (with completed phases)</label>
            <select v-model="reportGenInput.job_id" @change="fetchJobPhases(reportGenInput.job_id)" class="input-field">
              <option value="">-- Select a job --</option>
              <option v-for="job in availableJobs" :key="job.id" :value="job.id">
                {{ job.target }} ({{ job.id }})
              </option>
            </select>
          </div>

          <div v-if="selectedJobPhases.length > 0" class="bg-cyber-darker border border-gray-700 rounded-lg p-4">
            <p class="text-sm text-gray-400 mb-2">Available phases for this job:</p>
            <div class="flex flex-wrap gap-2">
              <span
                v-for="phase in selectedJobPhases"
                :key="phase.id"
                class="badge bg-green-900/50 text-green-300"
              >
                ✓ {{ phase.name }}
              </span>
            </div>
          </div>

          <div class="bg-blue-900/20 border border-blue-700/50 rounded-lg p-4">
            <p class="text-blue-300 text-sm">
              💡 <strong>Tip:</strong> The report will include all available phase data. You don't need to re-run the entire scan to test report generation!
            </p>
          </div>

          <button @click="runReportGeneration" :disabled="loading || !reportGenInput.job_id" class="btn-primary">
            {{ loading ? '⏳ Generating Report...' : '📄 Generate Report' }}
          </button>
        </div>
      </div>

      <!-- Phase 8: Retry Phase -->
      <div v-else-if="selectedPhase === 8">
        <h2 class="text-2xl font-bold text-white mb-2">
          <span class="text-yellow-400">🔄 Retry Phase</span>
        </h2>
        <p class="text-gray-400 mb-6">Retry a failed phase without re-running the entire scan</p>

        <div class="space-y-4">
          <div>
            <label class="input-label">Select Job</label>
            <select v-model="retryPhaseInput.job_id" @change="fetchJobPhases(retryPhaseInput.job_id)" class="input-field">
              <option value="">-- Select a job --</option>
              <option v-for="job in availableJobs" :key="job.id" :value="job.id">
                {{ job.target }} ({{ job.id }})
              </option>
            </select>
          </div>

          <div>
            <label class="input-label">Phase to Retry</label>
            <select v-model="retryPhaseInput.phase_name" class="input-field">
              <option value="">-- Select phase --</option>
              <option value="Information Gathering">Phase 1: Information Gathering</option>
              <option value="Web Enumeration">Phase 2: Web Enumeration</option>
              <option value="Web Analysis">Phase 3: Web Analysis</option>
              <option value="Vulnerability Analysis">Phase 4: Vulnerability Analysis</option>
              <option value="SQL Injection Testing">Phase 5: SQL Injection Testing</option>
              <option value="Authentication Testing">Phase 6: Authentication Testing</option>
              <option value="Report Generation">Phase 7: Report Generation</option>
            </select>
          </div>

          <!-- Conditional fields based on phase -->
          <div v-if="retryPhaseInput.phase_name === 'Web Enumeration'">
            <label class="input-label">Custom Wordlist (optional)</label>
            <input
              v-model="retryPhaseInput.custom_wordlist"
              type="text"
              placeholder="Path to custom wordlist"
              class="input-field"
            />
          </div>

          <div v-if="retryPhaseInput.phase_name === 'Web Analysis'">
            <label class="input-label">Max Pages to Analyze</label>
            <input
              v-model.number="retryPhaseInput.max_pages"
              type="number"
              min="1"
              max="200"
              class="input-field"
            />
          </div>

          <div class="bg-yellow-900/20 border border-yellow-700/50 rounded-lg p-4">
            <p class="text-yellow-300 text-sm">
              ⚠️ <strong>Warning:</strong> Retrying a phase will overwrite the existing phase data. Make sure dependent phases are aware of the changes.
            </p>
          </div>

          <button
            @click="runRetryPhase"
            :disabled="loading || !retryPhaseInput.job_id || !retryPhaseInput.phase_name"
            class="btn-primary"
          >
            {{ loading ? '⏳ Retrying...' : '🔄 Retry Phase' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Results Display -->
    <div v-if="result" class="card p-6">
      <h2 class="text-2xl font-bold text-white mb-4">Results</h2>

      <div class="flex items-center gap-3 mb-4">
        <span
          :class="[
            'badge',
            result.status === 'completed' ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'
          ]"
        >
          {{ result.status }}
        </span>
        <span class="text-gray-400 text-sm">Job ID: {{ result.job_id }}</span>
      </div>

      <div class="bg-cyber-darker border border-gray-700 rounded-lg p-4 overflow-x-auto mb-4">
        <pre class="text-gray-300 text-sm font-mono">{{ JSON.stringify(result.data, null, 2) }}</pre>
      </div>

      <div class="flex gap-2">
        <button @click="viewJob(result.job_id)" class="btn-secondary">
          📋 View Full Job Details
        </button>
        <button @click="result = null" class="btn-secondary">
          ✖️ Clear Results
        </button>
      </div>
    </div>

    <!-- Error Display -->
    <div
      v-if="error"
      class="card p-6 bg-gradient-to-r from-red-900/20 to-orange-900/20 border-red-700/50"
    >
      <div class="flex items-start gap-3">
        <div class="text-2xl">❌</div>
        <div class="flex-1">
          <h3 class="text-red-300 font-semibold text-lg mb-2">Error</h3>
          <p class="text-gray-300">{{ error }}</p>
        </div>
        <button @click="error = null" class="text-gray-400 hover:text-white">✖️</button>
      </div>
    </div>
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import api from '../services/api'
import axios from 'axios'

// No timeout for phase testing (nmap scans can take hours or even days)
const phaseTestApi = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000',
  timeout: 0, // No timeout
  headers: {
    'Content-Type': 'application/json',
  },
})

export default {
  name: 'PhaseTesting',
  setup() {
    const router = useRouter()
    const selectedPhase = ref(1)
    const loading = ref(false)
    const result = ref(null)
    const error = ref(null)
    const availableJobs = ref([])

    const phases = [
      { id: 1, name: 'Info Gathering', icon: '🔍' },
      { id: 2, name: 'Web Enumeration', icon: '🌐' },
      { id: 3, name: 'Vuln Analysis', icon: '🛡️' },
      { id: 4, name: 'SQLi Testing', icon: '💉' },
      { id: 5, name: 'Auth Testing', icon: '🔐' },
      { id: 6, name: 'Web Analysis', icon: '🧠' },
      { id: 7, name: 'Report Generation', icon: '📄' },
      { id: 8, name: 'Retry Phase', icon: '🔄' },
    ]

    const phase1Input = ref({ target: '' })
    const phase2Input = ref({ job_id: '', custom_wordlist: '' })
    const phase3Input = ref({ job_id: '' })
    const phase4Input = ref({ job_id: '' })
    const phase5Input = ref({ job_id: '' })
    const phase6Input = ref({ job_id: '', max_pages: 50 })
    const reportGenInput = ref({ job_id: '' })
    const retryPhaseInput = ref({ job_id: '', phase_name: '', custom_wordlist: '', max_pages: 50 })
    const availablePhases = ref([])
    const selectedJobPhases = ref([])

    const fetchAvailableJobs = async () => {
      try {
        const response = await phaseTestApi.get('/test-jobs')
        availableJobs.value = response.data.jobs
      } catch (err) {
        console.error('Failed to fetch jobs:', err)
      }
    }

    const runPhase1 = async () => {
      if (!phase1Input.value.target) {
        error.value = 'Please enter a target'
        return
      }

      loading.value = true
      error.value = null
      result.value = null

      try {
        const response = await phaseTestApi.post('/test-phase/info-gathering', phase1Input.value)
        result.value = response.data
        await fetchAvailableJobs()
      } catch (err) {
        error.value = err.response?.data?.detail || 'Failed to run Phase 1'
      } finally {
        loading.value = false
      }
    }

    const runPhase2 = async () => {
      loading.value = true
      error.value = null
      result.value = null

      try {
        const response = await phaseTestApi.post('/test-phase/web-enumeration', phase2Input.value)
        result.value = response.data
      } catch (err) {
        error.value = err.response?.data?.detail || 'Failed to run Phase 2'
      } finally {
        loading.value = false
      }
    }

    const runPhase3 = async () => {
      loading.value = true
      error.value = null
      result.value = null

      try {
        const response = await phaseTestApi.post('/test-phase/vulnerability-analysis', phase3Input.value)
        result.value = response.data
      } catch (err) {
        error.value = err.response?.data?.detail || 'Failed to run Phase 3'
      } finally {
        loading.value = false
      }
    }

    const runPhase4 = async () => {
      loading.value = true
      error.value = null
      result.value = null

      try {
        const response = await phaseTestApi.post('/test-phase/sqli-testing', phase4Input.value)
        result.value = response.data
      } catch (err) {
        error.value = err.response?.data?.detail || 'Failed to run Phase 4'
      } finally {
        loading.value = false
      }
    }

    const runPhase5 = async () => {
      loading.value = true
      error.value = null
      result.value = null

      try {
        const response = await phaseTestApi.post('/test-phase/authentication-testing', phase5Input.value)
        result.value = response.data
      } catch (err) {
        error.value = err.response?.data?.detail || 'Failed to run Phase 5'
      } finally {
        loading.value = false
      }
    }

    const runPhase6 = async () => {
      loading.value = true
      error.value = null
      result.value = null

      try {
        const response = await phaseTestApi.post('/test-phase/web-analysis', phase6Input.value)
        result.value = response.data
      } catch (err) {
        error.value = err.response?.data?.detail || 'Failed to run Phase 2.5 (Web Analysis)'
      } finally {
        loading.value = false
      }
    }

    const fetchJobPhases = async (jobId) => {
      if (!jobId) {
        selectedJobPhases.value = []
        return
      }

      try {
        const response = await phaseTestApi.get(`/job/${jobId}/phases`)
        selectedJobPhases.value = response.data.phases.filter(p => p.has_data)
      } catch (err) {
        console.error('Failed to fetch job phases:', err)
        selectedJobPhases.value = []
      }
    }

    const runReportGeneration = async () => {
      loading.value = true
      error.value = null
      result.value = null

      try {
        const response = await phaseTestApi.post('/test-phase/report-generation', reportGenInput.value)
        result.value = response.data

        // Show success message with phases used
        if (response.data.phases_used) {
          console.log('Report generated using phases:', response.data.phases_used)
        }
      } catch (err) {
        error.value = err.response?.data?.detail || 'Failed to generate report'
      } finally {
        loading.value = false
      }
    }

    const runRetryPhase = async () => {
      loading.value = true
      error.value = null
      result.value = null

      try {
        const payload = {
          job_id: retryPhaseInput.value.job_id,
          phase_name: retryPhaseInput.value.phase_name
        }

        // Add optional fields based on phase
        if (retryPhaseInput.value.phase_name === 'Web Enumeration' && retryPhaseInput.value.custom_wordlist) {
          payload.custom_wordlist = retryPhaseInput.value.custom_wordlist
        }

        if (retryPhaseInput.value.phase_name === 'Web Analysis') {
          payload.max_pages = retryPhaseInput.value.max_pages
        }

        const response = await phaseTestApi.post('/retry-phase', payload)
        result.value = response.data

        // Refresh job phases after retry
        await fetchJobPhases(retryPhaseInput.value.job_id)
      } catch (err) {
        error.value = err.response?.data?.detail || 'Failed to retry phase'
      } finally {
        loading.value = false
      }
    }

    const viewJob = (jobId) => {
      router.push(`/job/${jobId}`)
    }

    onMounted(() => {
      fetchAvailableJobs()
    })

    return {
      selectedPhase,
      loading,
      result,
      error,
      availableJobs,
      phases,
      phase1Input,
      phase2Input,
      phase3Input,
      phase4Input,
      phase5Input,
      phase6Input,
      reportGenInput,
      retryPhaseInput,
      selectedJobPhases,
      runPhase1,
      runPhase2,
      runPhase3,
      runPhase4,
      runPhase5,
      runPhase6,
      fetchJobPhases,
      runReportGeneration,
      runRetryPhase,
      viewJob,
    }
  },
}
</script>
