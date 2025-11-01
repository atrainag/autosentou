<template>
  <div class="space-y-6">
    <!-- Loading State -->
    <LoadingSpinner v-if="jobsStore.loading && !jobsStore.currentJob" text="Loading job details..." />

    <template v-else-if="jobsStore.currentJob">
      <!-- Header -->
      <div class="flex items-start justify-between">
        <div>
          <div class="flex items-center space-x-3 mb-2">
            <button
              @click="$router.back()"
              class="text-gray-400 hover:text-white"
            >
              ← Back
            </button>
            <StatusBadge :status="job.status" />
          </div>
          <h1 class="text-3xl font-bold text-white">{{ job.target }}</h1>
          <p class="text-gray-400 mt-1">{{ job.description || 'No description' }}</p>
          <div class="flex items-center space-x-4 mt-2 text-sm text-gray-500">
            <span>Created: {{ formatDate(job.created_at) }}</span>
            <span v-if="job.updated_at">Updated: {{ formatRelativeTime(job.updated_at) }}</span>
          </div>
        </div>
        <div class="flex space-x-3">
          <button
            v-if="job.status === 'running'"
            @click="refreshJob"
            class="btn-secondary"
          >
            🔄 Refresh
          </button>
          <router-link
            v-if="job.report_generated"
            :to="`/report/${job.id}`"
            class="btn-primary"
          >
            📄 View Report
          </router-link>
        </div>
      </div>

      <!-- Error Message -->
      <div v-if="job.error_message" class="card p-4 border-l-4 border-red-500">
        <div class="flex items-start space-x-3">
          <span class="text-2xl">⚠️</span>
          <div>
            <h3 class="text-white font-medium">Scan Failed</h3>
            <p class="text-sm text-gray-300 mt-1">{{ job.error_message }}</p>
          </div>
        </div>
      </div>

      <!-- Phase Progress -->
      <PhaseProgress :phases="phasesList" />

      <!-- Phase Results Tabs -->
      <div class="card">
        <div class="border-b border-gray-800">
          <nav class="flex space-x-8 px-6" aria-label="Tabs">
            <button
              v-for="tab in tabs"
              :key="tab.id"
              @click="activeTab = tab.id"
              :class="[
                'py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap',
                activeTab === tab.id
                  ? 'border-cyber-cyan text-cyber-cyan'
                  : 'border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-300'
              ]"
            >
              {{ tab.icon }} {{ tab.name }}
            </button>
          </nav>
        </div>

        <div class="p-6">
          <!-- Info Gathering Tab -->
          <div v-if="activeTab === 'info_gathering'" class="space-y-4">
            <h3 class="text-xl font-semibold text-white mb-4">Information Gathering Results</h3>
            <template v-if="infoGatheringData">
              <!-- Target Info -->
              <div class="p-4 bg-cyber-dark rounded-lg mb-4">
                <h4 class="text-lg font-medium text-white mb-2">Target Information</h4>
                <div class="text-sm text-gray-300 space-y-1">
                  <div><span class="text-gray-400">Target:</span> {{ infoGatheringData.target }}</div>
                  <div><span class="text-gray-400">Type:</span> {{ infoGatheringData.is_local_target ? 'Local/Private' : 'Public/External' }}</div>
                  <div v-if="infoGatheringData.nmap"><span class="text-gray-400">Open Ports:</span> {{ infoGatheringData.nmap.open_ports_count || 0 }}</div>
                </div>
              </div>

              <!-- Open Ports -->
              <div v-if="infoGatheringData.nmap?.parsed_ports">
                <h4 class="text-lg font-medium text-white mb-3">Open Ports</h4>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div
                    v-for="port in infoGatheringData.nmap.parsed_ports"
                    :key="port.port"
                    class="p-4 bg-cyber-dark rounded-lg"
                  >
                    <div class="flex items-center justify-between">
                      <span class="text-cyber-cyan font-mono">{{ port.port }}/{{ port.proto || 'tcp' }}</span>
                      <span class="badge bg-blue-600">{{ port.state }}</span>
                    </div>
                    <div class="mt-2 text-sm text-gray-300">
                      <div>{{ port.service || 'Unknown' }}</div>
                      <div v-if="port.version" class="text-gray-500">{{ port.version }}</div>
                    </div>
                  </div>
                </div>
              </div>
            </template>
            <EmptyState
              v-else
              icon="🔍"
              title="No data available"
              description="Information gathering phase not yet completed"
            />
          </div>

          <!-- Web Enumeration Tab -->
          <div v-if="activeTab === 'web_enumeration'" class="space-y-4">
            <h3 class="text-xl font-semibold text-white mb-4">Web Enumeration Results</h3>
            <template v-if="webEnumerationData">
              <!-- Summary Stats -->
              <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div class="p-4 bg-cyber-dark rounded-lg">
                  <div class="text-gray-400 text-sm">Total Paths</div>
                  <div class="text-2xl font-bold text-white">{{ webEnumerationData.directory_enumeration?.total_paths || 0 }}</div>
                </div>
                <div class="p-4 bg-cyber-dark rounded-lg">
                  <div class="text-gray-400 text-sm">Web Services</div>
                  <div class="text-2xl font-bold text-white">{{ webEnumerationData.web_services?.length || 0 }}</div>
                </div>
                <div class="p-4 bg-cyber-dark rounded-lg">
                  <div class="text-gray-400 text-sm">Risk Level</div>
                  <div class="text-2xl font-bold text-red-500">{{ webEnumerationData.path_analysis?.analysis?.risk_summary?.high || 0 }} High</div>
                </div>
              </div>

              <!-- Discovered Paths with Risk Analysis -->
              <div v-if="webEnumerationData.path_analysis?.analysis?.findings">
                <h4 class="text-lg font-medium text-white mb-3">Discovered Paths (Top 50)</h4>
                <div class="space-y-2">
                  <div
                    v-for="(finding, index) in webEnumerationData.path_analysis.analysis.findings.slice(0, 50)"
                    :key="index"
                    class="p-3 bg-cyber-dark rounded-lg"
                  >
                    <div class="flex items-start justify-between">
                      <div class="flex-1 min-w-0">
                        <div class="text-gray-300 font-mono text-sm truncate">{{ finding.clean_path }}</div>
                        <div v-if="finding.description" class="text-xs text-gray-500 mt-1">{{ finding.description }}</div>
                      </div>
                      <div class="flex items-center space-x-2 ml-4">
                        <span
                          v-if="finding.risk"
                          :class="[
                            'badge text-xs',
                            finding.risk === 'critical' ? 'bg-red-600' :
                            finding.risk === 'high' ? 'bg-orange-600' :
                            finding.risk === 'medium' ? 'bg-yellow-600' :
                            'bg-blue-600'
                          ]"
                        >
                          {{ finding.risk }}
                        </span>
                        <span v-if="finding.category" class="badge bg-gray-700 text-xs">{{ finding.category }}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </template>
            <EmptyState
              v-else
              icon="🌐"
              title="No data available"
              description="Web enumeration phase not yet completed"
            />
          </div>

          <!-- Vulnerabilities Tab -->
          <div v-if="activeTab === 'vulnerabilities'" class="space-y-4">
            <h3 class="text-xl font-semibold text-white mb-4">Vulnerability Analysis</h3>
            <template v-if="vulnerabilities && vulnerabilities.length > 0">
              <div class="mb-4 flex items-center space-x-4">
                <span class="text-gray-400">Filter by severity:</span>
                <button
                  v-for="severity in ['all', 'critical', 'high', 'medium', 'low']"
                  :key="severity"
                  @click="selectedSeverity = severity"
                  :class="[
                    'badge',
                    selectedSeverity === severity ? getSeverityColor(severity) : 'bg-gray-700'
                  ]"
                >
                  {{ severity.toUpperCase() }}
                </button>
              </div>
              <div v-for="vuln in filteredVulnerabilities" :key="vuln.cve_id || vuln.name">
                <VulnerabilityCard :vulnerability="vuln" />
              </div>
            </template>
            <EmptyState
              v-else
              icon="⚠️"
              title="No vulnerabilities found"
              description="Vulnerability analysis phase not yet completed or no vulnerabilities detected"
            />
          </div>

          <!-- SQL Injection Tab -->
          <div v-if="activeTab === 'sqli'" class="space-y-4">
            <h3 class="text-xl font-semibold text-white mb-4">SQL Injection Testing</h3>
            <template v-if="sqliData">
              <div v-if="sqliData.vulnerable_endpoints && sqliData.vulnerable_endpoints.length > 0">
                <div
                  v-for="(endpoint, index) in sqliData.vulnerable_endpoints"
                  :key="index"
                  class="card p-4 mb-3"
                >
                  <h4 class="text-white font-medium mb-2">{{ endpoint.url }}</h4>
                  <p class="text-sm text-gray-400 mb-2">{{ endpoint.injection_type }}</p>
                  <div class="text-xs text-gray-500">
                    <div>Parameter: {{ endpoint.parameter }}</div>
                    <div v-if="endpoint.database">Database: {{ endpoint.database }}</div>
                  </div>
                </div>
              </div>
              <div v-else class="text-gray-400">No SQL injection vulnerabilities found</div>
            </template>
            <EmptyState
              v-else
              icon="💉"
              title="No data available"
              description="SQL injection testing phase not yet completed"
            />
          </div>

          <!-- Authentication Testing Tab -->
          <div v-if="activeTab === 'auth'" class="space-y-4">
            <h3 class="text-xl font-semibold text-white mb-4">Authentication Testing</h3>
            <template v-if="authData">
              <div class="space-y-3">
                <div v-if="authData.username_enumeration" class="card p-4">
                  <h4 class="text-white font-medium mb-2">Username Enumeration</h4>
                  <p class="text-sm text-gray-300">{{ authData.username_enumeration.vulnerable ? 'Vulnerable' : 'Not Vulnerable' }}</p>
                </div>
                <div v-if="authData.security_controls" class="card p-4">
                  <h4 class="text-white font-medium mb-2">Security Controls</h4>
                  <div class="space-y-1 text-sm text-gray-300">
                    <div>Rate Limiting: {{ authData.security_controls.rate_limiting ? 'Yes' : 'No' }}</div>
                    <div>CAPTCHA: {{ authData.security_controls.captcha ? 'Yes' : 'No' }}</div>
                    <div>MFA: {{ authData.security_controls.mfa ? 'Yes' : 'No' }}</div>
                  </div>
                </div>
              </div>
            </template>
            <EmptyState
              v-else
              icon="🔐"
              title="No data available"
              description="Authentication testing phase not yet completed"
            />
          </div>
        </div>
      </div>
    </template>

    <!-- Job Not Found -->
    <EmptyState
      v-else
      icon="❌"
      title="Job not found"
      description="The requested job could not be found"
    >
      <template #action>
        <router-link to="/" class="btn-primary">
          Go to Dashboard
        </router-link>
      </template>
    </EmptyState>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { useJobsStore } from '../stores/jobs'
import StatusBadge from '../components/common/StatusBadge.vue'
import LoadingSpinner from '../components/common/LoadingSpinner.vue'
import EmptyState from '../components/common/EmptyState.vue'
import PhaseProgress from '../components/job-detail/PhaseProgress.vue'
import VulnerabilityCard from '../components/job-detail/VulnerabilityCard.vue'
import { formatDate, formatRelativeTime, getSeverityColor } from '../utils/formatters'

const route = useRoute()
const jobsStore = useJobsStore()

const activeTab = ref('info_gathering')
const selectedSeverity = ref('all')

const job = computed(() => jobsStore.currentJob)

const tabs = [
  { id: 'info_gathering', name: 'Info Gathering', icon: '🔍' },
  { id: 'web_enumeration', name: 'Web Enum', icon: '🌐' },
  { id: 'vulnerabilities', name: 'Vulnerabilities', icon: '⚠️' },
  { id: 'sqli', name: 'SQL Injection', icon: '💉' },
  { id: 'auth', name: 'Authentication', icon: '🔐' },
]

// Phase data extractors
const phasesList = computed(() => {
  if (!job.value?.phases) return []
  return job.value.phases
})

const getPhaseData = (phaseName) => {
  const phase = job.value?.phases?.find(p => p.phase_name === phaseName)
  return phase?.data || null
}

const infoGatheringData = computed(() => getPhaseData('Information Gathering'))
const webEnumerationData = computed(() => getPhaseData('Web Enumeration'))
const vulnAnalysisData = computed(() => getPhaseData('Vulnerability Analysis'))
const sqliData = computed(() => getPhaseData('SQL Injection Testing'))
const authData = computed(() => getPhaseData('Authentication Testing'))

const vulnerabilities = computed(() => {
  const allVulns = []

  // Get CVE vulnerabilities from vulnerability analysis phase
  if (vulnAnalysisData.value) {
    const vulnResults = vulnAnalysisData.value.vulnerability_results || []
    vulnResults.forEach(service => {
      const vulns = service.vulnerabilities || []
      vulns.forEach(vuln => {
        allVulns.push({
          cve_id: vuln.cve_id,
          name: vuln.cve_id || 'CVE',
          severity: vuln.severity || 'Unknown',
          description: vuln.description,
          remediation: vuln.remediation,
          service: service.service,
          port: service.port,
          type: 'cve'
        })
      })
    })
  }

  // Get SQL Injection vulnerabilities
  if (sqliData.value) {
    const sqliResults = sqliData.value.sqli_results || []
    sqliResults.forEach(result => {
      if (result.vulnerable) {
        allVulns.push({
          name: 'SQL Injection',
          severity: result.severity || 'High',
          description: `SQL Injection vulnerability found at ${result.url}`,
          url: result.url,
          parameter: result.parameter,
          injection_type: result.injection_type,
          type: 'sqli'
        })
      }
    })
  }

  // Get Authentication vulnerabilities
  if (authData.value) {
    const loginTests = authData.value.login_response_tests || []
    loginTests.forEach(test => {
      if (test.ai_analysis?.account_enumeration_possible) {
        allVulns.push({
          name: 'Account Enumeration',
          severity: test.ai_analysis?.classification?.severity || 'Medium',
          description: `Account enumeration possible at ${test.url}`,
          url: test.url,
          type: 'authentication'
        })
      }
    })
  }

  // Get Web Exposure vulnerabilities
  if (webEnumerationData.value) {
    const findings = webEnumerationData.value.path_analysis?.analysis?.findings || []
    findings.forEach(finding => {
      if (finding.risk && ['critical', 'high'].includes(finding.risk.toLowerCase())) {
        allVulns.push({
          name: finding.category || 'Web Exposure',
          severity: finding.risk,
          description: finding.description || `${finding.category} found at ${finding.clean_path || finding.path}`,
          url: finding.clean_path || finding.path,
          category: finding.category,
          type: 'web_exposure'
        })
      }
    })
  }

  return allVulns
})

const filteredVulnerabilities = computed(() => {
  if (selectedSeverity.value === 'all') return vulnerabilities.value
  return vulnerabilities.value.filter(v =>
    v.severity.toLowerCase() === selectedSeverity.value
  )
})

const refreshJob = async () => {
  await jobsStore.fetchJob(route.params.id)
}

onMounted(async () => {
  const jobId = route.params.id
  await jobsStore.fetchJob(jobId)

  // Start polling if job is running
  if (job.value && (job.value.status === 'running' || job.value.status === 'pending')) {
    jobsStore.startPolling(jobId, 3000)
  }
})

onUnmounted(() => {
  jobsStore.stopPolling()
})
</script>
