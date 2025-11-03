<template>
  <div class="space-y-6">
    <!-- Loading State -->
    <LoadingSpinner v-if="loading" text="Loading report..." />

    <template v-else-if="job">
      <!-- Header -->
      <div class="flex items-start justify-between">
        <div>
          <button
            @click="$router.back()"
            class="text-gray-400 hover:text-white mb-3"
          >
            ← Back
          </button>
          <h1 class="text-3xl font-bold text-white">📄 Penetration Test Report</h1>
          <p class="text-gray-400 mt-1">{{ job.target }}</p>
          <div class="text-sm text-gray-500 mt-2">
            Generated: {{ formatDate(job.report?.generated_at || job.updated_at) }}
          </div>
        </div>
        <div class="flex space-x-3">
          <router-link
            :to="`/findings/${job.id}`"
            class="btn-primary"
          >
            📊 Interactive Findings
          </router-link>
          <button
            @click="downloadReport('pdf')"
            class="btn-secondary"
          >
            📥 Download PDF
          </button>
          <button
            @click="downloadReport('docx')"
            class="btn-secondary"
          >
            📥 Download DOCX
          </button>
        </div>
      </div>

      <!-- Report Content -->
      <div v-if="job.report_generated" class="card p-8">
        <div class="prose prose-invert max-w-none">
          <div class="mb-8 pb-6 border-b border-gray-700">
            <h1 class="text-4xl font-bold text-white mb-2">Penetration Testing Report</h1>
            <div class="text-gray-400">
              <p><strong>Target:</strong> {{ job.target }}</p>
              <p><strong>Date:</strong> {{ formatDate(job.created_at) }}</p>
              <p v-if="job.description"><strong>Description:</strong> {{ job.description }}</p>
            </div>
          </div>

          <!-- Executive Summary -->
          <section class="mb-8">
            <h2 class="text-2xl font-bold text-white mb-4">Executive Summary</h2>
            <p class="text-gray-300">
              This penetration test was conducted on {{ job.target }} using the Autosentou automated
              penetration testing platform. The assessment included information gathering, web enumeration,
              vulnerability analysis, SQL injection testing, and authentication testing.
            </p>
            <div v-if="vulnerabilityStats" class="mt-4 grid grid-cols-4 gap-4">
              <div class="p-4 bg-cyber-dark rounded">
                <div class="text-severity-critical font-bold text-2xl">{{ vulnerabilityStats.critical }}</div>
                <div class="text-gray-400 text-sm">Critical</div>
              </div>
              <div class="p-4 bg-cyber-dark rounded">
                <div class="text-severity-high font-bold text-2xl">{{ vulnerabilityStats.high }}</div>
                <div class="text-gray-400 text-sm">High</div>
              </div>
              <div class="p-4 bg-cyber-dark rounded">
                <div class="text-severity-medium font-bold text-2xl">{{ vulnerabilityStats.medium }}</div>
                <div class="text-gray-400 text-sm">Medium</div>
              </div>
              <div class="p-4 bg-cyber-dark rounded">
                <div class="text-severity-low font-bold text-2xl">{{ vulnerabilityStats.low }}</div>
                <div class="text-gray-400 text-sm">Low</div>
              </div>
            </div>
          </section>

          <!-- Vulnerabilities -->
          <section v-if="vulnerabilities.length > 0" class="mb-8">
            <h2 class="text-2xl font-bold text-white mb-4">Identified Vulnerabilities</h2>
            <div class="space-y-4">
              <div
                v-for="(vuln, index) in vulnerabilities"
                :key="index"
                class="p-4 bg-cyber-dark rounded-lg"
              >
                <div class="flex items-start justify-between mb-2">
                  <h3 class="text-lg font-semibold text-white">{{ vuln.name || vuln.cve_id }}</h3>
                  <SeverityBadge :severity="vuln.severity" />
                </div>
                <p class="text-gray-300 text-sm mb-2">{{ vuln.description }}</p>
                <div v-if="vuln.remediation" class="text-sm">
                  <strong class="text-gray-400">Remediation:</strong>
                  <p class="text-gray-300">{{ vuln.remediation }}</p>
                </div>
              </div>
            </div>
          </section>

          <!-- Recommendations -->
          <section class="mb-8">
            <h2 class="text-2xl font-bold text-white mb-4">Recommendations</h2>
            <ul class="list-disc list-inside space-y-2 text-gray-300">
              <li>Address all critical and high severity vulnerabilities immediately</li>
              <li>Implement security patches and updates for identified services</li>
              <li>Conduct regular security assessments and penetration tests</li>
              <li>Implement proper input validation and output encoding</li>
              <li>Use security headers and enforce HTTPS</li>
              <li>Implement rate limiting and account lockout mechanisms</li>
            </ul>
          </section>
        </div>
      </div>

      <!-- No Report Generated -->
      <EmptyState
        v-else
        icon="📄"
        title="Report not generated"
        description="The scan is still in progress or failed to generate a report"
      >
        <template #action>
          <router-link :to="`/job/${job.id}`" class="btn-primary">
            View Job Details
          </router-link>
        </template>
      </EmptyState>
    </template>

    <!-- Job Not Found -->
    <EmptyState
      v-else
      icon="❌"
      title="Report not found"
      description="The requested report could not be found"
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
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useJobsStore } from '../stores/jobs'
import { useAppStore } from '../stores/app'
import LoadingSpinner from '../components/common/LoadingSpinner.vue'
import EmptyState from '../components/common/EmptyState.vue'
import SeverityBadge from '../components/common/SeverityBadge.vue'
import { formatDate } from '../utils/formatters'

const route = useRoute()
const jobsStore = useJobsStore()
const appStore = useAppStore()

const loading = ref(true)

const job = computed(() => jobsStore.currentJob)

const vulnerabilities = computed(() => {
  // Get vulnerabilities from all phases (CVE, SQLi, Auth, Web Exposure)
  const vulnPhase = job.value?.phases?.find(p => p.phase_name === 'vulnerability_analysis')
  const sqliPhase = job.value?.phases?.find(p => p.phase_name === 'SQL Injection Testing')
  const authPhase = job.value?.phases?.find(p => p.phase_name === 'Authentication Testing')
  const webPhase = job.value?.phases?.find(p => p.phase_name === 'Web Enumeration')

  const allVulns = []

  // CVE vulnerabilities
  const vulnResults = vulnPhase?.data?.vulnerability_results || []
  vulnResults.forEach(service => {
    service.vulnerabilities?.forEach(vuln => {
      allVulns.push({
        name: vuln.cve_id || vuln.name,
        cve_id: vuln.cve_id,
        severity: vuln.severity,
        description: vuln.description,
        remediation: vuln.remediation,
        type: 'cve'
      })
    })
  })

  // SQL Injection vulnerabilities
  const sqliResults = sqliPhase?.data?.sqli_results || []
  sqliResults.forEach(result => {
    if (result.vulnerable) {
      allVulns.push({
        name: 'SQL Injection',
        severity: result.severity || 'High',
        description: `SQL Injection vulnerability found at ${result.url}`,
        remediation: 'Use parameterized queries and input validation',
        type: 'sqli'
      })
    }
  })

  // Authentication vulnerabilities
  const authResults = authPhase?.data?.login_response_tests || []
  authResults.forEach(result => {
    if (result.ai_analysis?.account_enumeration_possible) {
      allVulns.push({
        name: 'Account Enumeration',
        severity: result.ai_analysis?.classification?.severity || 'Medium',
        description: `Account enumeration possible at ${result.url}`,
        remediation: 'Implement consistent error messages for login failures',
        type: 'authentication'
      })
    }
  })

  // Web Exposure vulnerabilities
  const webFindings = webPhase?.data?.path_analysis?.analysis?.findings || []
  webFindings.forEach(finding => {
    if (finding.risk && ['critical', 'high'].includes(finding.risk.toLowerCase())) {
      allVulns.push({
        name: finding.category || 'Web Exposure',
        severity: finding.risk,
        description: finding.description || `${finding.category} found at ${finding.clean_path || finding.path}`,
        remediation: 'Review and secure exposed resources',
        type: 'web_exposure'
      })
    }
  })

  return allVulns
})

const vulnerabilityStats = computed(() => {
  // Use the vulnerability_statistics from the API if available
  if (job.value?.vulnerability_statistics) {
    return {
      critical: job.value.vulnerability_statistics.critical || 0,
      high: job.value.vulnerability_statistics.high || 0,
      medium: job.value.vulnerability_statistics.medium || 0,
      low: job.value.vulnerability_statistics.low || 0,
    }
  }

  // Fallback to calculating from vulnerabilities array
  const stats = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  }

  vulnerabilities.value.forEach(vuln => {
    const severity = vuln.severity?.toLowerCase()
    if (stats[severity] !== undefined) {
      stats[severity]++
    }
  })

  return stats
})

const downloadReport = async (format) => {
  try {
    const reportPath = job.value.report?.report_path
    if (!reportPath) {
      appStore.showError('Report path not available')
      return
    }

    // Replace file extension based on requested format
    // reportPath is like "job_id/pentest_report_detailed.pdf"
    // We need to change it to "job_id/pentest_report_detailed.docx" for DOCX
    const pathWithoutExt = reportPath.replace(/\.(pdf|docx|md)$/i, '')
    const newPath = `${pathWithoutExt}.${format}`

    // Trigger download
    const url = `${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/report/${newPath}`
    window.open(url, '_blank')

    appStore.showSuccess(`Downloading report as ${format.toUpperCase()}`)
  } catch (error) {
    appStore.showError(`Failed to download report: ${error.message}`)
  }
}

onMounted(async () => {
  try {
    await jobsStore.fetchJob(route.params.id)
  } catch (error) {
    console.error('Failed to load job:', error)
  } finally {
    loading.value = false
  }
})
</script>
