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
          <h1 class="text-3xl font-bold text-white">{{ job.original_target || job.target }}</h1>
          <p v-if="job.original_target && job.target !== job.original_target" class="text-gray-300 mt-1 text-sm">
            <span class="text-gray-500">Scanning IP:</span> <span class="text-cyber-cyan">{{ job.target }}</span>
          </p>
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
            class="btn-secondary flex items-center space-x-2"
          >
            <ArrowPathIcon class="w-5 h-5" />
            <span>Refresh</span>
          </button>
          <button
            v-if="job.status === 'running'"
            @click="cancelScan"
            class="btn-warning flex items-center space-x-2"
            :disabled="cancelling"
          >
            <StopCircleIcon v-if="!cancelling" class="w-5 h-5" />
            <ArrowPathIcon v-else class="w-5 h-5 animate-spin" />
            <span>{{ cancelling ? 'Cancelling...' : 'Cancel Scan' }}</span>
          </button>
          <button
            v-if="job.status === 'suspended'"
            @click="resumeScan"
            class="btn-primary flex items-center space-x-2"
            :disabled="resuming"
          >
            <PlayCircleIcon v-if="!resuming" class="w-5 h-5" />
            <ArrowPathIcon v-else class="w-5 h-5 animate-spin" />
            <span>{{ resuming ? 'Resuming...' : 'Resume Scan' }}</span>
          </button>
          <router-link
            v-if="job.report_generated"
            :to="`/findings/${job.id}`"
            class="btn-primary flex items-center space-x-2"
          >
            <ChartBarIcon class="w-5 h-5" />
            <span>Interactive Findings</span>
          </router-link>
          <router-link
            v-if="job.report_generated"
            :to="`/report/${job.id}`"
            class="btn-secondary flex items-center space-x-2"
          >
            <DocumentTextIcon class="w-5 h-5" />
            <span>Summary PDF</span>
          </router-link>
          <button @click="openConfirmDialog" class="btn-danger flex items-center">
            <TrashIcon class="h-5 w-5 mr-2" />
            Delete
          </button>
        </div>
      </div>

      <!-- Error Message -->
      <div v-if="job.error_message" class="card p-4 border-l-4 border-red-500">
        <div class="flex items-start space-x-3">
          <ExclamationTriangleIcon class="w-8 h-8 text-red-400 flex-shrink-0" />
          <div>
            <h3 class="text-white font-medium">Scan Failed</h3>
            <p class="text-sm text-gray-300 mt-1">{{ job.error_message }}</p>
          </div>
        </div>
      </div>

      <!-- Suspended Status Message -->
      <div v-if="job.status === 'suspended'" class="card p-4 border-l-4 border-yellow-500">
        <div class="flex items-start space-x-3">
          <PauseCircleIcon class="w-8 h-8 text-yellow-400 flex-shrink-0" />
          <div class="flex-1">
            <h3 class="text-white font-medium">Scan Suspended</h3>
            <p class="text-sm text-gray-300 mt-1">
              {{ job.suspension_reason || 'AI rate limit exceeded' }}
            </p>
            <p v-if="job.resume_after" class="text-sm text-yellow-400 mt-2">
              Can resume after: {{ formatDate(job.resume_after) }}
            </p>
            <p v-if="job.last_completed_phase" class="text-sm text-gray-400 mt-1">
              Last completed phase: {{ job.last_completed_phase }}
            </p>
            <p class="text-sm text-gray-500 mt-2">
              Click "Resume Scan" to continue from where it left off.
            </p>
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
                'py-4 px-1 border-b-2 font-medium text-sm whitespace-nowrap flex items-center space-x-2',
                activeTab === tab.id
                  ? 'border-cyber-cyan text-cyber-cyan'
                  : 'border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-300'
              ]"
            >
              <component :is="tabIconMap[tab.icon]" class="w-5 h-5" />
              <span>{{ tab.name }}</span>
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

              <!-- OS Detection -->
              <div v-if="infoGatheringData.nmap?.os_detection" class="mb-4">
                <h4 class="text-lg font-medium text-white mb-3">Operating System Detection</h4>

                <!-- OS Matches -->
                <div v-if="infoGatheringData.nmap.os_detection.os_matches?.length > 0" class="p-4 bg-cyber-dark rounded-lg mb-3">
                  <h5 class="text-md font-medium text-cyber-cyan mb-2">Detected Operating Systems</h5>
                  <div class="space-y-2">
                    <div
                      v-for="(osMatch, index) in infoGatheringData.nmap.os_detection.os_matches.slice(0, 5)"
                      :key="index"
                      class="flex items-center justify-between p-2 bg-gray-800 rounded"
                    >
                      <span class="text-gray-300 text-sm">{{ osMatch.name }}</span>
                      <div class="flex items-center space-x-2">
                        <span
                          :class="[
                            'badge text-xs',
                            parseInt(osMatch.accuracy) >= 90 ? 'bg-green-600' :
                            parseInt(osMatch.accuracy) >= 70 ? 'bg-yellow-600' :
                            'bg-orange-600'
                          ]"
                        >
                          {{ osMatch.accuracy }}% accuracy
                        </span>
                        <span class="badge bg-gray-700 text-xs">{{ osMatch.type }}</span>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- OS Classes -->
                <div v-if="infoGatheringData.nmap.os_detection.os_classes?.length > 0" class="p-4 bg-cyber-dark rounded-lg mb-3">
                  <h5 class="text-md font-medium text-cyber-cyan mb-2">Operating System Classes</h5>
                  <div class="space-y-2">
                    <div
                      v-for="(osClass, index) in infoGatheringData.nmap.os_detection.os_classes"
                      :key="index"
                      class="text-sm text-gray-300"
                    >
                      <div class="flex items-center space-x-2">
                        <span class="text-white">{{ osClass.vendor }} {{ osClass.osfamily }}</span>
                        <span v-if="osClass.osgen" class="text-gray-500">{{ osClass.osgen }}</span>
                        <span class="badge bg-blue-600 text-xs">{{ osClass.accuracy }}%</span>
                      </div>
                    </div>
                  </div>
                </div>

                <!-- Fallback for simple OS info -->
                <div v-else-if="infoGatheringData.nmap.os_detection.running || infoGatheringData.nmap.os_detection.os_details" class="p-4 bg-cyber-dark rounded-lg">
                  <h5 class="text-md font-medium text-cyber-cyan mb-2">OS Information</h5>
                  <div class="text-sm text-gray-300 space-y-1">
                    <div v-if="infoGatheringData.nmap.os_detection.running">
                      <span class="text-gray-400">Running:</span> {{ infoGatheringData.nmap.os_detection.running }}
                    </div>
                    <div v-if="infoGatheringData.nmap.os_detection.os_details">
                      <span class="text-gray-400">Details:</span> {{ infoGatheringData.nmap.os_detection.os_details }}
                    </div>
                  </div>
                </div>

                <!-- No OS detection available -->
                <div v-else class="p-4 bg-cyber-dark rounded-lg text-sm text-gray-500">
                  OS detection not available (may require elevated privileges or target is blocking detection)
                </div>
              </div>

              <!-- Discovered Ports -->
              <div v-if="infoGatheringData.nmap?.parsed_ports && infoGatheringData.nmap.parsed_ports.length > 0">
                <h4 class="text-lg font-medium text-white mb-3">Discovered Ports</h4>
                <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div
                    v-for="port in infoGatheringData.nmap.parsed_ports"
                    :key="port.port"
                    class="p-4 bg-cyber-dark rounded-lg"
                  >
                    <div class="flex items-center justify-between">
                      <span class="text-cyber-cyan font-mono">{{ port.port }}/{{ port.proto || 'tcp' }}</span>
                      <span
                        :class="[
                          'badge text-xs',
                          port.state === 'open' ? 'bg-green-600' :
                          port.state === 'filtered' ? 'bg-yellow-600' :
                          'bg-gray-600'
                        ]"
                      >
                        {{ port.state }}
                      </span>
                    </div>
                    <div class="mt-2 text-sm text-gray-300">
                      <div>{{ port.service || 'Unknown' }}</div>
                      <div v-if="port.version" class="text-gray-500">{{ port.version }}</div>
                    </div>
                  </div>
                </div>
              </div>
              <div v-else-if="infoGatheringData.nmap" class="p-4 bg-cyber-dark rounded-lg text-sm text-gray-400">
                No ports discovered (host may be down or heavily firewalled)
              </div>
            </template>
            <EmptyState
              v-else
              title="No data available"
              description="Information gathering phase not yet completed"
            >
              <template #icon>
                <MagnifyingGlassIcon class="w-16 h-16 mx-auto text-gray-600" />
              </template>
            </EmptyState>
          </div>

          <!-- Web Enumeration Tab -->
          <div v-if="activeTab === 'web_enumeration'" class="space-y-4">
            <h3 class="text-xl font-semibold text-white mb-4">Path Discovery Results</h3>
            <div class="p-4 bg-blue-900/20 border border-blue-500/30 rounded-lg mb-4 flex items-start space-x-3">
              <InformationCircleIcon class="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
              <p class="text-sm text-blue-300">
                This phase discovers and prioritizes paths for testing. These are NOT confirmed vulnerabilities -
                see the "Web Vulnerabilities" tab for actual AI-tested findings.
              </p>
            </div>
            <template v-if="webEnumerationData">
              <!-- Summary Stats -->
              <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div class="p-4 bg-cyber-dark rounded-lg">
                  <div class="text-gray-400 text-sm">Total Paths Discovered</div>
                  <div class="text-2xl font-bold text-white">{{ webEnumerationData.directory_enumeration?.total_paths || 0 }}</div>
                </div>
                <div class="p-4 bg-cyber-dark rounded-lg">
                  <div class="text-gray-400 text-sm">Web Services</div>
                  <div class="text-2xl font-bold text-white">{{ webEnumerationData.web_services?.length || 0 }}</div>
                </div>
                <div class="p-4 bg-cyber-dark rounded-lg">
                  <div class="text-gray-400 text-sm">High Priority Paths</div>
                  <div class="text-2xl font-bold text-yellow-500">{{ webEnumerationData.path_analysis?.analysis?.risk_summary?.high || 0 }} High Risk</div>
                </div>
              </div>

              <!-- Discovered Paths with Risk Analysis -->
              <div v-if="webEnumerationData.path_analysis?.analysis?.findings">
                <h4 class="text-lg font-medium text-white mb-3">Prioritized Paths for Testing (Top 50)</h4>
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
                          {{ finding.risk }} priority
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
              title="No data available"
              description="Path discovery phase not yet completed"
            >
              <template #icon>
                <GlobeAltIcon class="w-16 h-16 mx-auto text-gray-600" />
              </template>
            </EmptyState>
          </div>

          <!-- Web Analysis Tab -->
          <div v-if="activeTab === 'web_analysis'" class="space-y-4">
            <h3 class="text-xl font-semibold text-white mb-4">Web Vulnerability Analysis</h3>
            <div class="p-4 bg-purple-900/20 border border-purple-500/30 rounded-lg mb-4">
              <p class="text-sm text-purple-300">
                🕷️ This phase uses AI + Playwright to actually test discovered paths for vulnerabilities.
                Each finding includes evidence, exploitation steps, and remediation guidance.
              </p>
            </div>
            <template v-if="webAnalysisData">
              <!-- Summary Stats -->
              <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div class="p-4 bg-cyber-dark rounded-lg">
                  <div class="text-gray-400 text-sm">Paths Analyzed</div>
                  <div class="text-2xl font-bold text-white">{{ webAnalysisData.analyzed_pages || 0 }}</div>
                </div>
                <div class="p-4 bg-cyber-dark rounded-lg">
                  <div class="text-gray-400 text-sm">Response Groups</div>
                  <div class="text-2xl font-bold text-white">{{ webAnalysisData.total_groups || 0 }}</div>
                </div>
                <div class="p-4 bg-cyber-dark rounded-lg">
                  <div class="text-gray-400 text-sm">Total Findings</div>
                  <div class="text-2xl font-bold text-red-500">{{ webAnalysisData.total_findings || 0 }}</div>
                </div>
                <div class="p-4 bg-cyber-dark rounded-lg">
                  <div class="text-gray-400 text-sm">High Priority</div>
                  <div class="text-2xl font-bold text-orange-500">{{ webAnalysisData.high_priority_paths || 0 }}</div>
                </div>
              </div>

              <!-- Web Vulnerabilities -->
              <div v-if="webAnalysisData.findings && webAnalysisData.findings.length > 0">
                <h4 class="text-lg font-medium text-white mb-3">Detected Vulnerabilities</h4>
                <div class="space-y-3">
                  <div
                    v-for="(finding, index) in webAnalysisData.findings"
                    :key="index"
                    class="p-4 bg-cyber-dark rounded-lg border-l-4"
                    :class="[
                      finding.severity === 'Critical' ? 'border-red-600' :
                      finding.severity === 'High' ? 'border-orange-600' :
                      finding.severity === 'Medium' ? 'border-yellow-600' :
                      'border-blue-600'
                    ]"
                  >
                    <!-- Header -->
                    <div class="flex items-start justify-between mb-3">
                      <div class="flex-1">
                        <h5 class="text-white font-medium text-lg">{{ finding.title }}</h5>
                        <div class="text-sm text-gray-400 font-mono mt-1">{{ finding.url }}</div>
                      </div>
                      <div class="flex items-center space-x-2 ml-4">
                        <span
                          :class="[
                            'badge',
                            finding.severity === 'Critical' ? 'bg-red-600' :
                            finding.severity === 'High' ? 'bg-orange-600' :
                            finding.severity === 'Medium' ? 'bg-yellow-600' :
                            'bg-blue-600'
                          ]"
                        >
                          {{ finding.severity }}
                        </span>
                        <span v-if="finding.owasp_category" class="badge bg-purple-600 text-xs">
                          {{ finding.owasp_category }}
                        </span>
                      </div>
                    </div>

                    <!-- Description -->
                    <div class="mb-3">
                      <p class="text-sm text-gray-300">{{ finding.description }}</p>
                    </div>

                    <!-- Evidence -->
                    <div v-if="finding.evidence" class="mb-3 p-3 bg-gray-800/50 rounded">
                      <div class="text-xs text-gray-400 mb-1">Evidence:</div>
                      <div class="text-sm text-gray-300 font-mono whitespace-pre-wrap">{{ finding.evidence }}</div>
                    </div>

                    <!-- Exploitation Steps -->
                    <div v-if="finding.exploitation_steps" class="mb-3">
                      <div class="text-xs text-gray-400 mb-1">Exploitation Steps:</div>
                      <ol class="list-decimal list-inside text-sm text-gray-300 space-y-1">
                        <li v-for="(step, idx) in finding.exploitation_steps.split('\n').filter(s => s.trim())" :key="idx">
                          {{ step.replace(/^\d+\.\s*/, '') }}
                        </li>
                      </ol>
                    </div>

                    <!-- Remediation -->
                    <div v-if="finding.remediation" class="p-3 bg-green-900/20 border border-green-500/30 rounded">
                      <div class="text-xs text-green-400 mb-1 flex items-center space-x-1">
                        <ShieldCheckIcon class="w-4 h-4" />
                        <span>Remediation:</span>
                      </div>
                      <div class="text-sm text-gray-300">{{ finding.remediation }}</div>
                    </div>

                    <!-- Additional Info -->
                    <div class="flex items-center space-x-4 mt-3 text-xs text-gray-500">
                      <span v-if="finding.cwe_id">{{ finding.cwe_id }}</span>
                      <span v-if="finding.category">{{ finding.category }}</span>
                    </div>
                  </div>
                </div>
              </div>
              <div v-else class="text-center py-8">
                <CheckCircleIcon class="w-20 h-20 mx-auto text-green-500" />
                <p class="text-gray-400 mt-4">No web vulnerabilities detected</p>
              </div>
            </template>
            <EmptyState
              v-else
              title="No data available"
              description="Web analysis phase not yet completed"
            >
              <template #icon>
                <BugAntIcon class="w-16 h-16 mx-auto text-gray-600" />
              </template>
            </EmptyState>
          </div>

          <!-- CVE Analysis Tab -->
          <div v-if="activeTab === 'vulnerabilities'" class="space-y-4">
            <h3 class="text-xl font-semibold text-white mb-4">CVE Vulnerability Analysis</h3>
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
              title="No vulnerabilities found"
              description="Vulnerability analysis phase not yet completed or no vulnerabilities detected"
            >
              <template #icon>
                <ShieldExclamationIcon class="w-16 h-16 mx-auto text-gray-600" />
              </template>
            </EmptyState>
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
              title="No data available"
              description="SQL injection testing phase not yet completed"
            >
              <template #icon>
                <BeakerIcon class="w-16 h-16 mx-auto text-gray-600" />
              </template>
            </EmptyState>
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
              title="No data available"
              description="Authentication testing phase not yet completed"
            >
              <template #icon>
                <LockClosedIcon class="w-16 h-16 mx-auto text-gray-600" />
              </template>
            </EmptyState>
          </div>
        </div>
      </div>
    </template>

    <!-- Job Not Found -->
    <EmptyState
      v-else
      title="Job not found"
      description="The requested job could not be found"
    >
      <template #icon>
        <XCircleIcon class="w-16 h-16 mx-auto text-red-500" />
      </template>
      <template #action>
        <router-link to="/" class="btn-primary">
          Go to Dashboard
        </router-link>
      </template>
    </EmptyState>

    <!-- Confirmation Dialog -->
    <ConfirmDialog
      v-if="job"
      :is-open="isConfirmOpen"
      title="Delete Scan Job"
      :message="`Are you sure you want to delete the scan for '${job.target}'? This action cannot be undone.`"
      confirm-text="Delete"
      cancel-text="Cancel"
      variant="danger"
      @confirm="handleDeleteJob"
      @close="closeConfirmDialog"
    />
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useJobsStore } from '../stores/jobs'
import { useAppStore } from '../stores/app'
import ConfirmDialog from '../components/common/ConfirmDialog.vue'
import {
  TrashIcon,
  ChartBarIcon,
  DocumentTextIcon,
  ExclamationTriangleIcon,
  PauseCircleIcon,
  MagnifyingGlassIcon,
  GlobeAltIcon,
  BugAntIcon,
  ShieldExclamationIcon,
  BeakerIcon,
  LockClosedIcon,
  InformationCircleIcon,
  CheckCircleIcon,
  XCircleIcon,
  ShieldCheckIcon,
  ArrowPathIcon,
  StopCircleIcon,
  PlayCircleIcon
} from '@heroicons/vue/24/outline'
import StatusBadge from '../components/common/StatusBadge.vue'
import LoadingSpinner from '../components/common/LoadingSpinner.vue'
import EmptyState from '../components/common/EmptyState.vue'
import PhaseProgress from '../components/job-detail/PhaseProgress.vue'
import VulnerabilityCard from '../components/job-detail/VulnerabilityCard.vue'
import { formatDate, formatRelativeTime, getSeverityColor } from '../utils/formatters'

const route = useRoute()
const router = useRouter()
const jobsStore = useJobsStore()
const appStore = useAppStore()

const activeTab = ref('info_gathering')
const selectedSeverity = ref('all')
const isConfirmOpen = ref(false)
const cancelling = ref(false)
const resuming = ref(false)

const job = computed(() => jobsStore.currentJob)

const tabs = [
  { id: 'info_gathering', name: 'Info Gathering', icon: 'magnifying-glass' },
  { id: 'web_enumeration', name: 'Path Discovery', icon: 'globe-alt' },
  { id: 'web_analysis', name: 'Web Vulnerabilities', icon: 'bug-ant' },
  { id: 'vulnerabilities', name: 'CVE Analysis', icon: 'shield-exclamation' },
  { id: 'sqli', name: 'SQL Injection', icon: 'beaker' },
  { id: 'auth', name: 'Authentication', icon: 'lock-closed' },
]

const tabIconMap = {
  'magnifying-glass': MagnifyingGlassIcon,
  'globe-alt': GlobeAltIcon,
  'bug-ant': BugAntIcon,
  'shield-exclamation': ShieldExclamationIcon,
  'beaker': BeakerIcon,
  'lock-closed': LockClosedIcon
}

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
const webAnalysisData = computed(() => getPhaseData('Web Analysis'))
const vulnAnalysisData = computed(() => getPhaseData('Vulnerability Analysis'))
const sqliData = computed(() => getPhaseData('SQL Injection Testing'))
const authData = computed(() => getPhaseData('Authentication Testing'))

const vulnerabilities = computed(() => {
  const allVulns = []

  // Get CVE and exploit-based vulnerabilities from vulnerability analysis phase
  if (vulnAnalysisData.value) {
    const vulnResults = vulnAnalysisData.value.vulnerability_results || []
    vulnResults.forEach(service => {
      const vulns = service.vulnerabilities || []
      vulns.forEach(vuln => {
        const vulnType = vuln.type || 'cve'

        // Handle exploit_available type vulnerabilities
        if (vulnType === 'exploit_available') {
          allVulns.push({
            name: `Public Exploits for ${service.service} ${service.version || ''}`.trim(),
            cve_id: vuln.cve_id || 'N/A',
            severity: vuln.severity || 'High',
            description: vuln.description,
            remediation: vuln.remediation,
            service: service.service,
            version: service.version,
            port: service.port,
            type: 'exploit_available',
            owasp_category: vuln.owasp_category || 'A06:2021 – Vulnerable and Outdated Components',
            exploit_count: vuln.exploit_count || 0,
            exploits: vuln.exploit_evidence || []
          })
        } else {
          // CVE-based vulnerability
          allVulns.push({
            cve_id: vuln.cve_id,
            name: vuln.cve_id || 'CVE',
            severity: vuln.severity || 'Unknown',
            description: vuln.description,
            remediation: vuln.remediation,
            service: service.service,
            version: service.version,
            port: service.port,
            type: 'cve',
            owasp_category: vuln.owasp_category
          })
        }
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

  // Note: Web exposure findings are NOT included here - they're shown in the "Web Vulnerabilities" tab
  // Path discovery is for prioritization only; actual web vulnerabilities come from Web Analysis phase

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

const cancelScan = async () => {
  if (!job.value || cancelling.value) return

  if (!confirm(`Are you sure you want to cancel this scan?\n\nThe scan will stop gracefully at the next phase boundary.`)) {
    return
  }

  cancelling.value = true

  try {
    const response = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/job/${job.value.id}/cancel`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    })

    if (!response.ok) {
      throw new Error('Failed to cancel scan')
    }

    const data = await response.json()

    appStore.showToast({
      message: data.message || 'Scan cancellation requested',
      type: 'info'
    })

    // Refresh job to show updated status
    await refreshJob()
  } catch (error) {
    console.error('Error cancelling scan:', error)
    appStore.showToast({
      message: 'Failed to cancel scan',
      type: 'error'
    })
  } finally {
    cancelling.value = false
  }
}

const resumeScan = async () => {
  if (!job.value || resuming.value) return

  resuming.value = true

  try {
    const response = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'}/job/${job.value.id}/resume`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    })

    const data = await response.json()

    if (!response.ok) {
      // Check if it's a timing issue
      if (data.resume_after) {
        appStore.showToast({
          message: `Cannot resume yet. Please wait until ${new Date(data.resume_after).toLocaleTimeString()}`,
          type: 'warning'
        })
      } else {
        throw new Error(data.detail || 'Failed to resume scan')
      }
      return
    }

    appStore.showToast({
      message: data.message || 'Scan resumed successfully',
      type: 'success'
    })

    // Refresh job to show updated status
    await refreshJob()
  } catch (error) {
    console.error('Error resuming scan:', error)
    appStore.showToast({
      message: error.message || 'Failed to resume scan',
      type: 'error'
    })
  } finally {
    resuming.value = false
  }
}

const openConfirmDialog = () => {
  isConfirmOpen.value = true
}

const closeConfirmDialog = () => {
  isConfirmOpen.value = false
}

const handleDeleteJob = async () => {
  if (!job.value) return

  try {
    await jobsStore.deleteJob(job.value.id)
    appStore.showToast({ message: `Job for '${job.value.target}' deleted.`, type: 'success' })
    router.push('/') // Navigate back to the jobs list
  } catch (error) {
    appStore.showToast({ message: 'Failed to delete job.', type: 'error' })
  }

  closeConfirmDialog()
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
