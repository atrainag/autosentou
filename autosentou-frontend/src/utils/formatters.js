import { format, formatDistanceToNow } from 'date-fns'

/**
 * Format date to readable string
 */
export const formatDate = (dateString) => {
  if (!dateString) return 'N/A'
  try {
    const date = new Date(dateString.replace(' ', 'T'));
    return format(date, 'MMM dd, yyyy HH:mm:ss');
  } catch (e) {
    return dateString;
  }
};

/**
 * Format date to relative time (e.g., "2 hours ago")
 */
export const formatRelativeTime = (dateString) => {
  if (!dateString) return 'N/A';
  try {
    const date = new Date(dateString.replace(' ', 'T'));
    return formatDistanceToNow(date, { addSuffix: true });
  } catch (e) {
    return dateString;
  }
};

/**
 * Format file size to human-readable format
 */
export const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes'
  if (!bytes) return 'N/A'

  const k = 1024
  const sizes = ['Bytes', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))

  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i]
}

/**
 * Get severity color class
 */
export const getSeverityColor = (severity) => {
  const colors = {
    critical: 'bg-severity-critical text-white',
    high: 'bg-severity-high text-white',
    medium: 'bg-severity-medium text-gray-900',
    low: 'bg-severity-low text-white',
    info: 'bg-severity-info text-white',
  }
  return colors[severity?.toLowerCase()] || colors.info
}

/**
 * Get status color class
 */
export const getStatusColor = (status) => {
  const colors = {
    running: 'bg-blue-600 text-white',
    pending: 'bg-yellow-600 text-white',
    completed: 'bg-green-600 text-white',
    success: 'bg-green-600 text-white',
    failed: 'bg-red-600 text-white',
    cancelled: 'bg-gray-600 text-white',
    suspended: 'bg-yellow-500 text-black',
  }
  return colors[status?.toLowerCase()] || 'bg-gray-600 text-white'
}

/**
 * Get status text
 */
export const getStatusText = (status) => {
  const texts = {
    running: 'Running',
    pending: 'Pending',
    completed: 'Success',
    success: 'Success',
    failed: 'Failed',
    cancelled: 'Cancelled',
    suspended: 'Suspended',
  }
  return texts[status?.toLowerCase()] || status
}

/**
 * Format phase name to readable text
 */
export const formatPhaseName = (phaseName) => {
  if (!phaseName) return 'N/A'

  return phaseName
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

/**
 * Get phase icon
 */
export const getPhaseIcon = (phaseName) => {
  const icons = {
    info_gathering: '🔍',
    web_enumeration: '🌐',
    web_analysis: '🕷️',
    vulnerability_analysis: '⚠️',
    sqli_testing: '💉',
    authentication_testing: '🔐',
    report_generation: '📄',
  }
  return icons[phaseName?.toLowerCase().replace(/ /g, '_')] || '📋'
}

/**
 * Truncate long text
 */
export const truncate = (text, maxLength = 50) => {
  if (!text) return ''
  if (text.length <= maxLength) return text
  return text.substring(0, maxLength) + '...'
}

/**
 * Format number with commas
 */
export const formatNumber = (num) => {
  if (num === null || num === undefined) return '0'
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',')
}

/**
 * Get OWASP category color
 */
export const getOwaspColor = (category) => {
  const colors = {
    'A01': 'bg-red-700',
    'A02': 'bg-orange-700',
    'A03': 'bg-yellow-700',
    'A04': 'bg-green-700',
    'A05': 'bg-blue-700',
    'A06': 'bg-indigo-700',
    'A07': 'bg-purple-700',
    'A08': 'bg-pink-700',
    'A09': 'bg-cyan-700',
    'A10': 'bg-teal-700',
  }
  return colors[category] || 'bg-gray-700'
}
