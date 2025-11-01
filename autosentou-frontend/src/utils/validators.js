/**
 * Validate IP address (IPv4)
 */
export const isValidIPv4 = (ip) => {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/
  if (!ipv4Regex.test(ip)) return false

  const parts = ip.split('.')
  return parts.every(part => {
    const num = parseInt(part, 10)
    return num >= 0 && num <= 255
  })
}

/**
 * Validate domain name
 */
export const isValidDomain = (domain) => {
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i
  return domainRegex.test(domain)
}

/**
 * Validate URL
 */
export const isValidURL = (url) => {
  try {
    new URL(url)
    return true
  } catch (e) {
    return false
  }
}

/**
 * Validate target (IP, domain, or URL)
 */
export const isValidTarget = (target) => {
  if (!target || target.trim() === '') return false

  // Remove protocol if present
  const cleanTarget = target.replace(/^https?:\/\//, '')

  // Check if it's an IP address
  if (isValidIPv4(cleanTarget)) return true

  // Check if it's a domain
  if (isValidDomain(cleanTarget)) return true

  // Check if it's a URL
  if (isValidURL(target)) return true

  // Check for localhost variations
  if (cleanTarget.toLowerCase().includes('localhost')) return true

  return false
}

/**
 * Validate file extension
 */
export const hasValidExtension = (filename, allowedExtensions) => {
  if (!filename) return false

  const extension = filename.split('.').pop().toLowerCase()
  return allowedExtensions.includes(extension)
}

/**
 * Validate file size
 */
export const isValidFileSize = (file, maxSizeInMB) => {
  if (!file) return false

  const maxSizeInBytes = maxSizeInMB * 1024 * 1024
  return file.size <= maxSizeInBytes
}

/**
 * Validate wordlist file
 */
export const isValidWordlist = (file) => {
  // Check extension
  const validExtensions = ['txt', 'lst', 'wordlist']
  if (!hasValidExtension(file.name, validExtensions)) {
    return { valid: false, error: 'Invalid file extension. Allowed: .txt, .lst, .wordlist' }
  }

  // Check size (max 50MB)
  if (!isValidFileSize(file, 50)) {
    return { valid: false, error: 'File size exceeds 50MB' }
  }

  return { valid: true }
}

/**
 * Validate port number
 */
export const isValidPort = (port) => {
  const portNum = parseInt(port, 10)
  return !isNaN(portNum) && portNum > 0 && portNum <= 65535
}

/**
 * Validate thread count
 */
export const isValidThreadCount = (threads) => {
  const threadNum = parseInt(threads, 10)
  return !isNaN(threadNum) && threadNum > 0 && threadNum <= 100
}

/**
 * Validate timeout value (in seconds)
 */
export const isValidTimeout = (timeout) => {
  const timeoutNum = parseInt(timeout, 10)
  return !isNaN(timeoutNum) && timeoutNum > 0 && timeoutNum <= 3600
}

/**
 * Sanitize input (remove special characters)
 */
export const sanitizeInput = (input) => {
  if (!input) return ''
  return input.replace(/[<>]/g, '')
}
