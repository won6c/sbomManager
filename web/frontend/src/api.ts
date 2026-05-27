import type {
  CveResponse,
  HealthResponse,
  ScanResult,
  SbomParseResponse,
} from './types'

const configuredBase = import.meta.env.VITE_API_BASE_URL?.trim() ?? ''
const API_BASE = configuredBase.endsWith('/')
  ? configuredBase.slice(0, -1)
  : configuredBase

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  if (!headers.has('Content-Type') && init?.body) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
  })

  if (!response.ok) {
    const detail = await response.text()
    throw new Error(detail || `${response.status} ${response.statusText}`)
  }

  return (await response.json()) as T
}

export function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/health')
}

export function runScan(binaryScanPaths: string[]): Promise<ScanResult> {
  return request<ScanResult>('/scan', {
    method: 'POST',
    body: JSON.stringify({ binary_scan_paths: binaryScanPaths }),
  })
}

export function queryCves(cpe: string, limit = 25): Promise<CveResponse> {
  return request<CveResponse>('/api/v1/intelligence/cve', {
    method: 'POST',
    body: JSON.stringify({
      cpe,
      limit,
      offset: 0,
      sort_by: 'severity',
    }),
  })
}

export function parseSbom(filePath: string): Promise<SbomParseResponse> {
  const params = new URLSearchParams({ file_path: filePath })
  return request<SbomParseResponse>(`/intelligence/sbom/parse?${params}`, {
    method: 'POST',
  })
}
