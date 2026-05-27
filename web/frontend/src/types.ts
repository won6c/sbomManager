export type Risk = {
  score: number
  level: string
  impact: number
  feasibility: number
  reason: string
}

export type Vulnerability = {
  cve_id: string
  severity: string
  cvss_score?: number | null
  description: string
  affected_versions?: string[]
  exploits?: Record<string, unknown>[]
  fixed_in?: string | null
}

export type KernelState = {
  version: string
  config: Record<string, string>
  is_root: boolean
}

export type MemoryRegion = [string, string]

export type DaemonAsset = {
  port?: number | null
  protocol?: string | null
  address: string
  exposure: string
  pid?: number | null
  binary_path: string
  user: string
  privilege_level: string
  description?: string | null
  cpe?: string | null
  version?: string | null
  vulnerabilities?: Vulnerability[]
  risk?: Risk | null
  is_reachable?: boolean
  memory_regions?: MemoryRegion[]
}

export type BinaryAsset = {
  path: string
  sha256: string
  permissions: string
  is_setuid: boolean
  is_setgid: boolean
  mitigations: Record<string, unknown>
  privilege_level: string
  purl?: string | null
  cpe?: string | null
  version?: string | null
  vulnerabilities?: Vulnerability[]
  risk?: Risk | null
  is_reachable?: boolean
  memory_regions?: MemoryRegion[]
}

export type ScanResult = {
  kernel: KernelState
  daemons: DaemonAsset[]
  binaries: BinaryAsset[]
  overall_risk_score: number
  overall_risk_level: string
  timestamp: string
}

export type AssetKind = 'daemon' | 'binary'

export type AssetRow = {
  id: string
  kind: AssetKind
  label: string
  path: string
  endpoint: string
  identity: string
  version?: string | null
  cpe?: string | null
  purl?: string | null
  risk?: Risk | null
  vulnerabilities: Vulnerability[]
  is_reachable: boolean
  memory_regions: MemoryRegion[]
  privilegeLevel: string
  exposure?: string | null
  user?: string | null
  pid?: number | null
  port?: number | null
  protocol?: string | null
  permissions?: string
  sha256?: string
  mitigations?: Record<string, unknown>
  is_setuid?: boolean
  is_setgid?: boolean
}

export type HealthResponse = {
  status: string
}

export type CveResponse = {
  cpe: string
  vulnerabilities: Vulnerability[]
  total_count: number
  limit: number
  offset: number
}

export type ParsedPackage = {
  name?: string | null
  version?: string | null
  purl?: string | null
  bom_ref?: string | null
}

export type SbomParseResponse = {
  format: string
  packages: ParsedPackage[]
}
