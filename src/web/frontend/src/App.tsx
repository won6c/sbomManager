import { useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import {
  Activity,
  AlertTriangle,
  Binary,
  CheckCircle2,
  Cpu,
  Database,
  FileJson,
  Filter,
  GitBranch,
  Globe2,
  LoaderCircle,
  Moon,
  Network,
  Play,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Target,
  UploadCloud,
  XCircle,
} from 'lucide-react'
import './App.css'
import { fetchHealth, parseSbom, queryCves, runScan } from './api'
import { demoScanResult } from './mockData'
import type {
  AssetKind,
  AssetRow,
  ParsedPackage,
  ScanResult,
  Vulnerability,
} from './types'

type CategoryFilter = 'all' | AssetKind
type SeverityFilter = 'all' | 'critical' | 'high' | 'medium' | 'low'
type ReachabilityFilter = 'all' | 'reachable' | 'not-reachable'
type HandlingFilter = 'all' | 'pending' | 'handled' | HandlingAction
type HealthState = 'checking' | 'healthy' | 'offline'
type DataMode = 'demo' | 'live'
type ThemeMode = 'light' | 'dark'
type HandlingAction = 'patch' | 'mitigate' | 'monitor' | 'accept'
type AssetHandlingState = Partial<Record<HandlingAction, boolean>>

const severityWeight: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  unknown: 1,
}

const defaultScanPaths = ['/bin', '/usr/bin']
const themeStorageKey = 'sbom-manager-theme'
const handlingOptions: { value: HandlingAction; label: string }[] = [
  { value: 'patch', label: 'Patch' },
  { value: 'mitigate', label: 'Mitigate' },
  { value: 'monitor', label: 'Monitor' },
  { value: 'accept', label: 'Accept' },
]

function isThemeMode(value: string | null): value is ThemeMode {
  return value === 'light' || value === 'dark'
}

function getInitialTheme(): ThemeMode {
  if (typeof window === 'undefined') return 'light'

  const storedTheme = window.localStorage.getItem(themeStorageKey)
  if (isThemeMode(storedTheme)) return storedTheme

  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

function normalizeLevel(value?: string | null): string {
  return value?.trim().toLowerCase() || 'unknown'
}

function displayLevel(value?: string | null): string {
  const normalized = normalizeLevel(value)
  return normalized.charAt(0).toUpperCase() + normalized.slice(1)
}

function riskClass(value?: string | null): string {
  const normalized = normalizeLevel(value)
  if (normalized.includes('critical')) return 'critical'
  if (normalized.includes('high')) return 'high'
  if (normalized.includes('medium')) return 'medium'
  if (normalized.includes('low')) return 'low'
  return 'unknown'
}

function formatNumber(value: number): string {
  return Number.isFinite(value) ? value.toFixed(value % 1 === 0 ? 0 : 1) : '0'
}

function formatDate(value?: string): string {
  if (!value) return 'No scan'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleString()
}

function fileName(path: string): string {
  const normalized = path.replace(/\/+$/, '')
  return normalized.split('/').pop() || normalized || 'Unknown'
}

function highestSeverity(vulnerabilities: Vulnerability[]): string {
  if (vulnerabilities.length === 0) return 'Unknown'
  return vulnerabilities.reduce((highest, current) => {
    const currentWeight = severityWeight[normalizeLevel(current.severity)] ?? 0
    const highestWeight = severityWeight[normalizeLevel(highest)] ?? 0
    return currentWeight > highestWeight ? current.severity : highest
  }, vulnerabilities[0].severity)
}

function assetSignalLevel(asset: AssetRow): string {
  const highestCveSeverity = highestSeverity(asset.vulnerabilities)
  const riskLevel = asset.risk?.level ?? 'Unknown'
  const cveWeight = severityWeight[normalizeLevel(highestCveSeverity)] ?? 0
  const riskWeight = severityWeight[riskClass(riskLevel)] ?? 0
  return cveWeight >= riskWeight ? highestCveSeverity : riskLevel
}

function flattenAssets(scan: ScanResult): AssetRow[] {
  const daemons = scan.daemons.map<AssetRow>((daemon, index) => {
    const label = daemon.description || fileName(daemon.binary_path)
    const endpoint =
      daemon.port == null
        ? daemon.address
        : `${daemon.address}:${daemon.port}/${daemon.protocol ?? 'tcp'}`

    return {
      id: `daemon-${index}-${daemon.port ?? 'none'}-${daemon.pid ?? 'none'}`,
      kind: 'daemon',
      label,
      path: daemon.binary_path,
      endpoint,
      identity: daemon.user,
      version: daemon.version,
      cpe: daemon.cpe,
      risk: daemon.risk,
      vulnerabilities: daemon.vulnerabilities ?? [],
      is_reachable: Boolean(daemon.is_reachable),
      memory_regions: daemon.memory_regions ?? [],
      privilegeLevel: daemon.privilege_level,
      exposure: daemon.exposure,
      user: daemon.user,
      pid: daemon.pid,
      port: daemon.port,
      protocol: daemon.protocol,
    }
  })

  const binaries = scan.binaries.map<AssetRow>((binary, index) => ({
    id: `binary-${index}-${binary.path}`,
    kind: 'binary',
    label: fileName(binary.path),
    path: binary.path,
    endpoint: binary.is_setuid ? 'setuid binary' : 'local binary',
    identity: binary.permissions,
    version: binary.version,
    cpe: binary.cpe,
    purl: binary.purl,
    risk: binary.risk,
    vulnerabilities: binary.vulnerabilities ?? [],
    is_reachable: Boolean(binary.is_reachable),
    memory_regions: binary.memory_regions ?? [],
    privilegeLevel: binary.privilege_level,
    permissions: binary.permissions,
    sha256: binary.sha256,
    mitigations: binary.mitigations,
    is_setuid: binary.is_setuid,
    is_setgid: binary.is_setgid,
  }))

  return [...daemons, ...binaries]
}

function updateAssetVulnerabilities(
  scan: ScanResult,
  target: AssetRow,
  vulnerabilities: Vulnerability[],
): ScanResult {
  if (target.kind === 'daemon') {
    return {
      ...scan,
      daemons: scan.daemons.map((daemon) =>
        daemon.binary_path === target.path && daemon.port === target.port
          ? { ...daemon, vulnerabilities }
          : daemon,
      ),
    }
  }

  return {
    ...scan,
    binaries: scan.binaries.map((binary) =>
      binary.path === target.path ? { ...binary, vulnerabilities } : binary,
    ),
  }
}

function getScanPaths(input: string): string[] {
  return input
    .split(/[\n,]/)
    .map((path) => path.trim())
    .filter(Boolean)
}

function App() {
  const [theme, setTheme] = useState<ThemeMode>(getInitialTheme)
  const [health, setHealth] = useState<HealthState>('checking')
  const [scanPaths, setScanPaths] = useState(defaultScanPaths.join('\n'))
  const [scanResult, setScanResult] = useState<ScanResult>(demoScanResult)
  const [dataMode, setDataMode] = useState<DataMode>('demo')
  const [selectedAssetId, setSelectedAssetId] = useState<string>('')
  const [category, setCategory] = useState<CategoryFilter>('all')
  const [severity, setSeverity] = useState<SeverityFilter>('all')
  const [reachability, setReachability] = useState<ReachabilityFilter>('all')
  const [handling, setHandling] = useState<HandlingFilter>('all')
  const [query, setQuery] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [isRefreshingCves, setIsRefreshingCves] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [sbomPath, setSbomPath] = useState('test_sbom.json')
  const [packages, setPackages] = useState<ParsedPackage[]>([])
  const [isParsingSbom, setIsParsingSbom] = useState(false)
  const [assetHandling, setAssetHandling] = useState<Record<string, AssetHandlingState>>(
    {},
  )

  const assets = useMemo(() => flattenAssets(scanResult), [scanResult])

  const filteredAssets = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()

    return assets.filter((asset) => {
      if (category !== 'all' && asset.kind !== category) return false
      if (reachability === 'reachable' && !asset.is_reachable) return false
      if (reachability === 'not-reachable' && asset.is_reachable) return false
      if (severity !== 'all' && riskClass(assetSignalLevel(asset)) !== severity) {
        return false
      }

      const hState = assetHandling[asset.id] || {}
      const isHandled = Object.values(hState).some(Boolean)
      if (handling === 'handled' && !isHandled) return false
      if (handling === 'pending' && isHandled) return false
      if (
        handling !== 'all' &&
        handling !== 'handled' &&
        handling !== 'pending' &&
        !hState[handling as HandlingAction]
      ) {
        return false
      }

      if (!normalizedQuery) return true

      const haystack = [
        asset.label,
        asset.path,
        asset.endpoint,
        asset.cpe,
        asset.version,
        asset.privilegeLevel,
        asset.exposure,
        ...asset.vulnerabilities.map((vuln) => vuln.cve_id),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase()

      return haystack.includes(normalizedQuery)
    })
  }, [assets, category, query, reachability, severity])

  const selectedAsset = useMemo(() => {
    return (
      assets.find((asset) => asset.id === selectedAssetId) ??
      filteredAssets[0] ??
      assets[0]
    )
  }, [assets, filteredAssets, selectedAssetId])

  const summary = useMemo(() => {
    const totalVulnerabilities = assets.reduce(
      (total, asset) => total + asset.vulnerabilities.length,
      0,
    )
    const reachableAssets = assets.filter((asset) => asset.is_reachable).length
    const externalDaemons = assets.filter(
      (asset) => asset.kind === 'daemon' && asset.exposure === 'External',
    ).length
    const highRiskAssets = assets.filter((asset) => {
      const level = riskClass(assetSignalLevel(asset))
      return level === 'critical' || level === 'high'
    }).length

    return {
      totalAssets: assets.length,
      totalVulnerabilities,
      reachableAssets,
      externalDaemons,
      highRiskAssets,
    }
  }, [assets])

  useEffect(() => {
    void refreshHealth()
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    window.localStorage.setItem(themeStorageKey, theme)
  }, [theme])

  async function refreshHealth() {
    setHealth('checking')
    try {
      const response = await fetchHealth()
      setHealth(response.status === 'healthy' ? 'healthy' : 'offline')
    } catch {
      setHealth('offline')
    }
  }

  async function handleScan() {
    const paths = getScanPaths(scanPaths)
    if (paths.length === 0) {
      setError('Add at least one scan path.')
      return
    }

    setIsScanning(true)
    setError(null)
    try {
      const result = await runScan(paths)
      setScanResult(result)
      setDataMode('live')
      const nextAssets = flattenAssets(result)
      setSelectedAssetId(nextAssets[0]?.id ?? '')
      setHealth('healthy')
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : 'Scan failed.')
      setHealth('offline')
    } finally {
      setIsScanning(false)
    }
  }

  function loadDemoData() {
    setScanResult(demoScanResult)
    setDataMode('demo')
    setSelectedAssetId('')
    setError(null)
  }

  async function handleRefreshCves() {
    if (!selectedAsset?.cpe || selectedAsset.cpe === 'Unknown') return

    setIsRefreshingCves(true)
    setError(null)
    try {
      const response = await queryCves(selectedAsset.cpe)
      setScanResult((current) =>
        updateAssetVulnerabilities(current, selectedAsset, response.vulnerabilities),
      )
    } catch (cveError) {
      setError(cveError instanceof Error ? cveError.message : 'CVE refresh failed.')
    } finally {
      setIsRefreshingCves(false)
    }
  }

  async function handleParseSbom() {
    if (!sbomPath.trim()) {
      setError('Add an SBOM file path.')
      return
    }

    setIsParsingSbom(true)
    setError(null)
    try {
      const response = await parseSbom(sbomPath.trim())
      setPackages(response.packages)
    } catch (parseError) {
      setError(parseError instanceof Error ? parseError.message : 'SBOM parse failed.')
    } finally {
      setIsParsingSbom(false)
    }
  }

  function toggleAssetHandling(assetId: string, action: HandlingAction) {
    setAssetHandling((current) => {
      const currentAssetState = current[assetId] ?? {}

      return {
        ...current,
        [assetId]: {
          ...currentAssetState,
          [action]: !currentAssetState[action],
        },
      }
    })
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand-block">
          <div className="brand-mark">
            <ShieldCheck size={22} aria-hidden="true" />
          </div>
          <div>
            <h1>SBOM Manager</h1>
            <p>
              {dataMode === 'live' ? 'Live scan' : 'Demo scan'} ·{' '}
              {formatDate(scanResult.timestamp)}
            </p>
          </div>
        </div>
        <div className="topbar-actions">
          <ThemeToggle theme={theme} onChange={setTheme} />
          <StatusPill health={health} />
          <button
            className="icon-button"
            type="button"
            title="Refresh API health"
            onClick={() => void refreshHealth()}
          >
            <RefreshCw size={17} aria-hidden="true" />
          </button>
        </div>
      </header>

      {error ? (
        <div className="error-banner" role="alert">
          <AlertTriangle size={18} aria-hidden="true" />
          <span>{error}</span>
          <button type="button" title="Dismiss" onClick={() => setError(null)}>
            <XCircle size={17} aria-hidden="true" />
          </button>
        </div>
      ) : null}

      <section className="scan-band" aria-label="Scan controls">
        <div className="scan-input">
          <label htmlFor="scan-paths">Binary scan paths</label>
          <textarea
            id="scan-paths"
            value={scanPaths}
            rows={3}
            onChange={(event) => setScanPaths(event.target.value)}
          />
        </div>
        <div className="scan-actions">
          <button
            className="primary-button"
            type="button"
            onClick={() => void handleScan()}
            disabled={isScanning}
          >
            {isScanning ? (
              <LoaderCircle className="spin" size={18} aria-hidden="true" />
            ) : (
              <Play size={18} aria-hidden="true" />
            )}
            Scan
          </button>
          <button className="secondary-button" type="button" onClick={loadDemoData}>
            <Database size={18} aria-hidden="true" />
            Demo
          </button>
        </div>
      </section>

      <section className="metric-grid" aria-label="System summary">
        <MetricTile
          icon={<ShieldAlert size={19} aria-hidden="true" />}
          label="Overall risk"
          value={`${displayLevel(scanResult.overall_risk_level)} ${formatNumber(
            scanResult.overall_risk_score,
          )}`}
          tone={riskClass(scanResult.overall_risk_level)}
        />
        <MetricTile
          icon={<Target size={19} aria-hidden="true" />}
          label="High risk assets"
          value={String(summary.highRiskAssets)}
          tone={summary.highRiskAssets > 0 ? 'high' : 'low'}
        />
        <MetricTile
          icon={<Activity size={19} aria-hidden="true" />}
          label="Reachable assets"
          value={`${summary.reachableAssets}/${summary.totalAssets}`}
          tone={summary.reachableAssets > 0 ? 'medium' : 'unknown'}
        />
        <MetricTile
          icon={<Globe2 size={19} aria-hidden="true" />}
          label="External daemons"
          value={String(summary.externalDaemons)}
          tone={summary.externalDaemons > 0 ? 'high' : 'low'}
        />
        <MetricTile
          icon={<AlertTriangle size={19} aria-hidden="true" />}
          label="CVEs"
          value={String(summary.totalVulnerabilities)}
          tone={summary.totalVulnerabilities > 0 ? 'medium' : 'low'}
        />
      </section>

      <section className="workspace">
        <div className="inventory-panel">
          <div className="panel-header">
            <div>
              <h2>Asset Inventory</h2>
              <p>{filteredAssets.length} matching assets</p>
            </div>
            <Filter size={18} aria-hidden="true" />
          </div>

          <div className="filter-strip" aria-label="Inventory filters">
            <SegmentedControl<CategoryFilter>
              label="Category"
              value={category}
              options={[
                ['all', 'All'],
                ['daemon', 'Daemons'],
                ['binary', 'Binaries'],
              ]}
              onChange={setCategory}
            />
            <SegmentedControl<SeverityFilter>
              label="Severity"
              value={severity}
              options={[
                ['all', 'All'],
                ['critical', 'Critical'],
                ['high', 'High'],
                ['medium', 'Medium'],
                ['low', 'Low'],
              ]}
              onChange={setSeverity}
            />
            <SegmentedControl<ReachabilityFilter>
              label="Reachability"
              value={reachability}
              options={[
                ['all', 'All'],
                ['reachable', 'Loaded'],
                ['not-reachable', 'Not loaded'],
              ]}
              onChange={setReachability}
            />
            <SegmentedControl<HandlingFilter>
              label="Handling"
              value={handling}
              options={[
                ['all', 'All'],
                ['pending', 'Pending'],
                ['handled', 'Handled'],
                ['patch', 'Patch'],
                ['mitigate', 'Mitigate'],
              ]}
              onChange={setHandling}
            />
            <label className="search-box" htmlFor="asset-query">
              <Search size={17} aria-hidden="true" />
              <input
                id="asset-query"
                value={query}
                placeholder="Search assets, CPEs, CVEs"
                onChange={(event) => setQuery(event.target.value)}
              />
            </label>
          </div>

          <AssetTable
            assets={filteredAssets}
            handlingState={assetHandling}
            selectedId={selectedAsset?.id}
            onSelect={setSelectedAssetId}
            onToggleHandling={toggleAssetHandling}
          />
        </div>

        <aside className="detail-panel">
          {selectedAsset ? (
            <AssetDetails
              asset={selectedAsset}
              onRefreshCves={() => void handleRefreshCves()}
              isRefreshingCves={isRefreshingCves}
            />
          ) : (
            <div className="empty-state">No selected asset</div>
          )}
        </aside>
      </section>

      <section className="lower-grid">
        <div className="graph-panel">
          <div className="panel-header">
            <div>
              <h2>Attack Path Graph</h2>
              <p>Port, process, binary, CVE</p>
            </div>
            <GitBranch size={18} aria-hidden="true" />
          </div>
          <AttackGraph
            assets={filteredAssets}
            selectedId={selectedAsset?.id}
            onSelect={setSelectedAssetId}
          />
        </div>

        <div className="sbom-panel">
          <div className="panel-header">
            <div>
              <h2>SBOM Intake</h2>
              <p>{packages.length} parsed packages</p>
            </div>
            <FileJson size={18} aria-hidden="true" />
          </div>
          <div className="sbom-controls">
            <label htmlFor="sbom-path">File path</label>
            <div className="inline-form">
              <input
                id="sbom-path"
                value={sbomPath}
                onChange={(event) => setSbomPath(event.target.value)}
              />
              <button
                className="secondary-button compact"
                type="button"
                onClick={() => void handleParseSbom()}
                disabled={isParsingSbom}
              >
                {isParsingSbom ? (
                  <LoaderCircle className="spin" size={16} aria-hidden="true" />
                ) : (
                  <UploadCloud size={16} aria-hidden="true" />
                )}
                Parse
              </button>
            </div>
          </div>
          <div className="package-list">
            {packages.length === 0 ? (
              <div className="empty-state">No packages parsed</div>
            ) : (
              packages.slice(0, 8).map((pkg, index) => (
                <div className="package-row" key={`${pkg.name}-${pkg.version}-${index}`}>
                  <span>{pkg.name || 'Unknown package'}</span>
                  <code>{pkg.version || 'unknown'}</code>
                </div>
              ))
            )}
          </div>
        </div>
      </section>
    </main>
  )
}

function ThemeToggle({
  theme,
  onChange,
}: {
  theme: ThemeMode
  onChange: (theme: ThemeMode) => void
}) {
  return (
    <div className="theme-toggle" aria-label="Background theme">
      <button
        className={theme === 'light' ? 'active' : ''}
        type="button"
        title="Light background"
        aria-pressed={theme === 'light'}
        onClick={() => onChange('light')}
      >
        <Sun size={16} aria-hidden="true" />
      </button>
      <button
        className={theme === 'dark' ? 'active' : ''}
        type="button"
        title="Dark background"
        aria-pressed={theme === 'dark'}
        onClick={() => onChange('dark')}
      >
        <Moon size={16} aria-hidden="true" />
      </button>
    </div>
  )
}

function StatusPill({ health }: { health: HealthState }) {
  const statusMap = {
    checking: {
      label: 'Checking',
      className: 'checking',
      icon: <LoaderCircle className="spin" size={15} aria-hidden="true" />,
    },
    healthy: {
      label: 'API healthy',
      className: 'healthy',
      icon: <CheckCircle2 size={15} aria-hidden="true" />,
    },
    offline: {
      label: 'API offline',
      className: 'offline',
      icon: <XCircle size={15} aria-hidden="true" />,
    },
  }
  const status = statusMap[health]

  return (
    <span className={`status-pill ${status.className}`}>
      {status.icon}
      {status.label}
    </span>
  )
}

function MetricTile({
  icon,
  label,
  value,
  tone,
}: {
  icon: ReactNode
  label: string
  value: string
  tone: string
}) {
  return (
    <div className={`metric-tile ${tone}`}>
      <div className="metric-icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  )
}

function SegmentedControl<TValue extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string
  value: TValue
  options: [TValue, string][]
  onChange: (value: TValue) => void
}) {
  return (
    <div className="segmented-control" aria-label={label}>
      {options.map(([optionValue, optionLabel]) => (
        <button
          key={optionValue}
          type="button"
          className={value === optionValue ? 'active' : ''}
          onClick={() => onChange(optionValue)}
        >
          {optionLabel}
        </button>
      ))}
    </div>
  )
}

function AssetTable({
  assets,
  handlingState,
  selectedId,
  onSelect,
  onToggleHandling,
}: {
  assets: AssetRow[]
  handlingState: Record<string, AssetHandlingState>
  selectedId?: string
  onSelect: (id: string) => void
  onToggleHandling: (assetId: string, action: HandlingAction) => void
}) {
  if (assets.length === 0) {
    return <div className="empty-state">No matching assets</div>
  }

  return (
    <div className="table-wrap">
      <table className="asset-table">
        <thead>
          <tr>
            <th>Risk</th>
            <th>Asset</th>
            <th>Endpoint</th>
            <th>Reachability</th>
            <th>CVEs</th>
            <th>Handling</th>
            <th>CPE</th>
          </tr>
        </thead>
        <tbody>
          {assets.map((asset) => {
            const level = assetSignalLevel(asset)
            const selected = asset.id === selectedId

            return (
              <tr
                key={asset.id}
                className={selected ? 'selected' : ''}
                onClick={() => onSelect(asset.id)}
              >
                <td>
                  <span className={`risk-badge ${riskClass(level)}`}>
                    {displayLevel(level)}
                  </span>
                </td>
                <td>
                  <div className="asset-cell">
                    <span className="asset-type">
                      {asset.kind === 'daemon' ? (
                        <Server size={15} aria-hidden="true" />
                      ) : (
                        <Binary size={15} aria-hidden="true" />
                      )}
                      {asset.kind}
                    </span>
                    <strong>{asset.label}</strong>
                    <code>{asset.path}</code>
                  </div>
                </td>
                <td>
                  <span>{asset.endpoint}</span>
                  <small>{asset.exposure || asset.privilegeLevel}</small>
                </td>
                <td>
                  <ReachabilityBadge loaded={asset.is_reachable} />
                </td>
                <td>
                  <strong>{asset.vulnerabilities.length}</strong>
                  <small>{highestSeverity(asset.vulnerabilities)}</small>
                </td>
                <td>
                  <div
                    className="handling-checklist"
                    onClick={(event) => event.stopPropagation()}
                  >
                    {handlingOptions.map((option) => (
                      <label className="handling-item" key={option.value}>
                        <input
                          type="checkbox"
                          checked={Boolean(handlingState[asset.id]?.[option.value])}
                          onChange={() => onToggleHandling(asset.id, option.value)}
                        />
                        <span>{option.label}</span>
                      </label>
                    ))}
                  </div>
                </td>
                <td>
                  <code className="cpe-code">{asset.cpe || 'Unknown'}</code>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function ReachabilityBadge({ loaded }: { loaded: boolean }) {
  return (
    <span className={`reachability-badge ${loaded ? 'loaded' : 'not-loaded'}`}>
      {loaded ? (
        <Activity size={14} aria-hidden="true" />
      ) : (
        <CheckCircle2 size={14} aria-hidden="true" />
      )}
      {loaded ? 'Loaded' : 'Not loaded'}
    </span>
  )
}

function AssetDetails({
  asset,
  onRefreshCves,
  isRefreshingCves,
}: {
  asset: AssetRow
  onRefreshCves: () => void
  isRefreshingCves: boolean
}) {
  const mitigations = Object.entries(asset.mitigations ?? {})

  return (
    <div className="asset-details">
      <div className="detail-title">
        <span className={`asset-kind ${asset.kind}`}>
          {asset.kind === 'daemon' ? (
            <Network size={16} aria-hidden="true" />
          ) : (
            <Cpu size={16} aria-hidden="true" />
          )}
          {asset.kind}
        </span>
        <h2>{asset.label}</h2>
        <code
          className="cpe-code"
          onClick={() => void navigator.clipboard.writeText(asset.cpe || asset.path)}
          title="Click to copy path/CPE"
        >
          {asset.cpe || asset.path}
        </code>
      </div>

      <div className="risk-box">
        <div>
          <span>Risk score</span>
          <strong>{formatNumber(asset.risk?.score ?? 0)}</strong>
        </div>
        <div>
          <span>Level</span>
          <strong className={riskClass(asset.risk?.level)}>
            {displayLevel(asset.risk?.level)}
          </strong>
        </div>
        <p>{asset.risk?.reason || 'No risk reason available.'}</p>
      </div>

      <dl className="detail-grid">
        <div>
          <dt>Version</dt>
          <dd>{asset.version || 'Unknown'}</dd>
        </div>
        <div>
          <dt>Privilege</dt>
          <dd>{asset.privilegeLevel}</dd>
        </div>
        <div>
          <dt>Endpoint</dt>
          <dd>{asset.endpoint}</dd>
        </div>
        <div>
          <dt>Memory regions</dt>
          <dd>{asset.memory_regions.length}</dd>
        </div>
      </dl>

      <div className="detail-section">
        <div className="section-heading">
          <h3>Vulnerabilities</h3>
          <button
            className="icon-text-button"
            type="button"
            onClick={onRefreshCves}
            disabled={isRefreshingCves || !asset.cpe || asset.cpe === 'Unknown'}
          >
            {isRefreshingCves ? (
              <LoaderCircle className="spin" size={15} aria-hidden="true" />
            ) : (
              <RefreshCw size={15} aria-hidden="true" />
            )}
            CVE
          </button>
        </div>
        <div className="vuln-list">
          {asset.vulnerabilities.length === 0 ? (
            <div className="empty-state compact">No CVEs mapped</div>
          ) : (
            asset.vulnerabilities.slice(0, 6).map((vuln) => (
              <div className="vuln-row" key={vuln.cve_id}>
                <div>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="cve-link"
                  >
                    {vuln.cve_id}
                  </a>
                  <span>{vuln.description}</span>
                </div>
                <span className={`risk-badge ${riskClass(vuln.severity)}`}>
                  {displayLevel(vuln.severity)}
                  {vuln.cvss_score ? ` ${formatNumber(vuln.cvss_score)}` : ''}
                </span>
              </div>
            ))
          )}
        </div>
      </div>

      <div className="detail-section">
        <h3>Signals</h3>
        <div className="signal-grid">
          <Signal
            label="CPE"
            value={asset.cpe || 'Unknown'}
            className="cpe-code"
            onClick={(val) => void navigator.clipboard.writeText(val)}
            title="Click to copy"
          />
          <Signal label="Reachability" value={asset.is_reachable ? 'Loaded' : 'Not loaded'} />
          <Signal label="User" value={asset.user || asset.identity || 'Unknown'} />
          <Signal
            label="Exploit refs"
            value={String(
              asset.vulnerabilities.reduce(
                (total, vuln) => total + (vuln.exploits?.length ?? 0),
                0,
              ),
            )}
          />
        </div>
      </div>

      {mitigations.length > 0 ? (
        <div className="detail-section">
          <h3>Mitigations</h3>
          <div className="mitigation-list">
            {mitigations.map(([key, value]) => (
              <span key={key}>
                {key}: {String(value)}
              </span>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  )
}

function Signal({
  label,
  value,
  className,
  onClick,
  title,
}: {
  label: string
  value: string
  className?: string
  onClick?: (val: string) => void
  title?: string
}) {
  return (
    <div className={className} onClick={() => onClick?.(value)} title={title}>
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  )
}

function attackStageValues(asset: AssetRow): { label: string; value: string }[] {
  const portValue =
    asset.kind === 'daemon' && asset.port != null
      ? `:${asset.port}/${asset.protocol ?? 'tcp'}`
      : asset.kind === 'daemon'
        ? 'daemon'
        : 'local'
  const processValue =
    asset.kind === 'daemon' ? `pid ${asset.pid ?? '?'}` : asset.is_setuid ? 'setuid' : 'binary'
  const cveValue =
    asset.vulnerabilities.length > 0
      ? `${asset.vulnerabilities.length} ${highestSeverity(asset.vulnerabilities)}`
      : 'No CVE'

  return [
    { label: 'Entry', value: portValue },
    { label: 'Process', value: processValue },
    { label: 'Binary', value: fileName(asset.path) },
    { label: 'CVE', value: cveValue },
  ]
}

function AttackGraph({
  assets,
  selectedId,
  onSelect,
}: {
  assets: AssetRow[]
  selectedId?: string
  onSelect: (id: string) => void
}) {
  const selected = assets.find((asset) => asset.id === selectedId)
  const graphAssets = useMemo(() => {
    const candidates = [...assets]
      .sort((left, right) => {
        const leftScore = left.risk?.score ?? 0
        const rightScore = right.risk?.score ?? 0
        return rightScore - leftScore
      })
      .slice(0, 5)

    if (!selected) return candidates
    return [selected, ...candidates.filter((asset) => asset.id !== selected.id)].slice(0, 5)
  }, [assets, selected])

  if (graphAssets.length === 0) {
    return <div className="empty-state">No graph data</div>
  }

  return (
    <div className="graph-canvas git-graph-canvas">
      <div className="git-graph" role="group" aria-label="Attack path git graph">
        {graphAssets.map((asset, index) => {
          const isSelected = asset.id === selectedId
          const risk = riskClass(assetSignalLevel(asset))
          const lane = `lane-${index % 3}`

          return (
            <button
              aria-pressed={isSelected}
              className={`git-graph-row ${lane} ${isSelected ? 'selected' : ''}`}
              key={asset.id}
              type="button"
              onClick={() => onSelect(asset.id)}
            >
              <span className="git-lanes" aria-hidden="true">
                <span className="git-rail rail-0" />
                <span className="git-rail rail-1" />
                <span className="git-rail rail-2" />
                <span className="git-branch-line" />
                <span className={`git-dot ${risk}`} />
              </span>
              <span className="git-path-card">
                <span className="git-path-header">
                  <span className="asset-type">
                    {asset.kind === 'daemon' ? (
                      <Server size={15} aria-hidden="true" />
                    ) : (
                      <Binary size={15} aria-hidden="true" />
                    )}
                    {asset.kind}
                  </span>
                  <span className={`risk-badge ${risk}`}>
                    {displayLevel(assetSignalLevel(asset))}
                  </span>
                </span>
                <strong className="git-asset-name">{asset.label}</strong>
                <code>{asset.path}</code>
                <span className="git-stage-strip">
                  {attackStageValues(asset).map((stage) => (
                    <span className="git-stage" key={stage.label}>
                      <small>{stage.label}</small>
                      <span>{stage.value}</span>
                    </span>
                  ))}
                </span>
              </span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

export default App
