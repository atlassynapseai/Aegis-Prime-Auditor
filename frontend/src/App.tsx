import { useState, useCallback } from 'react'
import './App.css'

// ═══════════════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════════════

interface Finding {
  id: string
  engine: string
  category: string
  severity: string
  message: string
  file: string
  line_start: number
  snippet?: string
  cwe?: string | string[]
}

interface ScanResult {
  scan_id: string
  timestamp: string
  file: string
  total_findings: number
  ai_analysis: {
    executive_summary: string
    risk_score: number
    risk_level: string
    top_priorities: string[]
  }
  heatmap_data: Array<{
    category: string
    severity: string
    count: number
    risk_weight: number
    normalized: number
  }>
  all_findings: Finding[]
  severity_breakdown: Record<string, number>
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPONENTS
// ═══════════════════════════════════════════════════════════════════════════════

function App() {
  const [file, setFile] = useState<File | null>(null)
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null)

  // Get backend URL from environment or use localhost
  const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000'

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
      setError(null)
    }
  }

  const handleScan = async () => {
    if (!file) {
      setError('Please select a file to scan')
      return
    }

    setScanning(true)
    setError(null)
    setResult(null)

    try {
      const formData = new FormData()
      formData.append('file', file)

      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: 'POST',
        body: formData
      })

      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`)
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Scan failed')
    } finally {
      setScanning(false)
    }
  }

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'CRITICAL': return 'rgb(220, 38, 38)'
      case 'HIGH': return 'rgb(234, 88, 12)'
      case 'MEDIUM': return 'rgb(234, 179, 8)'
      case 'LOW': return 'rgb(34, 197, 94)'
      default: return 'rgb(100, 116, 139)'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
      case 'ERROR':
        return 'rgb(220, 38, 38)'
      case 'HIGH':
        return 'rgb(234, 88, 12)'
      case 'MEDIUM':
      case 'WARNING':
        return 'rgb(234, 179, 8)'
      case 'LOW':
        return 'rgb(34, 197, 94)'
      default:
        return 'rgb(100, 116, 139)'
    }
  }

  const filteredFindings = result?.all_findings.filter(finding => {
    if (selectedCategory && finding.category !== selectedCategory) return false
    if (selectedSeverity && finding.severity !== selectedSeverity) return false
    return true
  }) || []

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-950/50 backdrop-blur-sm">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-500 rounded-lg flex items-center justify-center">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <h1 className="text-xl font-bold text-white">AEGIS PRIME</h1>
                <p className="text-xs text-slate-400">Security Auditor v1.0</p>
              </div>
            </div>
            
            {result && (
              <div className="flex gap-4 text-sm">
                <div className="text-slate-400">
                  Semgrep: <span className="text-white font-mono">{result.engines.semgrep?.findings?.length || 0}</span>
                </div>
                <div className="text-slate-400">
                  Gitleaks: <span className="text-white font-mono">{result.engines.gitleaks?.findings?.length || 0}</span>
                </div>
                <div className="text-slate-400">
                  Trivy: <span className="text-white font-mono">{result.engines.trivy?.findings?.length || 0}</span>
                </div>
                <div className="text-slate-400">
                  CodeQL: <span className="text-white font-mono">{result.engines.codeql?.findings?.length || 0}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        {/* Risk Score Banner */}
        {result && (
          <div 
            className="mb-8 p-6 rounded-xl border"
            style={{
              backgroundColor: `${getRiskColor(result.ai_analysis.risk_level)}15`,
              borderColor: getRiskColor(result.ai_analysis.risk_level)
            }}
          >
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-2xl font-bold text-white mb-2">
                  RISK SCORE: {result.ai_analysis.risk_score}/100
                </h2>
                <p className="text-slate-300">{result.ai_analysis.executive_summary}</p>
              </div>
              <div 
                className="px-6 py-3 rounded-lg font-bold text-lg"
                style={{ 
                  backgroundColor: getRiskColor(result.ai_analysis.risk_level),
                  color: 'white'
                }}
              >
                {result.ai_analysis.risk_level}
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column - Upload & AI Analysis */}
          <div className="lg:col-span-1 space-y-6">
            {/* File Upload */}
            <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-6">
              <h3 className="text-lg font-semibold text-white mb-4">SCAN TARGET</h3>
              
              <div className="space-y-4">
                <div className="border-2 border-dashed border-slate-700 rounded-lg p-8 text-center hover:border-blue-500 transition-colors">
                  <input
                    type="file"
                    onChange={handleFileSelect}
                    accept=".py,.js,.ts,.java,.go,.rb,.zip"
                    className="hidden"
                    id="file-upload"
                  />
                  <label htmlFor="file-upload" className="cursor-pointer">
                    <svg className="w-12 h-12 mx-auto mb-4 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>
                    {file ? (
                      <p className="text-blue-400 font-medium">{file.name}</p>
                    ) : (
                      <p className="text-slate-400">Drop file or click to browse</p>
                    )}
                    <p className="text-xs text-slate-500 mt-2">.py .js .ts .java .go .rb .zip</p>
                  </label>
                </div>

                <button
                  onClick={handleScan}
                  disabled={!file || scanning}
                  className="w-full py-3 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-700 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-colors"
                >
                  {scanning ? 'SCANNING...' : 'INITIATE SCAN'}
                </button>

                {error && (
                  <div className="p-4 bg-red-900/20 border border-red-500 rounded-lg">
                    <p className="text-red-400 text-sm">{error}</p>
                  </div>
                )}
              </div>
            </div>

            {/* AI Analysis */}
            {result && (
              <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-6">
                <h3 className="text-lg font-semibold text-white mb-4">AI ANALYSIS</h3>
                
                <div className="space-y-4">
                  <div>
                    <h4 className="text-sm font-semibold text-slate-400 mb-2">TOP PRIORITIES</h4>
                    <ul className="space-y-2">
                      {result.ai_analysis.top_priorities.map((priority, idx) => (
                        <li key={idx} className="text-sm text-slate-300 flex gap-2">
                          <span className="text-blue-400">P{idx + 1}</span>
                          <span>{priority}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Right Column - Heatmap & Findings */}
          <div className="lg:col-span-2 space-y-6">
            {/* Heatmap */}
            {result && (
              <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-6">
                <h3 className="text-lg font-semibold text-white mb-4">
                  RISK HEATMAP
                  <span className="ml-3 text-sm font-normal text-slate-400">
                    {result.total_findings} TOTAL FINDINGS
                  </span>
                </h3>

                <div className="overflow-x-auto">
                  <table className="w-full border-collapse">
                    <thead>
                      <tr>
                        <th className="p-2 text-left text-xs text-slate-500"></th>
                        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                          <th key={sev} className="p-2 text-center text-xs text-slate-400 font-semibold">
                            {sev}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {['SAST', 'Secrets', 'SCA', 'Deep Analysis'].map(category => (
                        <tr key={category}>
                          <td className="p-2 text-xs text-slate-400 font-semibold">{category}</td>
                          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(severity => {
                            const cell = result.heatmap_data.find(
                              d => d.category === category && d.severity === severity
                            )
                            const count = cell?.count || 0
                            const normalized = cell?.normalized || 0
                            
                            return (
                              <td
                                key={severity}
                                className="p-2 text-center cursor-pointer hover:ring-2 hover:ring-blue-500 transition-all"
                                onClick={() => {
                                  setSelectedCategory(category)
                                  setSelectedSeverity(severity)
                                }}
                                style={{
                                  backgroundColor: count > 0 
                                    ? `${getSeverityColor(severity)}${Math.floor(normalized * 255).toString(16).padStart(2, '0')}`
                                    : 'rgb(30, 41, 59)'
                                }}
                              >
                                <span className="text-white font-bold text-sm">{count}</span>
                              </td>
                            )
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {(selectedCategory || selectedSeverity) && (
                  <button
                    onClick={() => {
                      setSelectedCategory(null)
                      setSelectedSeverity(null)
                    }}
                    className="mt-4 text-sm text-blue-400 hover:text-blue-300"
                  >
                    Clear filters
                  </button>
                )}
              </div>
            )}

            {/* Findings Log */}
            {result && (
              <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-6">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-white">
                    AUDIT LOG
                    {(selectedCategory || selectedSeverity) && (
                      <span className="ml-3 text-sm font-normal text-slate-400">
                        Filtered: {filteredFindings.length} of {result.total_findings}
                      </span>
                    )}
                  </h3>
                  
                  <div className="flex gap-2 text-xs">
                    {Object.entries(result.severity_breakdown).map(([sev, count]) => (
                      count > 0 && (
                        <div key={sev} className="px-2 py-1 rounded" style={{ backgroundColor: `${getSeverityColor(sev)}20`, color: getSeverityColor(sev) }}>
                          {sev} {count}
                        </div>
                      )
                    ))}
                  </div>
                </div>

                <div className="space-y-3 max-h-[600px] overflow-y-auto">
                  {filteredFindings.length === 0 ? (
                    <p className="text-slate-500 text-center py-8">
                      {selectedCategory || selectedSeverity ? 'No findings match the selected filter' : 'No findings detected'}
                    </p>
                  ) : (
                    filteredFindings.map((finding, idx) => (
                      <div
                        key={idx}
                        className="p-4 rounded-lg border"
                        style={{
                          backgroundColor: `${getSeverityColor(finding.severity)}10`,
                          borderColor: `${getSeverityColor(finding.severity)}40`
                        }}
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <span
                              className="px-2 py-0.5 rounded text-xs font-bold"
                              style={{
                                backgroundColor: getSeverityColor(finding.severity),
                                color: 'white'
                              }}
                            >
                              {finding.severity}
                            </span>
                            <span className="text-xs text-slate-400 uppercase">{finding.engine}</span>
                            {finding.cwe && (
                              <span className="text-xs text-slate-500">
                                {Array.isArray(finding.cwe) ? finding.cwe[0] : finding.cwe}
                              </span>
                            )}
                          </div>
                          <span className="text-xs text-slate-500">
                            {finding.file}:{finding.line_start}
                          </span>
                        </div>
                        
                        <p className="text-sm text-slate-200 mb-2">{finding.message}</p>
                        
                        {finding.snippet && (
                          <pre className="text-xs bg-slate-950 p-2 rounded border border-slate-800 text-slate-400 overflow-x-auto">
                            {finding.snippet}
                          </pre>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* Empty State */}
            {!result && !scanning && (
              <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-12 text-center">
                <svg className="w-16 h-16 mx-auto mb-4 text-slate-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <h3 className="text-lg font-semibold text-slate-300 mb-2">Ready to Scan</h3>
                <p className="text-slate-500">Upload a code file to begin multi-engine security analysis</p>
              </div>
            )}

            {/* Scanning State */}
            {scanning && (
              <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-12 text-center">
                <div className="animate-spin w-16 h-16 mx-auto mb-4 border-4 border-blue-500 border-t-transparent rounded-full"></div>
                <h3 className="text-lg font-semibold text-white mb-2">Scanning...</h3>
                <p className="text-slate-400">Running Semgrep, Gitleaks, Trivy, and CodeQL analysis</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default App
