import { useState, useEffect } from 'react'
import './App.css'

interface Finding {
  id: string; engine: string; category: string; severity: string; message: string
  file: string; line_start: number; snippet?: string; cwe?: string | string[]
  package?: string; cve?: string
}

interface ScanResult {
  scan_id: string; timestamp: string; file: string; total_findings: number
  is_batch?: boolean; files_scanned?: number; file_results?: Array<{ file: string; findings: number }>
  ai_analysis: { executive_summary: string; risk_score: number; risk_level: string; top_priorities?: string[] }
  heatmap_data: Array<{ category: string; severity: string; count: number; normalized: number }>
  all_findings: Finding[]
  severity_breakdown: Record<string, number>
  engines: any
  status?: string
}

interface ComplianceData {
  frameworks: Record<string, any>
  overall_status: {
    recommendation: string
    critical_blockers: number
    estimated_remediation_time: string
  }
}

function App() {
  const [file, setFile] = useState<File | null>(null)
  const [scanning, setScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [compliance, setCompliance] = useState<ComplianceData | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selectedCat, setSelectedCat] = useState<string | null>(null)
  const [selectedSev, setSelectedSev] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [history, setHistory] = useState<ScanResult[]>([])
  const [showHistory, setShowHistory] = useState(false)
  const [showCompliance, setShowCompliance] = useState(false)
  const [isDragging, setIsDragging] = useState(false)
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error' } | null>(null)

  const BACKEND = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000'

  useEffect(() => {
    const saved = localStorage.getItem('atlas_history')
    if (saved) try { setHistory(JSON.parse(saved)) } catch { }
  }, [])

  useEffect(() => {
    if (result && result.status === 'completed' && !history.find(s => s.scan_id === result.scan_id)) {
      const updated = [result, ...history].slice(0, 20)
      setHistory(updated)
      localStorage.setItem('atlas_history', JSON.stringify(updated))
    }
  }, [result])

  const showToast = (msg: string, type: 'success' | 'error') => {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 4000)
  }

  const getFileIcon = (filename: string) => {
    const ext = filename.substring(filename.lastIndexOf('.')).toLowerCase()
    if (['.py'].includes(ext)) return '🐍'
    if (['.js', '.ts', '.jsx', '.tsx'].includes(ext)) return '⚡'
    if (['.java'].includes(ext)) return '☕'
    if (['.zip', '.tar', '.gz'].includes(ext)) return '📦'
    if (['.pdf'].includes(ext)) return '📄'
    if (['.docx', '.doc'].includes(ext)) return '📝'
    if (['.xlsx', '.xls'].includes(ext)) return '📊'
    if (['.html', '.htm'].includes(ext)) return '🌐'
    if (['.mp3', '.wav'].includes(ext)) return '🎵'
    if (['.mp4', '.avi', '.mov'].includes(ext)) return '🎬'
    if (['.jpg', '.png', '.gif'].includes(ext)) return '🖼️'
    return '📄'
  }

  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = e.target.files
    if (!selectedFiles || selectedFiles.length === 0) return

    // For now, just take the first file (multi-file requires backend changes)
    const f = selectedFiles[0]

    // TODO: Handle multiple files by creating a temporary ZIP

    const ext = f.name.substring(f.name.lastIndexOf('.'))
    const validExts = [
      '.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.cs',
      '.jsx', '.tsx', '.rs', '.kt', '.swift',
      '.html', '.htm', '.xml', '.svg',
      '.pdf', '.docx', '.doc', '.xlsx', '.xls',
      '.txt', '.md', '.json', '.yaml', '.yml',
      '.mp3', '.mp4', '.wav', '.avi', '.mov',
      '.jpg', '.jpeg', '.png', '.gif',
      '.zip', '.tar', '.gz'
    ]

    if (!validExts.includes(ext.toLowerCase())) {
      setError('Invalid file type. Accepted: Code, Documents, Web, Media, Archives')
      return
    }

    if (f.size > 50 * 1024 * 1024) {
      setError('File > 50MB')
      return
    }

    setFile(f)
    setError(null)
    setIsDragging(false)

    if (f.name.endsWith('.zip')) {
      showToast(`📦 ZIP archive: ${f.name} - Will extract and scan all code files`, 'success')
    } else if (['.pdf', '.docx', '.xlsx'].includes(ext)) {
      showToast(`📄 Document: ${f.name} - Will extract text and scan for secrets`, 'success')
    } else if (['.mp3', '.mp4', '.wav'].includes(ext)) {
      showToast(`🎵 Media file: ${f.name} - Will scan metadata only`, 'success')
    } else {
      showToast(`${getFileIcon(f.name)} Selected: ${f.name}`, 'success')
    }
  }

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = () => {
    setIsDragging(false)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const mockEvent = {
        target: { files: e.dataTransfer.files }
      } as React.ChangeEvent<HTMLInputElement>
      handleFile(mockEvent)
    }
  }

  const handleScan = async () => {
    if (!file) return

    setScanning(true)
    setError(null)
    setResult(null)
    setCompliance(null)
    setScanProgress(0)

    try {
      const fd = new FormData()

      // Note: Even though input has 'multiple', browser FileList from single file input
      // is handled as one file. True multi-file requires different approach.
      fd.append('files', file)  // Changed from 'file' to 'files'

      const progressInterval = setInterval(() => {
        setScanProgress(prev => Math.min(prev + 5, 90))
      }, 500)

      const resp = await fetch(`${BACKEND}/api/scan`, { method: 'POST', body: fd })
      clearInterval(progressInterval)
      setScanProgress(95)

      if (!resp.ok) throw new Error(`Scan failed: ${resp.statusText}`)

      const data = await resp.json()

      if (data.status === 'processing') {
        await pollScanStatus(data.scan_id)
        return
      }

      setScanProgress(100)
      setResult(data)

      try {
        const compResp = await fetch(`${BACKEND}/api/scan/${data.scan_id}/compliance`)
        if (compResp.ok) setCompliance(await compResp.json())
      } catch { }

      if (data.uploaded_files && data.uploaded_files.length > 1) {
        showToast(`✅ Multi-file scan: ${data.uploaded_files.length} files, ${data.total_findings} findings`, 'success')
      } else if (data.is_batch) {
        showToast(`✅ Batch scan: ${data.files_scanned} files, ${data.total_findings} findings`, 'success')
      } else {
        showToast(`✅ Scan complete: ${data.total_findings} findings`, 'success')
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Scan failed'
      setError(msg)
      showToast(msg, 'error')
    } finally {
      setScanning(false)
      setScanProgress(0)
    }
  }

  const pollScanStatus = async (scanId: string) => {
    const maxAttempts = 60
    let attempts = 0

    while (attempts < maxAttempts) {
      try {
        const resp = await fetch(`${BACKEND}/api/scan/${scanId}/status`)
        const status = await resp.json()

        if (status.progress) {
          setScanProgress(status.progress)
        }

        if (status.status === 'completed') {
          setResult(status.result)
          showToast('Background scan completed!', 'success')
          break
        } else if (status.status === 'failed') {
          setError(status.error || 'Scan failed')
          break
        }

        await new Promise(resolve => setTimeout(resolve, 2000))
        attempts++
      } catch {
        break
      }
    }

    setScanning(false)
  }

  const exportJSON = () => {
    if (!result) return
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `atlas-scan-${result.scan_id}.json`
    a.click()
    URL.revokeObjectURL(url)
    showToast('📥 Exported JSON', 'success')
  }

  const exportSBOM = async () => {
    if (!result) return
    try {
      const resp = await fetch(`${BACKEND}/api/scan/${result.scan_id}/sbom`)
      const sbom = await resp.json()
      const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `atlas-sbom-${result.scan_id}.json`
      a.click()
      URL.revokeObjectURL(url)
      showToast('📦 Exported SBOM', 'success')
    } catch {
      showToast('SBOM export failed', 'error')
    }
  }

  const exportPDF = () => {
    if (!result) return
    window.open(`${BACKEND}/api/scan/${result.scan_id}/report/html`, '_blank')
    showToast('📄 Opening report (Ctrl+P to save as PDF)', 'success')
  }

  const getColor = (s: string) => {
    const n = s === 'ERROR' ? 'CRITICAL' : s === 'WARNING' ? 'MEDIUM' : s
    return n === 'CRITICAL' ? '#dc2626' : n === 'HIGH' ? '#ea580c' :
      n === 'MEDIUM' ? '#eab308' : n === 'LOW' ? '#22c55e' : '#64748b'
  }

  const filtered = result?.all_findings.filter(f => {
    if (selectedCat && f.category !== selectedCat) return false
    if (selectedSev) {
      const ns = f.severity === 'ERROR' ? 'CRITICAL' : f.severity === 'WARNING' ? 'MEDIUM' : f.severity
      if (ns !== selectedSev) return false
    }
    if (search) {
      const q = search.toLowerCase()
      return f.message.toLowerCase().includes(q) || f.file.toLowerCase().includes(q) ||
        (f.snippet && f.snippet.toLowerCase().includes(q))
    }
    return true
  }) || []

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 animate-gradient">
      {toast && (
        <div className="fixed top-4 right-4 z-50 px-6 py-4 rounded-xl shadow-2xl animate-slide-in hover-glow"
          style={{ backgroundColor: toast.type === 'success' ? '#10b981' : '#ef4444', color: 'white' }}>
          <div className="flex gap-3 items-center">
            <svg className="w-5 h-5 animate-bounce" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d={toast.type === 'success' ? "M5 13l4 4L19 7" : "M6 18L18 6M6 6l12 12"} />
            </svg>
            <span className="font-medium">{toast.msg}</span>
          </div>
        </div>
      )}

      <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-xl sticky top-0 z-40 glass">
        <div className="container mx-auto px-6 py-4">
          <div className="flex justify-between items-center">
            <div className="flex gap-4 items-center">
              <div className="relative hover-scale transition-smooth">
                <div className="absolute inset-0 bg-blue-500 blur-xl opacity-30 animate-pulse-slow"></div>
                <div className="relative w-12 h-12 bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl flex items-center justify-center hover-glow">
                  <svg className="w-7 h-7 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
              </div>

              <div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
                  ATLAS SYNAPSE
                </h1>
                <p className="text-xs text-blue-400 font-semibold tracking-wider">
                  Trust Engine for AI Systems
                </p>
              </div>
            </div>

            <div className="flex gap-3 items-center">
              {result && (
                <>
                  <button
                    onClick={() => setShowCompliance(!showCompliance)}
                    className="px-3 py-1.5 bg-purple-600 hover:bg-purple-700 text-white rounded-lg text-sm font-medium flex items-center gap-2 hover-lift transition-smooth tooltip"
                    data-tooltip="View compliance framework status">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    Compliance
                  </button>

                  <div className="hidden md:flex gap-4 text-sm">
                    {[{ n: 'Semgrep', c: result.engines.semgrep?.findings?.length || 0 },
                    { n: 'Gitleaks', c: result.engines.gitleaks?.findings?.length || 0 },
                    { n: 'Trivy', c: result.engines.trivy?.findings?.length || 0 },
                    { n: 'CodeQL', c: result.engines.codeql?.findings?.length || 0 }].map(e => (
                      <div key={e.n} className="flex gap-2 items-center hover-scale transition-smooth">
                        <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse-slow"></div>
                        <span className="text-slate-400">{e.n}</span>
                        <span className="text-white font-mono font-bold badge-pulse">{e.c}</span>
                      </div>
                    ))}
                  </div>
                </>
              )}

              <button
                onClick={() => setShowHistory(!showHistory)}
                className="p-2 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-white transition-smooth tooltip hover-scale"
                data-tooltip="View scan history">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        {result && !showHistory && !showCompliance && (
          <>
            {result.is_batch && (
              <div className="mb-4 p-4 bg-blue-900/20 border-2 border-blue-500 rounded-xl animate-fade-in hover-lift transition-smooth">
                <div className="flex items-center gap-3">
                  <svg className="w-5 h-5 text-blue-400 animate-bounce" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <p className="text-blue-300 font-medium">
                    📦 Batch Scan: {result.files_scanned} files analyzed from archive
                  </p>
                </div>
              </div>
            )}

            <div className="mb-8 p-8 rounded-2xl border-2 shadow-2xl animate-fade-in hover-lift transition-smooth"
              style={{ backgroundColor: `${getColor(result.ai_analysis.risk_level)}08`, borderColor: `${getColor(result.ai_analysis.risk_level)}40` }}>
              <div className="flex justify-between gap-8">
                <div className="flex-1">
                  <div className="flex gap-3 mb-4 items-center">
                    <h2 className="text-4xl font-black text-white">
                      RISK: {result.ai_analysis.risk_score}<span className="text-slate-500">/100</span>
                    </h2>
                    <div className="px-4 py-2 rounded-lg font-bold text-sm animate-glow"
                      style={{ backgroundColor: getColor(result.ai_analysis.risk_level), color: 'white' }}>
                      {result.ai_analysis.risk_level}
                    </div>
                  </div>
                  <p className="text-slate-300 text-lg mb-4 leading-relaxed">{result.ai_analysis.executive_summary}</p>
                  {result.ai_analysis.top_priorities && (
                    <div className="space-y-2">
                      {result.ai_analysis.top_priorities.slice(0, 3).map((p, i) => (
                        <div key={i} className="flex gap-3 text-sm hover-lift transition-smooth">
                          <span className="px-2 py-0.5 rounded bg-blue-500 text-white font-bold text-xs">P{i + 1}</span>
                          <span className="text-slate-400">{p}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="flex flex-col gap-2">
                  <button onClick={exportJSON}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-sm font-medium flex gap-2 items-center hover-lift transition-smooth tooltip"
                    data-tooltip="Export as JSON">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3" />
                    </svg>
                    JSON
                  </button>
                  <button onClick={exportSBOM}
                    className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-sm font-medium flex gap-2 items-center hover-lift transition-smooth tooltip"
                    data-tooltip="Software Bill of Materials">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586" />
                    </svg>
                    SBOM
                  </button>
                  <button onClick={exportPDF}
                    className="px-4 py-2 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-sm font-medium flex gap-2 items-center hover-lift transition-smooth tooltip"
                    data-tooltip="Executive PDF report">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414" />
                    </svg>
                    PDF
                  </button>
                </div>
              </div>
            </div>
          </>
        )}

        {showCompliance && compliance && (
          <div className="mb-8 animate-fade-in">
            <div className="flex justify-between mb-6">
              <h2 className="text-2xl font-bold text-white">Compliance Assessment</h2>
              <button onClick={() => setShowCompliance(false)} className="text-slate-400 hover:text-white hover-scale transition-smooth">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-6 mb-6 hover-lift transition-smooth">
              <h3 className="text-lg font-bold text-white mb-4">Overall Status</h3>
              <p className="text-2xl font-bold mb-2" style={{ color: compliance.overall_status.critical_blockers > 0 ? '#dc2626' : '#22c55e' }}>
                {compliance.overall_status.recommendation}
              </p>
              <div className="grid grid-cols-2 gap-4 text-sm mt-4">
                <div className="hover-scale transition-smooth">
                  <span className="text-slate-500">Critical Blockers:</span>
                  <span className="ml-2 text-white font-bold badge-pulse">{compliance.overall_status.critical_blockers}</span>
                </div>
                <div className="hover-scale transition-smooth">
                  <span className="text-slate-500">Est. Remediation:</span>
                  <span className="ml-2 text-white font-bold">{compliance.overall_status.estimated_remediation_time}</span>
                </div>
              </div>
            </div>

            <div className="grid gap-4">
              {Object.entries(compliance.frameworks).map(([id, data]: [string, any]) => (
                <div key={id} className="bg-slate-900/50 rounded-xl border border-slate-800 p-6 hover-lift hover-glow transition-smooth">
                  <div className="flex justify-between items-start mb-3">
                    <div>
                      <h4 className="text-white font-bold">{data.name}</h4>
                      <p className="text-sm text-slate-500 mt-1">{id}</p>
                    </div>
                    <div className="text-right">
                      <div className="text-2xl font-bold badge-pulse" style={{ color: data.violations === 0 ? '#22c55e' : data.violations < 5 ? '#eab308' : '#dc2626' }}>
                        {data.compliance_percentage}%
                      </div>
                      <div className="text-xs text-slate-500">Compliance</div>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-4 text-sm">
                    <div className="hover-scale transition-smooth">
                      <span className="text-slate-500">Violations:</span>
                      <span className="ml-2 text-white font-bold">{data.violations}</span>
                    </div>
                    <div className="hover-scale transition-smooth">
                      <span className="text-slate-500">Controls:</span>
                      <span className="ml-2 text-white font-bold">{data.controls_affected.length}</span>
                    </div>
                    <div className="hover-scale transition-smooth">
                      <span className="text-slate-500">Critical:</span>
                      <span className="ml-2 text-red-400 font-bold">{data.severity_distribution?.CRITICAL || 0}</span>
                    </div>
                  </div>

                  {data.controls_affected.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-slate-800">
                      <p className="text-xs text-slate-500 mb-2">Affected Controls:</p>
                      <div className="flex flex-wrap gap-2">
                        {data.controls_affected.slice(0, 5).map((ctrl: string) => (
                          <span key={ctrl} className="px-2 py-1 bg-slate-800 text-slate-300 rounded text-xs font-mono hover-scale transition-smooth">
                            {ctrl.split(' - ')[0]}
                          </span>
                        ))}
                        {data.controls_affected.length > 5 && (
                          <span className="px-2 py-1 bg-slate-800 text-slate-500 rounded text-xs">
                            +{data.controls_affected.length - 5} more
                          </span>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        {!showHistory && !showCompliance && (
          <div className="grid lg:grid-cols-3 gap-8">
            <div className="space-y-6">
              <div className="bg-slate-900/50 rounded-2xl border border-slate-800 p-6 glass hover-lift transition-smooth">
                <h3 className="text-lg font-bold text-white mb-4 tracking-wide">SCAN TARGET</h3>

                <div className="space-y-4">
                  <div
                    className={`relative border-2 border-dashed rounded-xl p-10 text-center transition-all ${isDragging
                      ? 'border-blue-500 bg-blue-500/20 scale-105'
                      : 'border-slate-700 hover:border-blue-500 hover:bg-blue-500/5'
                      } group`}
                    onDragOver={handleDragOver}
                    onDragLeave={handleDragLeave}
                    onDrop={handleDrop}
                  >
                    <input
                      type="file"
                      multiple
                      onChange={handleFile}
                      accept=".py,.js,.ts,.java,.go,.rb,.php,.c,.cpp,.cs,.html,.pdf,.docx,.xlsx,.zip,.json,.xml,.mp3,.mp4,.wav"
                      className="absolute inset-0 opacity-0 cursor-pointer"
                    />

                    <svg className={`w-14 h-14 mx-auto mb-4 transition-all ${isDragging ? 'text-blue-500 scale-125' : 'text-slate-600 group-hover:text-blue-500'}`}
                      fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                    </svg>

                    {file ? (
                      <div className="animate-fade-in">
                        <p className="text-blue-400 font-semibold flex items-center justify-center gap-2">
                          <span className="text-2xl">{getFileIcon(file.name)}</span>
                          {file.name}
                        </p>
                        <p className="text-xs text-slate-500 mt-1">
                          {(file.size / 1024).toFixed(1)} KB
                          {file.name.endsWith('.zip') && ' • Archive'}
                        </p>
                      </div>
                    ) : (
                      <div>
                        <p className="text-slate-400 font-medium mb-2">
                          {isDragging ? '📂 Drop file here' : 'Drop file or click to browse'}
                        </p>
                        <p className="text-xs text-slate-600 font-mono mt-1">
                          Code • Documents • Web • Media • Archives
                        </p>
                        <div className="mt-3 flex flex-wrap gap-1 justify-center">
                          {['🐍.py', '⚡.js', '☕.java', '📄.pdf', '📝.docx', '📊.xlsx', '🌐.html', '📦.zip', '🎵.mp3', '🎬.mp4'].map(t => (
                            <span key={t} className="text-xs text-slate-700 px-2 py-1 bg-slate-800/30 rounded hover-scale transition-smooth">
                              {t}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  <button
                    onClick={handleScan}
                    disabled={!file || scanning}
                    className="w-full py-4 bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-600 disabled:from-slate-700 disabled:to-slate-700 text-white font-bold rounded-xl text-sm hover-lift transition-smooth disabled:cursor-not-allowed">
                    {scanning ? (
                      <span className="flex items-center justify-center gap-2">
                        <svg className="animate-spin h-5 w-5" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        SCANNING... {scanProgress > 0 && `${scanProgress}%`}
                      </span>
                    ) : (
                      'INITIATE SCAN'
                    )}
                  </button>

                  {scanProgress > 0 && scanning && (
                    <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-blue-600 to-blue-400 transition-all duration-500 animate-shimmer"
                        style={{ width: `${scanProgress}%` }}
                      ></div>
                    </div>
                  )}

                  {error && (
                    <div className="p-4 bg-red-900/20 border-2 border-red-500 rounded-xl animate-fade-in">
                      <div className="flex items-start gap-3">
                        <svg className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <p className="text-red-400 text-sm">{error}</p>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {result && (
                <div className="bg-slate-900/50 rounded-2xl border border-slate-800 p-6 glass hover-lift transition-smooth">
                  <h3 className="text-lg font-bold text-white mb-4 tracking-wide">SEVERITY</h3>
                  <div className="space-y-3">
                    {Object.entries(result.severity_breakdown).map(([s, c]) => c > 0 && (
                      <div key={s} className="flex justify-between hover-scale transition-smooth">
                        <div className="flex gap-3 items-center">
                          <div className="w-3 h-3 rounded-full animate-pulse-slow" style={{ backgroundColor: getColor(s) }}></div>
                          <span className="text-slate-300 text-sm font-medium">{s}</span>
                        </div>
                        <span className="text-white font-bold font-mono badge-pulse">{c}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="lg:col-span-2 space-y-6">
              {result && (
                <>
                  <div className="bg-slate-900/50 rounded-2xl border border-slate-800 p-6 glass animate-fade-in hover-lift transition-smooth">
                    <h3 className="text-lg font-bold text-white mb-6 tracking-wide">
                      RISK HEATMAP
                      <span className="ml-4 text-sm font-normal text-slate-500">
                        {result.total_findings} findings{result.is_batch && ` across ${result.files_scanned} files`}
                      </span>
                    </h3>

                    <table className="w-full">
                      <thead>
                        <tr>
                          <th className="p-3 text-left text-xs text-slate-600 uppercase tracking-wider"></th>
                          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s =>
                            <th key={s} className="p-3 text-center text-xs text-slate-500 font-bold uppercase tracking-wider">{s}</th>
                          )}
                        </tr>
                      </thead>
                      <tbody>
                        {['SAST', 'Secrets', 'SCA', 'Deep Analysis'].map((cat, idx) => (
                          <tr key={cat} className="border-t border-slate-800">
                            <td className="p-3 text-sm text-slate-400 font-bold">{cat}</td>
                            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
                              const cell = result.heatmap_data.find(d => d.category === cat && d.severity === sev)
                              const count = cell?.count || 0
                              return (
                                <td
                                  key={sev}
                                  onClick={() => {
                                    setSelectedCat(cat);
                                    setSelectedSev(sev);
                                    if (count > 0) showToast(`Filtered to ${cat} / ${sev}`, 'success')
                                  }}
                                  className="p-3 text-center cursor-pointer hover:ring-2 hover:ring-blue-400 hover:scale-105 rounded-lg transition-all"
                                  style={{
                                    backgroundColor: count > 0 ? `${getColor(sev)}${Math.floor((cell?.normalized || 0) * 180).toString(16).padStart(2, '0')}` : '#1e293b',
                                    animationDelay: `${idx * 100}ms`
                                  }}>
                                  <span className="text-white font-black text-lg">{count}</span>
                                </td>
                              )
                            })}
                          </tr>
                        ))}
                      </tbody>
                    </table>

                    {(selectedCat || selectedSev) && (
                      <div className="mt-4 flex items-center gap-3">
                        <span className="text-sm text-slate-400">
                          Showing {filtered.length} of {result.all_findings.length}
                        </span>
                        <button
                          onClick={() => { setSelectedCat(null); setSelectedSev(null); setSearch('') }}
                          className="text-sm text-blue-400 hover:text-blue-300 font-medium transition-smooth hover-scale">
                          Clear filters
                        </button>
                      </div>
                    )}
                  </div>

                  <div className="bg-slate-900/50 rounded-2xl border border-slate-800 p-6 glass animate-fade-in hover-lift transition-smooth">
                    <div className="flex gap-4 mb-6">
                      <h3 className="text-lg font-bold text-white flex-1 tracking-wide">AUDIT LOG</h3>
                      <div className="relative flex-1 max-w-md">
                        <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                        </svg>
                        <input
                          type="text"
                          value={search}
                          onChange={(e) => setSearch(e.target.value)}
                          placeholder="Search findings..."
                          className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-sm transition-all"
                        />
                      </div>
                    </div>

                    <div className="space-y-3 max-h-[700px] overflow-y-auto custom-scrollbar">
                      {filtered.length === 0 ? (
                        <p className="text-slate-500 text-center py-12">No findings match filters</p>
                      ) : (
                        filtered.map((f, i) => {
                          const isExp = expanded === f.id + i
                          return (
                            <div
                              key={i}
                              className="rounded-xl border-2 cursor-pointer hover-lift transition-all"
                              style={{
                                backgroundColor: `${getColor(f.severity)}08`,
                                borderColor: `${getColor(f.severity)}40`,
                                animationDelay: `${i * 50}ms`
                              }}
                              onClick={() => setExpanded(isExp ? null : f.id + i)}>
                              <div className="p-5">
                                <div className="flex justify-between mb-3">
                                  <div className="flex gap-2 flex-wrap items-center">
                                    <span className="px-3 py-1 rounded-lg text-xs font-black hover-glow transition-smooth"
                                      style={{ backgroundColor: getColor(f.severity), color: 'white' }}>
                                      {f.severity}
                                    </span>
                                    <span className="px-2 py-1 bg-slate-800 text-slate-300 rounded text-xs uppercase hover-scale transition-smooth">
                                      {f.engine}
                                    </span>
                                    {f.cwe && (
                                      <span className="text-xs text-slate-500 font-mono hover-scale transition-smooth">
                                        {Array.isArray(f.cwe) ? f.cwe[0] : f.cwe}
                                      </span>
                                    )}
                                  </div>
                                  <span className="text-xs text-slate-500 font-mono whitespace-nowrap">
                                    <span className="text-lg mr-1">{getFileIcon(f.file)}</span>
                                    {f.file}:{f.line_start}
                                  </span>
                                </div>

                                <p className="text-slate-200 mb-3 leading-relaxed">{f.message}</p>

                                {f.snippet && (
                                  <pre className="text-xs bg-slate-950/50 p-3 rounded-lg border border-slate-800 text-slate-400 font-mono overflow-x-auto hover:bg-slate-950/70 transition-all">
                                    {isExp ? f.snippet : (f.snippet.substring(0, 100) + (f.snippet.length > 100 ? '...' : ''))}
                                  </pre>
                                )}

                                <div className="mt-3 flex items-center justify-between">
                                  <span className="text-xs text-slate-600">{isExp ? 'Click to collapse' : 'Click for details'}</span>
                                  <svg
                                    className={`w-4 h-4 text-slate-600 transition-transform ${isExp ? 'rotate-180' : ''}`}
                                    fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                  </svg>
                                </div>
                              </div>
                            </div>
                          )
                        })
                      )}
                    </div>
                  </div>
                </>
              )}

              {!result && !scanning && (
                <div className="bg-slate-900/30 rounded-2xl border border-slate-800 p-16 text-center glass hover-lift transition-smooth">
                  <div className="relative inline-block mb-6">
                    <div className="absolute inset-0 bg-blue-500 blur-2xl opacity-20 animate-pulse-slow"></div>
                    <svg className="relative w-20 h-20 text-slate-700 hover-scale transition-smooth" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                  </div>
                  <h3 className="text-xl font-bold text-slate-300 mb-2">Ready to Scan</h3>
                  <p className="text-slate-500 mb-1">Upload code, documents, or archives</p>
                  <p className="text-xs text-slate-600">Supports 25+ file formats including PDF, DOCX, ZIP, and media files</p>
                </div>
              )}

              {scanning && (
                <div className="bg-slate-900/50 rounded-2xl border border-slate-800 p-16 text-center glass">
                  <div className="relative inline-block mb-6">
                    <div className="absolute inset-0 bg-blue-500 blur-2xl opacity-40 animate-pulse"></div>
                    <div className="relative animate-spin-slow w-20 h-20 border-4 border-blue-500/20 border-t-blue-500 rounded-full"></div>
                  </div>
                  <h3 className="text-xl font-bold text-white mb-3">Scanning...</h3>
                  <p className="text-slate-400 mb-2">
                    {file?.name.endsWith('.zip')
                      ? 'Extracting and analyzing code files...'
                      : 'Running 4 security engines + AI analysis'}
                  </p>
                  {scanProgress > 0 && (
                    <p className="text-blue-400 font-mono text-sm">{scanProgress}% complete</p>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {showHistory && (
          <div className="animate-fade-in">
            <div className="flex justify-between mb-6">
              <h2 className="text-2xl font-bold text-white">Scan History</h2>
              <button onClick={() => setShowHistory(false)} className="text-slate-400 hover:text-white hover-scale transition-smooth">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            {history.length === 0 ? (
              <div className="bg-slate-900/50 rounded-xl border border-slate-800 p-12 text-center glass">
                <p className="text-slate-500">No scan history yet</p>
              </div>
            ) : (
              <div className="grid gap-4">
                {history.map((s, idx) => (
                  <div
                    key={s.scan_id}
                    onClick={() => {
                      setResult(s);
                      setShowHistory(false);
                      fetch(`${BACKEND}/api/scan/${s.scan_id}/compliance`)
                        .then(r => r.json())
                        .then(setCompliance)
                        .catch(() => { })
                    }}
                    className="bg-slate-900/50 rounded-xl border border-slate-800 p-6 hover:border-blue-500 cursor-pointer hover-lift transition-smooth"
                    style={{ animationDelay: `${idx * 50}ms` }}>
                    <div className="flex justify-between">
                      <div className="flex-1">
                        <div className="flex gap-3 mb-2 items-center">
                          <span className="text-2xl">{getFileIcon(s.file)}</span>
                          <h3 className="text-white font-semibold">{s.file}</h3>
                          {s.is_batch && (
                            <span className="px-2 py-0.5 bg-blue-600 text-white rounded text-xs font-bold animate-glow">
                              {s.files_scanned} files
                            </span>
                          )}
                          <span className="text-xs text-slate-500 font-mono">{s.scan_id}</span>
                        </div>
                        <p className="text-sm text-slate-400">{new Date(s.timestamp).toLocaleString()} • {s.total_findings} findings</p>
                      </div>
                      <div className="text-right">
                        <div className="text-3xl font-bold text-white badge-pulse">{s.ai_analysis.risk_score}</div>
                        <div className="text-xs text-slate-500 uppercase tracking-wide">RISK</div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <footer className="border-t border-slate-800 mt-16 glass">
        <div className="container mx-auto px-6 py-6">
          <div className="flex items-center justify-between text-sm text-slate-500">
            <div className="hover-scale transition-smooth">
              Powered by <span className="text-slate-400 font-semibold">Semgrep</span> • <span className="text-slate-400 font-semibold">Gitleaks</span> • <span className="text-slate-400 font-semibold">Trivy</span> • <span className="text-slate-400 font-semibold">Gemini AI</span>
            </div>
            <div className="hover-scale transition-smooth">
              Built by <span className="text-blue-400 font-semibold">Atlas Synapse LLC</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default App