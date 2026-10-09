import React, {useEffect, useState} from 'react'
import axios from 'axios'
import Login from './pages/Login'
import Register from './pages/Register'
import Scan from './pages/Scan'
import Results from './pages/Results'

const base = 'http://127.0.0.1:8000'
const nav = [
  ['overview', '◈', 'Dashboard'],
  ['scan', '+', 'New Scan'],
  ['headers', '▤', 'Security Headers'],
  ['cookies', '◌', 'Cookies'],
  ['ssl', '⌁', 'SSL/TLS'],
  ['structure', '⌘', 'Website Analysis'],
  ['technology', '◫', 'Technologies'],
  ['findings', '!', 'Findings'],
  ['history', '◷', 'Scan History'],
  ['reports', '▣', 'Reports'],
]

export default function App(){
  const [token, setToken] = useState(localStorage.getItem('token'))
  const [scan, setScan] = useState(null)
  const [history, setHistory] = useState([])
  const [section, setSection] = useState('overview')
  const [showRegister, setShowRegister] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  function logout(){ localStorage.removeItem('token'); setToken(null); setScan(null) }
  async function loadHistory(){
    setLoading(true); setError('')
    try {
      const response = await axios.get(base + '/scan/history', {headers: {Authorization: `Bearer ${token}`}})
      setHistory(response.data)
      if (!scan && response.data.length) await openScan(response.data[0].id)
    } catch (err) { if (err.response?.status === 401) logout(); else setError('Could not load scan history.') }
    finally { setLoading(false) }
  }
  useEffect(() => { if (token) loadHistory() }, [token])
  async function openScan(id){
    try { const response = await axios.get(`${base}/scan/${id}`, {headers: {Authorization: `Bearer ${token}`}}); setScan(response.data); setSection('overview') }
    catch (err) { if (err.response?.status === 401) logout(); else setError('Could not open this scan.') }
  }
  async function downloadReport(id){
    try {
      const response = await axios.get(`${base}/scan/report/${id}`, {headers: {Authorization: `Bearer ${token}`}, responseType: 'blob'})
      const link = document.createElement('a'); link.href = URL.createObjectURL(response.data); link.download = `wasa-report-${id}.pdf`; link.click(); URL.revokeObjectURL(link.href)
      await loadHistory()
    } catch { setError('Could not generate this report.') }
  }
  if (!token) return showRegister ? <Register onRegistered={() => setShowRegister(false)} onBack={() => setShowRegister(false)} /> : <Login onLogin={t => {setToken(t); localStorage.setItem('token', t)}} onRegister={() => setShowRegister(true)} />
  const result = scan?.result
  return <div className="app-shell">
    <aside className="sidebar"><div className="brand"><span className="brand-mark">✦</span><span>WASA<small>SECURITY ANALYZER</small></span></div><div className="side-label">Workspace</div><nav>{nav.map(([id, icon, label], index) => <button key={`${id}-${index}`} className={section === id ? 'nav-item active' : 'nav-item'} onClick={() => setSection(id)}><b>{icon}</b>{label}</button>)}</nav><button className="logout" onClick={logout}>↪ Sign out</button></aside>
    <main className="main-content"><header className="topbar"><div><span className="eyebrow">SECURITY OPERATIONS</span><h1>{section === 'scan' ? 'Start a new analysis' : section === 'reports' ? 'Reports' : 'Web Application Attack Surface Analyzer'}</h1></div><div className="top-actions"><span className="live-dot">● System ready</span></div></header>
      {error && <div className="error-banner">{error}</div>}
      {section === 'scan' && <Scan token={token} onResult={data => {setScan(data); setSection('overview'); loadHistory()}} onUnauthorized={logout} />}
      {section === 'history' && <History items={history} loading={loading} onOpen={openScan} />}
      {section === 'reports' && <Reports items={history} onOpen={openScan} onDownload={downloadReport} />}
      {section !== 'scan' && section !== 'history' && section !== 'reports' && <Dashboard result={result} scan={scan} history={history} section={section} setSection={setSection} onStart={() => setSection('scan')} />}
    </main>
  </div>
}

function Dashboard({result, scan, history, section, setSection, onStart}){
  if (!result) return <Welcome onStart={onStart} />
  return <Results data={result} scan={scan} history={history} section={section} onStart={onStart} setSection={setSection} />
}
function Welcome({onStart}){const cards=[['Security Headers','Browser instructions that help reduce common web attacks.'],['Cookies','Browser storage and security attributes returned by the site.'],['SSL/TLS','Whether the connection is encrypted and its certificate details.'],['Website Structure','robots.txt, sitemap.xml, and public JavaScript resources.'],['Technology Detection','Evidence-based server, framework, and library signals.']];return <section className="welcome"><span className="eyebrow">WEB SECURITY ANALYSIS</span><h2>Web Application Attack Surface Analyzer</h2><p>Analyze publicly accessible website configuration and understand its security posture.</p><button className="primary start-button" onClick={onStart}>+ Start New Analysis</button><div className="welcome-grid">{cards.map(([title,text])=><article className="card" key={title}><span className="feature-icon">◇</span><h3>{title}</h3><p>{text}</p></article>)}</div></section>}
function History({items,loading,onOpen}){return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">ARCHIVE</span><h2>Scan history</h2></div><span className="muted">{items.length} saved scan{items.length === 1 ? '' : 's'}</span></div>{loading ? <Loading /> : items.length ? <div className="table-wrap"><table><thead><tr><th>Website</th><th>Score</th><th>Risk</th><th>Findings</th><th>Scan date</th><th>ID</th><th></th></tr></thead><tbody>{items.map(item => <tr key={item.id}><td className="strong">{item.url}</td><td>{item.score ?? '—'}</td><td><span className="status">{item.risk_level}</span></td><td>{item.finding_count}</td><td>{new Date(item.created_at).toLocaleString()}</td><td>#{item.id}</td><td><button className="text-button" onClick={() => onOpen(item.id)}>View scan →</button></td></tr>)}</tbody></table></div> : <Empty title="No scan history" text="Completed scans will appear here." />}</section>}
function Reports({items,onOpen,onDownload}){return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">DOCUMENT CENTER</span><h2>Reports</h2></div></div>{items.length ? <div className="report-grid">{items.map(item => <article className="report-card" key={item.id}><span className="report-icon">▣</span><div><h3>{item.url}</h3><p>{new Date(item.created_at).toLocaleString()} · Score {item.score ?? '—'} · {item.risk_level}</p><p className={item.report_available ? 'good' : 'muted'}>{item.report_available ? 'Generated report available' : 'Not generated yet'}</p></div><div className="report-actions"><button className="text-button" onClick={() => onOpen(item.id)}>View</button><button className="primary small" onClick={() => onDownload(item.id)}>{item.report_available ? 'Download PDF' : 'Generate / Download PDF'}</button></div></article>)}</div> : <Empty title="No reports yet" text="Run a scan to generate your first report." />}</section>}
function Empty({title,text}){return <div className="empty-state"><span className="empty-mark">⌁</span><h2>{title}</h2><p>{text}</p></div>}
function Loading(){return <div className="loading"><span className="spinner" />Loading scan history...</div>}
