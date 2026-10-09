import React from 'react'

const explanations = {
  headers: ['Security Headers', 'Security headers are browser instructions that help reduce common risks such as framing, MIME confusion, and unsafe browser behavior.'],
  cookies: ['Cookies', 'Cookies store small pieces of user state in the browser, and their attributes determine how safely they can be used.'],
  ssl: ['SSL/TLS', 'SSL/TLS protects the connection between a browser and the website so traffic is encrypted and authenticated.'],
  structure: ['Website Analysis', 'These checks show whether the site publishes crawl guidance and whether JavaScript resources are exposed for review.'],
  technology: ['Technologies', 'This identifies technologies that appear to be used by the website based on available evidence from headers, markup, and scripts.'],
  findings: ['Findings', 'Findings represent the most important posture issues from the completed review. Unavailable or uncertain checks are not treated as security failures.']
}

export default function Results({data, scan, history, section, onStart, setSection}) {
  const score = data.score || {}
  if (section === 'overview') return <Overview data={data} scan={scan} history={history} score={score} onStart={onStart} />
  if (section === 'headers') return <Panel title={explanations.headers[0]} text={explanations.headers[1]}><Headers data={data.headers || {}} /></Panel>
  if (section === 'cookies') return <Panel title={explanations.cookies[0]} text={explanations.cookies[1]}><Cookies data={data.cookies || {}} /></Panel>
  if (section === 'ssl') return <Panel title={explanations.ssl[0]} text={explanations.ssl[1]}><SSL data={data.ssl || {}} /></Panel>
  if (section === 'structure') return <Panel title={explanations.structure[0]} text={explanations.structure[1]}><Structure data={data} /></Panel>
  if (section === 'technology') return <Panel title={explanations.technology[0]} text={explanations.technology[1]}><Technology data={data.technologies || {}} /></Panel>
  if (section === 'findings') return <Panel title={explanations.findings[0]} text={explanations.findings[1]}><Findings data={data.findings || []} /></Panel>
  return <Overview data={data} scan={scan} history={history} score={score} onStart={onStart} />
}

function Overview({data, scan, history, score, onStart}) {
  const findings = data.findings || []
  const summary = data.summary || {passed: 0, warnings: 0, failed: 0, informational: 0}
  const recent = (history || []).slice(0, 4)
  const keyFindings = findings.slice(0, 5)

  return <section className="dashboard"><div className="hero-row"><div><span className="eyebrow">WEB APPLICATION ATTACK SURFACE ANALYZER</span><h2>{scan?.url || 'Website currently being analyzed'}</h2><p className="muted">{scan?.created_at ? new Date(scan.created_at).toLocaleString() : 'Most recent scan result'}</p></div><ScoreRing score={score.score} /></div><div className="stat-grid"><Stat label="Passed" value={summary.passed || 0} /><Stat label="Warnings" value={summary.warnings || 0} /><Stat label="Failed" value={summary.failed || 0} /><Stat label="Informational" value={summary.informational || 0} /></div><div className="overview-grid"><div className="card"><h3>Security Posture</h3><Chart data={data} /></div><div className="card"><h3>Key Findings</h3>{keyFindings.length ? keyFindings.map(item => <Finding key={`${item.title}-${item.issue_key || Math.random()}`} item={item} />) : <p className="muted">No important findings were generated from the current scan.</p>}</div></div><div className="card"><div className="card-heading"><h3>Recent Scans</h3><button className="text-button" onClick={onStart}>Start New Analysis</button></div>{recent.length ? <div className="table-wrap"><table><thead><tr><th>Website</th><th>Score</th><th>Risk</th><th>Date</th></tr></thead><tbody>{recent.map(item => <tr key={item.id}><td className="strong">{item.url}</td><td>{item.score ?? '—'}</td><td><Status value={item.risk_level || 'Could Not Determine'} /></td><td>{new Date(item.created_at).toLocaleString()}</td></tr>)}</tbody></table></div> : <p className="muted">No recent scan history is available yet.</p>}</div><button className="primary" onClick={onStart}>Start New Analysis</button></section>
}

function Panel({title, text, children}) {
  return <section className="page-section"><div className="section-heading"><div><span className="eyebrow">ANALYSIS MODULE</span><h2>{title}</h2></div></div><div className="explain"><span>?</span><div><b>What is this?</b><p>{text}</p></div></div>{children}</section>
}

function ScoreRing({score}) {
  const value = typeof score === 'number' ? Math.max(0, Math.min(100, score)) : 0
  return <div className="score-ring" style={{'--score': `${value}%`}} aria-label={`Score ${score ?? 'unavailable'} out of 100`}><strong>{score ?? '—'}</strong><span>/ 100</span></div>
}

function Headers({data}) {
  const details = Object.entries(data.details || {})
  if (!details.length) return <div className="card"><p className="muted">No header details were available for this scan.</p></div>
  return <div className="card"><div className="result-line"><Status value={data.status || 'COULD NOT DETERMINE'} /><span>{data.final_url || 'Final response URL'}</span></div>{details.map(([name, detail]) => <div key={name} className="finding full"><div className="finding-title"><Status value={detail.status} /><b>{detail.title || name}</b></div><p><b>Actual value:</b> {detail.value || 'Not set'}</p><p><b>What it does:</b> {detail.what_it_does}</p><p><b>Why it matters:</b> {detail.why_it_matters}</p><p><b>Recommendation:</b> {detail.recommendation}</p><p><b>Summary:</b> {detail.explanation}</p></div>)}</div>
}

function Cookies({data}) {
  if (!data) return <div className="card"><p className="muted">No cookie information was returned.</p></div>
  return <div className="card"><div className="result-line"><Status value={data.status || 'COULD NOT DETERMINE'} /><span>{data.count ?? 0} cookie{(data.count || 0) === 1 ? '' : 's'} observed</span></div>{data.cookies?.length ? <div className="table-wrap"><table><thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Attributes</th></tr></thead><tbody>{data.cookies.map(cookie => <tr key={`${cookie.name}-${cookie.raw}`}><td className="strong">{cookie.name}</td><td><BooleanValue value={cookie.secure} /></td><td><BooleanValue value={cookie.httponly} /></td><td>{cookie.samesite || 'Not set'}</td><td>{cookie.raw || 'Not available'}</td></tr>)}</tbody></table></div> : <p className="muted">No cookies were returned by the final HTTP response.</p>}</div>
}

function SSL({data}) {
  if (!data) return <div className="card"><p className="muted">No SSL/TLS information was returned.</p></div>
  return <div className="card"><div className="result-line"><Status value={data.status || 'COULD NOT DETERMINE'} /><span>{data.note || (data.https ? 'Encrypted HTTPS connection' : 'No HTTPS certificate was detected')}</span></div>{data.certificate && <div className="cert-grid"><Metric title="Subject" value={data.subject || 'Not available'} /><Metric title="Issuer" value={data.issuer || 'Not available'} /><Metric title="Valid until" value={data.not_after || 'Not available'} /><Metric title="Days remaining" value={data.days_until_expiry ?? 'Not available'} /></div>}{!data.certificate && <p className="muted">{data.error || 'TLS certificate details were not available.'}</p>}</div>
}

function Structure({data}) {
  return <div className="overview-grid"><Resource title="robots.txt" data={data.robots} /><Resource title="sitemap.xml" data={data.sitemap} /><Resource title="JavaScript resources" data={data.javascript} /></div>
}

function Resource({title, data = {}}) {
  const content = data.content || data.scripts?.join('\n')
  return <div className="card"><h3>{title}</h3><div className="result-line"><Status value={data.status || (content ? 'AVAILABLE' : 'NOT AVAILABLE')} /></div>{content ? <pre>{content}</pre> : <p className="muted">{data.error || 'No content was returned or the resource was not found.'}</p>}</div>
}

function Technology({data}) {
  if (!data || data.available === false) return <div className="card"><p className="muted">{data?.error || 'No technology signals were available for this scan.'}</p></div>
  return <div className="card">{data.technologies?.length ? data.technologies.map(item => <div className="tech-row" key={`${item.technology}-${item.value}`}><div><h3>{item.technology}</h3><p>{item.value}</p></div><div className="tech-evidence"><span className="tag">{item.confidence || 'Possible'}</span><small>Evidence: {item.evidence || 'Not enough evidence'}</small></div></div>) : <p className="muted">{data.message || 'Not enough evidence to identify a framework or library.'}</p>}</div>
}

function Findings({data}) {
  return <div className="card">{data.length ? data.map(item => <Finding key={`${item.title}-${item.issue_key || item.severity}`} item={item} full />) : <p className="muted">No findings were generated from the completed checks.</p>}</div>
}

function Finding({item, full}) {
  return <div className={full ? 'finding full' : 'finding'}><div className="finding-title"><Status value={item.severity} /><b>{item.title}</b></div><p>{item.explanation}</p>{full && <><p className="evidence"><b>Evidence:</b> {item.evidence || 'Not supplied'}</p><p className="recommendation"><b>Recommendation:</b> {item.recommendation}</p></>}</div>
}

function Chart({data}) {
  const counts = data.severity_counts || {}
  const levels = ['Critical', 'High', 'Medium', 'Low', 'Informational']
  const total = levels.reduce((sum, level) => sum + (counts[level] || 0), 0)
  const max = Math.max(...levels.map(level => counts[level] || 0), 1)
  return <div className="chart">{levels.map(level => <div className="bar-row" key={level}><span>{level}</span><div><i className={level.toLowerCase()} style={{width: `${Math.max(0, (counts[level] || 0) / max * 100)}%`}} /></div><b>{counts[level] || 0}</b></div>)}<p className="muted chart-total">Total findings: {total}</p></div>
}

function Stat({label, value}) { return <div className="stat"><span>{label}</span><strong>{value}</strong></div> }
function Metric({title, value}) { return <div className="metric"><span>{title}</span><strong>{value}</strong></div> }
function Status({value}) { return <span className="status">{value}</span> }
function BooleanValue({value}) { return <span className={value ? 'boolean yes' : 'boolean no'}>{value ? 'Yes' : 'No'}</span> }
