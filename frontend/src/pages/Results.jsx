import React from 'react'

export default function Results({data}){
  if(!data) return null
  const score = data.score || {}
  const headers = data.headers || {}
  const cookies = data.cookies || {}
  const technologies = data.technologies?.technologies || []
  const certificate = data.ssl?.certificate
  const list = (value) => Array.isArray(value) && value.length ? value.join('\n') : 'Not detected'
  return (
    <div className="bg-gray-800 p-4 rounded">
      <h3 className="text-lg font-semibold mb-2">Results</h3>
      {data.error && <div className="text-red-400">{data.error}</div>}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <div className="font-bold">Security Score</div>
          <div className="text-3xl">{score.score ?? 'Unavailable'}</div>
        </div>
        <div>
          <div className="font-bold">Risk Level</div>
          <div>{score.level || 'Unavailable'}</div>
        </div>
      </div>
      <div className="mt-4">
        <h4 className="font-semibold">Headers</h4>
        <div className="text-sm bg-gray-900 p-2 rounded">
          <div>Response: {headers.available ? `${headers.status_code} ${headers.final_url || ''}` : 'Unavailable'}</div>
          <div>Present: {list(headers.present)}</div>
          <div>Missing: {list(headers.missing)}</div>
        </div>
      </div>
      <div className="mt-4">
        <h4 className="font-semibold">Cookies</h4>
        <pre className="text-sm bg-gray-900 p-2 rounded max-h-48 overflow-auto">{cookies.available ? JSON.stringify(cookies.cookies || [], null, 2) : 'Unavailable'}</pre>
      </div>
      <div className="mt-4">
        <h4 className="font-semibold">SSL/TLS</h4>
        <pre className="text-sm bg-gray-900 p-2 rounded max-h-48 overflow-auto">{certificate ? JSON.stringify({subject: certificate.subject, issuer: certificate.issuer, validFrom: certificate.notBefore, validUntil: certificate.notAfter}, null, 2) : (data.ssl?.note || data.ssl?.error || 'Not detected')}</pre>
      </div>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <div><h4 className="font-semibold">robots.txt</h4><pre className="text-sm bg-gray-900 p-2 rounded max-h-32 overflow-auto">{data.robots?.content || (data.robots?.status_code ? `HTTP ${data.robots.status_code}` : 'Unavailable')}</pre></div>
        <div><h4 className="font-semibold">sitemap.xml</h4><pre className="text-sm bg-gray-900 p-2 rounded max-h-32 overflow-auto">{data.sitemap?.content || (data.sitemap?.status_code ? `HTTP ${data.sitemap.status_code}` : 'Unavailable')}</pre></div>
      </div>
      <div className="mt-4">
        <h4 className="font-semibold">Technologies</h4>
        <div className="text-sm bg-gray-900 p-2 rounded">{technologies.length ? technologies.map(item => <div key={`${item.name}-${item.value}`}>{item.name}: {item.value} <span className="text-gray-400">({item.evidence})</span></div>) : 'No known technologies detected'}</div>
      </div>
      <div className="mt-4">
        <h4 className="font-semibold">JavaScript resources</h4>
        <pre className="text-sm bg-gray-900 p-2 rounded max-h-32 overflow-auto">{list(data.javascript?.scripts)}</pre>
      </div>
      <div className="mt-4">
        <h4 className="font-semibold">Recommendations</h4>
        <div className="text-sm bg-gray-900 p-2 rounded">{list(data.recommendations)}</div>
      </div>
    </div>
  )
}
