import React from 'react'

export default function Results({data}){
  if(!data) return null
  const score = data.score || {}
  return (
    <div className="bg-gray-800 p-4 rounded">
      <h3 className="text-lg font-semibold mb-2">Results</h3>
      {data.error && <div className="text-red-400">{data.error}</div>}
      <div className="grid grid-cols-2 gap-4">
        <div>
          <div className="font-bold">Security Score</div>
          <div className="text-3xl">{score.score ?? 'N/A'}</div>
        </div>
        <div>
          <div className="font-bold">Risk Level</div>
          <div>{score.level || 'N/A'}</div>
        </div>
      </div>
      <div className="mt-4">
        <h4 className="font-semibold">Headers</h4>
        <pre className="text-sm bg-gray-900 p-2 rounded max-h-48 overflow-auto">{JSON.stringify(data.headers, null, 2)}</pre>
      </div>
      <div className="mt-4">
        <h4 className="font-semibold">Cookies</h4>
        <pre className="text-sm bg-gray-900 p-2 rounded max-h-48 overflow-auto">{JSON.stringify(data.cookies, null, 2)}</pre>
      </div>
    </div>
  )
}
