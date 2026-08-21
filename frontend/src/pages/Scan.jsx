import React, {useState} from 'react'
import axios from 'axios'

export default function Scan({token, onResult}){
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const base = 'http://127.0.0.1:8000'
  async function start(){
    if(!url.trim()){
      setError('Enter a URL to analyze')
      return
    }
    setLoading(true)
    setError('')
    try{
      const res = await axios.post(base + '/scan/start', {url}, {headers: {Authorization: `Bearer ${token}`}})
      onResult(res.data.result)
    }catch(e){
      console.error(e)
      const detail = e.response?.data?.detail
      setError(detail || 'Cannot connect to the backend. Start FastAPI on http://127.0.0.1:8000 and try again.')
      onResult(null)
    }finally{ setLoading(false) }
  }
  return (
    <div className="mb-6">
      <div className="flex gap-2">
        <input className="flex-1 p-2 rounded bg-gray-800" placeholder="https://example.com" value={url} onChange={e=>setUrl(e.target.value)} />
        <button className="bg-green-600 p-2 rounded" onClick={start} disabled={loading}>{loading? 'Scanning...':'Analyze'}</button>
      </div>
      {error && <div className="text-red-400 mt-2">{error}</div>}
    </div>
  )
}
