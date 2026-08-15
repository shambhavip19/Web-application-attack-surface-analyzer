import React, {useState} from 'react'
import axios from 'axios'

export default function Scan({token, onResult}){
  const [url, setUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const base = 'http://127.0.0.1:8000'
  async function start(){
    setLoading(true)
    try{
      const res = await axios.post(base + '/scan/start', {url}, {headers: {Authorization: `Bearer ${token}`}})
      onResult(res.data.result)
    }catch(e){
      console.error(e)
      onResult({error: 'Scan failed'})
    }finally{ setLoading(false) }
  }
  return (
    <div className="mb-6">
      <div className="flex gap-2">
        <input className="flex-1 p-2 rounded bg-gray-800" placeholder="https://example.com" value={url} onChange={e=>setUrl(e.target.value)} />
        <button className="bg-green-600 p-2 rounded" onClick={start} disabled={loading}>{loading? 'Scanning...':'Analyze'}</button>
      </div>
    </div>
  )
}
