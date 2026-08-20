import React, {useState} from 'react'
import axios from 'axios'

export default function Login({onLogin, onRegister}){
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [err, setErr] = useState('')
  const base = 'http://127.0.0.1:8000'
  async function doLogin(){
    try{
      const res = await axios.post(base + '/auth/login', {username: user, password: pass})
      onLogin(res.data.access_token)
    }catch(e){ setErr('Login failed') }
  }
  return (
    <div className="max-w-md mx-auto mt-20 bg-gray-800 p-6 rounded">
      <h2 className="text-xl font-semibold mb-4">Login</h2>
      <input className="w-full p-2 mb-2 rounded bg-gray-900" placeholder="username" value={user} onChange={e=>setUser(e.target.value)} />
      <input type="password" className="w-full p-2 mb-2 rounded bg-gray-900" placeholder="password" value={pass} onChange={e=>setPass(e.target.value)} />
      <button className="w-full bg-indigo-600 p-2 rounded" onClick={doLogin}>Login</button>
      <button className="w-full mt-3 border border-gray-600 p-2 rounded" onClick={onRegister}>Create an account</button>
      {err && <div className="text-red-400 mt-2">{err}</div>}
    </div>
  )
}
