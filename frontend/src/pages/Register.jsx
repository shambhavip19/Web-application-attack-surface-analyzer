import React, {useState} from 'react'
import axios from 'axios'

export default function Register({onRegistered, onBack}){
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [confirmPass, setConfirmPass] = useState('')
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')
  const base = 'http://127.0.0.1:8000'

  async function doRegister(event){
    event.preventDefault()
    setError('')
    setMessage('')
    if(!user.trim() || !pass){
      setError('Username and password are required')
      return
    }
    if(pass !== confirmPass){
      setError('Passwords do not match')
      return
    }
    try{
      await axios.post(base + '/auth/register', {username: user.trim(), password: pass})
      setMessage('Account created. You can now log in.')
      setTimeout(onRegistered, 700)
    }catch(e){
      setError(e.response?.data?.detail || 'Registration failed')
    }
  }

  return (
    <form className="max-w-md mx-auto mt-20 bg-gray-800 p-6 rounded" onSubmit={doRegister}>
      <h2 className="text-xl font-semibold mb-4">Create account</h2>
      <input className="w-full p-2 mb-2 rounded bg-gray-900" placeholder="username" value={user} onChange={e=>setUser(e.target.value)} />
      <input type="password" className="w-full p-2 mb-2 rounded bg-gray-900" placeholder="password" value={pass} onChange={e=>setPass(e.target.value)} />
      <input type="password" className="w-full p-2 mb-3 rounded bg-gray-900" placeholder="confirm password" value={confirmPass} onChange={e=>setConfirmPass(e.target.value)} />
      <button className="w-full bg-indigo-600 p-2 rounded" type="submit">Register</button>
      <button className="w-full mt-3 border border-gray-600 p-2 rounded" type="button" onClick={onBack}>Back to login</button>
      {message && <div className="text-green-400 mt-2">{message}</div>}
      {error && <div className="text-red-400 mt-2">{error}</div>}
    </form>
  )
}