import React from 'react'
import { useState } from 'react'
import Login from './pages/Login'
import Register from './pages/Register'
import Scan from './pages/Scan'
import Results from './pages/Results'

export default function App(){
  const [token, setToken] = useState(localStorage.getItem('token'))
  const [scanResult, setScanResult] = useState(null)
  const [showRegister, setShowRegister] = useState(false)
  if(!token) {
    return showRegister ? (
      <Register onRegistered={() => setShowRegister(false)} onBack={() => setShowRegister(false)} />
    ) : (
      <Login onLogin={(t)=>{setToken(t); localStorage.setItem('token', t)}} onRegister={() => setShowRegister(true)} />
    )
  }
  return (
    <div className="min-h-screen bg-gray-900 text-gray-100 p-6">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-2xl font-bold mb-4">Web Application Attack Surface Analyzer</h1>
        <Scan token={token} onResult={setScanResult} />
        {scanResult && <Results data={scanResult} />}
      </div>
    </div>
  )
}
