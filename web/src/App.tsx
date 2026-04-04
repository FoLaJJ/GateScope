import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/store/auth'
import { setAuthNavigator } from '@/api/client'
import AppLayout from '@/components/Layout'
import NotFound from '@/components/NotFound'
import Login from '@/pages/Login'
import Dashboard from '@/pages/Dashboard'
import Tasks from '@/pages/Tasks'
import TaskDetail from '@/pages/TaskDetail'
import Assets from '@/pages/Assets'
import Vulnerabilities from '@/pages/Vulnerabilities'

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.token)
  return token ? <>{children}</> : <Navigate to="/login" replace />
}

function AuthNavigatorSetup() {
  const navigate = useNavigate()
  useEffect(() => {
    setAuthNavigator(() => navigate('/login', { replace: true }))
  }, [navigate])
  return null
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthNavigatorSetup />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <PrivateRoute>
              <AppLayout />
            </PrivateRoute>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="tasks" element={<Tasks />} />
          <Route path="tasks/:id" element={<TaskDetail />} />
          <Route path="assets" element={<Assets />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Routes>
    </BrowserRouter>
  )
}
