import React, { Suspense, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { Spin } from 'antd'
import { useAuthStore } from '@/store/auth'
import { setAuthNavigator } from '@/api/client'
import AppLayout from '@/components/Layout'
import NotFound from '@/components/NotFound'

const Login = React.lazy(() => import('@/pages/Login'))
const Dashboard = React.lazy(() => import('@/pages/Dashboard'))
const Tasks = React.lazy(() => import('@/pages/Tasks'))
const TaskDetail = React.lazy(() => import('@/pages/TaskDetail'))
const Assets = React.lazy(() => import('@/pages/Assets'))
const Vulnerabilities = React.lazy(() => import('@/pages/Vulnerabilities'))
const Alerts = React.lazy(() => import('@/pages/Alerts'))
const Intel = React.lazy(() => import('@/pages/Intel'))

const PageLoading = () => <Spin size="large" style={{ display: 'block', margin: '120px auto' }} />

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
      <Suspense fallback={<PageLoading />}>
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
            <Route path="alerts" element={<Alerts />} />
            <Route path="intel" element={<Intel />} />
          </Route>
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  )
}
