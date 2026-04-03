import { useCallback, useMemo, useRef } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { buildQueryString, parseQueryParams, type QueryState } from '@/utils/query'

interface SetURLQueryOptions {
  replace?: boolean
}

export function useURLQueryState<T extends QueryState>(defaults: T) {
  const defaultsRef = useRef(defaults)
  const location = useLocation()
  const navigate = useNavigate()

  const params = useMemo(
    () => parseQueryParams(new URLSearchParams(location.search), defaultsRef.current),
    [location.search],
  )

  const setParams = useCallback(
    (patch: Partial<T>, options: SetURLQueryOptions = {}) => {
      const next = { ...params, ...patch }
      const search = buildQueryString(next)

      navigate(
        {
          pathname: location.pathname,
          search: search ? `?${search}` : '',
        },
        { replace: options.replace ?? true },
      )
    },
    [location.pathname, navigate, params],
  )

  const resetParams = useCallback(
    (patch: Partial<T> = {}, options: SetURLQueryOptions = {}) => {
      const next = { ...defaultsRef.current, ...patch }
      const search = buildQueryString(next)

      navigate(
        {
          pathname: location.pathname,
          search: search ? `?${search}` : '',
        },
        { replace: options.replace ?? true },
      )
    },
    [location.pathname, navigate],
  )

  return { params, setParams, resetParams }
}
