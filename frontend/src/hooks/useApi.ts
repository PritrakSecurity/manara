import { useState, useEffect } from 'react'
import { createApiClient } from '../api/client'

const api = createApiClient()

export function useApi<T>(
  fetchFn: () => Promise<T>,
  deps: any[] = []
) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  const refetch = async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await fetchFn()
      setData(result)
      setLoading(false)
    } catch (err: any) {
      setError(err)
      setLoading(false)
    }
  }

  useEffect(() => {
    let cancelled = false

    setLoading(true)
    setError(null)

    fetchFn()
      .then(result => {
        if (!cancelled) {
          setData(result)
          setLoading(false)
        }
      })
      .catch(err => {
        if (!cancelled) {
          setError(err)
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, deps)

  return { data, loading, error, refetch }
}

export { api }
