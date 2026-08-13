import axios from 'axios'
import { getBackendUrl } from '../utils/getBackendUrl'
import { useAuthStore } from '../store/authStore'

// Use the absolute backend URL so API calls work regardless of the Vite proxy.
// Override with VITE_API_URL if the backend is hosted elsewhere.
const API_BASE_URL = (import.meta as any).env?.VITE_API_URL || getBackendUrl()

export interface Policy {
  id: string
  name: string
  description?: string
  rules: string | any[]
  priority: number
  enabled: boolean
  is_default?: boolean
  created_at: string
  updated_at: string
}

export interface Endpoint {
  id: string
  agent_id: string
  hostname: string
  ip_address: string
  os_version: string
  agent_version: string
  last_seen: string
  created_at: string
  status: string
}

export interface Event {
  id: number
  agent_id: string
  event_type: string
  operation: string
  source_path: string
  destination: string
  application: string
  user_id: string
  data: any
  severity: string
  action_taken: string
  timestamp: string
}

export interface Incident {
  id: number
  agent_id: string
  rule_id: string
  user_id: string
  violation_type: string
  data_classification: string[]
  resolved: boolean
  created_at: string
}

export interface ApiClient {
  policies: PoliciesAPI
  endpoints: EndpointsAPI
  events: EventsAPI
  incidents: IncidentsAPI
}

export interface PoliciesAPI {
  list(): Promise<Policy[]>
  get(id: string): Promise<Policy>
  create(policy: Omit<Policy, 'id' | 'created_at' | 'updated_at'>): Promise<Policy>
  update(id: string, policy: Partial<Policy>): Promise<void>
  delete(id: string): Promise<void>
}

export interface EndpointsAPI {
  list(): Promise<Endpoint[]>
  get(id: string): Promise<Endpoint>
}

export interface EventsAPI {
  list(filters?: { agent_id?: string; event_type?: string; severity?: string }): Promise<Event[]>
}

export interface IncidentsAPI {
  list(resolved?: boolean): Promise<Incident[]>
  resolve(id: number, resolvedBy: string, notes: string): Promise<void>
}

// Global Axios instance. Every request automatically gets the JWT from the
// auth store, so callers never have to attach the Authorization header.
export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 10000,
})

// Inject the bearer token on every request from the Zustand auth store.
apiClient.interceptors.request.use(
  (config) => {
    const token = useAuthStore.getState().token
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Add response interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid, redirect to login
      localStorage.removeItem('auth-storage')
      window.location.href = '/login'
    }
    console.error('API Error:', error.message)
    return Promise.reject(error)
  }
)

export function createApiClient(_token?: string): ApiClient {
  return {
    policies: {
      list: () => apiClient.get('/api/policies').then(r => r.data).catch(() => []),
      get: (id) => apiClient.get(`/api/policies/${id}`).then(r => r.data),
      create: (p) => apiClient.post('/api/policies', p).then(r => r.data),
      update: (id, p) => apiClient.put(`/api/policies/${id}`, p),
      delete: (id) => apiClient.delete(`/api/policies/${id}`),
    },
    endpoints: {
      list: () => apiClient.get('/api/endpoints').then(r => r.data).catch(() => []),
      get: (id) => apiClient.get(`/api/endpoints/${id}`).then(r => r.data),
    },
    events: {
      list: (filters) => {
        const params = new URLSearchParams()
        if (filters?.agent_id) params.append('agent_id', filters.agent_id)
        if (filters?.event_type) params.append('event_type', filters.event_type)
        if (filters?.severity) params.append('severity', filters.severity)
        return apiClient.get(`/api/events?${params}`).then(r => r.data).catch(() => [])
      },
    },
    incidents: {
      list: (resolved) => {
        const params = resolved !== undefined ? `?resolved=${resolved}` : ''
        return apiClient.get(`/api/incidents${params}`).then(r => r.data).catch(() => [])
      },
      resolve: (id, resolvedBy, notes) => apiClient.patch(`/api/incidents/${id}`, { resolved_by: resolvedBy, notes }),
    }
  }
}
