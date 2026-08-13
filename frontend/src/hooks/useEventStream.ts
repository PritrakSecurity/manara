import { useState, useEffect, useCallback, useRef } from 'react'

export interface FileEvent {
  id: string
  device_id: string
  event_type: string
  file_path: string
  file_name: string
  classification: string
  risk_level: string
  classification_score: number
  keywords_found: string[]
  username: string
  created_at: string
}

export interface WebSocketMessage {
  type: string
  payload: FileEvent  // Changed from 'data' to match backend
  timestamp: string
}

interface UseEventStreamOptions {
  onEvent?: (event: FileEvent) => void
  onConnect?: () => void
  onDisconnect?: () => void
  onError?: (error: Event) => void
  maxEvents?: number
  autoConnect?: boolean
}

export function useEventStream(options: UseEventStreamOptions = {}) {
  const { maxEvents = 1000, autoConnect = true } = options

  const [events, setEvents] = useState<FileEvent[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [connectionError, setConnectionError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const reconnectAttempts = useRef(0)
  const isConnectingRef = useRef(false)
  const maxReconnectAttempts = 10
  const baseReconnectDelay = 1000

  // Stable options refs to avoid useCallback dependency changes
  const optionsRef = useRef(options)
  optionsRef.current = options

  const getWebSocketUrl = useCallback(() => {
    // Derive from the current page origin so the Vite /ws proxy (dev) and any
    // production reverse proxy are respected. No hardcoded backend port.
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    return `${protocol}//${window.location.host}/ws/events`
  }, [])

  const connect = useCallback(() => {
    // Prevent multiple simultaneous connection attempts
    if (wsRef.current?.readyState === WebSocket.OPEN || 
        wsRef.current?.readyState === WebSocket.CONNECTING ||
        isConnectingRef.current) {
      return
    }

    isConnectingRef.current = true

    try {
      const url = getWebSocketUrl()
      console.log('[WebSocket] Connecting to:', url)
      
      const ws = new WebSocket(url)
      wsRef.current = ws

      ws.onopen = () => {
        console.log('[WebSocket] Connected successfully')
        isConnectingRef.current = false
        setIsConnected(true)
        setConnectionError(null)
        reconnectAttempts.current = 0
        optionsRef.current.onConnect?.()
      }

      ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data)
          
          // Handle FILE_EVENT type - payload contains the event data
          if (message.type === 'FILE_EVENT' && message.payload) {
            const fileEvent = message.payload
            console.log('[WebSocket] Received event:', fileEvent.event_type, fileEvent.file_name)
            
            setEvents(prev => {
              // Add new event at the beginning, limit total events
              const updated = [fileEvent, ...prev]
              return updated.slice(0, maxEvents)
            })
            
            optionsRef.current.onEvent?.(fileEvent)
          } else if (message.type === 'HEARTBEAT') {
            // Handle heartbeat notifications silently
            console.debug('[WebSocket] Heartbeat:', message.payload)
          } else if (message.type === 'DEVICE_STATUS') {
            // Handle device status updates
            console.log('[WebSocket] Device status:', message.payload)
          }
        } catch (err) {
          console.error('[WebSocket] Failed to parse message:', err)
        }
      }

      ws.onclose = (event) => {
        console.log('[WebSocket] Disconnected:', event.code, event.reason)
        isConnectingRef.current = false
        setIsConnected(false)
        wsRef.current = null
        optionsRef.current.onDisconnect?.()

        // Only auto-reconnect on abnormal closure (not manual close)
        if (event.code !== 1000 && reconnectAttempts.current < maxReconnectAttempts) {
          const delay = baseReconnectDelay * Math.pow(2, Math.min(reconnectAttempts.current, 5))
          console.log(`[WebSocket] Reconnecting in ${delay}ms (attempt ${reconnectAttempts.current + 1})`)
          
          reconnectTimeoutRef.current = setTimeout(() => {
            reconnectAttempts.current++
            connect()
          }, delay)
        } else if (reconnectAttempts.current >= maxReconnectAttempts) {
          setConnectionError('Max reconnection attempts reached')
        }
      }

      ws.onerror = (error) => {
        console.error('[WebSocket] Error:', error)
        isConnectingRef.current = false
        setConnectionError('WebSocket connection error')
        optionsRef.current.onError?.(error)
      }
    } catch (err) {
      console.error('[WebSocket] Failed to create connection:', err)
      isConnectingRef.current = false
      setConnectionError('Failed to create WebSocket connection')
    }
  }, [getWebSocketUrl, maxEvents])  // Removed callback deps - using refs instead

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
    
    if (wsRef.current) {
      wsRef.current.close(1000, 'Client disconnect')  // Normal closure
      wsRef.current = null
    }
    
    isConnectingRef.current = false
    setIsConnected(false)
    reconnectAttempts.current = maxReconnectAttempts // Prevent auto-reconnect
  }, [])

  const clearEvents = useCallback(() => {
    setEvents([])
  }, [])

  // Auto-connect on mount - run only once
  useEffect(() => {
    if (autoConnect) {
      // Small delay to ensure component is fully mounted
      const timer = setTimeout(() => {
        connect()
      }, 100)
      return () => clearTimeout(timer)
    }
    return undefined
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current)
      }
      if (wsRef.current) {
        wsRef.current.close(1000, 'Component unmount')
      }
    }
  }, [])

  return {
    events,
    isConnected,
    connectionError,
    connect,
    disconnect,
    clearEvents,
  }
}

export default useEventStream
