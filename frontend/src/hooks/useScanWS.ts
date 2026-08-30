import { useEffect, useRef, useState } from 'react'
import { connectScanWS } from '../api/client'
import type { WSEvent, ScanProgress } from '../types'

export function useScanWS(scanId: string | undefined, onFinding?: () => void) {
  const [progress, setProgress] = useState<ScanProgress | null>(null)
  const [events, setEvents] = useState<WSEvent[]>([])
  const ws = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!scanId) return

    const socket = connectScanWS(scanId, (e: MessageEvent) => {
      try {
        const event: WSEvent = JSON.parse(e.data)
        setEvents(prev => [event, ...prev].slice(0, 100))

        if (event.type === 'scan.progress') {
          setProgress(event.payload as ScanProgress)
        }
        if (event.type === 'finding.new' && onFinding) {
          onFinding()
        }
      } catch { /* ignore parse errors */ }
    })

    ws.current = socket
    return () => { socket.close() }
  }, [scanId])

  return { progress, events }
}
