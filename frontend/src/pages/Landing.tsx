import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

/**
 * Pre-login landing. The marketing page lives as a self-contained static file
 * (public/landing.html) so its canvas globe, UFO cursor and easter eggs run
 * exactly as authored and are torn down automatically when we route away.
 * The page's "Sign in" posts a message that we turn into an in-app navigation.
 */
export function Landing() {
  const navigate = useNavigate()

  useEffect(() => {
    const onMessage = (e: MessageEvent) => {
      if (e.origin === window.location.origin && e.data === 'harbore:signin') {
        navigate('/login')
      }
    }
    window.addEventListener('message', onMessage)
    return () => window.removeEventListener('message', onMessage)
  }, [navigate])

  return (
    <iframe
      src="/landing.html"
      title="harbore — Continuous Exposure Management"
      style={{ position: 'fixed', inset: 0, width: '100%', height: '100%', border: 'none' }}
    />
  )
}
