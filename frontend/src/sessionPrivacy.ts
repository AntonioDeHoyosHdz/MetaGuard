const channelName = 'metaguard.session-invalidation'
type Notice = 'lock' | 'changed'

// Notifications are hints to hide/recheck the workspace, never authentication.
// Neither transport receives account identifiers, tokens or report data.
export function watchSession(onNotice: (notice: Notice) => void) {
  let channel: BroadcastChannel | undefined
  try { channel = new BroadcastChannel(channelName) } catch { /* storage fallback */ }
  const receive = (data: unknown) => {
    if (data === 'lock' || data === 'changed') onNotice(data)
  }
  if (channel) channel.onmessage = event => receive(event.data)
  const onStorage = (event: StorageEvent) => {
    if (event.key === channelName) receive(event.newValue)
  }
  window.addEventListener('storage', onStorage)
  return {
    notify(notice: Notice) {
      try {
        if (channel) { channel.postMessage(notice); return }
      } catch { /* try the fallback */ }
      try {
        window.localStorage.setItem(channelName, notice)
        window.localStorage.removeItem(channelName)
      } catch { /* browser settings may disable both transports */ }
    },
    close() {
      window.removeEventListener('storage', onStorage)
      channel?.close()
    },
  }
}
