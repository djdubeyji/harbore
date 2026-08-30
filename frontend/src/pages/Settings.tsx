import { useState, useRef, type ChangeEvent } from 'react'
import { User as UserIcon, Lock, Palette, Building2, Upload, Check, Plus, Moon, Sun } from 'lucide-react'
import { useAuth } from '../hooks/useAuth'
import { useOrg } from '../hooks/useOrg'
import { useTheme } from '../hooks/useTheme'
import { updateProfile, changePassword, createOrg, addOrgMember } from '../api/client'

export function SettingsPage() {
  const { user, refresh } = useAuth()
  const { orgs, activeOrg, refreshOrgs } = useOrg()
  const { theme, setTheme } = useTheme()
  const isAdmin = user?.role === 'admin'

  return (
    <div className="flex-1 overflow-y-auto">
      <div className="max-w-3xl mx-auto px-6 py-8 space-y-6">
        <div>
          <h1 className="text-xl font-bold text-white">Settings</h1>
          <p className="text-xs text-gray-500 mt-0.5">Manage your profile, security, appearance, and organizations</p>
        </div>

        <ProfileSection name={user?.name ?? ''} avatar={user?.avatar ?? ''} onSaved={refresh} />
        <PasswordSection />
        <AppearanceSection theme={theme} setTheme={setTheme} />
        {isAdmin && <OrgSection orgs={orgs} activeOrgId={activeOrg?.id} onChanged={refreshOrgs} />}
      </div>
    </div>
  )
}

function Card({ icon: Icon, title, children }: { icon: React.ComponentType<{ className?: string }>; title: string; children: React.ReactNode }) {
  return (
    <section className="card p-6">
      <div className="flex items-center gap-2 mb-4">
        <Icon className="w-4 h-4 text-accent-amber" />
        <h2 className="text-sm font-semibold text-white">{title}</h2>
      </div>
      {children}
    </section>
  )
}

function Status({ msg }: { msg: { ok: boolean; text: string } | null }) {
  if (!msg) return null
  return (
    <span className={`text-xs ${msg.ok ? 'text-accent-emerald' : 'text-[#FF6B7D]'}`}>{msg.text}</span>
  )
}

function ProfileSection({ name: initial, avatar: initialAvatar, onSaved }: { name: string; avatar: string; onSaved: () => Promise<void> }) {
  const [name, setName] = useState(initial)
  const [avatar, setAvatar] = useState(initialAvatar)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const onFile = (e: ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (!f) return
    if (f.size > 1_500_000) { setMsg({ ok: false, text: 'Image too large (max ~1.5MB)' }); return }
    const reader = new FileReader()
    reader.onload = () => setAvatar(reader.result as string)
    reader.readAsDataURL(f)
  }

  const save = async () => {
    setBusy(true); setMsg(null)
    try {
      await updateProfile(name, avatar)
      await onSaved()
      setMsg({ ok: true, text: 'Saved' })
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Failed' })
    } finally { setBusy(false) }
  }

  return (
    <Card icon={UserIcon} title="Profile">
      <div className="flex items-center gap-4 mb-4">
        <div className="w-16 h-16 rounded-full bg-accent-amber/15 border border-border flex items-center justify-center overflow-hidden">
          {avatar
            ? <img src={avatar} alt="avatar" className="w-full h-full object-cover" />
            : <span className="text-xl font-bold text-accent-amber uppercase">{name?.[0] ?? 'U'}</span>}
        </div>
        <div>
          <button onClick={() => fileRef.current?.click()} className="btn-ghost text-xs">
            <Upload className="w-3.5 h-3.5" /> Upload photo
          </button>
          {avatar && <button onClick={() => setAvatar('')} className="btn-ghost text-xs ml-2">Remove</button>}
          <input ref={fileRef} type="file" accept="image/*" className="hidden" onChange={onFile} />
          <p className="text-[10px] text-gray-600 mt-1">PNG or JPG, up to ~1.5MB</p>
        </div>
      </div>
      <label className="label">Display name</label>
      <input value={name} onChange={e => setName(e.target.value)} className="input mt-1 max-w-sm" />
      <div className="flex items-center gap-3 mt-4">
        <button onClick={save} disabled={busy || !name} className="btn-primary text-sm disabled:opacity-50">
          {busy ? 'Saving…' : 'Save changes'}
        </button>
        <Status msg={msg} />
      </div>
    </Card>
  )
}

function PasswordSection() {
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  const save = async () => {
    if (next !== confirm) { setMsg({ ok: false, text: 'New passwords do not match' }); return }
    if (next.length < 8) { setMsg({ ok: false, text: 'Must be at least 8 characters' }); return }
    setBusy(true); setMsg(null)
    try {
      await changePassword(cur, next)
      setCur(''); setNext(''); setConfirm('')
      setMsg({ ok: true, text: 'Password updated' })
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : 'Failed' })
    } finally { setBusy(false) }
  }

  return (
    <Card icon={Lock} title="Security">
      <div className="grid gap-3 max-w-sm">
        <div><label className="label">Current password</label><input type="password" value={cur} onChange={e => setCur(e.target.value)} className="input mt-1" /></div>
        <div><label className="label">New password</label><input type="password" value={next} onChange={e => setNext(e.target.value)} className="input mt-1" /></div>
        <div><label className="label">Confirm new password</label><input type="password" value={confirm} onChange={e => setConfirm(e.target.value)} className="input mt-1" /></div>
      </div>
      <div className="flex items-center gap-3 mt-4">
        <button onClick={save} disabled={busy || !cur || !next} className="btn-primary text-sm disabled:opacity-50">
          {busy ? 'Updating…' : 'Update password'}
        </button>
        <Status msg={msg} />
      </div>
    </Card>
  )
}

function AppearanceSection({ theme, setTheme }: { theme: 'dark' | 'light'; setTheme: (t: 'dark' | 'light') => void }) {
  return (
    <Card icon={Palette} title="Appearance">
      <div className="flex gap-3">
        {(['dark', 'light'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTheme(t)}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border text-sm capitalize transition-colors ${
              theme === t ? 'border-accent-amber bg-accent-amber/10 text-accent-amber' : 'border-border text-gray-300 hover:border-border-bright'
            }`}
          >
            {t === 'dark' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />}
            {t} mode
            {theme === t && <Check className="w-3.5 h-3.5" />}
          </button>
        ))}
      </div>
      <p className="text-[11px] text-gray-600 mt-3">Light mode is a first pass on the amber theme; dark is the primary experience.</p>
    </Card>
  )
}

function OrgSection({ orgs, activeOrgId, onChanged }: { orgs: { id: string; name: string; role?: string }[]; activeOrgId?: string; onChanged: () => Promise<void> }) {
  const [newOrg, setNewOrg] = useState('')
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)

  const create = async () => {
    if (!newOrg) return
    setBusy(true); setMsg(null)
    try { await createOrg(newOrg); setNewOrg(''); await onChanged(); setMsg({ ok: true, text: 'Organization created' }) }
    catch (e) { setMsg({ ok: false, text: e instanceof Error ? e.message : 'Failed' }) }
    finally { setBusy(false) }
  }
  const addMember = async () => {
    if (!email || !activeOrgId) return
    setBusy(true); setMsg(null)
    try { await addOrgMember(activeOrgId, email); setEmail(''); setMsg({ ok: true, text: 'Member added to current organization' }) }
    catch (e) { setMsg({ ok: false, text: e instanceof Error ? e.message : 'Failed' }) }
    finally { setBusy(false) }
  }

  return (
    <Card icon={Building2} title="Organizations">
      <div className="space-y-1.5 mb-4">
        {orgs.map(o => (
          <div key={o.id} className="flex items-center justify-between px-3 py-2 rounded-md bg-surface-3 border border-border text-sm">
            <span className="text-gray-200">{o.name}</span>
            <span className="flex items-center gap-2">
              {o.role && <span className="badge bg-surface-4 text-gray-400 border border-border capitalize">{o.role}</span>}
              {o.id === activeOrgId && <span className="text-[10px] text-accent-amber">active</span>}
            </span>
          </div>
        ))}
      </div>

      <div className="grid sm:grid-cols-2 gap-4">
        <div>
          <label className="label">Create organization</label>
          <div className="flex gap-2 mt-1">
            <input value={newOrg} onChange={e => setNewOrg(e.target.value)} placeholder="Name" className="input" />
            <button onClick={create} disabled={busy || !newOrg} className="btn-ghost text-sm disabled:opacity-50"><Plus className="w-3.5 h-3.5" /></button>
          </div>
        </div>
        <div>
          <label className="label">Add member to current org (by email)</label>
          <div className="flex gap-2 mt-1">
            <input value={email} onChange={e => setEmail(e.target.value)} placeholder="user@company.com" className="input" />
            <button onClick={addMember} disabled={busy || !email} className="btn-ghost text-sm disabled:opacity-50">Add</button>
          </div>
        </div>
      </div>
      <div className="mt-3"><Status msg={msg} /></div>
    </Card>
  )
}
