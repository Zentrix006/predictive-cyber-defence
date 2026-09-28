"use client";

import { useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import QRCode from 'qrcode';
import { QrCode, Wifi } from 'lucide-react';
import { demoApiBase } from '@/lib/demo-api';

export default function JoinPage() {
  const canvas = useRef<HTMLCanvasElement>(null); const [rolesUrl, setRolesUrl] = useState('');
  useEffect(() => { let closed=false; (async () => { let base=window.location.origin; try { const config=await fetch(`${demoApiBase()}/config`).then(r=>r.json()); base=config.public_base_url || base; } catch { /* browser origin remains a LAN-safe fallback */ } const url=`${base.replace(/\/$/, '')}/roles`; if(!closed) { setRolesUrl(url); if(canvas.current) await QRCode.toCanvas(canvas.current,url,{width:250,margin:1,color:{dark:'#07111f',light:'#eef5ff'}}); } })(); return ()=>{closed=true;}; }, []);
  return <main className="grid min-h-[100dvh] place-items-center bg-[var(--bg-primary)] p-5 text-[var(--text-primary)]"><section className="w-full max-w-xl rounded-2xl border border-[var(--border-primary)] bg-[var(--bg-secondary)] p-6 text-center shadow-2xl sm:p-8"><span className="mx-auto grid h-12 w-12 place-items-center rounded-xl border border-[var(--accent-blue)]/35 bg-[var(--accent-blue)]/10"><QrCode className="h-6 w-6 text-[var(--accent-blue)]" /></span><p className="mt-5 text-xs font-semibold uppercase tracking-[.16em] text-[var(--accent-blue)]">LAN cyber-range</p><h1 className="mt-2 text-2xl font-semibold">Scan to join</h1><p className="mx-auto mt-3 max-w-md text-sm leading-6 text-[var(--text-secondary)]">Scan with any device on this Wi‑Fi network. You will choose a role on the next page; enrollment only starts after that choice.</p><div className="my-6 inline-flex rounded-2xl border border-[var(--border-primary)] bg-white p-3"><canvas ref={canvas} aria-label="QR code for role selection" /></div><p className="break-all rounded-lg bg-[var(--bg-tertiary)] px-3 py-2 font-mono text-xs text-[var(--text-secondary)]">{rolesUrl || 'Resolving WLAN address…'}</p><Link href="/roles" className="mt-5 inline-flex items-center gap-2 rounded-lg bg-[var(--accent-blue)] px-4 py-2 text-sm font-medium text-white"><Wifi className="h-4 w-4" /> Continue on this device</Link></section></main>;
}
