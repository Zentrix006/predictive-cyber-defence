import { ReactNode } from 'react';
import { cn } from '@/utils/classnames';

export function Panel({
  title,
  subtitle,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn('panel-surface flex flex-col bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-xl overflow-hidden', className)}>
      {(title || actions) && (
        <div className="px-4 py-2.5 border-b border-[var(--border-primary)] bg-[var(--bg-tertiary)]/60 flex items-center justify-between gap-2">
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-[var(--text-primary)] truncate">{title}</h3>
            {subtitle && <p className="text-xs text-[var(--text-secondary)] truncate">{subtitle}</p>}
          </div>
          {actions && <div className="shrink-0 flex items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className={cn('p-4 overflow-auto', bodyClassName)}>{children}</div>
    </section>
  );
}

export function StatCard({
  label,
  value,
  hint,
  tone = 'blue',
  icon,
}: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: 'blue' | 'green' | 'yellow' | 'red' | 'violet';
  icon?: ReactNode;
}) {
  const tones: Record<string, string> = {
    blue: 'text-[var(--accent-blue)]',
    green: 'text-[var(--accent-green)]',
    yellow: 'text-[var(--accent-yellow)]',
    red: 'text-[var(--accent-red)]',
    violet: 'text-[var(--accent-purple)]',
  };
  return (
    <div className="metric-card flex items-center gap-3 bg-[var(--bg-secondary)] border border-[var(--border-primary)] rounded-xl px-4 py-3">
      {icon && <div className={cn('shrink-0', tones[tone])}>{icon}</div>}
      <div className="min-w-0">
        <div className="text-xs text-[var(--text-secondary)]">{label}</div>
        <div className="text-xl font-bold text-[var(--text-primary)] leading-tight truncate">{value}</div>
        {hint && <div className="text-[10px] text-[var(--text-muted)] truncate">{hint}</div>}
      </div>
    </div>
  );
}

export function RiskBadge({ risk }: { risk: string }) {
  const map: Record<string, string> = {
    low: 'bg-[var(--accent-green)]/15 text-[var(--accent-green)]',
    medium: 'bg-[var(--accent-blue)]/15 text-[var(--accent-blue)]',
    high: 'bg-[var(--accent-yellow)]/15 text-[var(--accent-yellow)]',
    critical: 'bg-[var(--accent-red)]/15 text-[var(--accent-red)]',
  };
  return (
    <span className={cn('px-2 py-0.5 rounded text-[11px] font-medium uppercase tracking-wide', map[risk] || 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)]')}>
      {risk}
    </span>
  );
}

export function Spinner() {
  return (
    <div className="flex items-center justify-center py-10 text-[var(--text-muted)]">
      <div className="w-5 h-5 border-2 border-[var(--border-primary)] border-t-[var(--accent-blue)] rounded-full animate-spin" />
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="text-center py-10 text-[var(--text-muted)] text-sm">{message}</div>
  );
}