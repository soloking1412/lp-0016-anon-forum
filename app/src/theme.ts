import type { CSSProperties } from 'react';

export const card: CSSProperties = {
  background: '#1a1a2e',
  borderRadius: 12,
  padding: 24,
  marginBottom: 24,
  border: '1px solid #2a2a4a',
};

export const heading: CSSProperties = { color: '#e2e8f0', marginTop: 0 };
export const sub: CSSProperties    = { color: '#94a3b8', fontSize: 14, marginBottom: 20 };
export const label: CSSProperties  = { color: '#cbd5e1', fontSize: 14, display: 'block', marginBottom: 8 };
export const hint: CSSProperties   = { color: '#64748b', fontSize: 12 };
export const code: CSSProperties   = { fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all' };

export const input: CSSProperties = {
  display: 'block',
  marginTop: 4,
  padding: '8px 12px',
  background: '#0f0f23',
  border: '1px solid #334155',
  borderRadius: 6,
  color: '#e2e8f0',
  width: '100%',
  boxSizing: 'border-box',
  fontFamily: 'inherit',
};

export const btn: CSSProperties = {
  padding: '10px 20px',
  background: '#6366f1',
  color: '#fff',
  border: 'none',
  borderRadius: 8,
  cursor: 'pointer',
  fontWeight: 600,
};

export const btnSecondary: CSSProperties = {
  padding: '6px 14px',
  background: 'transparent',
  color: '#6366f1',
  border: '1px solid #6366f1',
  borderRadius: 6,
  cursor: 'pointer',
  fontSize: 13,
};

export const btnSuccess: CSSProperties = {
  ...btn,
  background: '#059669',
};

export const success: CSSProperties = {
  marginTop: 12,
  padding: 12,
  background: '#052e16',
  border: '1px solid #16a34a',
  borderRadius: 8,
  color: '#86efac',
  fontSize: 13,
};

export const error: CSSProperties = {
  marginTop: 12,
  padding: 12,
  background: '#450a0a',
  border: '1px solid #dc2626',
  borderRadius: 8,
  color: '#fca5a5',
  fontSize: 13,
};

export const grid2: CSSProperties = {
  display: 'grid',
  gridTemplateColumns: '1fr 1fr',
  gap: 16,
};

export const section: CSSProperties = {
  background: '#0f172a',
  borderRadius: 8,
  padding: 16,
  marginBottom: 16,
};
