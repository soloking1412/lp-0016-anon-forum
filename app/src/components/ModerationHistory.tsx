import { useState, useEffect } from 'react';
import { listCerts, listForums, type ModerationCert } from '../api';
import * as t from '../theme';
import type { CSSProperties } from 'react';

const row: CSSProperties       = { background: '#0f172a', borderRadius: 8, padding: 14, marginBottom: 10, border: '1px solid #1e293b' };
const rowHeader: CSSProperties = { display: 'flex', justifyContent: 'space-between', marginBottom: 8 };
const badge: CSSProperties     = { background: '#7c3aed', color: '#fff', borderRadius: 20, padding: '2px 10px', fontSize: 12, fontWeight: 600 };
const field: CSSProperties     = { display: 'flex', alignItems: 'flex-start', gap: 8, marginBottom: 4 };
const fieldLabel: CSSProperties = { color: '#475569', fontSize: 12, width: 110, flexShrink: 0, paddingTop: 1 };
const hashCode: CSSProperties  = { fontFamily: 'monospace', fontSize: 11, color: '#93c5fd', wordBreak: 'break-all' };

export function ModerationHistory() {
  const [certs, setCerts]   = useState<ModerationCert[]>([]);
  const [forums, setForums] = useState<Array<{ forum_id_hex: string; deploy_tx: string; threshold_k: number; threshold_n: number; merkle_root: string }>>([]);
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState<string | null>(null);

  useEffect(() => {
    Promise.all([listCerts(), listForums()])
      .then(([c, f]) => { setCerts(c); setForums(f); })
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  function reload() {
    setLoading(true);
    Promise.all([listCerts(), listForums()])
      .then(([c, f]) => { setCerts(c); setForums(f); })
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false));
  }

  const entries = filter
    ? certs.filter(c =>
        c.member_tag.includes(filter) ||
        c.content_hash.includes(filter) ||
        c.votes.some(v => v.strike_reason.includes(filter)))
    : certs;

  return (
    <section style={t.card}>
      <h2 style={t.heading}>Audit Trail</h2>
      <p style={t.sub}>All on-chain forum instances and moderation certificates. Fully public audit trail.</p>

      {forums.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <strong style={{ ...t.label, fontSize: 14 }}>Deployed Forums</strong>
          {forums.map((f, i) => (
            <div key={i} style={{ ...row, borderColor: '#1e3a5f' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ color: '#60a5fa', fontSize: 13, fontWeight: 600 }}>Forum #{i + 1}</span>
                <span style={{ color: '#475569', fontSize: 12 }}>K={f.threshold_k} · N={f.threshold_n}</span>
              </div>
              <div style={field}>
                <span style={fieldLabel}>Forum ID</span>
                <code style={hashCode}>{f.forum_id_hex}</code>
              </div>
              <div style={field}>
                <span style={fieldLabel}>Deploy TX</span>
                <code style={{ ...hashCode, color: '#86efac' }}>{f.deploy_tx}</code>
              </div>
              <div style={field}>
                <span style={fieldLabel}>Merkle Root</span>
                <code style={hashCode}>{f.merkle_root}</code>
              </div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: 10, marginBottom: 16 }}>
        <input value={filter} onChange={e => setFilter(e.target.value)}
          placeholder="Filter by member_tag, content hash, or reason…"
          style={{ ...t.input, flex: 1, marginBottom: 0 }} />
        <button onClick={reload} style={t.btnSecondary}>Refresh</button>
      </div>

      {loading && <p style={{ color: '#64748b' }}>Loading…</p>}
      {error && <div style={t.error}>{error}</div>}

      {!loading && !error && entries.length === 0 && (
        <p style={{ color: '#64748b', textAlign: 'center', padding: 20 }}>No moderation certificates yet.</p>
      )}

      {entries.map((cert, i) => (
        <div key={i} style={row}>
          <div style={rowHeader}>
            <span style={badge}>{cert.votes.length} votes</span>
            <span style={{ color: '#475569', fontSize: 12 }}>{cert.forum_id.slice(0, 16)}…</span>
          </div>
          <div style={field}>
            <span style={fieldLabel}>member_tag</span>
            <code style={hashCode}>{cert.member_tag}</code>
          </div>
          <div style={field}>
            <span style={fieldLabel}>content_hash</span>
            <code style={hashCode}>{cert.content_hash}</code>
          </div>
          <div style={field}>
            <span style={fieldLabel}>reasons</span>
            <span style={{ color: '#94a3b8', fontSize: 13 }}>
              {cert.votes.map(v => v.strike_reason).join(', ')}
            </span>
          </div>
          <div style={field}>
            <span style={fieldLabel}>moderators</span>
            <span style={{ color: '#64748b', fontSize: 12 }}>
              {cert.votes.map(v => v.moderator_pubkey.slice(0, 8) + '…').join(', ')}
            </span>
          </div>
        </div>
      ))}
    </section>
  );
}
