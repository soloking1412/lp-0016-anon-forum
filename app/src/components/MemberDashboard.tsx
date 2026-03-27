import { useState } from 'react';
import { generateIdentity, registerOnChain, type RegisterOnChainResp } from '../api';
import * as t from '../theme';

interface Identity { id_secret_hex: string; commitment: string; }

export function MemberDashboard() {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [forumId, setForumId]   = useState('');
  const [reg, setReg]           = useState<RegisterOnChainResp | null>(null);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState<string | null>(null);

  async function handleKeygen() {
    setLoading(true); setError(null);
    try { setIdentity(await generateIdentity()); }
    catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  async function handleRegister() {
    if (!identity || !forumId) return;
    setLoading(true); setError(null);
    try {
      setReg(await registerOnChain({
        id_secret_hex: identity.id_secret_hex,
        forum_id: forumId,
        stake: 1000,
        threshold: 3,
        total: 5,
      }));
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  return (
    <section style={t.card}>
      <h2 style={t.heading}>Member Dashboard</h2>
      <p style={t.sub}>Generate an anonymous identity and register it on-chain with Shamir shares.</p>

      <div style={t.section}>
        <h3 style={{ ...t.label, fontSize: 16, marginTop: 0 }}>1 · Generate Identity</h3>
        <p style={t.hint}>Your id_secret never leaves this device.</p>
        <button onClick={handleKeygen} disabled={loading} style={t.btn}>
          {loading ? 'Generating…' : 'Generate Identity Key'}
        </button>
        {identity && (
          <div style={{ marginTop: 12, padding: 12, background: '#0f0f23', borderRadius: 8, fontSize: 13, color: '#94a3b8' }}>
            <div>commitment: <code style={t.code}>{identity.commitment}</code></div>
            <div style={{ marginTop: 6, color: '#fca5a5' }}>
              id_secret (keep private): <code style={t.code}>{identity.id_secret_hex}</code>
            </div>
          </div>
        )}
      </div>

      {identity && (
        <div style={t.section}>
          <h3 style={{ ...t.label, fontSize: 16, marginTop: 0 }}>2 · Register On-Chain</h3>
          <input value={forumId} onChange={e => setForumId(e.target.value)}
            placeholder="Forum ID (64-char hex from Create Forum tab)"
            style={t.input} />
          <button onClick={handleRegister} disabled={loading || !forumId}
            style={{ ...t.btn, marginTop: 10 }}>
            {loading ? 'Registering on-chain…' : 'Register & Deposit Stake On-Chain'}
          </button>

          {reg && (
            <div style={{ ...t.success, marginTop: 12 }}>
              <div style={{ marginBottom: 8 }}><strong>Registered on-chain!</strong></div>
              <div style={{ display: 'grid', gap: 8, fontSize: 13 }}>
                <div>
                  <span style={{ color: '#86efac' }}>Register TX:</span>
                  <br /><code style={{ ...t.code, wordBreak: 'break-all', fontSize: 11 }}>{reg.register_tx}</code>
                </div>
                <div>
                  <span style={{ color: '#86efac' }}>Merkle Root Update TX:</span>
                  <br /><code style={{ ...t.code, wordBreak: 'break-all', fontSize: 11 }}>{reg.root_tx}</code>
                </div>
                <div>member_tag: <code style={t.code}>{reg.member_tag}</code></div>
                <div>merkle_root: <code style={t.code}>{reg.merkle_root}</code></div>
                <div>leaf_index: <code style={t.code}>{reg.leaf_index}</code></div>
              </div>

              {/* Shamir shares — must be copied for the Slash step */}
              <div style={{ marginTop: 12 }}>
                <div style={{ color: '#fbbf24', fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
                  ⚠ Shamir shares — copy now, needed for Slash
                </div>
                <p style={{ color: '#64748b', fontSize: 12, marginTop: 0, marginBottom: 6 }}>
                  Paste K of these into the Slash section of the Moderation tab.
                </p>
                <textarea
                  readOnly
                  value={JSON.stringify(reg.shares, null, 2)}
                  style={{
                    ...t.input, fontFamily: 'monospace', fontSize: 11,
                    minHeight: 120, resize: 'vertical', color: '#93c5fd',
                    cursor: 'text',
                  }}
                  onClick={e => (e.target as HTMLTextAreaElement).select()}
                />
              </div>

              <div style={{ marginTop: 10, padding: 8, background: '#0f172a', borderRadius: 6, fontSize: 12, color: '#64748b' }}>
                Copy <strong style={{ color: '#93c5fd' }}>merkle_root</strong> + <strong style={{ color: '#93c5fd' }}>leaf_index</strong> → Post tab.{' '}
                Copy <strong style={{ color: '#93c5fd' }}>member_tag</strong> + <strong style={{ color: '#fbbf24' }}>Shamir shares</strong> → Moderation tab.
              </div>
            </div>
          )}
        </div>
      )}

      {error && <div style={t.error}>{error}</div>}
    </section>
  );
}
