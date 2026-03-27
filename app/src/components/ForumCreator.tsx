import { useState } from 'react';
import { deployForum, generateModKey, type DeployForumResp } from '../api';
import * as t from '../theme';

interface ModKey { signing_key_hex: string; pubkey_hex: string; }

export function ForumCreator() {
  const [thresholdK, setThresholdK] = useState(3);
  const [thresholdN, setThresholdN] = useState(2);
  const [moderatorPubkeys, setModeratorPubkeys] = useState<string[]>(['']);
  const [generatedKeys, setGeneratedKeys]       = useState<ModKey[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState<string | null>(null);
  const [result, setResult]   = useState<DeployForumResp | null>(null);

  function addModerator() {
    setModeratorPubkeys(p => [...p, '']);
  }
  function updateModerator(i: number, val: string) {
    setModeratorPubkeys(p => { const a = [...p]; a[i] = val; return a; });
  }

  async function handleGenModKey(i: number) {
    try {
      const k = await generateModKey();
      setGeneratedKeys(keys => { const a = [...keys]; a[i] = k; return a; });
      // auto-fill the pubkey field
      setModeratorPubkeys(p => { const a = [...p]; a[i] = k.pubkey_hex; return a; });
    } catch (e) { setError(String(e)); }
  }

  async function handleDeploy() {
    setLoading(true); setError(null);
    try {
      const resp = await deployForum({
        threshold_k: thresholdK,
        threshold_n: thresholdN,
        moderators: moderatorPubkeys.filter(s => s.trim().length === 64),
      });
      setResult(resp);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section style={t.card}>
      <h2 style={t.heading}>Create Forum</h2>
      <p style={t.sub}>Deploy a new anonymous forum on-chain. K = certs to slash. N = votes per cert.</p>

      <div style={t.grid2}>
        <label style={t.label}>
          Strike threshold K<br /><small style={t.hint}>Certs needed to slash</small>
          <input type="number" min={1} value={thresholdK}
            onChange={e => setThresholdK(+e.target.value)} style={t.input} />
        </label>
        <label style={t.label}>
          Vote threshold N<br /><small style={t.hint}>Votes needed per cert</small>
          <input type="number" min={1} value={thresholdN}
            onChange={e => setThresholdN(+e.target.value)} style={t.input} />
        </label>
      </div>

      <div style={{ marginTop: 16 }}>
        <strong style={t.label}>Moderators</strong>
        <p style={t.hint}>Generate a key for each moderator. The pubkey is stored on-chain; the signing key is used in the Moderation tab.</p>
        {moderatorPubkeys.map((pk, i) => (
          <div key={i} style={{ marginTop: 10, padding: 10, background: '#0f172a', borderRadius: 8 }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
              <span style={{ color: '#94a3b8', fontSize: 13, minWidth: 90 }}>Moderator {i + 1}</span>
              <button onClick={() => handleGenModKey(i)}
                style={{ ...t.btnSecondary, padding: '4px 10px', fontSize: 12 }}>
                Generate Key
              </button>
            </div>
            {generatedKeys[i] && (
              <div style={{ marginBottom: 6, fontSize: 12, color: '#64748b' }}>
                <div style={{ color: '#fca5a5', marginBottom: 2 }}>
                  Signing key (keep — paste into Moderation tab):
                </div>
                <code style={{ ...t.code, wordBreak: 'break-all', display: 'block', marginBottom: 4 }}>
                  {generatedKeys[i].signing_key_hex}
                </code>
              </div>
            )}
            <input value={pk} onChange={e => updateModerator(i, e.target.value)}
              placeholder="Ed25519 pubkey (64-char hex) — auto-filled after Generate Key"
              style={{ ...t.input, fontFamily: 'monospace', fontSize: 12, marginTop: 0 }} />
          </div>
        ))}
        <button onClick={addModerator} style={{ ...t.btnSecondary, marginTop: 8 }}>+ Add moderator</button>
      </div>

      <button onClick={handleDeploy} disabled={loading} style={{ ...t.btn, marginTop: 20 }}>
        {loading ? 'Deploying on-chain…' : 'Deploy Forum On-Chain'}
      </button>

      {result && (
        <div style={t.success}>
          <div style={{ marginBottom: 8 }}><strong>Forum deployed on-chain!</strong></div>
          <div style={{ marginBottom: 4, color: '#86efac', fontSize: 13 }}>TX Hash:</div>
          <code style={{ ...t.code, wordBreak: 'break-all', fontSize: 11, display: 'block' }}>{result.tx_hash}</code>
          <div style={{ marginTop: 10, display: 'grid', gap: 6, fontSize: 13 }}>
            <div>Forum ID: <code style={t.code}>{result.forum_id}</code></div>
            <div>Account:  <code style={t.code}>{result.account_id}</code></div>
            <div>K={result.threshold_k} · N={result.threshold_n}</div>
          </div>
          <div style={{ marginTop: 10, padding: 8, background: '#0f172a', borderRadius: 6, fontSize: 12, color: '#64748b' }}>
            Copy <strong style={{ color: '#93c5fd' }}>Forum ID</strong> → Member tab &amp; Post tab &amp; Moderation tab.
          </div>
        </div>
      )}

      {error && <div style={t.error}>{error}</div>}
    </section>
  );
}
