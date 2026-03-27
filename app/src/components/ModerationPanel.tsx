import { useState } from 'react';
import { draftVote, aggregateCert, submitCertOnChain, slashOnChain, generateModKey,
         type ModerationCert, type ModeratorVote } from '../api';
import * as t from '../theme';

export function ModerationPanel() {
  const [modKey, setModKey]           = useState('');
  const [forumId, setForumId]         = useState('');
  const [contentHash, setContentHash] = useState('a'.repeat(64));
  const [memberTag, setMemberTag]     = useState('');
  const [reason, setReason]           = useState('');
  const [votes, setVotes]             = useState<ModeratorVote[]>([]);
  const [thresholdN, setThresholdN]   = useState(2);
  const [cert, setCert]               = useState<ModerationCert | null>(null);
  const [certTx, setCertTx]           = useState<string | null>(null);
  const [certHistory, setCertHistory] = useState<Array<{ cert: ModerationCert; tx: string }>>([]);
  // Slash state
  const [shares, setShares]           = useState('');
  const [slashTx, setSlashTx]         = useState<string | null>(null);
  const [genKey, setGenKey]           = useState<{ signing_key_hex: string; pubkey_hex: string } | null>(null);
  const [loading, setLoading]         = useState(false);
  const [error, setError]             = useState<string | null>(null);

  async function handleGenModKey() {
    try { setGenKey(await generateModKey()); }
    catch (e) { setError(String(e)); }
  }

  async function handleVote() {
    setLoading(true); setError(null);
    try {
      const vote = await draftVote({ moderator_key_hex: modKey, forum_id: forumId,
        content_hash: contentHash, member_tag: memberTag, reason });
      setVotes(v => [...v, vote]);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  async function handleAggregate() {
    setLoading(true); setError(null);
    try { setCert(await aggregateCert({ votes, threshold_n: thresholdN })); }
    catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  async function handleSubmitCert() {
    if (!cert) return;
    setLoading(true); setError(null);
    try {
      const r = await submitCertOnChain({ forum_id: forumId, cert });
      setCertTx(r.tx_hash);
      setCertHistory(h => [...h, { cert, tx: r.tx_hash }]);
      setVotes([]); setCert(null); setCertTx(null);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  async function handleSlash() {
    setLoading(true); setError(null);
    try {
      let parsedShares: Array<{ index: number; value: string }> = [];
      try { parsedShares = JSON.parse(shares); } catch { throw new Error('shares must be valid JSON array'); }
      const r = await slashOnChain({
        forum_id: forumId,
        member_tag: memberTag,
        certs: certHistory.map(h => h.cert),
        shares: parsedShares,
      });
      setSlashTx(r.tx_hash);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  return (
    <section style={t.card}>
      <h2 style={t.heading}>Moderation Panel</h2>
      <p style={t.sub}>N moderators sign a vote. Once N votes are collected, a cert is aggregated and submitted on-chain.</p>

      <div style={t.grid2}>
        <label style={t.label}>Forum ID (hex)
          <input value={forumId} onChange={e => setForumId(e.target.value)} style={t.input} />
        </label>
        <label style={t.label}>Content hash (hex)
          <input value={contentHash} onChange={e => setContentHash(e.target.value)} style={t.input} />
        </label>
        <label style={t.label}>Member tag (hex)
          <input value={memberTag} onChange={e => setMemberTag(e.target.value)} style={t.input} />
        </label>
        <label style={t.label}>Strike reason
          <input value={reason} onChange={e => setReason(e.target.value)} placeholder="spam, harassment…" style={t.input} />
        </label>
      </div>

      <div style={{ marginTop: 12, padding: 12, background: '#0f172a', borderRadius: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
          <span style={{ color: '#94a3b8', fontSize: 13 }}>Moderator signing key</span>
          <button onClick={handleGenModKey} style={{ ...t.btnSecondary, padding: '4px 10px', fontSize: 12 }}>
            Generate New Key
          </button>
        </div>
        {genKey && (
          <div style={{ marginBottom: 8, fontSize: 12 }}>
            <div style={{ color: '#fca5a5', marginBottom: 2 }}>Signing key (auto-filled below):</div>
            <code style={{ ...t.code, wordBreak: 'break-all', display: 'block', fontSize: 11 }}>{genKey.signing_key_hex}</code>
            <div style={{ color: '#86efac', marginTop: 6, marginBottom: 2 }}>Pubkey (add to forum in Create tab before deploying):</div>
            <code style={{ ...t.code, wordBreak: 'break-all', display: 'block', fontSize: 11 }}>{genKey.pubkey_hex}</code>
          </div>
        )}
        <input
          value={modKey}
          onChange={e => setModKey(e.target.value)}
          placeholder="Paste signing key hex or click Generate New Key"
          style={{ ...t.input, fontFamily: 'monospace', fontSize: 12, marginTop: 0 }}
        />
        {genKey && !modKey && (
          <button onClick={() => setModKey(genKey.signing_key_hex)}
            style={{ ...t.btnSecondary, marginTop: 6, fontSize: 12 }}>
            Use generated key
          </button>
        )}
      </div>

      <button onClick={handleVote} disabled={loading} style={{ ...t.btn, marginTop: 12 }}>
        {loading ? 'Signing…' : 'Issue Vote'}
      </button>

      {votes.length > 0 && (
        <div style={{ marginTop: 16, padding: 12, background: '#0f172a', borderRadius: 8 }}>
          <span style={{ color: '#94a3b8', fontSize: 13 }}>Votes collected: {votes.length}</span>
          {votes.map((v, i) => (
            <div key={i} style={{ padding: '6px 0', borderBottom: '1px solid #1e293b', color: '#64748b', fontSize: 13 }}>
              #{i + 1} · mod: <code style={t.code}>{v.moderator_pubkey.slice(0, 16)}…</code> · {v.strike_reason}
            </div>
          ))}
          <div style={{ marginTop: 12, display: 'flex', gap: 12, alignItems: 'center' }}>
            <label style={{ ...t.label, margin: 0 }}>Required N:
              <input type="number" min={1} value={thresholdN}
                onChange={e => setThresholdN(+e.target.value)}
                style={{ ...t.input, width: 60, display: 'inline-block', marginLeft: 8 }} />
            </label>
            <button onClick={handleAggregate} disabled={votes.length < thresholdN || loading}
              style={t.btnSuccess}>Aggregate Certificate</button>
          </div>
        </div>
      )}

      {cert && !certTx && (
        <div style={{ ...t.success, marginTop: 12 }}>
          <div><strong>Certificate ready ({cert.votes.length} votes)</strong></div>
          <div style={{ marginTop: 6, fontSize: 13 }}>member_tag: <code style={t.code}>{cert.member_tag.slice(0,20)}…</code></div>
          <button onClick={handleSubmitCert} disabled={loading}
            style={{ ...t.btn, marginTop: 10, background: '#7c3aed' }}>
            {loading ? 'Submitting…' : 'Submit Cert On-Chain'}
          </button>
        </div>
      )}

      {certHistory.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <strong style={{ ...t.label, fontSize: 14 }}>Submitted Certs</strong>
          {certHistory.map((h, i) => (
            <div key={i} style={{ padding: 10, marginTop: 8, background: '#0f172a', borderRadius: 8, fontSize: 13 }}>
              <span style={{ color: '#86efac' }}>Cert #{i + 1} TX:</span>
              <br /><code style={{ ...t.code, wordBreak: 'break-all', fontSize: 11 }}>{h.tx}</code>
            </div>
          ))}
        </div>
      )}

      {certHistory.length > 0 && (
        <div style={{ marginTop: 20, padding: 16, background: '#1a0a2e', borderRadius: 10, border: '1px solid #7c3aed' }}>
          <strong style={{ color: '#c4b5fd', fontSize: 15 }}>Slash Member</strong>
          <p style={{ color: '#94a3b8', fontSize: 13, marginTop: 4 }}>
            Provide K Shamir shares (JSON array from registration) to reconstruct identity on-chain.
          </p>
          <div style={{ marginBottom: 8, padding: 8, background: '#0f0a1a', borderRadius: 6, fontSize: 12, color: '#94a3b8' }}>
            <strong style={{ color: '#fbbf24' }}>Where to get shares:</strong> Go to the <strong>Member tab</strong> → after registering,
            scroll down to the yellow <em>"Shamir shares"</em> box → click it to select all → copy → paste here.
            You need at least K shares (any K of the {'{total}'} generated).
          </div>
          <label style={t.label}>Shamir shares (JSON — paste from Member tab)
            <textarea value={shares} onChange={e => setShares(e.target.value)}
              placeholder={'[\n  {"index":1,"value":"aabbcc..."},\n  {"index":2,"value":"ddeeff..."}\n]'}
              style={{ ...t.input, minHeight: 120, fontFamily: 'monospace', fontSize: 11, resize: 'vertical', color: shares ? '#93c5fd' : undefined }} />
          </label>
          {shares && (() => {
            try {
              const parsed = JSON.parse(shares);
              return Array.isArray(parsed)
                ? <div style={{ fontSize: 12, color: '#86efac', marginTop: 4 }}>✓ Valid JSON — {parsed.length} shares parsed</div>
                : <div style={{ fontSize: 12, color: '#f87171', marginTop: 4 }}>✗ Must be a JSON array</div>;
            } catch {
              return <div style={{ fontSize: 12, color: '#f87171', marginTop: 4 }}>✗ Invalid JSON</div>;
            }
          })()}
          <button onClick={handleSlash} disabled={loading}
            style={{ ...t.btn, marginTop: 10, background: '#dc2626' }}>
            {loading ? 'Slashing…' : `Slash (${certHistory.length} certs on-chain)`}
          </button>

          {slashTx && (
            <div style={{ ...t.success, marginTop: 10, borderColor: '#dc2626' }}>
              <div><strong>Member slashed on-chain!</strong></div>
              <div style={{ marginTop: 8, fontSize: 13 }}>
                <span style={{ color: '#fca5a5' }}>Slash TX:</span>
                <br /><code style={{ ...t.code, wordBreak: 'break-all', fontSize: 11 }}>{slashTx}</code>
              </div>
            </div>
          )}
        </div>
      )}

      {error && <div style={t.error}>{error}</div>}
    </section>
  );
}
