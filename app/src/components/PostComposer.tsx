import { useState } from 'react';
import { provePost, submitPost, type SubmitPostResp } from '../api';
import * as t from '../theme';

export function PostComposer() {
  const [idSecret, setIdSecret]     = useState('');
  const [forumId, setForumId]       = useState('');
  const [topicId, setTopicId]       = useState('a'.repeat(64));
  const [merkleRoot, setMerkleRoot] = useState('');
  const [leafIndex, setLeafIndex]   = useState(0);
  const [proof, setProof]           = useState<{ member_tag: string; post_nullifier: string; receipt_hex: string } | null>(null);
  const [onChain, setOnChain]       = useState<SubmitPostResp | null>(null);
  const [loading, setLoading]       = useState(false);
  const [error, setError]           = useState<string | null>(null);
  const numLeaves = 4;

  async function handleProve() {
    if (leafIndex >= numLeaves) { setError(`leaf_index must be < ${numLeaves}`); return; }
    setLoading(true); setError(null); setProof(null); setOnChain(null);
    try {
      const r = await provePost({ id_secret_hex: idSecret, forum_id: forumId,
        topic_id: topicId, merkle_root: merkleRoot, leaf_index: leafIndex, num_leaves: numLeaves });
      setProof(r);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  async function handleSubmit() {
    if (!proof) return;
    setLoading(true); setError(null);
    try { setOnChain(await submitPost({ forum_id: forumId, receipt_hex: proof.receipt_hex })); }
    catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  }

  return (
    <section style={t.card}>
      <h2 style={t.heading}>Post Anonymously</h2>
      <p style={t.sub}>
        Generate a ZK membership proof, then submit it on-chain. Posts are unlinkable across topics.
      </p>

      <div style={t.grid2}>
        <label style={t.label}>
          Forum ID (hex)
          <input value={forumId} onChange={e => setForumId(e.target.value)} placeholder="64-char hex" style={t.input} />
        </label>
        <label style={t.label}>
          Topic ID (hex)
          <input value={topicId} onChange={e => setTopicId(e.target.value)} placeholder="64-char hex" style={t.input} />
        </label>
        <label style={t.label}>
          Merkle root (hex)
          <input value={merkleRoot} onChange={e => setMerkleRoot(e.target.value)} placeholder="From Member tab" style={t.input} />
        </label>
        <label style={t.label}>
          Leaf index (0–{numLeaves - 1})
          <input type="number" min={0} max={numLeaves - 1} value={leafIndex}
            onChange={e => setLeafIndex(+e.target.value)} style={t.input} />
        </label>
      </div>

      <label style={{ ...t.label, marginTop: 4 }}>
        id_secret (hex)
        <input type="password" value={idSecret} onChange={e => setIdSecret(e.target.value)}
          placeholder="64-char hex — stays local" style={t.input} />
      </label>

      <button onClick={handleProve} disabled={loading} style={{ ...t.btn, marginTop: 16 }}>
        {loading ? 'Generating ZK proof…' : 'Step 1 · Generate ZK Proof'}
      </button>

      {proof && (
        <div style={{ ...t.success, marginTop: 12 }}>
          <div><strong>ZK proof generated!</strong></div>
          <div style={{ marginTop: 8, display: 'grid', gap: 4, fontSize: 13 }}>
            <div>member_tag: <code style={t.code}>{proof.member_tag}</code></div>
            <div>post_nullifier: <code style={t.code}>{proof.post_nullifier}</code></div>
          </div>
          <button onClick={handleSubmit} disabled={loading}
            style={{ ...t.btn, marginTop: 12, background: '#059669' }}>
            {loading ? 'Submitting on-chain…' : 'Step 2 · Submit Post On-Chain'}
          </button>
        </div>
      )}

      {onChain && (
        <div style={{ ...t.success, marginTop: 10, borderColor: '#059669' }}>
          <div><strong>Post verified on-chain!</strong></div>
          <div style={{ marginTop: 8, fontSize: 13 }}>
            <span style={{ color: '#86efac' }}>TX Hash:</span>
            <br /><code style={{ ...t.code, wordBreak: 'break-all', fontSize: 11 }}>{onChain.tx_hash}</code>
          </div>
          <div style={{ marginTop: 8, fontSize: 13 }}>
            post_nullifier: <code style={t.code}>{onChain.post_nullifier}</code>
          </div>
        </div>
      )}

      {error && <div style={t.error}>{error}</div>}
    </section>
  );
}
