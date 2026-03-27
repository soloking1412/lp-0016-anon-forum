import { useState } from 'react';
import { ForumCreator } from './components/ForumCreator';
import { MemberDashboard } from './components/MemberDashboard';
import { PostComposer } from './components/PostComposer';
import { ModerationPanel } from './components/ModerationPanel';
import { ModerationHistory } from './components/ModerationHistory';

type Tab = 'forum' | 'member' | 'post' | 'moderate' | 'audit';

const TABS: { id: Tab; label: string }[] = [
  { id: 'forum',    label: 'Create Forum' },
  { id: 'member',   label: 'Member' },
  { id: 'post',     label: 'Post' },
  { id: 'moderate', label: 'Moderation' },
  { id: 'audit',    label: 'Audit Trail' },
];

export default function App() {
  const [tab, setTab] = useState<Tab>('forum');

  return (
    <div style={styles.root}>
      <header style={styles.header}>
        <div style={styles.logo}>
          <span style={styles.logoIcon}>⬡</span>
          <span>Forum Anon</span>
        </div>
        <p style={styles.tagline}>
          Anonymous forum with threshold moderation — LP-0016 / Logos λPrize
        </p>
      </header>

      <nav style={styles.nav}>
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              ...styles.tabBtn,
              ...(tab === t.id ? styles.tabActive : {}),
            }}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <main style={styles.main}>
        {tab === 'forum'    && <ForumCreator />}
        {tab === 'member'   && <MemberDashboard />}
        {tab === 'post'     && <PostComposer />}
        {tab === 'moderate' && <ModerationPanel />}
        {tab === 'audit'    && <ModerationHistory />}
      </main>

      <footer style={styles.footer}>
        <span>
          Built for <a href="https://github.com/logos-co/lambda-prize" style={styles.link}>Logos λPrize</a>
          {' · '}
          Risc0 zkVM · SHA256-Merkle · Shamir K-of-N · Ed25519 N-of-M certs
        </span>
      </footer>
    </div>
  );
}

const styles = {
  root: { minHeight: '100vh', background: '#0a0a1a', fontFamily: 'system-ui, sans-serif', color: '#e2e8f0' } as React.CSSProperties,
  header: { padding: '32px 40px 20px', borderBottom: '1px solid #1e293b' } as React.CSSProperties,
  logo: { display: 'flex', alignItems: 'center', gap: 10, fontSize: 22, fontWeight: 700, color: '#a78bfa' } as React.CSSProperties,
  logoIcon: { fontSize: 28 } as React.CSSProperties,
  tagline: { color: '#475569', fontSize: 13, margin: '6px 0 0' } as React.CSSProperties,
  nav: { display: 'flex', gap: 4, padding: '0 40px', borderBottom: '1px solid #1e293b', background: '#0d0d1f' } as React.CSSProperties,
  tabBtn: { padding: '12px 18px', background: 'transparent', color: '#64748b', border: 'none', cursor: 'pointer', fontSize: 14, fontWeight: 500, borderBottom: '2px solid transparent', transition: 'all 0.15s' } as React.CSSProperties,
  tabActive: { color: '#a78bfa', borderBottomColor: '#a78bfa' } as React.CSSProperties,
  main: { maxWidth: 900, margin: '0 auto', padding: '32px 40px' } as React.CSSProperties,
  footer: { textAlign: 'center', padding: '24px 40px', color: '#334155', fontSize: 13, borderTop: '1px solid #1e293b' } as React.CSSProperties,
  link: { color: '#6366f1', textDecoration: 'none' } as React.CSSProperties,
};
