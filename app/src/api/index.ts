// REST client for the forum-anon CLI daemon (localhost:3101).
// The daemon wraps Risc0 proof generation which cannot run in the browser.

const BASE = 'http://localhost:3101';

export interface RegistrationData {
  commitment: string;
  member_tag: string;
  shamir_commitments: string[];
  shares: Array<{ index: number; value: string }>;
}

export interface PostProof {
  member_tag: string;
  post_nullifier: string;
  merkle_root: string;
  receipt_hex: string;
}

export interface ModeratorVote {
  forum_id: string;
  content_hash: string;
  member_tag: string;
  strike_reason: string;
  moderator_pubkey: string;
  signature: string;
}

export interface ModerationCert {
  forum_id: string;
  content_hash: string;
  member_tag: string;
  votes: ModeratorVote[];
}

async function apiFetch<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: body !== undefined ? 'POST' : 'GET',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : {},
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`daemon error: ${text}`);
  }
  return res.json() as Promise<T>;
}

export async function generateIdentity(): Promise<{ id_secret_hex: string; commitment: string }> {
  return apiFetch('/keygen', {});
}

export async function generateModKey(): Promise<{ signing_key_hex: string; pubkey_hex: string }> {
  return apiFetch('/generate-mod-key', {});
}

export async function register(params: {
  id_secret_hex: string;
  forum_id: string;
  stake: number;
  threshold: number;
  total: number;
}): Promise<RegistrationData> {
  return apiFetch('/register', params);
}

export async function provePost(params: {
  id_secret_hex: string;
  forum_id: string;
  topic_id: string;
  merkle_root: string;
  leaf_index: number;
  num_leaves: number;
}): Promise<PostProof> {
  return apiFetch('/prove-post', params);
}

export async function draftVote(params: {
  moderator_key_hex: string;
  forum_id: string;
  content_hash: string;
  member_tag: string;
  reason: string;
}): Promise<ModeratorVote> {
  return apiFetch('/moderate', params);
}

export async function aggregateCert(params: {
  votes: ModeratorVote[];
  threshold_n: number;
}): Promise<ModerationCert> {
  return apiFetch('/aggregate-cert', params);
}

export async function listCerts(forum_id?: string): Promise<ModerationCert[]> {
  const url = forum_id
    ? `${BASE}/certs?forum_id=${encodeURIComponent(forum_id)}`
    : `${BASE}/certs`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export interface DeployForumResp {
  tx_hash: string;
  forum_id: string;
  account_id: string;
  threshold_k: number;
  threshold_n: number;
}

export async function deployForum(params: {
  forum_id?: string;
  threshold_k: number;
  threshold_n: number;
  moderators: string[];
}): Promise<DeployForumResp> {
  return apiFetch('/deploy-forum', params);
}

export interface RegisterOnChainResp {
  register_tx: string;
  root_tx: string;
  commitment: string;
  member_tag: string;
  merkle_root: string;
  leaf_index: number;
  shares: Array<{ index: number; value: string }>;
}

export async function registerOnChain(params: {
  id_secret_hex: string;
  forum_id: string;
  stake: number;
  threshold: number;
  total: number;
}): Promise<RegisterOnChainResp> {
  return apiFetch('/register-onchain', params);
}

export interface SubmitPostResp {
  tx_hash: string;
  post_nullifier: string;
  member_tag: string;
}

export async function submitPost(params: {
  forum_id: string;
  receipt_hex: string;
}): Promise<SubmitPostResp> {
  return apiFetch('/submit-post', params);
}

export interface SubmitCertResp {
  tx_hash: string;
}

export async function submitCertOnChain(params: {
  forum_id: string;
  cert: ModerationCert;
}): Promise<SubmitCertResp> {
  return apiFetch('/submit-cert', params);
}

export interface SlashOnChainResp {
  tx_hash: string;
}

export async function slashOnChain(params: {
  forum_id: string;
  member_tag: string;
  certs: ModerationCert[];
  shares: Array<{ index: number; value: string }>;
}): Promise<SlashOnChainResp> {
  return apiFetch('/slash-onchain', params);
}

export async function listForums(): Promise<Array<{
  forum_id_hex: string;
  account_id: string;
  threshold_k: number;
  threshold_n: number;
  deploy_tx: string;
  merkle_root: string;
}>> {
  return apiFetch('/forums');
}
