const BASE = '';  // Vite proxies /api → localhost:8000

async function api(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, options);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Request failed: ${res.status}`);
  }
  return res.json();
}

export const auditContract = (code, name = 'Unknown', mode = 'full') =>
  api('/api/audit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ contract_code: code, contract_name: name, mode }),
  });

export const getSampleContract = (id) => api(`/api/samples/${id}`);
export const getStats = () => api('/api/stats');
export const getHistory = (limit = 8) => api(`/api/history?limit=${limit}`);
export const healthCheck = () => api('/api/health').catch(() => null);
