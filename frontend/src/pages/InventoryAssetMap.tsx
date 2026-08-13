import { useState, useEffect, useCallback } from 'react';
import { Database, FingerprintPattern, Lock, Ghost, Search, RefreshCw, FolderOpen, Inbox } from 'lucide-react';
import { apiClient } from '../api/client';

interface InventoryAsset {
  id: string;
  file_path: string;
  file_hash_sha256: string;
  owner_user_id: string;
  classification: string;
  file_size_bytes: number;
  last_accessed_at: string;
  first_scanned_at: string;
  created_at: string;
}

const classificationOptions = [
  'PUBLIC',
  'INTERNAL',
  'CONFIDENTIAL',
  'RESTRICTED',
  'TOP_SECRET',
  'PII',
  'PCI',
  'PHI',
  'UNKNOWN',
];

function formatBytes(n: number): string {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let value = n;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i++;
  }
  return `${value.toFixed(value >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function classificationColor(c: string): string {
  switch (c) {
    case 'RESTRICTED':
    case 'TOP_SECRET':
      return 'bg-red-100 text-red-700';
    case 'CONFIDENTIAL':
      return 'bg-orange-100 text-orange-700';
    case 'INTERNAL':
      return 'bg-blue-100 text-blue-700';
    case 'PII':
    case 'PCI':
    case 'PHI':
      return 'bg-purple-100 text-purple-700';
    default:
      return 'bg-gray-100 text-gray-700';
  }
}

export default function InventoryAssetMap() {
  const [assets, setAssets] = useState<InventoryAsset[]>([]);
  const [stats, setStats] = useState<Record<string, number>>({});
  const [unmanaged, setUnmanaged] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [classification, setClassification] = useState('');

  // Debounce the search input
  useEffect(() => {
    const t = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(t);
  }, [search]);

  const loadStats = useCallback(async () => {
    try {
      const [statsRes, unmanagedRes] = await Promise.all([
        apiClient.get('/api/v1/dspm/stats'),
        apiClient.get('/api/v1/dspm/inventory?limit=500'),
      ]);
      setStats(statsRes.data || {});
      const list: InventoryAsset[] = unmanagedRes.data?.data || [];
      setUnmanaged(list.filter((a) => !a.owner_user_id || a.owner_user_id === 'unknown').length);
    } catch {
      // stats/unmanaged are best-effort; the table drives the page
    }
  }, []);

  const loadAssets = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({ limit: '50' });
      if (classification) params.append('classification', classification);
      if (debouncedSearch) params.append('search', debouncedSearch);
      const res = await apiClient.get(`/api/v1/dspm/inventory?${params.toString()}`);
      setAssets(res.data?.data || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load inventory');
    } finally {
      setLoading(false);
    }
  }, [classification, debouncedSearch]);

  useEffect(() => {
    loadStats();
  }, [loadStats]);

  useEffect(() => {
    loadAssets();
  }, [loadAssets]);

  const total = stats.TOTAL || 0;
  const pii = stats.PII || 0;
  const restricted = (stats.RESTRICTED || 0) + (stats.TOP_SECRET || 0);

  const statCards = [
    { label: 'Total Data Assets', value: total, icon: Database, color: 'text-blue-600', bg: 'bg-blue-100' },
    { label: 'PII Found', value: pii, icon: FingerprintPattern, color: 'text-yellow-600', bg: 'bg-yellow-100' },
    { label: 'Restricted Files', value: restricted, icon: Lock, color: 'text-red-600', bg: 'bg-red-100' },
    { label: 'Unmanaged Data', value: unmanaged, icon: Ghost, color: 'text-gray-600', bg: 'bg-gray-100' },
  ];

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Data Inventory & Asset Map</h1>
          <p className="text-gray-600 mt-1">Sensitive data discovered across your environment</p>
        </div>
        <button
          onClick={() => { loadStats(); loadAssets(); }}
          className="flex items-center gap-2 px-4 py-2 bg-[#fd382f] text-white rounded-lg hover:bg-[#e02f26] transition-colors font-medium"
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        {statCards.map((card) => (
          <div key={card.label} className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
            <div className={`w-11 h-11 rounded-lg ${card.bg} flex items-center justify-center mb-3`}>
              <card.icon className={`h-5 w-5 ${card.color}`} />
            </div>
            <div className="text-3xl font-bold text-gray-900">{card.value.toLocaleString()}</div>
            <div className="text-sm text-gray-500 mt-1">{card.label}</div>
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-4 mb-6">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by file path..."
              className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-[#fd382f] focus:border-[#fd382f]"
            />
          </div>
          <select
            value={classification}
            onChange={(e) => setClassification(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-[#fd382f]"
          >
            <option value="">All Classifications</option>
            {classificationOptions.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          {loading ? (
            <div className="p-12 text-center text-gray-500">Loading data assets...</div>
          ) : assets.length === 0 ? (
            <div className="p-12 text-center">
              <Inbox className="h-12 w-12 text-gray-300 mx-auto mb-4" />
              <p className="text-gray-500">No data assets discovered yet</p>
              <p className="text-gray-400 text-sm mt-1">
                Sensitive files reported by connected agents will appear here.
              </p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-50 border-b">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">File Path</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Classification</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">File Size</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Last Scanned</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {assets.map((asset) => (
                  <tr key={asset.id} className="hover:bg-gray-50">
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-2">
                        <FolderOpen size={16} className="text-gray-400 flex-shrink-0" />
                        <span className="text-sm text-gray-900 break-all">{asset.file_path}</span>
                      </div>
                    </td>
                    <td className="px-6 py-3">
                      <span className={`inline-block px-2 py-1 rounded text-xs font-medium ${classificationColor(asset.classification)}`}>
                        {asset.classification}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">{formatBytes(asset.file_size_bytes)}</td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {new Date(asset.last_accessed_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
