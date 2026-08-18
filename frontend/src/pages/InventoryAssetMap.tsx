import { useState, useEffect, useCallback } from 'react';
import { AlertTriangle, ShieldAlert, Database, Globe, Search, RefreshCw, FolderOpen, Inbox, ShieldCheck } from 'lucide-react';
import { apiClient } from '../api/client';
import { FindingsCell, type FindingView } from '../components/FindingsCell';

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
  exposure_level: string;
  risk_score: number;
  content_snippet: string;
  findings?: FindingView[];
}

interface RiskDistribution {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
}

interface DSPMStats {
  TOTAL?: number;
  risk_distribution?: RiskDistribution;
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

function riskBucket(score: number): { label: string; text: string; bar: string; badge: string } {
  if (score >= 76) {
    return { label: 'Critical', text: 'text-red-600', bar: 'bg-red-500', badge: 'bg-red-100 text-red-700' };
  }
  if (score >= 51) {
    return { label: 'High', text: 'text-orange-600', bar: 'bg-orange-500', badge: 'bg-orange-100 text-orange-700' };
  }
  if (score >= 26) {
    return { label: 'Medium', text: 'text-yellow-600', bar: 'bg-yellow-400', badge: 'bg-yellow-100 text-yellow-700' };
  }
  return { label: 'Low', text: 'text-green-600', bar: 'bg-green-500', badge: 'bg-green-100 text-green-700' };
}

function exposureBadge(level: string): string {
  switch (level) {
    case 'PUBLIC':
      return 'bg-red-100 text-red-700 border-red-200';
    case 'INTERNAL':
      return 'bg-blue-100 text-blue-700 border-blue-200';
    case 'RESTRICTED':
      return 'bg-gray-100 text-gray-600 border-gray-200';
    default:
      return 'bg-gray-50 text-gray-500 border-gray-200';
  }
}

export default function InventoryAssetMap() {
  const [assets, setAssets] = useState<InventoryAsset[]>([]);
  const [stats, setStats] = useState<DSPMStats>({});
  const [publicCount, setPublicCount] = useState(0);
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
      setPublicCount(list.filter((a) => (a.exposure_level || '').toUpperCase() === 'PUBLIC').length);
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

  const riskDist = stats.risk_distribution || {};
  const critical = riskDist.critical || 0;
  const high = riskDist.high || 0;
  const total = stats.TOTAL || 0;

  const statCards = [
    {
      label: 'Critical Risk Assets',
      value: critical,
      icon: AlertTriangle,
      color: 'text-red-600',
      bg: 'bg-red-100',
      ring: 'ring-red-200',
      subtitle: 'Score 76–100',
    },
    {
      label: 'High Risk Assets',
      value: high,
      icon: ShieldAlert,
      color: 'text-orange-600',
      bg: 'bg-orange-100',
      ring: 'ring-orange-200',
      subtitle: 'Score 51–75',
    },
    {
      label: 'Total Sensitive Files',
      value: total,
      icon: Database,
      color: 'text-blue-600',
      bg: 'bg-blue-100',
      ring: 'ring-blue-200',
      subtitle: 'All classifications',
    },
    {
      label: 'Publicly Exposed Files',
      value: publicCount,
      icon: Globe,
      color: 'text-yellow-600',
      bg: 'bg-yellow-100',
      ring: 'ring-yellow-200',
      subtitle: 'Exposure: PUBLIC',
    },
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
          className="flex items-center gap-2 px-4 py-2 bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors font-medium"
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
          <div
            key={card.label}
            className="manara-card relative overflow-hidden"
          >
            <div className={`absolute top-0 left-0 h-1 w-full ${card.bg}`} />
            <div className="flex items-start justify-between">
              <div className={`w-11 h-11 rounded-lg ${card.bg} ring-2 ${card.ring} flex items-center justify-center`}>
                <card.icon className={`h-5 w-5 ${card.color}`} />
              </div>
            </div>
            <div className="text-3xl font-bold text-gray-900 mt-4">{card.value.toLocaleString()}</div>
            <div className="text-sm font-medium text-gray-600 mt-1">{card.label}</div>
            {card.subtitle && <div className="text-xs text-gray-400 mt-0.5">{card.subtitle}</div>}
          </div>
        ))}
      </div>

      {/* Filters */}
      <div className="manara-card p-4 mb-6">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by file path..."
              className="w-full pl-9 pr-3 py-2 border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
            />
          </div>
          <select
            value={classification}
            onChange={(e) => setClassification(e.target.value)}
            className="px-3 py-2 border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand"
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
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Risk Score</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Exposure</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Snippet</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Findings</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">File Size</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Last Scanned</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {assets.map((asset) => {
                  const risk = riskBucket(asset.risk_score || 0);
                  const exposure = (asset.exposure_level || 'UNKNOWN').toUpperCase();
                  return (
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
                      <td className="px-6 py-3">
                        <div className="flex items-center gap-2">
                          <span className={`inline-flex items-center gap-1.5 px-2 py-1 rounded text-xs font-semibold ${risk.badge}`}>
                            <ShieldCheck size={12} />
                            {asset.risk_score ?? 0}
                          </span>
                          <div className="hidden xl:block w-20 h-1.5 rounded-full bg-gray-200 overflow-hidden">
                            <div
                              className={`h-full rounded-full ${risk.bar}`}
                              style={{ width: `${Math.min(100, Math.max(0, asset.risk_score ?? 0))}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-3">
                        <span className={`inline-block px-2 py-1 rounded text-xs font-medium border ${exposureBadge(exposure)}`}>
                          {exposure}
                        </span>
                      </td>
                      <td className="px-6 py-3">
                        {asset.content_snippet ? (
                          <span
                            title={asset.content_snippet}
                            className="block max-w-[280px] truncate font-mono text-xs text-gray-600 cursor-help"
                          >
                            {asset.content_snippet}
                          </span>
                        ) : (
                          <span className="text-xs text-gray-400">—</span>
                        )}
                      </td>
                      <td className="px-6 py-3">
                        <FindingsCell findings={asset.findings} />
                      </td>
                      <td className="px-6 py-3 text-sm text-gray-600">{formatBytes(asset.file_size_bytes)}</td>
                      <td className="px-6 py-3 text-sm text-gray-600">
                        {new Date(asset.last_accessed_at).toLocaleString()}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
