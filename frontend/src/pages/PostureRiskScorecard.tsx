import { useState, useEffect, useCallback } from 'react';
import { Gauge, FileWarning, Database, Lock, RefreshCw, PieChart as PieIcon } from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';
import { apiClient } from '../api/client';
import { mockRiskiestAssets } from '../__mocks__';

const PIE_COLORS = ['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#a855f7'];

export default function PostureRiskScorecard() {
  const [stats, setStats] = useState<Record<string, number>>({});

  const load = useCallback(async () => {
    try {
      const res = await apiClient.get('/api/v1/dspm/stats');
      setStats(res.data || {});
    } catch {
      // best-effort
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const total = stats.TOTAL || 0;
  const pii = stats.PII || 0;
  const restricted = stats.RESTRICTED || 0;

  // Heuristic risk score weighted towards high-risk classifications.
  const riskScore = total === 0 ? 0 : Math.min(100, Math.round(25 + pii * 4 + restricted * 6));

  const pieData = [
    { name: 'Public', value: stats.PUBLIC || 0 },
    { name: 'Internal', value: stats.INTERNAL || 0 },
    { name: 'Confidential', value: stats.CONFIDENTIAL || 0 },
    { name: 'Restricted', value: restricted },
    { name: 'PII', value: pii },
  ].filter((d) => d.value > 0);

  const riskiestAssets = mockRiskiestAssets;

  const gaugeColor = riskScore >= 70 ? '#ef4444' : riskScore >= 40 ? '#f59e0b' : '#10b981';

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Posture & Risk Scorecard</h1>
          <p className="text-gray-600 mt-1">Data risk at a glance</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-4 py-2 bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors font-medium"
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        {/* Risk score */}
        <div className="manara-card flex flex-col items-center justify-center">
          <div className="w-14 h-14 rounded-full bg-brand/10 flex items-center justify-center mb-4">
            <Gauge className="h-7 w-7 text-brand" />
          </div>
          <div className="text-5xl font-bold" style={{ color: gaugeColor }}>{riskScore}</div>
          <div className="text-sm text-gray-500 mt-1">Risk Score / 100</div>
          <p className="text-xs text-gray-400 mt-4 text-center">
            Weighted from discovered PII and restricted data assets.
          </p>
        </div>

        {/* Distribution */}
        <div className="manara-card col-span-2">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Data Distribution</h2>
          {pieData.length === 0 ? (
            <div className="h-56 flex flex-col items-center justify-center text-gray-400">
              <PieIcon className="h-8 w-8 text-gray-300 mb-2" />
              No classification data yet
            </div>
          ) : (
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label>
                    {pieData.map((_, i) => (
                      <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Riskiest assets */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100 flex items-center gap-2">
          <FileWarning className="h-5 w-5 text-brand" />
          <h2 className="text-lg font-semibold text-gray-900">Top Riskiest Assets</h2>
        </div>
        <ul className="divide-y divide-gray-200">
          {riskiestAssets.length === 0 ? (
            <li className="px-6 py-8 text-center text-gray-400">No riskiest asset data available.</li>
          ) : (
            riskiestAssets.map((asset, i) => (
              <li key={asset} className="px-6 py-3 flex items-center gap-3">
                <span className="text-sm font-semibold text-gray-400 w-6">{i + 1}</span>
                {asset.includes('sql') || asset.includes('credentials') ? (
                  <Database className="h-4 w-4 text-red-500 flex-shrink-0" />
                ) : (
                  <Lock className="h-4 w-4 text-yellow-500 flex-shrink-0" />
                )}
                <span className="text-sm text-gray-900 break-all">{asset}</span>
              </li>
            ))
          )}
        </ul>
      </div>
    </div>
  );
}
