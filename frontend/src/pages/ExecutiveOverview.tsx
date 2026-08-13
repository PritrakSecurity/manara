import { useState, useEffect, useCallback } from 'react';
import { Monitor, Wifi, FileWarning, ShieldAlert, RefreshCw } from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts';
import { apiClient } from '../api/client';

interface Device {
  id: string;
  hostname: string;
  status?: string;
}

interface Incident {
  id: string;
  device_id: string;
  severity: string;
  description?: string;
  status?: string;
  file_involved?: string;
  user_involved?: string;
  created_at: string;
}

export default function ExecutiveOverview() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [stats, setStats] = useState<Record<string, number>>({});
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [devicesRes, statsRes, incidentsRes] = await Promise.all([
        apiClient.get('/api/devices'),
        apiClient.get('/api/v1/dspm/stats'),
        apiClient.get('/api/v1/incidents'),
      ]);
      setDevices(Array.isArray(devicesRes.data) ? devicesRes.data : []);
      setStats(statsRes.data || {});
      setIncidents(incidentsRes.data?.incidents || []);
    } catch {
      // best-effort; empty states render below
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const online = devices.filter((d) => d.status === 'online').length;
  const activeIncidents = incidents.filter((i) => i.status !== 'RESOLVED').length;

  const cards = [
    { label: 'Total Endpoints', value: devices.length, icon: Monitor, color: 'text-blue-600', bg: 'bg-blue-100' },
    { label: 'Online Agents', value: online, icon: Wifi, color: 'text-green-600', bg: 'bg-green-100' },
    { label: 'Sensitive Files Found', value: stats.TOTAL || 0, icon: FileWarning, color: 'text-yellow-600', bg: 'bg-yellow-100' },
    { label: 'Active Incidents', value: activeIncidents, icon: ShieldAlert, color: 'text-red-600', bg: 'bg-red-100' },
  ];

  const classificationData = Object.entries(stats)
    .filter(([k]) => k !== 'TOTAL')
    .map(([name, value]) => ({ name, count: value }));

  const recentIncidents = [...incidents]
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Executive Overview</h1>
          <p className="text-gray-600 mt-1">Command center at a glance</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-4 py-2 bg-[#fd382f] text-white rounded-lg hover:bg-[#e02f26] transition-colors font-medium"
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        {cards.map((card) => (
          <div key={card.label} className="bg-white rounded-xl border border-gray-200 shadow-sm p-5">
            <div className={`w-11 h-11 rounded-lg ${card.bg} flex items-center justify-center mb-3`}>
              <card.icon className={`h-5 w-5 ${card.color}`} />
            </div>
            <div className="text-3xl font-bold text-gray-900">{card.value.toLocaleString()}</div>
            <div className="text-sm text-gray-500 mt-1">{card.label}</div>
          </div>
        ))}
      </div>

      {/* Chart */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 mb-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Sensitive Files by Classification</h2>
        {loading ? (
          <div className="h-64 flex items-center justify-center text-gray-500">Loading...</div>
        ) : classificationData.length === 0 ? (
          <div className="h-64 flex items-center justify-center text-gray-400">No classification data yet</div>
        ) : (
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={classificationData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                <XAxis dataKey="name" tick={{ fontSize: 12, fill: '#6b7280' }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 12, fill: '#6b7280' }} />
                <Tooltip cursor={{ fill: '#f9fafb' }} />
                <Bar dataKey="count" name="Assets" fill="#fd382f" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Recent incidents */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100">
          <h2 className="text-lg font-semibold text-gray-900">Recent Incidents</h2>
        </div>
        <div className="overflow-x-auto">
          {recentIncidents.length === 0 ? (
            <div className="p-8 text-center text-gray-400">No incidents recorded</div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-50 border-b">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Time</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">File</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Severity</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {recentIncidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-gray-50">
                    <td className="px-6 py-3 text-sm text-gray-600">{new Date(inc.created_at).toLocaleString()}</td>
                    <td className="px-6 py-3 text-sm text-gray-900 break-all">{inc.file_involved || '—'}</td>
                    <td className="px-6 py-3">
                      <span className={`inline-block px-2 py-1 rounded text-xs font-medium ${
                        inc.severity === 'HIGH' || inc.severity === 'CRITICAL'
                          ? 'bg-red-100 text-red-700'
                          : inc.severity === 'MEDIUM' || inc.severity === 'MEDIUM_HIGH'
                            ? 'bg-yellow-100 text-yellow-700'
                            : 'bg-green-100 text-green-700'
                      }`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">{inc.status || '—'}</td>
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
