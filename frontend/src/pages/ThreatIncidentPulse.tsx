import { useState, useEffect, useCallback } from 'react';
import { Activity, RefreshCw, AlertTriangle } from 'lucide-react';
import { apiClient } from '../api/client';

interface Device {
  id: string;
  hostname: string;
}

interface Incident {
  id: string;
  device_id: string;
  severity: string;
  status?: string;
  file_involved?: string;
  user_involved?: string;
  action_taken?: string;
  created_at: string;
}

export default function ThreatIncidentPulse() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [hostnameMap, setHostnameMap] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [incidentsRes, devicesRes] = await Promise.all([
        apiClient.get('/api/v1/incidents?limit=10'),
        apiClient.get('/api/devices'),
      ]);
      setIncidents(incidentsRes.data?.incidents || []);
      const list: Device[] = Array.isArray(devicesRes.data) ? devicesRes.data : [];
      const map: Record<string, string> = {};
      for (const d of list) map[d.id] = d.hostname;
      setHostnameMap(map);
    } catch {
      // best-effort
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const severityClass = (s: string) =>
    s === 'HIGH' || s === 'CRITICAL'
      ? 'bg-red-100 text-red-700'
      : s === 'MEDIUM' || s === 'MEDIUM_HIGH'
        ? 'bg-yellow-100 text-yellow-700'
        : 'bg-green-100 text-green-700';

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Threat & Incident Pulse</h1>
          <p className="text-gray-600 mt-1">Live feed of security incidents</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-4 py-2 bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors font-medium"
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-100 flex items-center gap-2">
          <Activity className="h-5 w-5 text-brand" />
          <h2 className="text-lg font-semibold text-gray-900">Incident Feed</h2>
        </div>
        <div className="overflow-x-auto">
          {loading ? (
            <div className="p-12 text-center text-gray-500">Loading incidents...</div>
          ) : incidents.length === 0 ? (
            <div className="p-12 text-center">
              <AlertTriangle className="h-12 w-12 text-gray-300 mx-auto mb-4" />
              <p className="text-gray-500">No security incidents detected</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-50 border-b">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Time</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Hostname</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">User</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">File Path</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Action Taken</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Severity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-gray-50">
                    <td className="px-6 py-3 text-sm text-gray-600 whitespace-nowrap">
                      {new Date(inc.created_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-900">
                      {hostnameMap[inc.device_id] || 'Unknown'}
                    </td>
                    <td className="px-6 py-3 text-sm text-gray-600">{inc.user_involved || '—'}</td>
                    <td className="px-6 py-3 text-sm text-gray-900 break-all">{inc.file_involved || '—'}</td>
                    <td className="px-6 py-3 text-sm text-gray-600">{inc.action_taken || '—'}</td>
                    <td className="px-6 py-3">
                      <span className={`inline-block px-2 py-1 rounded text-xs font-medium ${severityClass(inc.severity)}`}>
                        {inc.severity}
                      </span>
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
