import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Monitor, HeartPulse } from 'lucide-react';
import { apiClient } from '../api/client';

interface Device {
  id: string;
  hostname: string;
  ipAddress?: string;
  agentVersion?: string;
  status?: string;
  lastSeen?: string;
}

export default function SensorHealth() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiClient.get('/api/devices');
      // The backend returns a bare array; some endpoints wrap it as {devices:[...]}.
      const raw = Array.isArray(res.data) ? res.data : (res.data?.devices || []);
      const mapped: Device[] = raw.map((d: any) => ({
        id: d.id || d.hostname,
        hostname: d.hostname,
        ipAddress: d.ipAddress || d.ip_address,
        agentVersion: d.agentVersion || d.agent_version,
        status: d.status,
        lastSeen: d.lastSeen || d.last_seen,
      }));
      setDevices(mapped);
    } catch {
      // best-effort
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const statusDot = (status?: string) => {
    const s = status || 'offline';
    const color = s === 'online' ? 'bg-green-500' : s === 'warning' ? 'bg-yellow-500' : 'bg-red-500';
    return <span className={`inline-block w-2.5 h-2.5 rounded-full ${color} mr-2`} />;
  };

  const statusLabel = (status?: string) => {
    const s = status || 'offline';
    const text = s === 'online' ? 'text-green-600' : s === 'warning' ? 'text-yellow-600' : 'text-red-600';
    return <span className={`text-sm font-medium capitalize ${text}`}>{s}</span>;
  };

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Sensor Health & Telemetry</h1>
          <p className="text-gray-600 mt-1">Status of all connected agents</p>
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
          <HeartPulse className="h-5 w-5 text-brand" />
          <h2 className="text-lg font-semibold text-gray-900">Connected Agents</h2>
        </div>
        <div className="overflow-x-auto">
          {loading ? (
            <div className="p-12 text-center text-gray-500">Loading agents...</div>
          ) : devices.length === 0 ? (
            <div className="p-12 text-center">
              <Monitor className="h-12 w-12 text-gray-300 mx-auto mb-4" />
              <p className="text-gray-500">No agents connected yet</p>
            </div>
          ) : (
            <table className="w-full">
              <thead className="bg-gray-50 border-b">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Hostname</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">IP Address</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Agent Version</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Last Heartbeat</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {devices.map((d) => (
                  <tr key={d.id} className="hover:bg-gray-50">
                    <td className="px-6 py-3 text-sm text-gray-900 font-medium">{d.hostname}</td>
                    <td className="px-6 py-3 text-sm text-gray-600">{d.ipAddress || '—'}</td>
                    <td className="px-6 py-3 text-sm text-gray-600">{d.agentVersion || '—'}</td>
                    <td className="px-6 py-3 text-sm text-gray-600">
                      {d.lastSeen ? new Date(d.lastSeen).toLocaleString() : '—'}
                    </td>
                    <td className="px-6 py-3">
                      <span className="flex items-center">
                        {statusDot(d.status)}
                        {statusLabel(d.status)}
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
