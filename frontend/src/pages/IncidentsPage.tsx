import { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import { AlertTriangle, CheckCircle, Clock, Eye, Shield } from 'lucide-react';

interface Incident {
    id: string;
    device_id: string;
    event_id: string;
    incident_type: string;
    severity: string;
    description: string;
    status: string;
    rule_name: string;
    rule_triggered_reason: string;
    file_involved: string;
    user_involved: string;
    action_taken: string;
    created_at: string;
    updated_at: string;
    resolved_at: string | null;
}

export function IncidentsPage() {
    const [incidents, setIncidents] = useState<Incident[]>([]);
    const [filteredIncidents, setFilteredIncidents] = useState<Incident[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
    const [filters] = useState({ status: '', severity: '' });

    useEffect(() => { loadIncidents(); const iv = setInterval(loadIncidents, 3000); return () => clearInterval(iv); }, []);
    useEffect(() => applyFilters(), [incidents, filters]);

    const loadIncidents = async () => {
        try {
            setLoading(true);
            const params = new URLSearchParams();
            if (filters.status) params.append('status', filters.status);
            if (filters.severity) params.append('severity', filters.severity);

            const res = await apiClient.get(`/api/v1/incidents?${params.toString()}`);
            const data = res.data;
            setIncidents(data.incidents || []);
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Error loading incidents');
        } finally { setLoading(false); }
    };

    const applyFilters = () => {
        let filtered = incidents;
        if (filters.status && filters.status !== 'ALL') filtered = filtered.filter(i => i.status === filters.status);
        if (filters.severity && filters.severity !== 'ALL') filtered = filtered.filter(i => i.severity === filters.severity);
        setFilteredIncidents(filtered);
    };

    const resolveIncident = async (incidentID: string) => {
        try {
            await apiClient.put(`/api/v1/incidents/${incidentID}/resolve`);
            await loadIncidents(); setSelectedIncident(null);
        } catch (err) { setError(err instanceof Error ? err.message : 'Error resolving incident'); }
    };

    const getSeverityColor = (severity: string) => {
        const colors: Record<string, string> = { 'CRITICAL': 'bg-red-100 text-red-800 border-red-300', 'HIGH': 'bg-orange-100 text-orange-800 border-orange-300', 'MEDIUM': 'bg-yellow-100 text-yellow-800 border-yellow-300', 'LOW': 'bg-green-100 text-green-800 border-green-300' };
        return colors[severity] || 'bg-gray-100 text-gray-800';
    };

    const getStatusIcon = (status: string) => { if (status === 'RESOLVED') return <CheckCircle className="w-5 h-5 text-green-600"/>; if (status === 'OPEN') return <AlertTriangle className="w-5 h-5 text-red-600"/>; return <Clock className="w-5 h-5 text-gray-600"/>; };

    const openIncidentDetails = (incident: Incident) => setSelectedIncident(incident);

    return (
        <div className="p-6 bg-gray-50 min-h-screen">
            <div className="flex justify-between items-center mb-6"><div><h1 className="text-3xl font-bold text-gray-900">Incidents</h1><p className="text-gray-600">View and manage security incidents</p></div></div>

            {error && <div className="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded">{error}</div>}

            <div className="grid grid-cols-4 gap-4 mb-6">
                <div className="bg-white rounded-lg border border-gray-200 p-4"><div className="text-sm text-gray-600">Total Incidents</div><div className="text-3xl font-bold">{incidents.length}</div></div>
                <div className="bg-white rounded-lg border border-gray-200 p-4"><div className="text-sm text-gray-600">Open</div><div className="text-3xl font-bold text-red-600">{incidents.filter(i => i.status === 'OPEN').length}</div></div>
                <div className="bg-white rounded-lg border border-gray-200 p-4"><div className="text-sm text-gray-600">Critical</div><div className="text-3xl font-bold text-red-700">{incidents.filter(i => i.severity === 'CRITICAL').length}</div></div>
                <div className="bg-white rounded-lg border border-gray-200 p-4"><div className="text-sm text-gray-600">Resolved</div><div className="text-3xl font-bold text-green-600">{incidents.filter(i => i.status === 'RESOLVED').length}</div></div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
                <div className="overflow-x-auto">
                    {loading ? <div className="p-8 text-center text-gray-500">Loading incidents...</div> : filteredIncidents.length === 0 ? <div className="p-8 text-center text-gray-500"><Shield className="w-12 h-12 mx-auto mb-3 text-green-600"/> <p>No incidents found. All clear!</p></div> : (
                        <table className="w-full">
                            <thead className="bg-gray-50 border-b"><tr><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Status</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Type</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Rule</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Severity</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">File Involved</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">User</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Created</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Actions</th></tr></thead>
                            <tbody className="divide-y divide-gray-200">
                                {filteredIncidents.map(incident => (
                                    <tr key={incident.id} className="hover:bg-gray-50 cursor-pointer"><td className="px-6 py-4">{getStatusIcon(incident.status)}</td><td className="px-6 py-4 text-sm font-medium">{incident.incident_type}</td><td className="px-6 py-4 text-sm">{incident.rule_name}</td><td className="px-6 py-4"><span className={`text-xs px-2 py-1 rounded border ${getSeverityColor(incident.severity)}`}>{incident.severity}</span></td><td className="px-6 py-4 text-sm text-gray-700">{incident.file_involved}</td><td className="px-6 py-4 text-sm">{incident.user_involved}</td><td className="px-6 py-4 text-sm text-gray-500">{new Date(incident.created_at).toLocaleString()}</td><td className="px-6 py-4"><button onClick={() => openIncidentDetails(incident)} className="text-blue-600 hover:text-blue-800 flex items-center gap-1"><Eye size={16}/> View</button></td></tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            </div>

            {selectedIncident && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
                    <div className="bg-white rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto p-6">
                        <div className="flex justify-between items-start mb-4"><h2 className="text-2xl font-bold">{selectedIncident.incident_type}</h2><button onClick={() => setSelectedIncident(null)} className="text-gray-600 hover:text-gray-900 text-2xl">×</button></div>
                        <div className="space-y-4">
                            <div className="grid grid-cols-2 gap-4"><div><p className="text-sm text-gray-600">Status</p><p className="font-semibold">{selectedIncident.status}</p></div><div><p className="text-sm text-gray-600">Severity</p><span className={`text-sm px-2 py-1 rounded ${getSeverityColor(selectedIncident.severity)}`}>{selectedIncident.severity}</span></div></div>
                            <div className="border-t pt-4"><p className="text-sm text-gray-600 mb-1">File Involved</p><p className="font-mono text-sm bg-gray-100 p-2 rounded">{selectedIncident.file_involved}</p></div>
                            <div className="border-t pt-4"><p className="text-sm text-gray-600 mb-1">Description</p><p className="text-sm">{selectedIncident.description}</p></div>
                            <div className="border-t pt-4"><p className="text-sm text-gray-600 mb-1">Rule Trigger Reason</p><p className="text-sm">{selectedIncident.rule_triggered_reason}</p></div>
                            <div className="border-t pt-4"><p className="text-sm text-gray-600 mb-1">Action Taken</p><p className="text-sm font-semibold">{selectedIncident.action_taken}</p></div>
                            <div className="grid grid-cols-2 gap-2 text-xs text-gray-500 border-t pt-4"><div>Created: {new Date(selectedIncident.created_at).toLocaleString()}</div><div>Updated: {new Date(selectedIncident.updated_at).toLocaleString()}</div></div>
                            {selectedIncident.status !== 'RESOLVED' && (<div className="flex gap-2 pt-4 border-t"><button onClick={() => resolveIncident(selectedIncident.id)} className="flex-1 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700">Resolve Incident</button><button onClick={() => setSelectedIncident(null)} className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded hover:bg-gray-50">Close</button></div>)}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

export default IncidentsPage;
