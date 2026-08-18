import { useState, useEffect } from 'react';
import { Filter, RefreshCw, AlertTriangle, CheckCircle, Wifi, WifiOff } from 'lucide-react';
import { useEventStream } from '../hooks/useEventStream';
import { apiClient } from '../api/client';
import { FindingsCell, type FindingView } from '../components/FindingsCell';

interface EventLog {
    id: string;
    device_id: string;
    event_type: string;
    file_path: string;
    file_name: string;
    file_size: number;
    file_extension: string;
    source_location: string;
    destination_location: string;
    classification: string;
    risk_level: string;
    keywords_found: string[];
    process_name: string;
    username: string;
    operation_result: string;
    was_blocked: boolean;
    block_reason: string;
    created_at: string;
    findings?: FindingView[];
}

export function EventLogsPage() {
    const [events, setEvents] = useState<EventLog[]>([]);
    const [filteredEvents, setFilteredEvents] = useState<EventLog[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [filters, setFilters] = useState({ event_type: '', classification: '', risk_level: '', username: '' });

    // WebSocket for real-time events
    const { events: wsEvents, isConnected } = useEventStream({
        onEvent: (event) => {
            console.log('[EventLogsPage] Real-time event received:', event.event_type, event.file_name);
        }
    });

    // Merge WebSocket events with polled events
    useEffect(() => {
        if (wsEvents.length > 0) {
            setEvents(prev => {
                // Merge new WebSocket events with existing events, avoiding duplicates
                const existingIds = new Set(prev.map(e => e.id));
                const newEvents = wsEvents.filter(e => !existingIds.has(e.id)).map(e => ({
                    ...e,
                    file_size: 0,
                    file_extension: '',
                    source_location: '',
                    destination_location: '',
                    process_name: '',
                    operation_result: '',
                    was_blocked: false,
                    block_reason: ''
                } as EventLog));
                if (newEvents.length > 0) {
                    return [...newEvents, ...prev].slice(0, 1000);
                }
                return prev;
            });
        }
    }, [wsEvents]);

    useEffect(() => { loadEvents(); const iv = setInterval(loadEvents, 10000); return () => clearInterval(iv); }, []);
    useEffect(() => applyFilters(), [events, filters]);

    const loadEvents = async () => {
        try {
            setLoading(true);
            const params = new URLSearchParams();
            if (filters.event_type) params.append('event_type', filters.event_type);
            if (filters.classification) params.append('classification', filters.classification);
            if (filters.risk_level) params.append('risk_level', filters.risk_level);
            if (filters.username) params.append('username', filters.username);

            // apiClient injects the JWT automatically.
            const res = await apiClient.get(`/api/v1/event-logs?${params.toString()}`);
            const data = res.data;
            setEvents((data.events || []).slice(0, 1000));
            setError(null);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Error loading events');
        } finally { setLoading(false); }
    };

    const applyFilters = () => {
        let filtered = events;
        if (filters.event_type) filtered = filtered.filter(e => e.event_type === filters.event_type);
        if (filters.classification) filtered = filtered.filter(e => e.classification === filters.classification);
        if (filters.risk_level) filtered = filtered.filter(e => e.risk_level === filters.risk_level);
        if (filters.username) filtered = filtered.filter(e => e.username?.toLowerCase().includes(filters.username.toLowerCase()));
        setFilteredEvents(filtered);
    };

    const getRiskColor = (riskLevel: string) => {
        const colors: Record<string, string> = { 
            'CRITICAL': 'bg-red-100 text-red-800', 
            'HIGH': 'bg-orange-100 text-orange-800', 
            'MEDIUM_HIGH': 'bg-amber-100 text-amber-800',
            'MEDIUM': 'bg-yellow-100 text-yellow-800', 
            'LOW': 'bg-green-100 text-green-800',
            'NONE': 'bg-gray-100 text-gray-800'
        };
        return colors[riskLevel] || 'bg-gray-100 text-gray-800';
    };

    const getClassificationColor = (classification: string) => {
        const colors: Record<string, string> = { 
            'RESTRICTED': 'bg-red-100 text-red-800', 
            'CONFIDENTIAL': 'bg-orange-100 text-orange-800', 
            'INTERNAL': 'bg-yellow-100 text-yellow-800', 
            'PUBLIC': 'bg-green-100 text-green-800',
            'PENDING': 'bg-purple-100 text-purple-800'
        };
        return colors[classification] || 'bg-blue-100 text-blue-800';
    };

    const getStatusIcon = (event: EventLog) => event.was_blocked ? <AlertTriangle className="w-5 h-5 text-red-600"/> : <CheckCircle className="w-5 h-5 text-green-600"/>;

    return (
        <div className="p-6 bg-gray-50 min-h-screen">
            <div className="flex justify-between items-center mb-6">
                <div>
                    <h1 className="text-3xl font-bold text-gray-900">Event Logs</h1>
                    <p className="text-gray-600">Real-time file activity monitoring</p>
                </div>
                <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2">
                        {isConnected ? (
                            <><Wifi size={18} className="text-green-600" /><span className="text-sm text-green-600">Live</span></>
                        ) : (
                            <><WifiOff size={18} className="text-gray-400" /><span className="text-sm text-gray-400">Connecting...</span></>
                        )}
                    </div>
                    <button onClick={loadEvents} className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"><RefreshCw size={18}/> Refresh</button>
                </div>
            </div>

            {error && <div className="mb-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded">{error}</div>}

            <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6">
                <div className="flex items-center gap-2 mb-3"><Filter size={20} className="text-gray-600"/><h3 className="font-semibold">Filters</h3></div>
                <div className="grid grid-cols-4 gap-4">
                    <select value={filters.event_type} onChange={(e)=>setFilters({...filters,event_type:e.target.value})} className="px-3 py-2 border border-gray-300 rounded">
                        <option value="">All Events</option>
                        <option value="file_created">File Created</option>
                        <option value="file_modified">File Modified</option>
                        <option value="file_deleted">File Deleted</option>
                        <option value="file_renamed">File Renamed</option>
                        <option value="file_copied">File Copied</option>
                        <option value="file_moved">File Moved</option>
                        <option value="usb_copy">USB Copy</option>
                        <option value="usb_delete">USB Delete</option>
                    </select>

                    <select value={filters.classification} onChange={(e)=>setFilters({...filters,classification:e.target.value})} className="px-3 py-2 border border-gray-300 rounded">
                        <option value="">All Classifications</option>
                        <option value="PUBLIC">Public</option>
                        <option value="INTERNAL">Internal</option>
                        <option value="CONFIDENTIAL">Confidential</option>
                        <option value="RESTRICTED">Restricted</option>
                        <option value="PENDING">Pending</option>
                    </select>

                    <select value={filters.risk_level} onChange={(e)=>setFilters({...filters,risk_level:e.target.value})} className="px-3 py-2 border border-gray-300 rounded">
                        <option value="">All Risk Levels</option>
                        <option value="NONE">None</option>
                        <option value="LOW">Low</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="MEDIUM_HIGH">Medium-High</option>
                        <option value="HIGH">High</option>
                        <option value="CRITICAL">Critical</option>
                    </select>

                    <input type="text" placeholder="Username" value={filters.username} onChange={(e)=>setFilters({...filters,username:e.target.value})} className="px-3 py-2 border border-gray-300 rounded"/>
                </div>
            </div>

            <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
                <div className="overflow-x-auto">
                    {loading ? <div className="p-8 text-center text-gray-500">Loading events...</div> : filteredEvents.length === 0 ? <div className="p-8 text-center text-gray-500">No events found</div> : (
                        <table className="w-full">
                            <thead className="bg-gray-50 border-b"><tr><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Status</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Event</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">File</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">User</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Classification</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Risk</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Findings</th><th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Time</th></tr></thead>
                            <tbody className="divide-y divide-gray-200">
                                {filteredEvents.map(event => (
                                    <tr key={event.id} className="hover:bg-gray-50"><td className="px-6 py-4">{getStatusIcon(event)}</td><td className="px-6 py-4"><span className="text-sm font-medium">{event.event_type}</span></td><td className="px-6 py-4"><div className="text-sm"><p className="font-medium">{event.file_name}</p><p className="text-gray-500 text-xs">{event.file_path}</p></div></td><td className="px-6 py-4 text-sm">{event.username || '-'}</td><td className="px-6 py-4"><span className={`text-xs px-2 py-1 rounded ${getClassificationColor(event.classification)}`}>{event.classification}</span></td><td className="px-6 py-4"><span className={`text-xs px-2 py-1 rounded ${getRiskColor(event.risk_level)}`}>{event.risk_level}</span></td><td className="px-6 py-4"><FindingsCell findings={event.findings} /></td><td className="px-6 py-4 text-sm text-gray-500">{new Date(event.created_at).toLocaleString()}</td></tr>
                                ))}
                            </tbody>
                        </table>
                    )}
                </div>
            </div>
        </div>
    );
}

export default EventLogsPage;
