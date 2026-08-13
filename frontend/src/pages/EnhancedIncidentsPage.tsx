import React, { useEffect, useState } from 'react';
import { useIncidentsStore, Incident } from '../store/incidentsStore';
import { useAuthStore } from '../store/authStore';
import { SeverityBadge } from '../components/SeverityBadge';
import { StatusBadge } from '../components/StatusBadge';
import { ClassificationBadge } from '../components/ClassificationBadge';

const EnhancedIncidentsPage: React.FC = () => {
  const {
    incidents,
    total,
    stats,
    loading,
    error,
    filters,
    fetchIncidents,
    fetchStats,
    updateStatus: _updateStatus,
    assignIncident,
    resolveIncident,
    markFalsePositive,
    setFilters,
  } = useIncidentsStore();

  // Suppress unused variable warning - updateStatus is available for future use
  void _updateStatus;

  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [showActionModal, setShowActionModal] = useState(false);
  const [actionType, setActionType] = useState<'assign' | 'resolve' | 'false_positive'>('assign');
  const [actionValue, setActionValue] = useState('');

  // Fetch the real user from the auth store to attribute actions
  const currentUser = useAuthStore((s) => s.user);
  const actorName = currentUser?.name || currentUser?.email || 'unknown';

  useEffect(() => {
    fetchIncidents();
    fetchStats();
  }, []);

  const handleFilterChange = (key: string, value: string) => {
    setFilters({ [key]: value, offset: 0 });
    fetchIncidents({ [key]: value, offset: 0 });
  };

  const openActionModal = (incident: Incident, type: 'assign' | 'resolve' | 'false_positive') => {
    setSelectedIncident(incident);
    setActionType(type);
    setActionValue('');
    setShowActionModal(true);
  };

  const handleAction = async () => {
    if (!selectedIncident) return;

    try {
      switch (actionType) {
        case 'assign':
          await assignIncident(selectedIncident.id, actionValue, actorName);
          break;
        case 'resolve':
          await resolveIncident(selectedIncident.id, actionValue, actorName);
          break;
        case 'false_positive':
          await markFalsePositive(selectedIncident.id, actionValue, actorName);
          break;
      }
      setShowActionModal(false);
      setSelectedIncident(null);
    } catch (err) {
      console.error('Action failed:', err);
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  const getDecisionIcon = (decision: string) => {
    switch (decision) {
      case 'BLOCK': return '🚫';
      case 'ALLOW': return '✓';
      case 'PENDING_APPROVAL': return '⏳';
      default: return '?';
    }
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Incidents</h1>
          <p className="text-gray-400 text-sm mt-1">
            Security incidents and policy violations ({total} total)
          </p>
        </div>
      </div>

      {/* Stats Row */}
      {stats && (
        <div className="grid grid-cols-4 gap-4 mb-6">
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
            <div className="text-red-400 text-sm font-medium">Critical</div>
            <div className="text-2xl font-bold text-white">{stats.by_severity?.CRITICAL || 0}</div>
          </div>
          <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4">
            <div className="text-orange-400 text-sm font-medium">High</div>
            <div className="text-2xl font-bold text-white">{stats.by_severity?.HIGH || 0}</div>
          </div>
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
            <div className="text-yellow-400 text-sm font-medium">Medium</div>
            <div className="text-2xl font-bold text-white">{stats.by_severity?.MEDIUM || 0}</div>
          </div>
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
            <div className="text-blue-400 text-sm font-medium">Open</div>
            <div className="text-2xl font-bold text-white">{stats.open_count || 0}</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-gray-800 rounded-lg p-4 mb-6 flex gap-4 flex-wrap">
        <input
          type="text"
          placeholder="Search..."
          value={filters.search || ''}
          onChange={(e) => handleFilterChange('search', e.target.value)}
          className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
        />
        <select
          value={filters.severity || ''}
          onChange={(e) => handleFilterChange('severity', e.target.value)}
          className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select
          value={filters.status || ''}
          onChange={(e) => handleFilterChange('status', e.target.value)}
          className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="ESCALATED">Escalated</option>
          <option value="RESOLVED">Resolved</option>
          <option value="FALSE_POSITIVE">False Positive</option>
        </select>
        <select
          value={filters.decision || ''}
          onChange={(e) => handleFilterChange('decision', e.target.value)}
          className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          <option value="">All Decisions</option>
          <option value="BLOCK">Blocked</option>
          <option value="ALLOW">Allowed</option>
          <option value="PENDING_APPROVAL">Pending</option>
        </select>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg mb-6">
          {error}
        </div>
      )}

      {/* Timeline View */}
      <div className="space-y-4">
        {loading ? (
          <div className="text-center py-8 text-gray-400">Loading incidents...</div>
        ) : incidents.length === 0 ? (
          <div className="text-center py-12 bg-gray-800 rounded-lg">
            <div className="text-4xl mb-4">🛡️</div>
            <h3 className="text-lg font-medium text-white mb-2">No Incidents Found</h3>
            <p className="text-gray-400">No incidents match your current filters.</p>
          </div>
        ) : (
          incidents.map((incident) => (
            <div
              key={incident.id}
              className={`bg-gray-800 rounded-lg p-4 border-l-4 hover:bg-gray-700/50 transition-colors cursor-pointer ${
                incident.severity === 'CRITICAL' ? 'border-red-500' :
                incident.severity === 'HIGH' ? 'border-orange-500' :
                incident.severity === 'MEDIUM' ? 'border-yellow-500' :
                'border-gray-500'
              }`}
              onClick={() => { setSelectedIncident(incident); setShowDetailsModal(true); }}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-3 mb-2">
                    <SeverityBadge severity={incident.severity} size="sm" />
                    <StatusBadge status={incident.status} size="sm" />
                    <span className="text-gray-400 text-sm">{incident.incident_id}</span>
                    <span className="text-xl">{getDecisionIcon(incident.decision)}</span>
                  </div>

                  <h3 className="text-white font-medium mb-1">
                    {incident.action_attempted}: {incident.file_name || 'Unknown file'}
                  </h3>

                  <div className="flex items-center gap-4 text-sm text-gray-400">
                    <span>👤 {incident.username}</span>
                    {incident.hostname && <span>🖥️ {incident.hostname}</span>}
                    {incident.file_classification && (
                      <ClassificationBadge classification={incident.file_classification} size="sm" />
                    )}
                    {incident.destination_detail && (
                      <span>📍 {incident.destination_detail}</span>
                    )}
                  </div>

                  {incident.block_reason && (
                    <p className="text-red-400 text-sm mt-2">
                      Reason: {incident.block_reason}
                    </p>
                  )}
                </div>

                <div className="text-right ml-4">
                  <div className="text-gray-400 text-sm">{formatDate(incident.timestamp)}</div>
                  {incident.assigned_to && (
                    <div className="text-blue-400 text-xs mt-1">
                      Assigned: {incident.assigned_to}
                    </div>
                  )}

                  <div className="flex gap-2 mt-2" onClick={(e) => e.stopPropagation()}>
                    {incident.status === 'OPEN' && (
                      <>
                        <button
                          onClick={() => openActionModal(incident, 'assign')}
                          className="text-xs px-2 py-1 bg-blue-600 text-white rounded hover:bg-blue-700"
                        >
                          Assign
                        </button>
                        <button
                          onClick={() => openActionModal(incident, 'resolve')}
                          className="text-xs px-2 py-1 bg-green-600 text-white rounded hover:bg-green-700"
                        >
                          Resolve
                        </button>
                        <button
                          onClick={() => openActionModal(incident, 'false_positive')}
                          className="text-xs px-2 py-1 bg-gray-600 text-white rounded hover:bg-gray-500"
                        >
                          FP
                        </button>
                      </>
                    )}
                  </div>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Pagination */}
      {total > (filters.limit || 50) && (
        <div className="flex justify-center gap-4 mt-6">
          <button
            disabled={(filters.offset || 0) === 0}
            onClick={() => {
              const newOffset = Math.max(0, (filters.offset || 0) - (filters.limit || 50));
              setFilters({ offset: newOffset });
              fetchIncidents({ offset: newOffset });
            }}
            className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 disabled:opacity-50"
          >
            Previous
          </button>
          <span className="px-4 py-2 text-gray-400">
            Showing {(filters.offset || 0) + 1} - {Math.min((filters.offset || 0) + (filters.limit || 50), total)} of {total}
          </span>
          <button
            disabled={(filters.offset || 0) + (filters.limit || 50) >= total}
            onClick={() => {
              const newOffset = (filters.offset || 0) + (filters.limit || 50);
              setFilters({ offset: newOffset });
              fetchIncidents({ offset: newOffset });
            }}
            className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 disabled:opacity-50"
          >
            Next
          </button>
        </div>
      )}

      {/* Details Modal */}
      {showDetailsModal && selectedIncident && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-start mb-4">
              <div>
                <h2 className="text-xl font-bold text-white">{selectedIncident.incident_id}</h2>
                <div className="flex items-center gap-2 mt-1">
                  <SeverityBadge severity={selectedIncident.severity} />
                  <StatusBadge status={selectedIncident.status} />
                </div>
              </div>
              <button
                onClick={() => setShowDetailsModal(false)}
                className="text-gray-400 hover:text-white text-2xl"
              >
                ×
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div className="bg-gray-700 rounded-lg p-3">
                <div className="text-gray-400 text-sm">User</div>
                <div className="text-white">{selectedIncident.username}</div>
                <div className="text-gray-500 text-xs">{selectedIncident.user_email || 'No email'}</div>
              </div>
              <div className="bg-gray-700 rounded-lg p-3">
                <div className="text-gray-400 text-sm">Device</div>
                <div className="text-white">{selectedIncident.hostname || 'Unknown'}</div>
                <div className="text-gray-500 text-xs">{selectedIncident.ip_address || 'No IP'}</div>
              </div>
            </div>

            <div className="bg-gray-700 rounded-lg p-3 mb-4">
              <div className="text-gray-400 text-sm mb-2">File Details</div>
              <div className="text-white">{selectedIncident.file_name || 'Unknown file'}</div>
              <div className="text-gray-500 text-xs">{selectedIncident.file_path}</div>
              <div className="flex items-center gap-3 mt-2">
                {selectedIncident.file_classification && (
                  <ClassificationBadge classification={selectedIncident.file_classification} />
                )}
                <span className="text-gray-400 text-sm">
                  {selectedIncident.file_size ? `${(selectedIncident.file_size / 1024).toFixed(1)} KB` : ''}
                </span>
                <span className="text-gray-400 text-sm">{selectedIncident.file_type}</span>
              </div>
            </div>

            <div className="bg-gray-700 rounded-lg p-3 mb-4">
              <div className="text-gray-400 text-sm mb-2">Action Attempted</div>
              <div className="text-white font-medium">{selectedIncident.action_attempted}</div>
              {selectedIncident.destination_type && (
                <div className="text-gray-400 text-sm">
                  To: {selectedIncident.destination_type} - {selectedIncident.destination_detail}
                </div>
              )}
            </div>

            <div className="bg-gray-700 rounded-lg p-3 mb-4">
              <div className="text-gray-400 text-sm mb-2">Decision</div>
              <div className={`font-medium ${
                selectedIncident.decision === 'BLOCK' ? 'text-red-400' :
                selectedIncident.decision === 'ALLOW' ? 'text-green-400' :
                'text-yellow-400'
              }`}>
                {getDecisionIcon(selectedIncident.decision)} {selectedIncident.decision}
              </div>
              {selectedIncident.block_reason && (
                <div className="text-gray-400 text-sm mt-1">{selectedIncident.block_reason}</div>
              )}
              {selectedIncident.policy_name && (
                <div className="text-blue-400 text-sm mt-1">Policy: {selectedIncident.policy_name}</div>
              )}
            </div>

            {selectedIncident.matched_keywords?.length > 0 && (
              <div className="bg-gray-700 rounded-lg p-3 mb-4">
                <div className="text-gray-400 text-sm mb-2">Matched Keywords</div>
                <div className="flex flex-wrap gap-2">
                  {selectedIncident.matched_keywords.map((kw, idx) => (
                    <span key={idx} className="bg-purple-500/20 text-purple-400 px-2 py-1 rounded text-sm">
                      {kw}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {(selectedIncident.investigation_notes || selectedIncident.resolution_notes) && (
              <div className="bg-gray-700 rounded-lg p-3 mb-4">
                <div className="text-gray-400 text-sm mb-2">Notes</div>
                {selectedIncident.investigation_notes && (
                  <div className="text-gray-300 text-sm">{selectedIncident.investigation_notes}</div>
                )}
                {selectedIncident.resolution_notes && (
                  <div className="text-green-400 text-sm mt-2">
                    Resolution: {selectedIncident.resolution_notes}
                  </div>
                )}
              </div>
            )}

            <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
              <button
                onClick={() => setShowDetailsModal(false)}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Action Modal */}
      {showActionModal && selectedIncident && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold text-white mb-4">
              {actionType === 'assign' ? '📋 Assign Incident' :
               actionType === 'resolve' ? '✓ Resolve Incident' :
               '❌ Mark as False Positive'}
            </h2>

            <div className="bg-gray-700 rounded-lg p-3 mb-4">
              <div className="text-white font-medium">{selectedIncident.incident_id}</div>
              <div className="text-gray-400 text-sm">{selectedIncident.file_name}</div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">
                {actionType === 'assign' ? 'Assign to' : 'Notes'}
              </label>
              {actionType === 'assign' ? (
                <select
                  value={actionValue}
                  onChange={(e) => setActionValue(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="">Select analyst...</option>
                  <option value="analyst1@company.com">Analyst 1</option>
                  <option value="analyst2@company.com">Analyst 2</option>
                  <option value="security@company.com">Security Team</option>
                </select>
              ) : (
                <textarea
                  value={actionValue}
                  onChange={(e) => setActionValue(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  rows={4}
                  placeholder={actionType === 'resolve' ? 'Resolution notes...' : 'Reason for marking as false positive...'}
                />
              )}
            </div>

            <div className="flex justify-end gap-3 pt-4 mt-4 border-t border-gray-700">
              <button
                onClick={() => setShowActionModal(false)}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleAction}
                disabled={!actionValue}
                className={`px-4 py-2 text-white rounded-lg transition-colors disabled:opacity-50 ${
                  actionType === 'assign' ? 'bg-blue-600 hover:bg-blue-700' :
                  actionType === 'resolve' ? 'bg-green-600 hover:bg-green-700' :
                  'bg-gray-600 hover:bg-gray-500'
                }`}
              >
                {actionType === 'assign' ? 'Assign' :
                 actionType === 'resolve' ? 'Resolve' :
                 'Mark as FP'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default EnhancedIncidentsPage;
