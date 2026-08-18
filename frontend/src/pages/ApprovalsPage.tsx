import React, { useEffect, useState } from 'react';
import { useApprovalsStore, ApprovalRequest } from '../store/approvalsStore';
import { useAuthStore } from '../store/authStore';
import { ClassificationBadge } from '../components/ClassificationBadge';
import { StatusBadge } from '../components/StatusBadge';

const ApprovalsPage: React.FC = () => {
  const {
    pendingRequests,
    history,
    pendingCount,
    loading,
    error,
    fetchPending,
    fetchHistory,
    approveRequest,
    denyRequest,
  } = useApprovalsStore();

  const [activeTab, setActiveTab] = useState<'pending' | 'history'>('pending');
  const [selectedRequest, setSelectedRequest] = useState<ApprovalRequest | null>(null);
  const [showDecisionModal, setShowDecisionModal] = useState(false);
  const [decisionType, setDecisionType] = useState<'approve' | 'deny'>('approve');
  const [comment, setComment] = useState('');
  const [makePermanent, setMakePermanent] = useState(false);

  // Fetch the real user from the auth store and use it as the file owner
  const currentUser = useAuthStore((s) => s.user);
  const actorSID = currentUser?.id || currentUser?.email || '';

  useEffect(() => {
    if (!actorSID) return;

    fetchPending(actorSID);
    fetchHistory(actorSID);

    // Refresh pending every 30 seconds
    const interval = setInterval(() => {
      fetchPending(actorSID);
    }, 30000);

    return () => clearInterval(interval);
  }, [actorSID]);

  const handleDecision = async () => {
    if (!selectedRequest) return;

    try {
      if (decisionType === 'approve') {
        await approveRequest(selectedRequest.request_id, comment, makePermanent);
      } else {
        await denyRequest(selectedRequest.request_id, comment);
      }
      setShowDecisionModal(false);
      setSelectedRequest(null);
      setComment('');
      setMakePermanent(false);
    } catch (err) {
      console.error('Failed to process decision:', err);
    }
  };

  const openDecisionModal = (request: ApprovalRequest, type: 'approve' | 'deny') => {
    setSelectedRequest(request);
    setDecisionType(type);
    setShowDecisionModal(true);
  };

  const formatTimeRemaining = (seconds: number) => {
    if (seconds <= 0) return 'Expired';
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}:${secs.toString().padStart(2, '0')}`;
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  const getActionLabel = (action: string) => {
    const labels: Record<string, string> = {
      UPLOAD: '📤 Upload',
      USB_TRANSFER: '💾 USB Transfer',
      EMAIL_ATTACH: '📧 Email Attachment',
      PRINT: '🖨️ Print',
      COPY: '📋 Copy',
      CLOUD_SYNC: '☁️ Cloud Sync',
      NETWORK_SHARE: '🌐 Network Share',
    };
    return labels[action] || action;
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Approval Requests</h1>
          <p className="text-gray-600 text-sm mt-1">
            Manage file access approval requests as file owner
          </p>
        </div>
        <div className="flex items-center gap-4">
          {pendingCount > 0 && (
            <span className="bg-yellow-500/20 text-yellow-400 px-3 py-1 rounded-full text-sm font-medium">
              {pendingCount} pending
            </span>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-200 mb-6">
        <button
          onClick={() => setActiveTab('pending')}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === 'pending'
              ? 'text-brand border-b-2 border-brand'
              : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          Pending Requests ({pendingRequests.length})
        </button>
        <button
          onClick={() => setActiveTab('history')}
          className={`px-4 py-2 text-sm font-medium transition-colors ${
            activeTab === 'history'
              ? 'text-brand border-b-2 border-brand'
              : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          History
        </button>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg mb-6">
          {error}
        </div>
      )}

      {/* Pending Requests */}
      {activeTab === 'pending' && (
        <div className="space-y-4">
          {loading ? (
            <div className="text-center py-8 text-gray-400">Loading pending requests...</div>
          ) : pendingRequests.length === 0 ? (
            <div className="text-center py-12 bg-white border border-gray-200 rounded-lg">
              <div className="text-4xl mb-4">✓</div>
              <h3 className="text-lg font-semibold text-gray-900 mb-2">No Pending Requests</h3>
              <p className="text-gray-600">You don't have any pending approval requests.</p>
            </div>
          ) : (
            pendingRequests.map((request) => (
              <div
                key={request.request_id}
                className="bg-white rounded-lg p-4 border border-gray-200 hover:border-gray-300 transition-colors shadow-sm"
              >
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <span className="text-lg text-gray-900">{getActionLabel(request.action_type)}</span>
                      <ClassificationBadge classification={request.file_classification || 'PRIVATE'} size="sm" />
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${
                        request.seconds_remaining > 120
                          ? 'bg-green-100 text-green-700'
                          : request.seconds_remaining > 60
                          ? 'bg-yellow-100 text-yellow-700'
                          : 'bg-red-100 text-red-700'
                      }`}>
                        {formatTimeRemaining(request.seconds_remaining)}
                      </span>
                    </div>

                    <h3 className="text-gray-900 font-semibold mb-1">
                      {request.file_name || 'Unknown file'}
                    </h3>

                    <div className="text-sm text-gray-600 space-y-1">
                      <p>
                        <span className="text-gray-500">Requester:</span>{' '}
                        <span className="text-gray-900 font-medium">{request.requester_username}</span>
                        {request.requester_hostname && (
                          <span className="text-gray-500"> on {request.requester_hostname}</span>
                        )}
                      </p>
                      {request.destination_detail && (
                        <p>
                          <span className="text-gray-500">Destination:</span>{' '}
                          <code className="bg-gray-100 px-1 rounded text-gray-900 font-mono">{request.destination_detail}</code>
                        </p>
                      )}
                      <p>
                        <span className="text-gray-500">Requested:</span>{' '}
                        {formatDate(request.created_at)}
                      </p>
                    </div>
                  </div>

                  <div className="flex gap-2 ml-4">
                    <button
                      onClick={() => openDecisionModal(request, 'approve')}
                      className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
                    >
                      ✓ Approve
                    </button>
                    <button
                      onClick={() => openDecisionModal(request, 'deny')}
                      className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
                    >
                      ✕ Deny
                    </button>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* History */}
      {activeTab === 'history' && (
        <div className="bg-white rounded-lg overflow-hidden border border-gray-200 shadow-sm">
          <table className="w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-700 uppercase">File</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-700 uppercase">Requester</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-700 uppercase">Action</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-700 uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-700 uppercase">Decision Date</th>
                <th className="px-4 py-3 text-left text-xs font-semibold text-gray-700 uppercase">Comment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-gray-400">Loading history...</td>
                </tr>
              ) : history.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-gray-400">No approval history found.</td>
                </tr>
              ) : (
                history.map((request) => (
                  <tr key={request.request_id} className="hover:bg-gray-700/50">
                    <td className="px-4 py-3">
                      <div>
                        <p className="text-white">{request.file_name || 'Unknown'}</p>
                        <ClassificationBadge classification={request.file_classification || 'PRIVATE'} size="sm" />
                      </div>
                    </td>
                    <td className="px-4 py-3 text-gray-300">{request.requester_username}</td>
                    <td className="px-4 py-3 text-gray-300">{getActionLabel(request.action_type)}</td>
                    <td className="px-4 py-3">
                      <StatusBadge status={request.status} variant="approval" />
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-sm">
                      {request.decided_at ? formatDate(request.decided_at) : '-'}
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-sm max-w-xs truncate">
                      {request.decision_comment || '-'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Decision Modal */}
      {showDecisionModal && selectedRequest && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold text-white mb-4">
              {decisionType === 'approve' ? '✓ Approve Request' : '✕ Deny Request'}
            </h2>

            <div className="bg-gray-700 rounded-lg p-3 mb-4">
              <p className="text-white font-medium">{selectedRequest.file_name}</p>
              <p className="text-gray-400 text-sm">
                {getActionLabel(selectedRequest.action_type)} by {selectedRequest.requester_username}
              </p>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Comment (optional)
                </label>
                <textarea
                  value={comment}
                  onChange={(e) => setComment(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  rows={3}
                  placeholder="Add a comment for the requester..."
                />
              </div>

              {decisionType === 'approve' && (
                <label className="flex items-center gap-2 text-gray-300">
                  <input
                    type="checkbox"
                    checked={makePermanent}
                    onChange={(e) => setMakePermanent(e.target.checked)}
                    className="w-4 h-4 rounded bg-gray-700 border-gray-600"
                  />
                  Remember this decision for future requests
                </label>
              )}
            </div>

            <div className="flex justify-end gap-3 pt-4 mt-4 border-t border-gray-700">
              <button
                onClick={() => { setShowDecisionModal(false); setSelectedRequest(null); setComment(''); }}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleDecision}
                disabled={loading}
                className={`px-4 py-2 text-white rounded-lg transition-colors disabled:opacity-50 ${
                  decisionType === 'approve'
                    ? 'bg-green-600 hover:bg-green-700'
                    : 'bg-red-600 hover:bg-red-700'
                }`}
              >
                {loading ? 'Processing...' : decisionType === 'approve' ? 'Approve' : 'Deny'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ApprovalsPage;
