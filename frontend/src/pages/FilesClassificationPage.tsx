import React, { useEffect, useState } from 'react';
import { apiClient } from '../api/client';
import { useAuthStore } from '../store/authStore';
import { ClassificationBadge } from '../components/ClassificationBadge';

interface ClassifiedFile {
  file_hash: string;
  file_name: string;
  file_path: string;
  classification: string;
  classification_reason: string;
  matched_keywords: string[];
  first_seen: string;
  last_accessed: string;
  access_count: number;
  file_size: number;
  file_type: string;
  mime_type: string;
  owner_sid: string;
  owner_username: string;
  quarantined: boolean;
  quarantined_at?: string;
  quarantined_by?: string;
}

interface FileStats {
  by_classification: Record<string, number>;
  quarantined_count: number;
  total_count: number;
}

const FilesClassificationPage: React.FC = () => {
  const [files, setFiles] = useState<ClassifiedFile[]>([]);
  const [stats, setStats] = useState<FileStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<ClassifiedFile | null>(null);
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [showReclassifyModal, setShowReclassifyModal] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);
  const [filters, setFilters] = useState({
    classification: '',
    file_type: '',
    search: '',
    quarantined: '',
  });
  const [testContent, setTestContent] = useState('');
  const [testResult, setTestResult] = useState<any>(null);
  const [newClassification, setNewClassification] = useState('');
  const [reclassifyReason, setReclassifyReason] = useState('');

  const currentUser = useAuthStore((s) => s.user);
  const actorName = currentUser?.name || currentUser?.email || 'unknown';

  useEffect(() => {
    fetchFiles();
    fetchStats();
  }, [filters]);

  const fetchFiles = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      Object.entries(filters).forEach(([key, value]) => {
        if (value) params.append(key, value);
      });
      params.append('limit', '50');

      const response = await apiClient.get(`/api/files/classified?${params}`);
      const data = response.data;
      setFiles(data.files || []);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const response = await apiClient.get('/api/files/stats');
      setStats(response.data);
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    }
  };

  const handleReclassify = async () => {
    if (!selectedFile || !newClassification) return;

    try {
      await apiClient.post(
        `/api/files/${selectedFile.file_hash}/reclassify`,
        {
          classification: newClassification,
          reason: reclassifyReason,
          changed_by: actorName,
        },
        { params: { hash: selectedFile.file_hash } }
      );

      setShowReclassifyModal(false);
      setSelectedFile(null);
      setNewClassification('');
      setReclassifyReason('');
      fetchFiles();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleQuarantine = async (file: ClassifiedFile) => {
    try {
      await apiClient.post(
        `/api/files/${file.file_hash}/quarantine`,
        { quarantined_by: actorName },
        { params: { hash: file.file_hash } }
      );
      fetchFiles();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleTestClassify = async () => {
    if (!testContent) return;

    try {
      const response = await apiClient.post('/api/files/classify', { content: testContent });
      setTestResult(response.data);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">File Classification</h1>
          <p className="text-gray-600 text-sm mt-1">
            View and manage classified files ({stats?.total_count || 0} total)
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => window.location.hash = '/policy-studio/classifiers-rules'}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
            </svg>
            Manage Rules
          </button>
          <button
            onClick={() => setShowTestModal(true)}
            className="px-4 py-2 bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors"
          >
            Test Classification
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-5 gap-4 mb-6">
          {['PUBLIC', 'PRIVATE', 'CONFIDENTIAL', 'RESTRICTED'].map((cls) => (
            <div key={cls} className="bg-white rounded-lg p-4 border border-gray-200 shadow-sm">
              <ClassificationBadge classification={cls} size="lg" />
              <div className="text-2xl font-bold text-gray-900 mt-2">
                {stats.by_classification?.[cls] || 0}
              </div>
              <div className="text-gray-600 text-xs">files</div>
            </div>
          ))}
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 shadow-sm">
            <div className="text-red-700 text-sm font-semibold">Quarantined</div>
            <div className="text-2xl font-bold text-red-700">{stats.quarantined_count || 0}</div>
            <div className="text-gray-500 text-xs">files</div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-white rounded-lg p-4 mb-6 flex gap-4 flex-wrap border border-gray-200 shadow-sm">
        <input
          type="text"
          placeholder="Search files..."
          value={filters.search}
          onChange={(e) => setFilters({ ...filters, search: e.target.value })}
          className="px-3 py-2 bg-white border border-gray-300 rounded-lg text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
        />
        <select
          value={filters.classification}
          onChange={(e) => setFilters({ ...filters, classification: e.target.value })}
          className="px-3 py-2 bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
        >
          <option value="">All Classifications</option>
          <option value="PUBLIC">Public</option>
          <option value="PRIVATE">Private</option>
          <option value="CONFIDENTIAL">Confidential</option>
          <option value="RESTRICTED">Restricted</option>
        </select>
        <select
          value={filters.quarantined}
          onChange={(e) => setFilters({ ...filters, quarantined: e.target.value })}
          className="px-3 py-2 bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
        >
          <option value="">All Files</option>
          <option value="true">Quarantined Only</option>
          <option value="false">Not Quarantined</option>
        </select>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg mb-6">
          {error}
        </div>
      )}

      {/* Files Table */}
      <div className="bg-gray-800 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-700">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">File</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Classification</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Owner</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Size</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">First Seen</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {loading ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-400">Loading files...</td>
              </tr>
            ) : files.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-400">No classified files found.</td>
              </tr>
            ) : (
              files.map((file) => (
                <tr key={file.file_hash} className="hover:bg-gray-700/50">
                  <td className="px-4 py-3">
                    <div>
                      <p className="text-white font-medium truncate max-w-xs">{file.file_name}</p>
                      <p className="text-gray-500 text-xs truncate max-w-xs">{file.file_path}</p>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <ClassificationBadge classification={file.classification} size="sm" />
                    {file.classification_reason && (
                      <p className="text-gray-500 text-xs mt-1 truncate max-w-xs" title={file.classification_reason}>
                        {file.classification_reason}
                      </p>
                    )}
                  </td>
                  <td className="px-4 py-3 text-gray-300">
                    {file.owner_username || 'Unknown'}
                  </td>
                  <td className="px-4 py-3 text-gray-300">
                    {formatBytes(file.file_size)}
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-sm">
                    {formatDate(file.first_seen)}
                  </td>
                  <td className="px-4 py-3">
                    {file.quarantined ? (
                      <span className="text-red-400 text-xs px-2 py-1 bg-red-500/20 rounded">🚫 Quarantined</span>
                    ) : (
                      <span className="text-green-400 text-xs px-2 py-1 bg-green-500/20 rounded">✓ Active</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2">
                      <button
                        onClick={() => { setSelectedFile(file); setShowDetailsModal(true); }}
                        className="text-blue-400 hover:text-blue-300 text-sm"
                      >
                        View
                      </button>
                      <button
                        onClick={() => {
                          setSelectedFile(file);
                          setNewClassification(file.classification);
                          setShowReclassifyModal(true);
                        }}
                        className="text-yellow-400 hover:text-yellow-300 text-sm"
                      >
                        Reclassify
                      </button>
                      {!file.quarantined && (
                        <button
                          onClick={() => handleQuarantine(file)}
                          className="text-red-400 hover:text-red-300 text-sm"
                        >
                          Quarantine
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Details Modal */}
      {showDetailsModal && selectedFile && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-bold text-white mb-4">File Details</h2>

            <div className="space-y-4">
              <div>
                <div className="text-gray-400 text-sm">File Name</div>
                <div className="text-white">{selectedFile.file_name}</div>
              </div>
              <div>
                <div className="text-gray-400 text-sm">File Path</div>
                <div className="text-white break-all">{selectedFile.file_path}</div>
              </div>
              <div>
                <div className="text-gray-400 text-sm">File Hash</div>
                <code className="text-green-400 text-xs break-all">{selectedFile.file_hash}</code>
              </div>
              <div className="flex gap-4">
                <div>
                  <div className="text-gray-400 text-sm">Classification</div>
                  <ClassificationBadge classification={selectedFile.classification} size="lg" />
                </div>
                <div>
                  <div className="text-gray-400 text-sm">File Type</div>
                  <div className="text-white">{selectedFile.file_type}</div>
                </div>
                <div>
                  <div className="text-gray-400 text-sm">Size</div>
                  <div className="text-white">{formatBytes(selectedFile.file_size)}</div>
                </div>
              </div>
              {selectedFile.classification_reason && (
                <div>
                  <div className="text-gray-400 text-sm">Classification Reason</div>
                  <div className="text-white">{selectedFile.classification_reason}</div>
                </div>
              )}
              {selectedFile.matched_keywords?.length > 0 && (
                <div>
                  <div className="text-gray-400 text-sm">Matched Keywords</div>
                  <div className="flex flex-wrap gap-2 mt-1">
                    {selectedFile.matched_keywords.map((kw, idx) => (
                      <span key={idx} className="bg-purple-500/20 text-purple-400 px-2 py-1 rounded text-sm">
                        {kw}
                      </span>
                    ))}
                  </div>
                </div>
              )}
              <div>
                <div className="text-gray-400 text-sm">Owner</div>
                <div className="text-white">{selectedFile.owner_username || 'Unknown'}</div>
              </div>
              <div className="flex gap-4">
                <div>
                  <div className="text-gray-400 text-sm">First Seen</div>
                  <div className="text-white">{formatDate(selectedFile.first_seen)}</div>
                </div>
                <div>
                  <div className="text-gray-400 text-sm">Last Accessed</div>
                  <div className="text-white">{formatDate(selectedFile.last_accessed)}</div>
                </div>
              </div>
              <div>
                <div className="text-gray-400 text-sm">Access Count</div>
                <div className="text-white">{selectedFile.access_count}</div>
              </div>
              {selectedFile.quarantined && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
                  <div className="text-red-400 font-medium">🚫 File is Quarantined</div>
                  <div className="text-gray-400 text-sm">
                    By: {selectedFile.quarantined_by} on {formatDate(selectedFile.quarantined_at || '')}
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end pt-4 mt-4 border-t border-gray-700">
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

      {/* Reclassify Modal */}
      {showReclassifyModal && selectedFile && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-md">
            <h2 className="text-xl font-bold text-white mb-4">Reclassify File</h2>

            <div className="bg-gray-700 rounded-lg p-3 mb-4">
              <div className="text-white font-medium">{selectedFile.file_name}</div>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-gray-400">Current:</span>
                <ClassificationBadge classification={selectedFile.classification} size="sm" />
              </div>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">New Classification</label>
                <select
                  value={newClassification}
                  onChange={(e) => setNewClassification(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                >
                  <option value="PUBLIC">Public</option>
                  <option value="PRIVATE">Private</option>
                  <option value="CONFIDENTIAL">Confidential</option>
                  <option value="RESTRICTED">Restricted</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Reason</label>
                <textarea
                  value={reclassifyReason}
                  onChange={(e) => setReclassifyReason(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  rows={3}
                  placeholder="Why are you changing the classification?"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-4 mt-4 border-t border-gray-700">
              <button
                onClick={() => { setShowReclassifyModal(false); setSelectedFile(null); }}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleReclassify}
                disabled={!newClassification || newClassification === selectedFile.classification}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
              >
                Reclassify
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Test Classification Modal */}
      {showTestModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-bold text-white mb-4">🔍 Test Content Classification</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Enter content to classify
                </label>
                <textarea
                  value={testContent}
                  onChange={(e) => setTestContent(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  rows={6}
                  placeholder="Paste sample content here to test classification..."
                />
              </div>

              <button
                onClick={handleTestClassify}
                disabled={!testContent.trim()}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
              >
                Classify Content
              </button>

              {testResult && (
                <div className="border-t border-gray-700 pt-4">
                  <h3 className="text-lg font-medium text-white mb-3">Classification Result</h3>

                  <div className="grid grid-cols-2 gap-4 mb-4">
                    <div className="bg-gray-700 rounded-lg p-3">
                      <div className="text-gray-400 text-sm">Classification</div>
                      <ClassificationBadge classification={testResult.classification} size="lg" />
                    </div>
                    <div className="bg-gray-700 rounded-lg p-3">
                      <div className="text-gray-400 text-sm">Hard Blocked</div>
                      <div className={`text-xl font-bold ${testResult.hard_blocked ? 'text-red-400' : 'text-green-400'}`}>
                        {testResult.hard_blocked ? '🚫 YES' : '✓ NO'}
                      </div>
                    </div>
                  </div>

                  {testResult.classification_reason && (
                    <div className="bg-gray-700 rounded-lg p-3 mb-4">
                      <div className="text-gray-400 text-sm">Reason</div>
                      <div className="text-white">{testResult.classification_reason}</div>
                    </div>
                  )}

                  {testResult.matched_keywords?.length > 0 && (
                    <div className="bg-gray-700 rounded-lg p-3">
                      <div className="text-gray-400 text-sm mb-2">Matched Keywords</div>
                      <div className="flex flex-wrap gap-2">
                        {testResult.matched_keywords.map((kw: string, idx: number) => (
                          <span key={idx} className="bg-purple-500/20 text-purple-400 px-2 py-1 rounded text-sm">
                            {kw}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex justify-end pt-4 mt-4 border-t border-gray-700">
              <button
                onClick={() => { setShowTestModal(false); setTestContent(''); setTestResult(null); }}
                className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FilesClassificationPage;
