import React, { useEffect, useState } from 'react';
import { useKeywordsStore, Keyword } from '../store/keywordsStore';
import { ClassificationBadge } from '../components/ClassificationBadge';

const KeywordsPage: React.FC = () => {
  const {
    keywords,
    total,
    loading,
    error,
    fetchKeywords,
    fetchGroups,
    createKeyword,
    updateKeyword,
    deleteKeyword,
    testKeywords,
    validateRegex,
  } = useKeywordsStore();

  const [showModal, setShowModal] = useState(false);
  const [showTestModal, setShowTestModal] = useState(false);
  const [editingKeyword, setEditingKeyword] = useState<Keyword | null>(null);
  const [testContent, setTestContent] = useState('');
  const [testResults, setTestResults] = useState<any>(null);
  const [filters, setFilters] = useState({
    classification: '',
    match_type: '',
    search: '',
  });
  const [formData, setFormData] = useState<{
    keyword: string;
    match_type: 'EXACT' | 'PARTIAL' | 'REGEX';
    case_sensitive: boolean;
    classification: 'PUBLIC' | 'PRIVATE' | 'CONFIDENTIAL' | 'RESTRICTED';
    priority: number;
    hard_block: boolean;
    description: string;
    tags: string[];
    enabled: boolean;
  }>({
    keyword: '',
    match_type: 'PARTIAL',
    case_sensitive: false,
    classification: 'PRIVATE',
    priority: 50,
    hard_block: false,
    description: '',
    tags: [],
    enabled: true,
  });
  const [regexError, setRegexError] = useState('');

  useEffect(() => {
    fetchKeywords(filters);
    fetchGroups();
  }, [filters]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Validate regex if needed
    if (formData.match_type === 'REGEX') {
      const result = await validateRegex(formData.keyword);
      if (!result.valid) {
        setRegexError(result.error);
        return;
      }
    }

    try {
      if (editingKeyword) {
        await updateKeyword(editingKeyword.id, formData);
      } else {
        await createKeyword(formData);
      }
      setShowModal(false);
      resetForm();
    } catch (err) {
      console.error('Failed to save keyword:', err);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteKeyword(id);
    } catch (err) {
      console.error('Failed to delete keyword:', err);
    }
  };

  const handleTest = async () => {
    if (!testContent.trim()) return;
    try {
      const results = await testKeywords(testContent);
      setTestResults(results);
    } catch (err) {
      console.error('Failed to test keywords:', err);
    }
  };

  const resetForm = () => {
    setFormData({
      keyword: '',
      match_type: 'PARTIAL',
      case_sensitive: false,
      classification: 'PRIVATE',
      priority: 50,
      hard_block: false,
      description: '',
      tags: [],
      enabled: true,
    });
    setEditingKeyword(null);
    setRegexError('');
  };

  const openEditModal = (keyword: Keyword) => {
    setEditingKeyword(keyword);
    setFormData({
      keyword: keyword.keyword,
      match_type: keyword.match_type,
      case_sensitive: keyword.case_sensitive,
      classification: keyword.classification,
      priority: keyword.priority,
      hard_block: keyword.hard_block,
      description: keyword.description || '',
      tags: keyword.tags || [],
      enabled: keyword.enabled,
    });
    setShowModal(true);
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Keywords Management</h1>
          <p className="text-gray-400 text-sm mt-1">
            Manage content inspection keywords and patterns ({total} total)
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => setShowTestModal(true)}
            className="px-4 py-2 bg-gray-700 text-white rounded-lg hover:bg-gray-600 transition-colors"
          >
            🔍 Test Keywords
          </button>
          <button
            onClick={() => { resetForm(); setShowModal(true); }}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            + Add Keyword
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-gray-800 rounded-lg p-4 mb-6 flex gap-4 flex-wrap">
        <input
          type="text"
          placeholder="Search keywords..."
          value={filters.search}
          onChange={(e) => setFilters({ ...filters, search: e.target.value })}
          className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
        />
        <select
          value={filters.classification}
          onChange={(e) => setFilters({ ...filters, classification: e.target.value })}
          className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          <option value="">All Classifications</option>
          <option value="PUBLIC">Public</option>
          <option value="PRIVATE">Private</option>
          <option value="CONFIDENTIAL">Confidential</option>
          <option value="RESTRICTED">Restricted</option>
        </select>
        <select
          value={filters.match_type}
          onChange={(e) => setFilters({ ...filters, match_type: e.target.value })}
          className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
        >
          <option value="">All Match Types</option>
          <option value="EXACT">Exact</option>
          <option value="PARTIAL">Partial</option>
          <option value="REGEX">Regex</option>
        </select>
      </div>

      {/* Error display */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg mb-6">
          {error}
        </div>
      )}

      {/* Keywords Table */}
      <div className="bg-gray-800 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-700">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Keyword</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Type</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Classification</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Priority</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Hard Block</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Status</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {loading ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-400">
                  Loading keywords...
                </td>
              </tr>
            ) : keywords.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-gray-400">
                  No keywords found. Create your first keyword to get started.
                </td>
              </tr>
            ) : (
              keywords.map((kw) => (
                <tr key={kw.id} className="hover:bg-gray-700/50">
                  <td className="px-4 py-3">
                    <div>
                      <code className="text-white bg-gray-700 px-2 py-1 rounded text-sm font-mono">
                        {kw.keyword.length > 40 ? kw.keyword.slice(0, 40) + '...' : kw.keyword}
                      </code>
                      {kw.description && (
                        <p className="text-gray-500 text-xs mt-1">{kw.description}</p>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-1 rounded ${
                      kw.match_type === 'REGEX' ? 'bg-purple-500/20 text-purple-400' :
                      kw.match_type === 'EXACT' ? 'bg-blue-500/20 text-blue-400' :
                      'bg-gray-500/20 text-gray-400'
                    }`}>
                      {kw.match_type}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <ClassificationBadge classification={kw.classification} size="sm" />
                  </td>
                  <td className="px-4 py-3 text-gray-300">{kw.priority}</td>
                  <td className="px-4 py-3">
                    {kw.hard_block ? (
                      <span className="text-red-400 font-bold">🚫 YES</span>
                    ) : (
                      <span className="text-gray-500">No</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs px-2 py-1 rounded ${
                      kw.enabled ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                    }`}>
                      {kw.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex gap-2">
                      <button
                        onClick={() => openEditModal(kw)}
                        className="text-blue-400 hover:text-blue-300 text-sm"
                      >
                        Edit
                      </button>
                      <button
                        onClick={() => handleDelete(kw.id)}
                        className="text-red-400 hover:text-red-300 text-sm"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Add/Edit Keyword Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-lg max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-bold text-white mb-4">
              {editingKeyword ? 'Edit Keyword' : 'Add New Keyword'}
            </h2>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Keyword/Pattern *
                </label>
                <input
                  type="text"
                  value={formData.keyword}
                  onChange={(e) => { setFormData({ ...formData, keyword: e.target.value }); setRegexError(''); }}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  placeholder={formData.match_type === 'REGEX' ? 'Enter regex pattern...' : 'Enter keyword...'}
                  required
                />
                {regexError && (
                  <p className="text-red-400 text-sm mt-1">{regexError}</p>
                )}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-1">Match Type</label>
                  <select
                    value={formData.match_type}
                    onChange={(e) => setFormData({ ...formData, match_type: e.target.value as 'EXACT' | 'PARTIAL' | 'REGEX' })}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="EXACT">Exact</option>
                    <option value="PARTIAL">Partial</option>
                    <option value="REGEX">Regex</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-400 mb-1">Classification</label>
                  <select
                    value={formData.classification}
                    onChange={(e) => setFormData({ ...formData, classification: e.target.value as 'PUBLIC' | 'PRIVATE' | 'CONFIDENTIAL' | 'RESTRICTED' })}
                    className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="PUBLIC">Public</option>
                    <option value="PRIVATE">Private</option>
                    <option value="CONFIDENTIAL">Confidential</option>
                    <option value="RESTRICTED">Restricted</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Priority (0-100)
                </label>
                <input
                  type="number"
                  min="0"
                  max="100"
                  value={formData.priority}
                  onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 50 })}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Description</label>
                <textarea
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  rows={2}
                  placeholder="Optional description..."
                />
              </div>

              <div className="flex gap-4">
                <label className="flex items-center gap-2 text-gray-300">
                  <input
                    type="checkbox"
                    checked={formData.case_sensitive}
                    onChange={(e) => setFormData({ ...formData, case_sensitive: e.target.checked })}
                    className="w-4 h-4 rounded bg-gray-700 border-gray-600"
                  />
                  Case Sensitive
                </label>
                <label className="flex items-center gap-2 text-gray-300">
                  <input
                    type="checkbox"
                    checked={formData.hard_block}
                    onChange={(e) => setFormData({ ...formData, hard_block: e.target.checked })}
                    className="w-4 h-4 rounded bg-gray-700 border-gray-600"
                  />
                  <span className="text-red-400">Hard Block (No Override)</span>
                </label>
              </div>

              <label className="flex items-center gap-2 text-gray-300">
                <input
                  type="checkbox"
                  checked={formData.enabled}
                  onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
                  className="w-4 h-4 rounded bg-gray-700 border-gray-600"
                />
                Enabled
              </label>

              <div className="flex justify-end gap-3 pt-4 border-t border-gray-700">
                <button
                  type="button"
                  onClick={() => { setShowModal(false); resetForm(); }}
                  className="px-4 py-2 text-gray-400 hover:text-white transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
                >
                  {loading ? 'Saving...' : editingKeyword ? 'Update' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Test Keywords Modal */}
      {showTestModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-lg p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <h2 className="text-xl font-bold text-white mb-4">🔍 Test Keywords</h2>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">
                  Enter content to test
                </label>
                <textarea
                  value={testContent}
                  onChange={(e) => setTestContent(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  rows={6}
                  placeholder="Paste sample content here to test keyword matching..."
                />
              </div>

              <button
                onClick={handleTest}
                disabled={!testContent.trim()}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50"
              >
                Run Test
              </button>

              {testResults && (
                <div className="border-t border-gray-700 pt-4">
                  <h3 className="text-lg font-medium text-white mb-3">Results</h3>

                  <div className="grid grid-cols-3 gap-4 mb-4">
                    <div className="bg-gray-700 rounded-lg p-3">
                      <p className="text-gray-400 text-sm">Matches Found</p>
                      <p className="text-2xl font-bold text-white">{testResults.match_count}</p>
                    </div>
                    <div className="bg-gray-700 rounded-lg p-3">
                      <p className="text-gray-400 text-sm">Classification</p>
                      <ClassificationBadge classification={testResults.classification} size="lg" />
                    </div>
                    <div className="bg-gray-700 rounded-lg p-3">
                      <p className="text-gray-400 text-sm">Hard Block</p>
                      <p className={`text-xl font-bold ${testResults.has_hard_block ? 'text-red-400' : 'text-green-400'}`}>
                        {testResults.has_hard_block ? '🚫 YES' : '✓ NO'}
                      </p>
                    </div>
                  </div>

                  {testResults.matches?.length > 0 && (
                    <div className="bg-gray-700 rounded-lg p-4 max-h-64 overflow-y-auto">
                      <h4 className="text-sm font-medium text-gray-400 mb-2">Matched Keywords</h4>
                      <div className="space-y-2">
                        {testResults.matches.map((match: any, idx: number) => (
                          <div key={idx} className="flex items-center gap-3 text-sm">
                            <code className="bg-gray-600 px-2 py-1 rounded text-white">{match.keyword}</code>
                            <span className="text-gray-400">→</span>
                            <ClassificationBadge classification={match.classification} size="sm" />
                            {match.hard_block && <span className="text-red-400 text-xs">HARD BLOCK</span>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="flex justify-end pt-4 mt-4 border-t border-gray-700">
              <button
                onClick={() => { setShowTestModal(false); setTestContent(''); setTestResults(null); }}
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

export default KeywordsPage;
