import { useState, useEffect } from 'react';
import { Plus, Trash2, Edit2, AlertCircle, Check } from 'lucide-react';
import { apiClient } from '../api/client';

interface ClassificationRule {
  id?: number;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  condition_field: string;
  condition_operator: string;
  condition_value: string;
  action_type: string;
  action_classification: string;
  created_by?: string;
  created_at?: string;
}

interface AddRuleModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSave: (rule: ClassificationRule) => void;
  editingRule?: ClassificationRule;
}

// Modal Component
function AddRuleModal({ isOpen, onClose, onSave, editingRule }: AddRuleModalProps) {
  const [formError, setFormError] = useState('');
  const [formData, setFormData] = useState<ClassificationRule>(
    editingRule || {
      name: '',
      description: '',
      enabled: true,
      priority: 100,
      condition_field: 'keyword',
      condition_operator: 'contains',
      condition_value: '',
      action_type: 'classify_as',
      action_classification: 'PRIVATE'
    }
  );

  const conditionFields = [
    { value: 'keyword', label: 'File Name Keyword' },
    { value: 'file_extension', label: 'File Extension' },
    { value: 'file_size', label: 'File Size (MB)' },
    { value: 'directory_path', label: 'Directory Path' },
    { value: 'content_pattern', label: 'Content Pattern' },
  ];

  const operators: Record<string, string[]> = {
    'keyword': ['equals', 'contains', 'matches_regex'],
    'file_extension': ['equals', 'in_list'],
    'file_size': ['gt', 'lt', 'equals'],
    'directory_path': ['equals', 'contains', 'matches_regex'],
    'content_pattern': ['contains', 'matches_regex'],
  };

  const classifications = ['PUBLIC', 'PRIVATE', 'CONFIDENTIAL', 'RESTRICTED'];

  const operatorLabels: Record<string, string> = {
    'equals': 'equals',
    'contains': 'contains',
    'matches_regex': 'matches regex',
    'gt': 'greater than',
    'lt': 'less than',
    'in_list': 'in list'
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg shadow-lg max-w-2xl w-full mx-4 max-h-[80vh] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex justify-between items-center">
          <h2 className="text-xl font-semibold text-gray-900">
            {editingRule ? 'Edit Classification Rule' : 'Add Classification Rule'}
          </h2>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-gray-700 text-xl font-bold"
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-4">
          {/* Rule Name */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Rule Name
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="e.g., Payroll Files Classification"
              className="w-full px-3 py-2 bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Description
            </label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Explain what this rule does..."
              className="w-full px-3 py-2 bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
              rows={2}
            />
          </div>

          {/* Priority */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Priority (0-1000, lower = higher priority)
            </label>
            <input
              type="number"
              value={formData.priority}
              onChange={(e) => setFormData({ ...formData, priority: parseInt(e.target.value) || 100 })}
              min="0"
              max="1000"
              className="w-full px-3 py-2 bg-white border border-gray-300 rounded-lg text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
            />
            <p className="text-xs text-gray-500 mt-1">Recommended: 0-99 (system), 100-500 (user high), 500-1000 (user low)</p>
          </div>

          {/* Enable Toggle */}
          <div className="flex items-center">
            <input
              type="checkbox"
              id="enabled"
              checked={formData.enabled}
              onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
              className="w-4 h-4 rounded border-gray-300"
            />
            <label htmlFor="enabled" className="ml-2 text-sm font-medium text-gray-700">
              Enable this rule
            </label>
          </div>

          {/* Condition Section */}
          <div className="border-t border-gray-200 pt-4">
            <h3 className="text-sm font-semibold text-gray-900 mb-3">Condition</h3>
            <div className="grid grid-cols-3 gap-3">
              {/* Condition Field */}
              <div>
                <label className="block text-xs text-gray-600 mb-1">Field</label>
                <select
                  value={formData.condition_field}
                  onChange={(e) => setFormData({ ...formData, condition_field: e.target.value })}
                  className="w-full px-2 py-1.5 bg-white border border-gray-300 rounded text-sm text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand"
                >
                  {conditionFields.map((field) => (
                    <option key={field.value} value={field.value}>
                      {field.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Condition Operator */}
              <div>
                <label className="block text-xs text-gray-600 mb-1">Operator</label>
                <select
                  value={formData.condition_operator}
                  onChange={(e) => setFormData({ ...formData, condition_operator: e.target.value })}
                  className="w-full px-2 py-1.5 bg-white border border-gray-300 rounded text-sm text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand"
                >
                  {(operators[formData.condition_field] || []).map((op) => (
                    <option key={op} value={op}>
                      {operatorLabels[op] || op}
                    </option>
                  ))}
                </select>
              </div>

              {/* Condition Value */}
              <div>
                <label className="block text-xs text-gray-600 mb-1">Value</label>
                <input
                  type="text"
                  value={formData.condition_value}
                  onChange={(e) => setFormData({ ...formData, condition_value: e.target.value })}
                  placeholder={
                    formData.condition_field === 'file_size'
                      ? 'e.g., 100 (for 100MB)'
                      : formData.condition_field === 'file_extension'
                      ? 'e.g., .xlsx, .sql'
                      : 'e.g., payroll'
                  }
                  className="w-full px-2 py-1.5 bg-white border border-gray-300 rounded text-sm text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand"
                />
              </div>
            </div>
          </div>

          {/* Action Section */}
          <div className="border-t border-gray-200 pt-4">
            <h3 className="text-sm font-semibold text-gray-900 mb-3">Action</h3>
            <div>
              <label className="block text-xs text-gray-600 mb-2">Classify As</label>
              <div className="grid grid-cols-4 gap-2">
                {classifications.map((classification) => (
                  <button
                    key={classification}
                    onClick={() => setFormData({ ...formData, action_classification: classification })}
                    className={`px-3 py-2 rounded text-sm font-medium transition-colors ${
                      formData.action_classification === classification
                        ? classification === 'PUBLIC'
                          ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                          : classification === 'PRIVATE'
                          ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                          : classification === 'CONFIDENTIAL'
                          ? 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                          : 'bg-red-500/10 text-red-400 border border-red-500/30'
                        : 'bg-gray-100 text-gray-700 border border-gray-300 hover:border-gray-400'
                    }`}
                  >
                    {classification}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Example */}
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
            <div className="flex gap-2 text-sm">
              <AlertCircle className="w-4 h-4 text-blue-600 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-blue-900 font-medium">Example</p>
                <p className="text-blue-800 text-xs mt-1">
                  This rule will match files where <strong>{formData.condition_field}</strong> {formData.condition_operator} <strong>"{formData.condition_value}"</strong> and classify them as <strong>{formData.action_classification}</strong>.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 bg-gray-50 border-t border-gray-200 px-6 py-3 flex justify-end gap-3">
          {formError && (
            <div className="flex-1 flex items-center gap-1 text-red-600 text-sm">
              <AlertCircle className="w-4 h-4" />
              {formError}
            </div>
          )}
          <button
            onClick={onClose}
            className="px-4 py-2 text-gray-700 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={async () => {
              if (!formData.name || !formData.condition_value) {
                setFormError('Please fill in all required fields');
                return;
              }
              setFormError('');
              await onSave(formData);
            }}
            className="px-4 py-2 bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors flex items-center gap-2"
          >
            <Check className="w-4 h-4" />
            Save Rule
          </button>
        </div>
      </div>
    </div>
  );
}

// Main Rules Component
export function ClassificationRules() {
  const [rules, setRules] = useState<ClassificationRule[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<ClassificationRule | undefined>();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Load rules on mount
    apiClient.get('/api/rules')
      .then((res) => {
        setRules(res.data.rules || []);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Failed to load rules:', err);
        setLoading(false);
      });
  }, []);

  const handleAddRule = () => {
    setEditingRule(undefined);
    setIsModalOpen(true);
  };

  const handleEditRule = (rule: ClassificationRule) => {
    setEditingRule(rule);
    setIsModalOpen(true);
  };

  const handleSaveRule = async (formData: ClassificationRule) => {
    try {
      if (editingRule) {
        await apiClient.put(`/api/rules/${editingRule.id}`, formData);
      } else {
        await apiClient.post('/api/rules', formData);
      }

      // Reload rules
      const updatedRules = await apiClient.get('/api/rules');
      setRules(updatedRules.data.rules || []);
      setIsModalOpen(false); // Close modal on success
    } catch (err) {
      console.error('Failed to save rule:', err);
    }
  };

  const handleDeleteRule = async (ruleId: number) => {
    try {
      await apiClient.delete(`/api/rules/${ruleId}`);
      setRules((prev) => prev.filter((r) => r.id !== ruleId));
    } catch (err) {
      console.error('Failed to delete rule:', err);
    }
  };

  const getClassificationColor = (classification: string) => {
    switch (classification) {
      case 'PUBLIC':
        return { bg: 'bg-green-500/10', text: 'text-green-400', border: 'border-green-500/30' };
      case 'PRIVATE':
        return { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' };
      case 'CONFIDENTIAL':
        return { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' };
      case 'RESTRICTED':
        return { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' };
      default:
        return { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' };
    }
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Classification Rules</h1>
          <p className="text-gray-600 text-sm mt-1">
            Create custom rules to automatically classify files based on filename, extension, size, or content
          </p>
        </div>
        <button
          onClick={handleAddRule}
          className="flex items-center gap-2 px-4 py-2 bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Rule
        </button>
      </div>

      {/* Add Rule Modal */}
      <AddRuleModal
        isOpen={isModalOpen}
        onClose={() => {
          setIsModalOpen(false);
          setEditingRule(undefined);
        }}
        onSave={handleSaveRule}
        editingRule={editingRule}
      />

      {/* Rules List */}
      {loading ? (
        <div className="text-center py-12 text-gray-500">Loading rules...</div>
      ) : rules.length === 0 ? (
        <div className="bg-white rounded-lg border border-gray-200 p-8 text-center">
          <p className="text-gray-500 mb-4">No classification rules yet. Create one to automate file classification!</p>
          <button
            onClick={handleAddRule}
            className="px-4 py-2 bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors"
          >
            Create Your First Rule
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {rules.map((rule) => {
            const colors = getClassificationColor(rule.action_classification);
            return (
              <div
                key={rule.id}
                className={`bg-white border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow ${
                  !rule.enabled ? 'opacity-60' : ''
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <h3 className="font-semibold text-gray-900">{rule.name}</h3>
                      {!rule.enabled && (
                        <span className="px-2 py-0.5 bg-gray-200 text-gray-600 text-xs rounded font-medium">
                          Disabled
                        </span>
                      )}
                      <span className="text-xs text-gray-500">Priority: {rule.priority}</span>
                    </div>
                    <p className="text-sm text-gray-600 mb-3">{rule.description}</p>

                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-gray-600">Condition: </span>
                        <code className="bg-gray-100 px-2 py-1 rounded text-xs">
                          {rule.condition_field} {rule.condition_operator} "{rule.condition_value}"
                        </code>
                      </div>
                      <div>
                        <span className="text-gray-600">Action: </span>
                        <span
                          className={`inline-flex items-center font-medium rounded border px-2 py-0.5 text-xs ${colors.bg} ${colors.text} ${colors.border}`}
                        >
                          {rule.action_classification}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex gap-2 ml-4">
                    <button
                      onClick={() => handleEditRule(rule)}
                      className="p-2 text-gray-600 hover:text-brand hover:bg-red-50 rounded transition-colors"
                      title="Edit rule"
                    >
                      <Edit2 className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => rule.id && handleDeleteRule(rule.id)}
                      className="p-2 text-gray-600 hover:text-red-600 hover:bg-red-50 rounded transition-colors"
                      title="Delete rule"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default ClassificationRules;
