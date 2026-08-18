import { useState } from 'react';
import {
  Cloud,
  Database,
  HardDrive,
  Share2,
  Plus,
  Loader2,
  ScanSearch,
  ShieldAlert,
  CheckCircle2,
  HeartPulse,
  AlertTriangle,
  PieChart,
} from 'lucide-react';
import { apiClient } from '../api/client';
import Modal from '../components/common/Modal';

interface Finding {
  id: string;
  connector_id: string;
  provider: string;
  resource_type: string;
  resource_id: string;
  category: string;
  rule_id: string;
  severity: string;
  status: string;
  title: string;
  evidence: Record<string, string>;
  detected_at: string;
}

interface ScanError {
  scope: string;
  resource: string;
  category: string;
  retryable: boolean;
  message: string;
}

interface ScanResult {
  scan_id: string;
  started_at: string;
  completed_at: string;
  findings: Finding[];
  errors: ScanError[];
  truncated: boolean;
}

type ConnectorStatus = 'available' | 'connected' | 'planned';
type ConnectorTier = 'free' | 'enterprise';

interface Connector {
  id: string;
  name: string;
  category: string;
  icon: React.ComponentType<{ className?: string }>;
  status: ConnectorStatus;
  tier: ConnectorTier;
}

const CONNECTORS: Connector[] = [
  {
    id: 'aws-s3',
    name: 'Amazon S3',
    category: 'Cloud Storage',
    icon: Cloud,
    status: 'available',
    tier: 'free',
  },
  {
    id: 'azure-blob',
    name: 'Azure Blob Storage',
    category: 'Cloud Storage',
    icon: Database,
    status: 'planned',
    tier: 'enterprise',
  },
  {
    id: 'gcs',
    name: 'Google Cloud Storage',
    category: 'Cloud Storage',
    icon: HardDrive,
    status: 'planned',
    tier: 'enterprise',
  },
  {
    id: 'm365-sharepoint',
    name: 'Microsoft 365 / SharePoint',
    category: 'SaaS',
    icon: Share2,
    status: 'planned',
    tier: 'enterprise',
  },
  {
    id: 'snowflake',
    name: 'Snowflake',
    category: 'Data Warehouse',
    icon: Database,
    status: 'planned',
    tier: 'enterprise',
  },
  {
    id: 'google-drive',
    name: 'Google Drive',
    category: 'SaaS',
    icon: HardDrive,
    status: 'planned',
    tier: 'enterprise',
  },
  {
    id: 'slack',
    name: 'Slack',
    category: 'SaaS',
    icon: Share2,
    status: 'planned',
    tier: 'enterprise',
  },
];

const STATUS_STYLES: Record<ConnectorStatus, string> = {
  available: 'bg-green-100 text-green-700',
  connected: 'bg-blue-100 text-blue-700',
  planned: 'bg-gray-100 text-gray-600',
};

const TIER_STYLES: Record<ConnectorTier, string> = {
  free: 'bg-gray-100 text-gray-600',
  enterprise: 'bg-amber-100 text-amber-700',
};

const severityColor = (severity: string) => {
  switch (severity) {
    case 'critical':
      return 'bg-red-100 text-red-700';
    case 'high':
      return 'bg-orange-100 text-orange-700';
    case 'medium':
      return 'bg-yellow-100 text-yellow-700';
    case 'low':
      return 'bg-blue-100 text-blue-700';
    default:
      return 'bg-gray-100 text-gray-600';
  }
};

const statusColor = (status: string) => {
  switch (status) {
    case 'noncompliant':
      return 'bg-red-100 text-red-700';
    case 'compliant':
      return 'bg-green-100 text-green-700';
    case 'unsupported':
      return 'bg-gray-100 text-gray-600';
    case 'error':
      return 'bg-red-100 text-red-700';
    default:
      return 'bg-gray-100 text-gray-600';
  }
};

export default function CloudSaaS() {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [roleArn, setRoleArn] = useState('');
  const [externalId, setExternalId] = useState('');
  const [scanning, setScanning] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState('');

  const openS3Modal = () => {
    setError('');
    setResult(null);
    setIsModalOpen(true);
  };

  const closeModal = () => {
    if (scanning) return;
    setIsModalOpen(false);
  };

  const handleScan = async () => {
    setError('');
    setResult(null);
    if (!roleArn.trim()) {
      setError('AWS Role ARN is required.');
      return;
    }
    setScanning(true);
    try {
      const res = await apiClient.post('/api/v1/cloud/aws/s3/scan', {
        role_arn: roleArn.trim(),
        external_id: externalId.trim(),
      });
      setResult(res.data);
    } catch (err: any) {
      const message = err?.response?.data?.message || err?.message || 'Scan failed. Please try again.';
      setError(message);
    } finally {
      setScanning(false);
    }
  };

  const summaryCards = [
    {
      label: 'Connected Services',
      value: '0',
      icon: CheckCircle2,
      iconClass: 'bg-green-100 text-green-600',
    },
    {
      label: 'Healthy Connections',
      value: '0',
      icon: HeartPulse,
      iconClass: 'bg-blue-100 text-blue-600',
    },
    {
      label: 'Requires Attention',
      value: '0',
      icon: AlertTriangle,
      iconClass: 'bg-yellow-100 text-yellow-600',
    },
    {
      label: 'Overall Coverage',
      value: '0%',
      icon: PieChart,
      iconClass: 'bg-purple-100 text-purple-600',
    },
  ];

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      {/* Page header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Cloud &amp; SaaS Coverage</h1>
          <p className="text-gray-600 mt-1">
            Centralized visibility and control over data across cloud and SaaS applications.
          </p>
        </div>
        <button
          onClick={openS3Modal}
          className="flex items-center gap-2 px-4 py-2.5 bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors font-medium self-start md:self-auto"
        >
          <Plus size={18} />
          Add Connection
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {summaryCards.map((card) => (
          <div
            key={card.label}
            className="bg-white rounded-xl border border-gray-200 shadow-sm p-5 flex items-center gap-4"
          >
            <div className={`w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0 ${card.iconClass}`}>
              <card.icon className="h-6 w-6" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-900">{card.value}</p>
              <p className="text-sm text-gray-500">{card.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Connector grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {CONNECTORS.map((connector) => {
          const planned = connector.status === 'planned';
          const Icon = connector.icon;
          return (
            <div
              key={connector.id}
              className={`bg-white rounded-xl border border-gray-200 shadow-sm p-5 flex flex-col ${
                planned ? 'opacity-50 cursor-not-allowed' : 'hover:shadow-md transition-shadow'
              }`}
            >
              <div className="flex items-start justify-between mb-4">
                <div className="w-12 h-12 bg-gray-100 rounded-lg flex items-center justify-center">
                  <Icon className="h-6 w-6 text-gray-600" />
                </div>
                <div className="flex flex-col items-end gap-1.5">
                  <span className={`px-2.5 py-1 rounded-full text-xs font-medium capitalize ${STATUS_STYLES[connector.status]}`}>
                    {connector.status}
                  </span>
                  <span className={`px-2.5 py-1 rounded-full text-xs font-medium capitalize ${TIER_STYLES[connector.tier]}`}>
                    {connector.tier}
                  </span>
                </div>
              </div>

              <h3 className="text-lg font-semibold text-gray-900">{connector.name}</h3>
              <p className="text-sm text-gray-500 mb-5">{connector.category}</p>

              {planned ? (
                <button
                  disabled
                  className="mt-auto px-4 py-2 bg-gray-100 text-gray-400 rounded-lg font-medium cursor-not-allowed w-full"
                >
                  Coming Soon
                </button>
              ) : (
                <button
                  onClick={openS3Modal}
                  className="mt-auto px-4 py-2 bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors font-medium w-full"
                >
                  Configure
                </button>
              )}
            </div>
          );
        })}
      </div>

      {/* AWS S3 configuration modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={closeModal}
        title="Configure AWS S3 Connection"
        size="lg"
      >
        {scanning ? (
          <div className="py-10 text-center">
            <Loader2 className="h-10 w-10 text-brand animate-spin mx-auto mb-4" />
            <p className="text-gray-700 font-medium">Scanning AWS environment...</p>
            <p className="text-gray-500 text-sm mt-1">This may take a few minutes.</p>
          </div>
        ) : result ? (
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-5 w-5 text-brand" />
                <h3 className="text-lg font-semibold text-gray-900">Findings</h3>
              </div>
              <div className="flex items-center gap-3 text-sm text-gray-500">
                <span>
                  {result.findings.length} finding{result.findings.length !== 1 ? 's' : ''}
                </span>
                {result.truncated && <span className="text-yellow-600 font-medium">Truncated</span>}
              </div>
            </div>

            <div className="overflow-x-auto border border-gray-200 rounded-lg">
              {result.findings.length === 0 ? (
                <div className="p-10 text-center">
                  <Cloud className="h-12 w-12 text-gray-300 mx-auto mb-4" />
                  <p className="text-gray-500">No findings detected</p>
                </div>
              ) : (
                <table className="w-full">
                  <thead className="bg-gray-50 border-b">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Bucket Name</th>
                      <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Finding Category</th>
                      <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Severity</th>
                      <th className="px-6 py-3 text-left text-xs font-semibold text-gray-700">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100">
                    {result.findings.map((f) => (
                      <tr key={f.id} className="hover:bg-gray-50">
                        <td className="px-6 py-3 text-sm font-medium text-gray-900">{f.resource_id}</td>
                        <td className="px-6 py-3 text-sm text-gray-600 capitalize">
                          {f.category.replace(/-/g, ' ')}
                        </td>
                        <td className="px-6 py-3 text-sm">
                          <span className={`inline-block px-2.5 py-1 rounded-full text-xs font-medium capitalize ${severityColor(f.severity)}`}>
                            {f.severity}
                          </span>
                        </td>
                        <td className="px-6 py-3 text-sm">
                          <span className={`inline-block px-2.5 py-1 rounded-full text-xs font-medium capitalize ${statusColor(f.status)}`}>
                            {f.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>

            {result.errors.length > 0 && (
              <div className="mt-4 px-4 py-3 border border-gray-200 rounded-lg bg-gray-50">
                <h4 className="text-sm font-semibold text-gray-700 mb-2">Scan errors</h4>
                <ul className="space-y-1">
                  {result.errors.map((e, i) => (
                    <li key={i} className="text-sm text-gray-600">
                      <span className="font-medium">{e.resource || e.scope}:</span> {e.message}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="mt-6 flex justify-end">
              <button
                onClick={closeModal}
                className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors font-medium"
              >
                Close
              </button>
            </div>
          </div>
        ) : (
          <div>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">AWS Role ARN</label>
                <input
                  type="text"
                  value={roleArn}
                  onChange={(e) => setRoleArn(e.target.value)}
                  placeholder="arn:aws:iam::123456789012:role/ManaraScan"
                  className="w-full px-4 py-2.5 border border-gray-300 rounded-lg text-gray-800 placeholder-gray-400 focus:ring-2 focus:ring-brand focus:border-brand transition"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">External ID</label>
                <input
                  type="text"
                  value={externalId}
                  onChange={(e) => setExternalId(e.target.value)}
                  placeholder="External ID configured on the role trust policy"
                  className="w-full px-4 py-2.5 border border-gray-300 rounded-lg text-gray-800 placeholder-gray-400 focus:ring-2 focus:ring-brand focus:border-brand transition"
                />
              </div>
            </div>

            {error && (
              <div className="mt-4 bg-red-50 border border-red-200 rounded-lg p-3 text-red-700 text-sm">
                {error}
              </div>
            )}

            <div className="mt-6 flex justify-end">
              <button
                onClick={handleScan}
                className="flex items-center gap-2 px-5 py-2.5 bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors font-medium"
              >
                <ScanSearch className="h-4 w-4" />
                Scan AWS
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
