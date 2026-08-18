import { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { ShieldCheck, HeartPulse, CreditCard, ArrowRight, RefreshCw } from 'lucide-react';
import { apiClient } from '../api/client';

export default function ComplianceSnapshot() {
  const [stats, setStats] = useState<Record<string, number>>({});

  const load = useCallback(async () => {
    try {
      const res = await apiClient.get('/api/v1/dspm/stats');
      setStats(res.data || {});
    } catch {
      // best-effort
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const frameworks = [
    {
      name: 'GDPR',
      icon: ShieldCheck,
      iconColor: 'text-blue-600',
      iconBg: 'bg-blue-100',
      description: 'General Data Protection Regulation — EU personal data protection.',
      matching: stats.PII || 0,
      route: '/compliance/framework-mapping',
    },
    {
      name: 'HIPAA',
      icon: HeartPulse,
      iconColor: 'text-purple-600',
      iconBg: 'bg-purple-100',
      description: 'Health Insurance Portability and Accountability Act — PHI protection.',
      matching: stats.PHI || 0,
      route: '/compliance/framework-mapping',
    },
    {
      name: 'PCI-DSS',
      icon: CreditCard,
      iconColor: 'text-yellow-600',
      iconBg: 'bg-yellow-100',
      description: 'Payment Card Industry Data Security Standard — cardholder data.',
      matching: stats.PCI || 0,
      route: '/compliance/framework-mapping',
    },
  ];

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Compliance Snapshot</h1>
          <p className="text-gray-600 mt-1">Regulatory posture at a glance</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-4 py-2 bg-brand text-white rounded-lg hover:bg-brand-hover transition-colors font-medium"
        >
          <RefreshCw size={16} />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {frameworks.map((f) => (
          <div key={f.name} className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
            <div className={`w-12 h-12 rounded-lg ${f.iconBg} flex items-center justify-center mb-4`}>
              <f.icon className={`h-6 w-6 ${f.iconColor}`} />
            </div>
            <h2 className="text-xl font-bold text-gray-900">{f.name}</h2>
            <p className="text-sm text-gray-500 mt-2 leading-relaxed">{f.description}</p>
            <div className="mt-6 flex items-baseline gap-2">
              <span className="text-3xl font-bold text-gray-900">{f.matching}</span>
              <span className="text-sm text-gray-500">matching assets</span>
            </div>
            <Link
              to={f.route}
              className="mt-6 inline-flex items-center gap-2 px-4 py-2 border border-brand text-brand rounded-lg hover:bg-brand/5 transition-colors font-medium"
            >
              View Framework Mapping
              <ArrowRight size={16} />
            </Link>
          </div>
        ))}
      </div>
    </div>
  );
}
