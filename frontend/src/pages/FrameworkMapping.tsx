import { ShieldCheck, Lock, Eye, FileCheck2, ScrollText } from 'lucide-react';
import { useUIStore } from '../stores/uiStore';

interface Framework {
  name: string;
  icon: typeof ShieldCheck;
  color: string;
  bg: string;
  description: string;
}

const frameworks: Framework[] = [
  {
    name: 'GDPR',
    icon: ScrollText,
    color: 'text-blue-600',
    bg: 'bg-blue-100',
    description: 'EU General Data Protection Regulation — lawful processing of EU personal data.',
  },
  {
    name: 'HIPAA',
    icon: ShieldCheck,
    color: 'text-purple-600',
    bg: 'bg-purple-100',
    description: 'US Health Insurance Portability and Accountability Act — protected health information.',
  },
  {
    name: 'PCI-DSS',
    icon: FileCheck2,
    color: 'text-yellow-600',
    bg: 'bg-yellow-100',
    description: 'Payment Card Industry Data Security Standard — cardholder data environment.',
  },
  {
    name: 'SOC 2',
    icon: Eye,
    color: 'text-green-600',
    bg: 'bg-green-100',
    description: 'Service Organization Control 2 — security, availability and confidentiality trust services.',
  },
];

export default function FrameworkMapping() {
  const openUpgradeModal = useUIStore((s) => s.openUpgradeModal);

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900">Framework Mapping</h1>
        <p className="text-gray-600 mt-1">
          Map controls to industry compliance frameworks
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {frameworks.map((f) => (
          <div key={f.name} className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
            <div className="flex items-center gap-3 mb-4">
              <div className={`w-12 h-12 rounded-lg ${f.bg} flex items-center justify-center`}>
                <f.icon className={`h-6 w-6 ${f.color}`} />
              </div>
              <h2 className="text-xl font-bold text-gray-900">{f.name}</h2>
            </div>
            <p className="text-sm text-gray-500 leading-relaxed">{f.description}</p>
            <button
              onClick={() =>
                openUpgradeModal(
                  `${f.name} Controls`,
                  'enterprise',
                  `${f.name} control mapping is an Enterprise feature in the Pritrak DLP platform.`
                )
              }
              className="mt-6 inline-flex items-center gap-2 px-4 py-2 bg-[#fd382f] text-white rounded-lg hover:bg-[#e02f26] transition-colors font-medium"
            >
              <Lock size={16} />
              View Controls
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
