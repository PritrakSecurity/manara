import { Shield } from 'lucide-react';

export default function EnhancedPoliciesPage() {
  return (
    <div className="min-h-screen bg-white p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-900 flex items-center gap-3">
          <Shield className="w-8 h-8 text-brand" />
          DLP Policies
        </h1>
        <p className="text-gray-600 mt-1">Define and manage data loss prevention policies</p>
      </div>

      {/* Empty State */}
      <div className="bg-white border border-gray-200 rounded-lg p-16 text-center shadow-sm">
        <Shield className="w-16 h-16 text-gray-300 mx-auto mb-4" />
        <h2 className="text-lg font-semibold text-gray-900 mb-2">No policies configured</h2>
        <p className="text-gray-500 text-sm max-w-md mx-auto">
          DLP policies will appear here once they are configured. Create a policy to
          define what data is sensitive and how it should be protected.
        </p>
      </div>
    </div>
  );
}
