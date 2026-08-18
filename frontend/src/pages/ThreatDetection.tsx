import { Activity } from 'lucide-react';

export default function ThreatDetection() {
  return (
    <div className="p-6 bg-white min-h-screen">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-gray-900 flex items-center gap-3 mb-2">
          <Activity className="w-6 h-6 text-brand" />
          Threat Detection
        </h1>
        <p className="text-gray-600">Monitor and analyze security threats in real-time</p>
      </div>

      {/* Empty State */}
      <div className="bg-white border border-gray-200 rounded-lg p-16 text-center shadow-sm">
        <Activity className="w-16 h-16 text-gray-300 mx-auto mb-4" />
        <h2 className="text-lg font-semibold text-gray-900 mb-2">No threats detected</h2>
        <p className="text-gray-500 text-sm max-w-md mx-auto">
          Threat detection results will appear here as events are analyzed by the system.
        </p>
      </div>
    </div>
  );
}
