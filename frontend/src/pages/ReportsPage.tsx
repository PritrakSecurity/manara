import { FileText } from 'lucide-react';

export default function ReportsPage() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white flex items-center gap-3">
          <FileText className="w-8 h-8 text-cyan-400" />
          Reports Center
        </h1>
        <p className="text-gray-400 mt-1">Generate, schedule, and manage security reports</p>
      </div>

      {/* Empty State */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-16 text-center">
        <FileText className="w-16 h-16 text-gray-600 mx-auto mb-4" />
        <h2 className="text-lg font-semibold text-white mb-2">No reports generated yet</h2>
        <p className="text-gray-400 text-sm max-w-md mx-auto">
          Reports will appear here once they are generated. Connect a report source or
          check back after the system has collected security data.
        </p>
      </div>
    </div>
  );
}
