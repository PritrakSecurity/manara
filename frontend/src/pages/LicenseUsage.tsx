import { useState, useEffect, useCallback } from 'react';
import { Crown, Monitor, Database, AlertTriangle, Sparkles } from 'lucide-react';
import { apiClient } from '../api/client';
import { useUIStore } from '../stores/uiStore';

export default function LicenseUsage() {
  const [deviceCount, setDeviceCount] = useState(0);
  const [assetCount, setAssetCount] = useState(0);
  const openUpgradeModal = useUIStore((s) => s.openUpgradeModal);

  const load = useCallback(async () => {
    try {
      const [devicesRes, statsRes] = await Promise.all([
        apiClient.get('/api/devices'),
        apiClient.get('/api/v1/dspm/stats'),
      ]);
      setDeviceCount(Array.isArray(devicesRes.data) ? devicesRes.data.length : 0);
      setAssetCount(statsRes.data?.TOTAL || 0);
    } catch {
      // best-effort
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const endpointLimit = 15;
  const assetLimit = 3;
  const endpointsPct = Math.min(100, Math.round((deviceCount / endpointLimit) * 100));
  const assetsPct = Math.min(100, Math.round((assetCount / assetLimit) * 100));
  const limitReached = deviceCount >= endpointLimit || assetCount >= assetLimit;

  const barColor = (pct: number) => (pct >= 100 ? 'bg-[#fd382f]' : pct >= 75 ? 'bg-yellow-500' : 'bg-green-500');

  return (
    <div className="p-6 bg-gray-50 min-h-full">
      <div className="mb-6">
        <h1 className="text-3xl font-bold text-gray-900">License & Usage</h1>
        <p className="text-gray-600 mt-1">Pritrak DLP Open-Core usage</p>
      </div>

      <div className="flex items-center gap-3 mb-6">
        <div className="w-12 h-12 rounded-full bg-[#fd382f]/10 flex items-center justify-center">
          <Crown className="h-6 w-6 text-[#fd382f]" />
        </div>
        <div>
          <span className="inline-block px-3 py-1 bg-gray-900 text-white rounded-full text-sm font-semibold">
            Community Edition
          </span>
          <p className="text-xs text-gray-500 mt-1">Visibility is free. Control is paid.</p>
        </div>
      </div>

      {limitReached && (
        <div className="mb-6 p-4 bg-yellow-50 border border-yellow-300 rounded-xl flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-yellow-600 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <p className="text-yellow-800 font-semibold">Community limit reached</p>
            <p className="text-yellow-700 text-sm mt-1">
              You have reached the free-tier limit. Upgrade to continue discovering and securing data at scale.
            </p>
            <button
              onClick={() =>
                openUpgradeModal('Starter Plan', 'starter', 'Expand your coverage with the Pritrak DLP Starter plan.')
              }
              className="mt-3 inline-flex items-center gap-2 px-4 py-2 bg-[#fd382f] text-white rounded-lg hover:bg-[#e02f26] transition-colors font-medium"
            >
              <Sparkles size={16} />
              Start Free Trial
            </button>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Endpoints */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-11 h-11 rounded-lg bg-blue-100 flex items-center justify-center">
              <Monitor className="h-5 w-5 text-blue-600" />
            </div>
            <h2 className="text-lg font-semibold text-gray-900">Endpoints</h2>
          </div>
          <div className="text-3xl font-bold text-gray-900 mb-1">
            {deviceCount} <span className="text-lg font-normal text-gray-500">/ {endpointLimit}</span>
          </div>
          <div className="h-2.5 bg-gray-200 rounded-full overflow-hidden mb-2">
            <div className={`h-full ${barColor(endpointsPct)} transition-all`} style={{ width: `${endpointsPct}%` }} />
          </div>
          <p className="text-xs text-gray-500">Agents connected in the Community tier</p>
        </div>

        {/* Data assets */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-11 h-11 rounded-lg bg-purple-100 flex items-center justify-center">
              <Database className="h-5 w-5 text-purple-600" />
            </div>
            <h2 className="text-lg font-semibold text-gray-900">Data Assets</h2>
          </div>
          <div className="text-3xl font-bold text-gray-900 mb-1">
            {assetCount} <span className="text-lg font-normal text-gray-500">/ {assetLimit}</span>
          </div>
          <div className="h-2.5 bg-gray-200 rounded-full overflow-hidden mb-2">
            <div className={`h-full ${barColor(assetsPct)} transition-all`} style={{ width: `${assetsPct}%` }} />
          </div>
          <p className="text-xs text-gray-500">Sensitive data assets discovered in the Community tier</p>
        </div>
      </div>
    </div>
  );
}
