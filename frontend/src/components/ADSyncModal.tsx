import React, { useState } from 'react';
import { X, Server, RefreshCw, CheckCircle, XCircle, AlertCircle, Loader2 } from 'lucide-react';
import { apiClient } from '../api/client';

interface ADSyncModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSyncComplete?: () => void;
  onSync?: (syncedDevices: any[]) => void;
}

export default function ADSyncModal({ isOpen, onClose, onSyncComplete, onSync }: ADSyncModalProps) {
  const [step, setStep] = useState<'config' | 'syncing' | 'discover'>('config');
  const [progress, setProgress] = useState(0);
  const [syncStats, setSyncStats] = useState({ found: 0, added: 0, updated: 0 });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [testing, setTesting] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'success' | 'error' | ''>('');
  const [connectionMessage, setConnectionMessage] = useState('');
  const [discoveredDevices, setDiscoveredDevices] = useState<any[]>([]);
  const [discovering, setDiscovering] = useState(false);
  const [useTLS, setUseTLS] = useState(false);

  const [config, setConfig] = useState({
    server: '',
    port: 389,
    username: '',
    password: '',
    baseDN: 'CN=Computers,DC=corp,DC=local',
  });

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setConfig({
      ...config,
      [name]: name === 'port' ? parseInt(value) || 389 : value,
    });
  };

  const testLDAPConnection = async () => {
    setTesting(true);
    setConnectionStatus('');
    setConnectionMessage('');
    setError('');

    try {
      const response = await apiClient.post('/api/ad/test', {
        server: config.server,
        port: config.port,
        baseDN: config.baseDN,
        username: config.username,
        password: config.password,
        useTLS: useTLS
      });

      if (response.data.success) {
        setConnectionStatus('success');
        setConnectionMessage('LDAP connection successful!');
      } else {
        setConnectionStatus('error');
        setConnectionMessage(response.data.error || 'Connection failed');
      }
    } catch (error: any) {
      setConnectionStatus('error');
      setConnectionMessage(
        error.response?.data?.error || 
        'Failed to connect to LDAP server'
      );
    } finally {
      setTesting(false);
    }
  };

  const discoverADDevices = async () => {
    setDiscovering(true);
    setError('');
    
    try {
      const response = await apiClient.post('/api/ad/discover', {
        server: config.server,
        port: config.port,
        baseDN: config.baseDN,
        username: config.username,
        password: config.password,
        filter: '(&(objectClass=computer)(operatingSystem=Windows*))'
      });

      const devices = response.data.devices || [];
      setDiscoveredDevices(devices);
      setStep('discover');

      console.log(`✅ Found ${devices.length} devices in Active Directory`);
    } catch (error: any) {
      console.error('❌ AD discovery failed:', error);
      setConnectionStatus('error');
      setConnectionMessage('Failed to discover devices from AD');
      setError(error.response?.data?.error || 'Discovery failed');
    } finally {
      setDiscovering(false);
    }
  };

  const handleStartSync = async () => {
    if (!config.server || !config.port || !config.username || !config.password) {
      setError('All fields are required');
      return;
    }

    try {
      setLoading(true);
      setError('');

      const response = await apiClient.post(
        '/api/devices/sync-ad/start',
        {
          server: config.server,
          port: config.port,
          username: config.username,
          password: config.password,
          base_dn: config.baseDN,
        }
      );

      if (response.data.jobId) {
        setStep('syncing');
        setProgress(0);
        pollProgress(response.data.jobId);
      } else {
        setError('Failed to start sync');
      }
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to start sync');
    } finally {
      setLoading(false);
    }
  };

  const pollProgress = (id: string) => {
    const interval = setInterval(async () => {
      try {
        const response = await apiClient.get(`/api/devices/sync-ad/progress/${id}`);

        const { progress, found, added, updated, status } = response.data.data;
        setProgress(progress);
        setSyncStats({ found, added, updated });

        if (status === 'completed') {
          clearInterval(interval);
          setTimeout(() => {
            if (onSyncComplete) onSyncComplete();
            onClose();
          }, 1500);
        }
      } catch (err) {
        console.error('Poll error:', err);
      }
    }, 500);
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div 
        className="bg-white rounded-xl border border-gray-200 w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-6 border-b border-gray-200 flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 bg-[#fd382f]/10 rounded-lg flex items-center justify-center">
              <Server className="h-6 w-6 text-[#fd382f]" />
            </div>
            <div>
              <h2 className="text-2xl font-bold text-gray-900">Active Directory Integration</h2>
              <p className="text-gray-600 text-sm mt-1">
                Sync devices from your LDAP/Active Directory domain
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
          >
            <X className="h-5 w-5 text-gray-400" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-auto p-6">
        {step === 'config' && (
            <div className="space-y-6">
            {error && (
                <div className="bg-red-50 border-l-4 border-red-400 p-4 rounded">
                  <div className="flex items-start gap-3">
                    <AlertCircle className="h-5 w-5 text-red-600 flex-shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-red-800 block mb-1">Error</strong>
                      <p className="text-red-700 text-sm">{error}</p>
                    </div>
                  </div>
              </div>
            )}

              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">LDAP Configuration</h3>
                
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      AD Server <span className="text-red-500">*</span>
                </label>
                <input
                  type="text"
                  name="server"
                  value={config.server}
                  onChange={handleInputChange}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#fd382f] focus:border-[#fd382f] transition"
                  placeholder="dc1.corp.local"
                      disabled={loading || testing}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Port <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="number"
                    name="port"
                    value={config.port}
                    onChange={handleInputChange}
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#fd382f] focus:border-[#fd382f] transition"
                        disabled={loading || testing}
                  />
                </div>

                <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Username <span className="text-red-500">*</span>
                  </label>
                  <input
                    type="text"
                    name="username"
                    value={config.username}
                    onChange={handleInputChange}
                        className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#fd382f] focus:border-[#fd382f] transition"
                    placeholder="administrator@corp.local"
                        disabled={loading || testing}
                  />
                </div>
              </div>

              <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Password <span className="text-red-500">*</span>
                </label>
                <input
                  type="password"
                  name="password"
                  value={config.password}
                  onChange={handleInputChange}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#fd382f] focus:border-[#fd382f] transition"
                      disabled={loading || testing}
                />
              </div>

              <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                  Base DN (Optional)
                </label>
                <input
                  type="text"
                  name="baseDN"
                  value={config.baseDN}
                  onChange={handleInputChange}
                      className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#fd382f] focus:border-[#fd382f] transition"
                  placeholder="CN=Computers,DC=corp,DC=local"
                      disabled={loading || testing}
                />
                    <p className="text-xs text-gray-500 mt-1">Distinguished Name for LDAP search base</p>
            </div>

                  <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="useTLS"
                checked={useTLS}
                onChange={(e) => setUseTLS(e.target.checked)}
                      className="w-4 h-4 text-[#fd382f] border-gray-300 rounded focus:ring-[#fd382f]"
                      disabled={loading || testing}
              />
                    <label htmlFor="useTLS" className="text-sm text-gray-700 cursor-pointer">
                      Use TLS/SSL (LDAPS - Port 636)
              </label>
                  </div>
                </div>
              </div>

              {/* Connection Test */}
              <div className="border-t border-gray-200 pt-6">
                <button
                  onClick={testLDAPConnection}
                  disabled={loading || testing || !config.server || !config.username || !config.password}
                  className="flex items-center justify-center gap-2 px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium"
                >
                  {testing ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Testing Connection...
                    </>
                  ) : (
                    <>
                      <RefreshCw className="h-4 w-4" />
                      Test Connection
                    </>
                  )}
                </button>

                {connectionStatus === 'success' && (
                  <div className="mt-4 flex items-center gap-2 p-3 bg-green-50 border border-green-200 rounded-lg">
                    <CheckCircle className="h-5 w-5 text-green-600 flex-shrink-0" />
                    <p className="text-sm text-green-800 font-medium">{connectionMessage}</p>
                  </div>
                )}

                {connectionStatus === 'error' && (
                  <div className="mt-4 flex items-center gap-2 p-3 bg-red-50 border border-red-200 rounded-lg">
                    <XCircle className="h-5 w-5 text-red-600 flex-shrink-0" />
                    <p className="text-sm text-red-800 font-medium">{connectionMessage}</p>
                  </div>
                )}
              </div>

              {/* Instructions */}
              <div className="bg-blue-50 border-l-4 border-blue-400 p-4 rounded">
                <strong className="text-blue-800 block mb-2">How to use:</strong>
                <ol className="text-blue-700 text-sm space-y-1 list-decimal list-inside">
                  <li>Enter your LDAP/Active Directory server details</li>
                  <li>Provide credentials with read access to computer objects</li>
                  <li>Click "Test Connection" to verify settings</li>
                  <li>Click "Discover Devices" to preview or "Start Sync" to import</li>
                </ol>
              </div>
            </div>
          )}

          {step === 'discover' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                  Discovered Devices ({discoveredDevices.length})
                </h3>
                {discoveredDevices.length > 0 ? (
                  <div className="border border-gray-200 rounded-lg overflow-hidden">
                    <div className="max-h-96 overflow-y-auto">
                      <table className="w-full text-sm">
                        <thead className="bg-gray-50 border-b border-gray-200">
                          <tr>
                            <th className="text-left py-3 px-4 text-gray-700 font-semibold">Hostname</th>
                            <th className="text-left py-3 px-4 text-gray-700 font-semibold">IP Address</th>
                            <th className="text-left py-3 px-4 text-gray-700 font-semibold">OS Version</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-200">
                          {discoveredDevices.map((device, idx) => (
                            <tr key={idx} className="hover:bg-gray-50">
                              <td className="py-3 px-4 text-gray-900 font-medium">{device.hostname}</td>
                              <td className="py-3 px-4 text-gray-600 font-mono text-xs">{device.ipAddress}</td>
                              <td className="py-3 px-4 text-gray-600 text-xs">{device.osVersion}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <p>No devices found in Active Directory</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {step === 'syncing' && (
            <div className="space-y-6">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 mb-4">Syncing from Active Directory</h3>
                
                <div className="space-y-6">
                  <div>
                    <div className="flex justify-between text-sm mb-2">
                      <span className="text-gray-700 font-medium">Progress</span>
                      <span className="text-[#fd382f] font-bold">{progress}%</span>
                    </div>
                    <div className="w-full h-3 bg-gray-200 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-gradient-to-r from-[#fd382f] to-[#e02f26] transition-all duration-300"
                        style={{ width: `${progress}%` }}
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-4">
                    <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                      <div className="text-2xl font-bold text-blue-600">{syncStats.found}</div>
                      <div className="text-xs text-gray-600 mt-1">Found</div>
                    </div>
                    <div className="bg-green-50 border border-green-200 rounded-lg p-4">
                      <div className="text-2xl font-bold text-green-600">{syncStats.added}</div>
                      <div className="text-xs text-gray-600 mt-1">Added</div>
                    </div>
                    <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                      <div className="text-2xl font-bold text-yellow-600">{syncStats.updated}</div>
                      <div className="text-xs text-gray-600 mt-1">Updated</div>
                    </div>
                  </div>

                  <div className="text-center py-4">
                    <Loader2 className="h-8 w-8 animate-spin text-[#fd382f] mx-auto mb-2" />
                    <p className="text-gray-600">Syncing devices from Active Directory...</p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-gray-200 flex gap-3 flex-shrink-0 bg-gray-50">
          {step === 'config' && (
            <>
              <button
                onClick={onClose}
                disabled={loading || testing}
                className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-100 transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={discoverADDevices}
                disabled={loading || discovering || !config.server || !config.username || !config.password}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors disabled:opacity-50 font-medium"
              >
                {discovering ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin inline mr-2" />
                    Discovering...
                  </>
                ) : (
                  'Discover Devices'
                )}
              </button>
              <button
                onClick={handleStartSync}
                disabled={loading || connectionStatus !== 'success'}
                className="flex-1 px-4 py-2 bg-[#fd382f] hover:bg-[#e02f26] text-white rounded-lg transition-colors disabled:opacity-50 font-medium"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin inline mr-2" />
                    Starting...
                  </>
                ) : (
                  'Start Sync'
                )}
              </button>
          </>
        )}

        {step === 'discover' && (
          <>
              <button
                onClick={() => setStep('config')}
                className="px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-100 transition-colors"
              >
                Back
              </button>
                <button
                  onClick={() => {
                    if (onSync) onSync(discoveredDevices);
                    if (onSyncComplete) onSyncComplete();
                    onClose();
                  }}
                className="flex-1 px-4 py-2 bg-[#fd382f] hover:bg-[#e02f26] text-white rounded-lg transition-colors font-medium"
                >
                  Import Devices
                </button>
          </>
        )}

        {step === 'syncing' && (
              <button
                onClick={onClose}
              className="w-full px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-100 transition-colors"
              >
                Close
              </button>
          )}
            </div>
      </div>
    </div>
  );
}
