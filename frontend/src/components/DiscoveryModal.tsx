import { useState, useEffect } from 'react';
import { Search, CheckCircle } from 'lucide-react';
import { apiClient } from '../api/client';
import Modal from './common/Modal';

interface DiscoveredDevice {
  id: string;
  hostname: string;
  ipAddress: string;
  os: string;
  osVersion: string;
  macAddress: string;
  domain: string;
  username: string;
  status: 'eligible' | 'ineligible';
}

interface DiscoveryModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDiscoveryComplete: (devices: DiscoveredDevice[]) => void;
}

export default function DiscoveryModal({
  isOpen,
  onClose,
  onDiscoveryComplete
}: DiscoveryModalProps) {
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [message, setMessage] = useState('Initializing network discovery');
  const [errorMsg, setErrorMsg] = useState('');
  const [foundDevices, setFoundDevices] = useState<DiscoveredDevice[]>([]);
  const [totalScanned, setTotalScanned] = useState(0);
  const [totalEligible, setTotalEligible] = useState(0);
  const [scanDuration, setScanDuration] = useState(0);
  const [pollInterval, setPollInterval] = useState<ReturnType<typeof setInterval> | null>(null);

  const startDiscovery = async () => {
    console.log('Starting network discovery...');
    setIsScanning(true);
    setProgress(0);
    setFoundDevices([]);
    setTotalScanned(0);
    setTotalEligible(0);
    setMessage('Initializing network discovery');
    setErrorMsg('');

    // helper to start polling discovery progress
    const startPolling = () => {
      let pollAttempts = 0;
      const maxPollAttempts = 300; // 5 minutes max

      const interval = setInterval(async () => {
        pollAttempts++;

        if (pollAttempts > maxPollAttempts) {
          console.error('Discovery timeout after 5 minutes');
          clearInterval(interval);
          setIsScanning(false);
          setPollInterval(null);
          setMessage('Discovery timeout - took too long. Please try again.');
          return;
        }

        try {
          const response = await apiClient.get('/api/devices/discover/progress');

          const data = response.data.data || response.data;
          console.log('Progress update:', data);

          setProgress(data.progress || 0);
          setMessage(data.message || 'Scanning network...');
          
          // Update live device list (only show responding devices)
          const liveDevices = (data.foundDevices || []).filter((d: any) => 
            d.isOnline !== false && d.status !== 'scanning'
          );
          setFoundDevices(liveDevices);
          setTotalScanned(data.totalScanned || 0);
          setTotalEligible(data.totalEligible || 0);
          setScanDuration(data.scanDuration || 0);

          if (data.status === 'completed' || data.status === 'failed') {
            clearInterval(interval);
            setIsScanning(false);
            setPollInterval(null);

            if (data.status === 'completed') {
              console.log('Discovery complete:', liveDevices.length, 'devices found');
              // Only show eligible devices
              const eligibleDevices = liveDevices.filter((d: any) => d.status === 'eligible');
              setTimeout(() => {
                onDiscoveryComplete(eligibleDevices);
                onClose();
              }, 1500);
            } else if (data.status === 'failed') {
              console.error('Discovery failed:', data.message);
              setMessage(data.message || 'Discovery failed. Check backend logs for details.');
            }
          }
        } catch (err: any) {
          console.error('Progress polling error:', err);
          // Don't stop on polling errors, just log them
          if (err.code === 'ECONNABORTED' || err.message?.includes('timeout')) {
            console.warn('Polling timeout, will retry...');
          }
        }
      }, 1000);

      setPollInterval(interval);
    };

    try {
      await apiClient.post('/api/devices/discover', {});
      startPolling();
    } catch (error: any) {
      console.error('Discovery start error:', error);

      // If scan already in progress (409), start polling progress instead of failing
      if (error.response?.status === 409) {
        console.warn('Discovery already in progress on server; switching to progress polling');
        setIsScanning(true);
        setMessage('Resuming discovery progress...');
        startPolling();
        return;
      }

      let errorMessage = 'Failed to start discovery';
      if (error.response?.status === 500) {
        errorMessage = `Server error: ${error.response?.data?.error || error.response?.data?.message || 'Internal server error'}`;
      } else if (error.response?.status === 400) {
        errorMessage = `Invalid request: ${error.response?.data?.error || error.response?.data?.message || 'Bad request'}`;
      } else if (error.message) {
        errorMessage = error.message;
      }

      setIsScanning(false);
      setMessage(errorMessage);
      setErrorMsg(errorMessage);
    }
  };

  const stopDiscovery = async () => {
    if (pollInterval) {
      clearInterval(pollInterval);
      setPollInterval(null);
    }

    try {
      await apiClient.post('/api/devices/discover/stop');
    } catch (error) {
      console.error('Stop discovery error:', error);
    }

    setIsScanning(false);
  };

  useEffect(() => {
    return () => {
      if (pollInterval) {
        clearInterval(pollInterval);
      }
    };
  }, [pollInterval]);

  useEffect(() => {
    if (!isOpen) {
      // Reset state when modal closes
      setIsScanning(false);
      setProgress(0);
      setFoundDevices([]);
      setTotalScanned(0);
      setTotalEligible(0);
      setScanDuration(0);
      if (pollInterval) {
        clearInterval(pollInterval);
        setPollInterval(null);
      }
    }
  }, [isOpen, pollInterval]);

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Network Device Discovery" size="lg">
      <div className="space-y-6">

        {!isScanning && foundDevices.length === 0 ? (
          <div className="py-12 text-center">
            <Search className="w-16 h-16 text-[#fd382f] mx-auto mb-4" />
            <p className="text-[#7f8c8d] mb-6">
              Click below to scan your network for eligible Windows devices
            </p>
            <button
              onClick={startDiscovery}
              disabled={isScanning}
              className="px-6 py-3 bg-[#fd382f] text-white font-semibold rounded-lg hover:bg-[#e02f26] disabled:opacity-50 transition"
            >
              Start Discovery Scan
            </button>
          </div>
        ) : (
          <>
            <div>
              <div className="flex items-center justify-between mb-3">
                <p className="text-[#2c3e50] font-medium">Searching eligible devices</p>
                <span className="text-[#fd382f] font-bold">{progress}%</span>
              </div>
              <div className="w-full h-3 bg-[#f1f3f5] rounded-full overflow-hidden">
                <div
                  className="h-full bg-[#fd382f] transition-all duration-300 rounded-full"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <p className="text-[#7f8c8d] text-sm mt-2">{message}</p>
              {errorMsg && (
                <p className="text-[#dc3545] text-sm mt-2 bg-[#fee] p-2 rounded border border-[#fcc]">{errorMsg}</p>
              )}
            </div>

            <div className="grid grid-cols-3 gap-4">
              <div className="bg-[#f8f9fa] border border-[#e1e4e8] rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-[#fd382f]">{totalScanned}</div>
                <div className="text-xs text-[#7f8c8d] mt-1">Hosts Scanned</div>
              </div>
              <div className="bg-[#f8f9fa] border border-[#e1e4e8] rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-[#28a745]">{totalEligible}</div>
                <div className="text-xs text-[#7f8c8d] mt-1">Eligible Found</div>
              </div>
              <div className="bg-[#f8f9fa] border border-[#e1e4e8] rounded-lg p-4 text-center">
                <div className="text-2xl font-bold text-[#17a2b8]">{scanDuration}s</div>
                <div className="text-xs text-[#7f8c8d] mt-1">Scan Duration</div>
              </div>
            </div>

            {/* LIVE RESULTS - Show devices as they're found */}
            {foundDevices.length > 0 && (
              <div className="bg-[#f8f9fa] border-2 border-[#e1e4e8] rounded-lg p-4">
                <h3 className="text-[#2c3e50] font-semibold mb-3 flex items-center gap-2">
                  <Search className="w-5 h-5 text-[#fd382f]" />
                  Devices Found: {foundDevices.length}
                </h3>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {foundDevices.map((device, idx) => (
                    <div key={device.id || idx} className="bg-white border border-[#e1e4e8] rounded-lg p-3 flex items-center gap-3 animate-in">
                      <div className="w-10 h-10 bg-[#e0f2fe] rounded-lg flex items-center justify-center">
                        <Search className="w-5 h-5 text-[#0284c7]" />
                      </div>
                      <div className="flex-1">
                        <div className="font-semibold text-[#1e293b]">{device.hostname || 'Unknown'}</div>
                        <div className="text-sm text-[#64748b] font-mono">{device.ipAddress}</div>
                      </div>
                      <div className="flex items-center gap-2 text-sm text-[#16a34a]">
                        <CheckCircle className="w-4 h-4" />
                        <span>{device.status === 'eligible' ? 'Eligible' : 'Online'}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {foundDevices.length === 0 && isScanning && totalScanned > 10 && (
              <div className="text-center py-8 text-[#64748b]">
                <p>Scanning... no devices found yet</p>
                <p className="text-xs mt-2 italic">This is normal if devices are offline or blocking ICMP</p>
              </div>
            )}

            <div className="flex gap-3 pt-6 border-t border-[#e1e4e8]">
              <button
                onClick={isScanning ? stopDiscovery : onClose}
                className="flex-1 px-4 py-2 bg-[#f8f9fa] text-[#2c3e50] border border-[#e1e4e8] rounded-lg hover:bg-[#f0f0f0] transition font-medium"
              >
                {isScanning ? 'Stop Scan' : 'Close'}
              </button>
              {foundDevices.length > 0 && !isScanning && (
                <button
                  onClick={() => {
                    onDiscoveryComplete(foundDevices);
                    onClose();
                  }}
                  className="flex-1 px-4 py-2 bg-[#fd382f] text-white rounded-lg hover:bg-[#e02f26] transition font-medium"
                >
                  Import {totalEligible} Device{totalEligible !== 1 ? 's' : ''}
                </button>
              )}
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
