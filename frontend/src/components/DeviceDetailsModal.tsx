import { useState, useEffect } from 'react';
import { Download, Activity, AlertCircle, CheckCircle, Clock } from 'lucide-react';
import { apiClient } from '../api/client';
import Modal from './common/Modal';

interface DeviceDetailsModalProps {
  deviceId: string | null;
  isOpen: boolean;
  onClose: () => void;
}

interface DeviceDetails {
  id: string;
  hostname: string;
  ipAddress: string;
  osVersion: string;
  agentVersion: string;
  status: string;
  lastSeen: string;
  registeredAt: string;
  cpuUsage?: number;
  memoryUsage?: number;
  diskUsage?: number;
  registrationMethod: string;
  logs?: DeviceLog[];
  recentEvents: number;
  totalLogs: number;
  uptimePercent: number;
}

interface DeviceLog {
  id: number;
  device_id: string;
  log_level: string;
  category: string;
  message: string;
  details?: string;
  timestamp: string;
}

export function DeviceDetailsModal({ deviceId, isOpen, onClose }: DeviceDetailsModalProps) {
  const [device, setDevice] = useState<DeviceDetails | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen || !deviceId) {
      setDevice(null);
      setError(null);
      return;
    }

    fetchDeviceDetails();
  }, [isOpen, deviceId]);

  const fetchDeviceDetails = async () => {
    if (!deviceId) return;

    setLoading(true);
    setError(null);

    try {
      // apiClient injects the JWT automatically.
      const response = await apiClient.get(`/api/devices/${deviceId}`);
      setDevice(response.data);
    } catch (err) {
      console.error('Error fetching device details:', err);
      setError(err instanceof Error ? err.message : 'Failed to load device details');
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadLogs = async () => {
    if (!deviceId) return;

    try {
      // apiClient injects the JWT; response comes back as a blob.
      const response = await apiClient.get(`/api/devices/${deviceId}/logs`, { responseType: 'blob' });
      const url = URL.createObjectURL(response.data as Blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `device-logs-${deviceId}.txt`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Error downloading logs:', err);
    }
  };

  if (!isOpen) return null;

  return (
    <Modal isOpen={isOpen} onClose={onClose} title={device?.hostname || 'Device Details'} size="lg">
          {loading && (
            <div className="modal-loading">
              <Activity className="spinning" size={32} />
              <p>Loading device details...</p>
            </div>
          )}

          {error && (
            <div className="modal-error">
              <AlertCircle size={24} />
              <p>{error}</p>
              <button onClick={fetchDeviceDetails} className="btn-retry">
                Retry
              </button>
            </div>
          )}

          {device && !loading && !error && (
            <>
              {/* Device Information */}
              <section className="detail-section">
                <h3>Device Information</h3>
                <div className="info-grid">
                  <div className="info-item">
                    <label>Hostname</label>
                    <div className="detail-value">{device.hostname}</div>                  </div>
                  <div className="info-item">
                    <label>IP Address</label>
                    <div className="detail-value"><code>{device.ipAddress}</code></div>
                  </div>
                  <div className="info-item">
                    <label>OS Version</label>
                    <div className="detail-value">{device.osVersion}</div>
                  </div>
                  <div className="info-item">
                    <label>Agent Version</label>
                    <div className="detail-value"><span className="version-badge">{device.agentVersion}</span></div>
                  </div>
                  <div className="info-item">
                    <label>Status</label>
                    <div className="detail-value">
                      <span className={`status-badge status-${device.status}`}>
                        {device.status === 'online' && <CheckCircle size={14} />}
                        {device.status === 'offline' && <AlertCircle size={14} />}
                        {device.status === 'warning' && <AlertCircle size={14} />}
                        {device.status}
                      </span>
                    </div>
                  </div>
                  <div className="info-item">
                    <label>Registration Method</label>
                    <div className="detail-value">
                      <span className={`method-badge method-${device.registrationMethod}`}>
                        {device.registrationMethod === 'discovery' && 'Discovery'}
                        {device.registrationMethod === 'manual' && 'Manual'}
                        {device.registrationMethod === 'ad_sync' && 'AD Sync'}
                        {device.registrationMethod === 'heartbeat' && 'Heartbeat'}
                      </span>
                    </div>
                  </div>
                  <div className="info-item">
                    <label>Last Seen</label>
                    <div className="detail-value">
                      <Clock size={14} style={{ display: 'inline', marginRight: '4px' }} />
                      {formatLastSeen(device.lastSeen)}
                    </div>
                  </div>
                  <div className="info-item">
                    <label>Registered At</label>
                    <div className="detail-value">{new Date(device.registeredAt).toLocaleString()}</div>
                  </div>
                </div>
              </section>

              {/* System Health */}
              {(device.cpuUsage !== undefined || device.memoryUsage !== undefined || device.diskUsage !== undefined) && (
                <section className="detail-section">
                  <h3>System Health</h3>
                  <div className="health-grid">
                    {device.cpuUsage !== undefined && (
                      <div className="health-item">
                        <label>CPU Usage</label>
                        <div className="progress-bar">
                          <div 
                            className="progress-fill"
                            style={{ 
                              width: `${device.cpuUsage}%`,
                              background: getHealthColor(device.cpuUsage)
                            }}
                          />
                        </div>
                        <span className="health-value">{device.cpuUsage.toFixed(1)}%</span>
                      </div>
                    )}
                    {device.memoryUsage !== undefined && (
                      <div className="health-item">
                        <label>Memory Usage</label>
                        <div className="progress-bar">
                          <div 
                            className="progress-fill"
                            style={{ 
                              width: `${device.memoryUsage}%`,
                              background: getHealthColor(device.memoryUsage)
                            }}
                          />
                        </div>
                        <span className="health-value">{device.memoryUsage.toFixed(1)}%</span>
                      </div>
                    )}
                    {device.diskUsage !== undefined && (
                      <div className="health-item">
                        <label>Disk Usage</label>
                        <div className="progress-bar">
                          <div 
                            className="progress-fill"
                            style={{ 
                              width: `${device.diskUsage}%`,
                              background: getHealthColor(device.diskUsage)
                            }}
                          />
                        </div>
                        <span className="health-value">{device.diskUsage.toFixed(1)}%</span>
                      </div>
                    )}
                    <div className="health-item">
                      <label>Uptime</label>
                      <div className="progress-bar">
                        <div 
                          className="progress-fill"
                          style={{ 
                            width: `${device.uptimePercent}%`,
                            background: getHealthColor(100 - device.uptimePercent)
                          }}
                        />
                      </div>
                      <span className="health-value">{device.uptimePercent.toFixed(1)}%</span>
                    </div>
                  </div>
                </section>
              )}

              {/* Recent Logs */}
              <section className="detail-section">
                <div className="section-header">
                  <h3>Recent Logs</h3>
                  <div className="section-actions">
                    <span className="log-count">
                      {device.totalLogs} total logs
                    </span>
                    <button onClick={handleDownloadLogs} className="btn-download">
                      <Download size={16} />
                      Download All Logs
                    </button>
                  </div>
                </div>

                {device.logs && device.logs.length > 0 ? (
                  <div className="logs-table-container">
                    <table className="logs-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Level</th>
                          <th>Category</th>
                          <th>Message</th>
                        </tr>
                      </thead>
                      <tbody>
                        {device.logs.map((log) => (
                          <tr key={log.id}>
                            <td className="log-time">
                              {new Date(log.timestamp).toLocaleString()}
                            </td>
                            <td>
                              <span className={`log-level log-level-${log.log_level.toLowerCase()}`}>
                                {log.log_level}
                              </span>
                            </td>
                            <td>
                              <span className="log-category">{log.category}</span>
                            </td>
                            <td className="log-message">{log.message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="logs-empty">
                    <p>No logs available for this device</p>
                  </div>
                )}
              </section>
            </>
          )}

      <div className="mt-6 flex justify-end">
        <button onClick={onClose} className="btn-secondary">
          Close
        </button>
      </div>

        <style>{`
          .modal-backdrop {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            z-index: 999;
            animation: fadeIn 0.2s;
          }

          .modal-container {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            z-index: 1000;
            width: 90%;
            max-width: 900px;
            max-height: 90vh;
            display: flex;
            flex-direction: column;
            animation: slideUp 0.3s;
          }

          .modal-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 24px;
            border-bottom: 1px solid #e2e8f0;
          }

          .modal-title {
            display: flex;
            align-items: center;
            gap: 12px;
          }

          .modal-title h2 {
            margin: 0;
            font-size: 24px;
            font-weight: 700;
            color: var(--text-primary);
          }

          .modal-icon {
            color: var(--color-brand-primary);
          }

          .modal-close-btn {
            padding: 8px;
            border: none;
            background: transparent;
            border-radius: 8px;
            cursor: pointer;
            color: #64748b;
            transition: all 0.2s;
          }

          .modal-close-btn:hover {
            background: #f1f5f9;
            color: #334155;
          }

          .modal-body {
            flex: 1;
            overflow-y: auto;
            padding: 24px;
          }

          .modal-footer {
            padding: 16px 24px;
            border-top: 1px solid #e2e8f0;
            display: flex;
            justify-content: flex-end;
            gap: 12px;
          }

          .modal-loading, .modal-error {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 60px 20px;
            text-align: center;
          }

          .modal-error {
            color: #dc2626;
          }

          .detail-section {
            margin-bottom: 32px;
          }

          .detail-section h3 {
            font-size: 18px;
            font-weight: 600;
            color: var(--text-primary);
            margin: 0 0 16px;
          }

          .section-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
          }

          .section-actions {
            display: flex;
            align-items: center;
            gap: 12px;
          }

          .log-count {
            font-size: 14px;
            color: #64748b;
          }

          .info-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
          }

          .info-item {
            display: flex;
            flex-direction: column;
            gap: 4px;
          }

          .info-item label {
            font-size: 13px;
            color: #64748b;
            font-weight: 500;
          }

          .info-item .detail-value {
            font-size: 15px;
            color: var(--text-primary);
          }

          .health-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 16px;
          }

          .health-item {
            display: flex;
            flex-direction: column;
            gap: 8px;
          }

          .health-item label {
            font-size: 14px;
            color: #64748b;
            font-weight: 500;
          }

          .progress-bar {
            height: 24px;
            background: #e2e8f0;
            border-radius: 12px;
            overflow: hidden;
            position: relative;
          }

          .progress-fill {
            height: 100%;
            transition: width 0.3s;
            border-radius: 12px;
          }

          .health-value {
            font-size: 14px;
            font-weight: 600;
            color: #334155;
            text-align: right;
          }

          .logs-table-container {
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            overflow: hidden;
          }

          .logs-table {
            width: 100%;
            border-collapse: collapse;
          }

          .logs-table thead {
            background: var(--bg-page-surface);
            border-bottom: 2px solid #e2e8f0;
          }

          .logs-table th {
            padding: 12px 16px;
            text-align: left;
            font-size: 13px;
            font-weight: 600;
            color: #475569;
            text-transform: uppercase;
            letter-spacing: 0.5px;
          }

          .logs-table td {
            padding: 12px 16px;
            border-bottom: 1px solid #f1f5f9;
            font-size: 14px;
            color: #334155;
          }

          .logs-table tbody tr:last-child td {
            border-bottom: none;
          }

          .log-time {
            color: #64748b;
            font-size: 13px;
            white-space: nowrap;
          }

          .log-level {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
          }

          .log-level-info {
            background: #dbeafe;
            color: #1e40af;
          }

          .log-level-warning {
            background: #fef3c7;
            color: #ca8a04;
          }

          .log-level-error {
            background: #fee2e2;
            color: #dc2626;
          }

          .log-category {
            display: inline-block;
            padding: 4px 8px;
            background: #f1f5f9;
            border-radius: 4px;
            font-size: 12px;
            color: #475569;
          }

          .log-message {
            max-width: 400px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
          }

          .logs-empty {
            padding: 40px;
            text-align: center;
            color: #64748b;
            background: var(--bg-page-surface);
            border-radius: 8px;
          }

          .btn-download {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            background: var(--color-brand-primary);
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
          }

          .btn-download:hover {
            background: var(--color-brand-hover);
            transform: translateY(-1px);
          }

          .btn-retry {
            margin-top: 16px;
            padding: 10px 20px;
            background: var(--color-brand-primary);
            color: white;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
          }

          .btn-secondary {
            padding: 10px 24px;
            background: white;
            color: #334155;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
          }

          .btn-secondary:hover {
            background: var(--bg-page-surface);
            border-color: #cbd5e1;
          }

          .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: capitalize;
          }

          .status-badge.status-online {
            background: #dcfce7;
            color: #16a34a;
          }

          .status-badge.status-offline {
            background: #fee2e2;
            color: #dc2626;
          }

          .status-badge.status-warning {
            background: #fef3c7;
            color: #ca8a04;
          }

          .version-badge {
            display: inline-block;
            padding: 4px 8px;
            background: #f1f5f9;
            border-radius: 4px;
            font-size: 12px;
            font-family: 'Courier New', monospace;
          }

          .method-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
          }

          .method-badge.method-discovery {
            background: #dbeafe;
            color: #1e40af;
          }

          .method-badge.method-manual {
            background: #e0e7ff;
            color: #4338ca;
          }

          .method-badge.method-ad_sync {
            background: #fce7f3;
            color: #be185d;
          }

          .method-badge.method-heartbeat {
            background: #dcfce7;
            color: #16a34a;
          }

          .spinning {
            animation: spin 1s linear infinite;
          }

          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }

          @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
          }

          @keyframes slideUp {
            from {
              opacity: 0;
              transform: translate(-50%, -45%);
            }
            to {
              opacity: 1;
              transform: translate(-50%, -50%);
            }
          }
        `}</style>
    </Modal>
  );
}

function formatLastSeen(timestamp: string): string {
  const date = new Date(timestamp);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;

  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 7) return `${diffDays}d ago`;

  return date.toLocaleDateString();
}

function getHealthColor(value: number): string {
  if (value < 60) return '#16a34a'; // green
  if (value < 80) return '#ca8a04'; // yellow
  return '#dc2626'; // red
}
