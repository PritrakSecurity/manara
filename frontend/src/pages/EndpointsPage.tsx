import React, { useState, useEffect } from 'react';
import { 
  Monitor, 
  Server, 
  RefreshCw, 
  Plus, 
  Download,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Search,
  Filter,
  Activity
} from 'lucide-react';
import DiscoveryModal from '../components/DiscoveryModal';
import ManualRegisterModal from '../components/ManualRegisterModal';
import ADSyncModal from '../components/ADSyncModal';
import { DeviceDetailsModal } from '../components/DeviceDetailsModal';
import { useAuthStore } from '../store/authStore';
import { apiClient } from '../api/client';

interface Device {
  id: string;
  hostname: string;
  ipAddress: string;
  osVersion: string;
  agentVersion: string;
  status: 'online' | 'offline' | 'warning';
  lastSeen: string;
  cpuUsage?: number;
  memoryUsage?: number;
  diskUsage?: number;
  registrationMethod: 'discovery' | 'manual' | 'ad_sync';
  installedAt: string;
}

export function EndpointsPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // Pagination
  const [pageSize, setPageSize] = useState<number>(20);
  const [currentPage, setCurrentPage] = useState<number>(1);

  const user = useAuthStore((s) => s.user);
  const adImportedDevicesStorageKey = React.useMemo(() => {
    const userKey = user?.email || user?.id || 'anonymous';
    return `ad-imported-devices:${userKey}`;
  }, [user?.email, user?.id]);

  const loadImportedDevicesFromStorage = (): Device[] => {
    try {
      const raw = localStorage.getItem(adImportedDevicesStorageKey);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      if (!Array.isArray(parsed)) return [];
      // Trust only known fields
      return parsed
        .filter((d: any) => d && typeof d.hostname === 'string')
        .map((d: any) => ({
          id: String(d.id || `ad-${d.hostname}`),
          hostname: String(d.hostname),
          ipAddress: String(d.ipAddress || 'Unknown'),
          osVersion: String(d.osVersion || 'Unknown'),
          agentVersion: String(d.agentVersion || 'Not Installed'),
          status: (d.status === 'online' || d.status === 'offline' || d.status === 'warning') ? d.status : 'offline',
          lastSeen: String(d.lastSeen || new Date().toISOString()),
          cpuUsage: typeof d.cpuUsage === 'number' ? d.cpuUsage : 0,
          memoryUsage: typeof d.memoryUsage === 'number' ? d.memoryUsage : 0,
          diskUsage: typeof d.diskUsage === 'number' ? d.diskUsage : 0,
          registrationMethod: 'ad_sync' as const,
          installedAt: String(d.installedAt || new Date().toISOString()),
        } as Device));
    } catch {
      return [];
    }
  };

  const persistImportedDevicesToStorage = (nextDevices: Device[]) => {
    try {
      localStorage.setItem(adImportedDevicesStorageKey, JSON.stringify(nextDevices));
    } catch (e) {
      console.warn('Failed to persist imported AD devices:', e);
    }
  };

  const mergeDevicesByHostname = (a: Device[], b: Device[]): Device[] => {
    const byHostname = new Map<string, Device>();
    const add = (d: Device) => {
      const key = d.hostname.toLowerCase();
      const existing = byHostname.get(key);
      if (!existing) {
        byHostname.set(key, d);
        return;
      }
      // Prefer non-"Unknown" fields and online statuses.
      byHostname.set(key, {
        ...existing,
        ...d,
        ipAddress: (existing.ipAddress && existing.ipAddress !== 'Unknown') ? existing.ipAddress : d.ipAddress,
        osVersion: (existing.osVersion && existing.osVersion !== 'Unknown') ? existing.osVersion : d.osVersion,
        agentVersion: (existing.agentVersion && existing.agentVersion !== 'Not Installed') ? existing.agentVersion : d.agentVersion,
        status: existing.status === 'online' ? existing.status : d.status,
      });
    };
    a.forEach(add);
    b.forEach(add);
    return Array.from(byHostname.values());
  };
  
  // Modals
  const [discoveryModalOpen, setDiscoveryModalOpen] = useState(false);
  const [manualModalOpen, setManualModalOpen] = useState(false);
  const [adSyncModalOpen, setAdSyncModalOpen] = useState(false);
  const [deviceDetailsModalOpen, setDeviceDetailsModalOpen] = useState(false);
  const [selectedDeviceId, setSelectedDeviceId] = useState<string | null>(null);

  // Fetch devices from backend
  const fetchDevices = async () => {
    setLoading(true);
    try {
      // The global apiClient injects the JWT automatically.
      const response = await apiClient.get('/api/devices');
      
      // Backend returns array directly, not wrapped in {devices: [...]}
      const devicesData = Array.isArray(response.data) ? response.data : (response.data.devices || []);
      
      const imported = loadImportedDevicesFromStorage();
      if (devicesData && devicesData.length > 0) {
        const backendDevices: Device[] = devicesData.map((d: any) => ({
          id: d.id || d.hostname,
          hostname: d.hostname,
          ipAddress: d.ipAddress || d.ip_address || '0.0.0.0',
          osVersion: d.osVersion || d.os_version || 'Unknown',
          agentVersion: d.agentVersion || d.agent_version || 'v1.2.5',
          status: (d.status === 'online' || d.status === 'offline' || d.status === 'warning') ? d.status : 'offline',
          lastSeen: d.lastSeen || d.last_seen || new Date().toISOString(),
          cpuUsage: d.cpuUsage || d.cpu_usage || 0,
          memoryUsage: d.memoryUsage || d.memory_usage || 0,
          diskUsage: d.diskUsage || d.disk_usage || 0,
          registrationMethod: d.registrationMethod || d.registration_method || 'manual',
          installedAt: d.installedAt || d.installed_at || d.registeredAt || d.registered_at || new Date().toISOString(),
        }));

        setDevices(mergeDevicesByHostname(backendDevices, imported));
      } else {
        // No backend devices - still show locally imported AD devices
        setDevices(imported);
      }
    } catch (error: any) {
      console.error('Failed to fetch devices:', error);
      // If backend is down/unavailable, keep showing imported AD devices.
      setDevices(loadImportedDevicesFromStorage());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // On first mount, show locally imported AD devices immediately (fast UX)
    setDevices(loadImportedDevicesFromStorage());
    fetchDevices();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchDevices, 30000);
    return () => clearInterval(interval);
  }, []);

  // Filter devices
  const filteredDevices = devices.filter(device => {
    const matchesSearch = 
      device.hostname.toLowerCase().includes(searchQuery.toLowerCase()) ||
      device.ipAddress.includes(searchQuery);
    
    const matchesStatus = 
      statusFilter === 'all' || device.status === statusFilter;
    
    return matchesSearch && matchesStatus;
  });

  // Reset to page 1 when filters/search change
  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery, statusFilter, pageSize]);

  const totalPages = Math.max(1, Math.ceil(filteredDevices.length / pageSize));
  const safeCurrentPage = Math.min(currentPage, totalPages);
  const startIndex = (safeCurrentPage - 1) * pageSize;
  const endIndex = startIndex + pageSize;
  const paginatedDevices = filteredDevices.slice(startIndex, endIndex);

  // Stats
  const stats = {
    total: devices.length,
    online: devices.filter(d => d.status === 'online').length,
    offline: devices.filter(d => d.status === 'offline').length,
    warning: devices.filter(d => d.status === 'warning').length,
  };

  const handleDiscoveryComplete = (_discoveredDevices: any[]) => {
    // Add discovered devices to list
    fetchDevices();
    setDiscoveryModalOpen(false);
  };

  const handleADSync = (syncedDevices: any[]) => {
    // Add discovered devices to the device list (in-memory until database is set up)
    if (syncedDevices && syncedDevices.length > 0) {
      const newDevices: Device[] = syncedDevices.map((device, index) => ({
        id: `ad-${Date.now()}-${index}`,
        hostname: device.hostname || 'Unknown',
        ipAddress: device.ipAddress || 'Unknown',
        osVersion: device.osVersion || 'Unknown',
        status: 'offline' as const, // AD-discovered devices start as offline
        lastSeen: new Date().toISOString(),
        agentVersion: 'Not Installed',
        registrationMethod: 'ad_sync' as const,
        installedAt: new Date().toISOString(),
      }));
      
      // Add to existing devices (avoid duplicates by hostname)
      setDevices((prevDevices) => {
        const existingHostnames = new Set(prevDevices.map(d => d.hostname.toLowerCase()));
        const uniqueNewDevices = newDevices.filter(
          d => !existingHostnames.has(d.hostname.toLowerCase())
        );
        const merged = [...prevDevices, ...uniqueNewDevices];
        // Persist the AD-imported view so it survives reloads and refresh pulls.
        const adOnly = merged.filter(d => d.registrationMethod === 'ad_sync');
        persistImportedDevicesToStorage(adOnly);
        return merged;
      });
      
      console.log(`✅ Imported ${newDevices.length} devices from Active Directory`);
    }
    
    // Also try to refresh from backend (in case database is set up)
    fetchDevices();
    setAdSyncModalOpen(false);
  };

  return (
    <div className="devices-page">
      {/* Header */}
      <div className="page-header">
        <div className="header-left">
          <Monitor className="page-icon" size={32} />
          <div>
            <h1>Device Management</h1>
            <p className="page-subtitle">
              Monitor and manage endpoint agents across your network
            </p>
          </div>
        </div>

        <div className="header-actions">
          <button 
            className="btn-secondary" 
            onClick={fetchDevices}
            disabled={loading}
          >
            <RefreshCw className={loading ? 'spinning' : ''} size={18} />
            Refresh
          </button>
          
          <button 
            className="btn-primary" 
            onClick={() => setDiscoveryModalOpen(true)}
          >
            <Search size={18} />
            Discover Devices
          </button>
          
          <button 
            className="btn-primary" 
            onClick={() => setManualModalOpen(true)}
          >
            <Plus size={18} />
            Manual Install
          </button>

          <button 
            className="btn-primary" 
            onClick={() => setAdSyncModalOpen(true)}
          >
            <Server size={18} />
            AD Sync
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card">
          <div className="stat-icon blue">
            <Monitor size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.total}</div>
            <div className="stat-label">Total Devices</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon green">
            <CheckCircle size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.online}</div>
            <div className="stat-label">Online</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon red">
            <XCircle size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.offline}</div>
            <div className="stat-label">Offline</div>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-icon yellow">
            <AlertTriangle size={24} />
          </div>
          <div className="stat-content">
            <div className="stat-value">{stats.warning}</div>
            <div className="stat-label">Warnings</div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="filters-bar">
        <div className="search-box">
          <Search size={18} />
          <input
            type="text"
            placeholder="Search by hostname or IP address..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="filter-group">
          <Filter size={18} />
          <select 
            value={statusFilter} 
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="all">All Status</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="warning">Warning</option>
          </select>
        </div>
      </div>

      {/* Devices Table */}
      <div className="devices-table-container">
        {loading ? (
          <div className="loading-state">
            <RefreshCw className="spinning" size={32} />
            <p>Loading devices...</p>
          </div>
        ) : filteredDevices.length === 0 ? (
          <div className="empty-state">
            <Monitor size={48} />
            <h3>No Devices Found</h3>
            <p>
              {searchQuery || statusFilter !== 'all'
                ? 'No devices match your filters'
                : 'Start by discovering devices or manually registering agents'}
            </p>
            <button 
              className="btn-primary" 
              onClick={() => setDiscoveryModalOpen(true)}
            >
              <Search size={18} />
              Discover Devices
            </button>
          </div>
        ) : (
          <>
          <div className="devices-pagination-bar">
            <div className="pagination-left">
              <span className="pagination-meta">
                Showing <strong>{filteredDevices.length === 0 ? 0 : startIndex + 1}</strong>-
                <strong>{Math.min(endIndex, filteredDevices.length)}</strong> of <strong>{filteredDevices.length}</strong>
              </span>
            </div>

            <div className="pagination-right">
              <label className="page-size-label">
                Rows per page
                <select
                  value={pageSize}
                  onChange={(e) => setPageSize(parseInt(e.target.value, 10))}
                >
                  <option value={20}>20</option>
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                </select>
              </label>

              <div className="pager">
                <button
                  className="btn-secondary"
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  disabled={safeCurrentPage <= 1}
                >
                  Prev
                </button>

                <div className="page-numbers">
                  {Array.from({ length: totalPages }, (_, i) => i + 1)
                    .slice(
                      Math.max(0, safeCurrentPage - 3),
                      Math.min(totalPages, safeCurrentPage + 2)
                    )
                    .map((page) => (
                      <button
                        key={page}
                        className={`page-number ${page === safeCurrentPage ? 'active' : ''}`}
                        onClick={() => setCurrentPage(page)}
                      >
                        {page}
                      </button>
                    ))}
                </div>

                <button
                  className="btn-secondary"
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  disabled={safeCurrentPage >= totalPages}
                >
                  Next
                </button>
              </div>
            </div>
          </div>

          <table className="devices-table">
            <thead>
              <tr>
                <th>Status</th>
                <th>Hostname</th>
                <th>IP Address</th>
                <th>OS Version</th>
                <th>Agent Version</th>
                <th>Method</th>
                <th>Last Seen</th>
                <th>Health</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {paginatedDevices.map(device => (
                <tr key={device.id}>
                  <td>
                    <span className={`status-badge status-${device.status}`}>
                      {device.status === 'online' && <CheckCircle size={14} />}
                      {device.status === 'offline' && <XCircle size={14} />}
                      {device.status === 'warning' && <AlertTriangle size={14} />}
                      {device.status}
                    </span>
                  </td>
                  <td className="hostname-cell">
                    <Monitor size={16} />
                    <strong>{device.hostname}</strong>
                  </td>
                  <td><code>{device.ipAddress}</code></td>
                  <td>{device.osVersion}</td>
                  <td>
                    <span className="version-badge">{device.agentVersion}</span>
                  </td>
                  <td>
                    <span className={`method-badge method-${device.registrationMethod}`}>
                      {device.registrationMethod === 'discovery' && 'Discovery'}
                      {device.registrationMethod === 'manual' && 'Manual'}
                      {device.registrationMethod === 'ad_sync' && 'AD Sync'}
                    </span>
                  </td>
                  <td>{formatLastSeen(device.lastSeen)}</td>
                  <td>
                    <div className="health-indicators">
                      <HealthIndicator 
                        label="CPU" 
                        value={device.cpuUsage} 
                      />
                      <HealthIndicator 
                        label="MEM" 
                        value={device.memoryUsage} 
                      />
                      <HealthIndicator 
                        label="DISK" 
                        value={device.diskUsage} 
                      />
                    </div>
                  </td>
                  <td>
                    <div className="action-buttons">
                      <button 
                        className="btn-icon" 
                        title="View Details"
                        onClick={() => {
                          setSelectedDeviceId(device.id);
                          setDeviceDetailsModalOpen(true);
                        }}
                      >
                        <Activity size={16} />
                      </button>
                      <button 
                        className="btn-icon" 
                        title="Download Logs"
                        onClick={async () => {
                          try {
                            const resp = await apiClient.get(`/api/devices/${device.id}/logs`, { responseType: 'blob' });
                            const url = URL.createObjectURL(resp.data as Blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = `device-logs-${device.id}.txt`;
                            document.body.appendChild(a);
                            a.click();
                            document.body.removeChild(a);
                            URL.revokeObjectURL(url);
                          } catch (err) {
                            console.error('Error downloading logs:', err);
                          }
                        }}
                      >
                        <Download size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </>
        )}
      </div>

      {/* Modals */}
      <DiscoveryModal
        isOpen={discoveryModalOpen}
        onClose={() => setDiscoveryModalOpen(false)}
        onDiscoveryComplete={handleDiscoveryComplete}
      />

      <ManualRegisterModal
        isOpen={manualModalOpen}
        onClose={() => setManualModalOpen(false)}
      />

      <ADSyncModal
        isOpen={adSyncModalOpen}
        onClose={() => setAdSyncModalOpen(false)}
        onSyncComplete={() => fetchDevices()}
        onSync={handleADSync}
      />

      <DeviceDetailsModal
        deviceId={selectedDeviceId}
        isOpen={deviceDetailsModalOpen}
        onClose={() => {
          setDeviceDetailsModalOpen(false);
          setSelectedDeviceId(null);
        }}
      />

      <style>{`
        .devices-page {
          padding: 24px;
        }

        .page-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-start;
          margin-bottom: 24px;
        }

        .header-left {
          display: flex;
          gap: 16px;
          align-items: flex-start;
        }

        .page-icon {
          color: var(--color-brand-primary);
        }

        .page-header h1 {
          margin: 0;
          font-size: 28px;
          font-weight: 700;
          color: var(--text-primary);
        }

        .page-subtitle {
          margin: 4px 0 0;
          font-size: 14px;
          color: #64748b;
        }

        .header-actions {
          display: flex;
          gap: 12px;
        }

        .stats-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 20px;
          margin-bottom: 24px;
        }

        .stat-card {
          background: white;
          border-radius: 12px;
          padding: 20px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          display: flex;
          gap: 16px;
          align-items: center;
        }

        .stat-icon {
          width: 48px;
          height: 48px;
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .stat-icon.blue { background: #e0f2fe; color: #0284c7; }
        .stat-icon.green { background: #dcfce7; color: #16a34a; }
        .stat-icon.red { background: #fee2e2; color: #dc2626; }
        .stat-icon.yellow { background: #fef3c7; color: #ca8a04; }

        .stat-value {
          font-size: 32px;
          font-weight: 700;
          color: var(--text-primary);
          line-height: 1;
        }

        .stat-label {
          font-size: 14px;
          color: #64748b;
          margin-top: 4px;
        }

        .filters-bar {
          display: flex;
          gap: 16px;
          margin-bottom: 20px;
        }

        .search-box {
          flex: 1;
          display: flex;
          align-items: center;
          gap: 12px;
          background: white;
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          padding: 0 16px;
        }

        .search-box input {
          flex: 1;
          border: none;
          outline: none;
          padding: 12px 0;
          font-size: 14px;
        }

        .filter-group {
          display: flex;
          align-items: center;
          gap: 12px;
          background: white;
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          padding: 0 16px;
        }

        .filter-group select {
          border: none;
          outline: none;
          padding: 12px 0;
          font-size: 14px;
          cursor: pointer;
        }

        .devices-table-container {
          background: white;
          border-radius: 12px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          overflow: hidden;
        }

        .devices-pagination-bar {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 16px;
          padding: 12px 16px;
          border-bottom: 1px solid #e2e8f0;
          background: #ffffff;
          flex-wrap: wrap;
        }

        .pagination-meta {
          font-size: 13px;
          color: #64748b;
        }

        .pagination-right {
          display: flex;
          align-items: center;
          gap: 16px;
          flex-wrap: wrap;
        }

        .page-size-label {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 13px;
          color: #475569;
          white-space: nowrap;
        }

        .page-size-label select {
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          padding: 6px 10px;
          font-size: 13px;
          background: white;
          cursor: pointer;
        }

        .pager {
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .page-numbers {
          display: flex;
          align-items: center;
          gap: 6px;
        }

        .page-number {
          border: 1px solid #e2e8f0;
          background: #fff;
          color: #334155;
          border-radius: 8px;
          padding: 6px 10px;
          font-size: 13px;
          cursor: pointer;
          min-width: 34px;
        }

        .page-number.active {
          border-color: var(--color-brand-primary);
          color: var(--color-brand-primary);
          font-weight: 700;
        }

        .devices-table {
          width: 100%;
          border-collapse: collapse;
        }

        .devices-table thead {
          background: var(--bg-page-surface);
          border-bottom: 2px solid #e2e8f0;
        }

        .devices-table th {
          padding: 16px;
          text-align: left;
          font-size: 13px;
          font-weight: 600;
          color: #475569;
          text-transform: uppercase;
          letter-spacing: 0.5px;
        }

        .devices-table td {
          padding: 16px;
          border-bottom: 1px solid #f1f5f9;
          font-size: 14px;
          color: #334155;
        }

        .devices-table tr:hover {
          background: var(--bg-page-surface);
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

        .hostname-cell {
          display: flex;
          align-items: center;
          gap: 8px;
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

        .health-indicators {
          display: flex;
          gap: 8px;
        }

        .health-indicator {
          display: flex;
          flex-direction: column;
          gap: 2px;
          min-width: 50px;
        }

        .health-bar {
          width: 50px;
          height: 6px;
          background: #e2e8f0;
          border-radius: 3px;
          overflow: hidden;
        }

        .health-fill {
          height: 100%;
          border-radius: 3px;
          transition: width 0.3s;
        }

        .health-label {
          font-size: 10px;
          color: #64748b;
          text-align: center;
        }

        .action-buttons {
          display: flex;
          gap: 8px;
        }

        .btn-icon {
          padding: 6px;
          border: none;
          background: transparent;
          border-radius: 4px;
          cursor: pointer;
          color: #64748b;
          transition: all 0.2s;
        }

        .btn-icon:hover {
          background: #f1f5f9;
          color: #334155;
        }

        .empty-state, .loading-state {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          padding: 80px 20px;
          text-align: center;
        }

        .empty-state h3 {
          margin: 16px 0 8px;
          font-size: 20px;
          color: var(--text-primary);
        }

        .empty-state p {
          margin: 0 0 24px;
          color: #64748b;
          max-width: 400px;
        }

        .spinning {
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        .btn-primary {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 10px 20px;
          background: var(--color-brand-primary);
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
        }

        .btn-primary:hover {
          background: var(--color-brand-hover);
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(253, 56, 47, 0.3);
        }

        .btn-secondary {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 10px 20px;
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

        .btn-secondary:disabled {
          opacity: 0.5;
          cursor: not-allowed;
        }
      `}</style>
    </div>
  );
}

// Helper Components
function HealthIndicator({ label, value }: { label: string; value?: number }) {
  if (value === undefined) return null;
  
  const getColor = (val: number) => {
    if (val < 60) return '#16a34a';
    if (val < 80) return '#ca8a04';
    return '#dc2626';
  };

  return (
    <div className="health-indicator" title={`${label}: ${value}%`}>
      <div className="health-bar">
        <div 
          className="health-fill" 
          style={{ 
            width: `${value}%`, 
            background: getColor(value) 
          }}
        />
      </div>
      <span className="health-label">{label}</span>
    </div>
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
  return `${diffDays}d ago`;
}

// (removed unused getMockDevices helper)
