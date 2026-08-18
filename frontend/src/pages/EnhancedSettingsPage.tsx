import { useState, useEffect } from 'react';
import { apiClient } from '../api/client';
import {
  Settings,
  Server,
  Bell,
  Users,
  Shield,
  ScrollText,
  Save,
  RefreshCw,
  Plus,
  Trash2,
  Edit2,
  XCircle,
  AlertTriangle,
  Network,
  Mail,
  Slack,
  Webhook,
  Key,
  Clock,
  Download,
  Upload,
  Eye,
  EyeOff,
} from 'lucide-react';

// Types
interface NotificationChannel {
  id: string;
  type: 'email' | 'slack' | 'webhook' | 'teams';
  name: string;
  config: Record<string, string>;
  enabled: boolean;
  events: string[];
}

interface ADConfig {
  server: string;
  port: number;
  baseDN: string;
  bindUser: string;
  bindPassword: string;
  useTLS: boolean;
  syncInterval: number;
  lastSync: string | null;
  syncStatus: 'success' | 'failed' | 'never';
}

interface UserRole {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  userCount: number;
  isSystem: boolean;
}

interface AuditLogEntry {
  id: string;
  timestamp: string;
  admin: string;
  action: string;
  resourceType: string;
  resourceId: string;
  details: string;
  ipAddress: string;
}

interface AgentConfig {
  version: string;
  updateChannel: 'stable' | 'beta' | 'dev';
  autoUpdate: boolean;
  scanInterval: number;
  maxLogSize: number;
  debugMode: boolean;
  offlineMode: boolean;
  syncOnStartup: boolean;
}

// Mock data
const initialNotificationChannels: NotificationChannel[] = [
  {
    id: '1',
    type: 'email',
    name: 'Security Team Email',
    config: { to: 'security@company.com', from: 'dlp@company.com' },
    enabled: true,
    events: ['critical_incident', 'blocked_transfer'],
  },
  {
    id: '2',
    type: 'slack',
    name: 'SOC Slack Channel',
    config: { webhook: 'https://hooks.slack.com/xxx', channel: '#soc-alerts' },
    enabled: true,
    events: ['critical_incident', 'high_incident'],
  },
  {
    id: '3',
    type: 'webhook',
    name: 'SIEM Integration',
    config: { url: 'https://siem.company.com/api/events', headers: '{"Authorization": "Bearer xxx"}' },
    enabled: false,
    events: ['all'],
  },
];

const initialADConfig: ADConfig = {
  server: 'ldap://dc.company.local',
  port: 389,
  baseDN: 'DC=company,DC=local',
  bindUser: 'CN=DLP Service,OU=Service Accounts,DC=company,DC=local',
  bindPassword: '********',
  useTLS: true,
  syncInterval: 60,
  lastSync: null,
  syncStatus: 'never',
};

const initialRoles: UserRole[] = [
  {
    id: 'role-admin',
    name: 'Administrator',
    description: 'Full system access',
    permissions: ['*'],
    userCount: 2,
    isSystem: true,
  },
  {
    id: 'analyst',
    name: 'Security Analyst',
    description: 'View and investigate incidents',
    permissions: ['incidents:read', 'incidents:update', 'reports:read', 'endpoints:read'],
    userCount: 5,
    isSystem: true,
  },
  {
    id: 'auditor',
    name: 'Auditor',
    description: 'Read-only access for compliance',
    permissions: ['*:read'],
    userCount: 3,
    isSystem: true,
  },
  {
    id: 'policy-manager',
    name: 'Policy Manager',
    description: 'Manage policies and keywords',
    permissions: ['policies:*', 'keywords:*', 'incidents:read'],
    userCount: 2,
    isSystem: false,
  },
];

const initialAuditLogs: AuditLogEntry[] = [];

const initialAgentConfig: AgentConfig = {
  version: '2.1.0',
  updateChannel: 'stable',
  autoUpdate: true,
  scanInterval: 30,
  maxLogSize: 100,
  debugMode: false,
  offlineMode: false,
  syncOnStartup: true,
};

// Tab content components
function GeneralSettingsTab() {
  const [settings, setSettings] = useState({
    systemName: 'PRITRAK DLP',
    timezone: 'America/New_York',
    dateFormat: 'MM/DD/YYYY',
    sessionTimeout: 30,
    maxLoginAttempts: 5,
    passwordPolicy: 'strong',
    mfaRequired: true,
    dataRetentionDays: 90,
  });
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [saveError, setSaveError] = useState('');

  // Load settings from backend
  useEffect(() => {
    let mounted = true
    ;(async () => {
      try {
        const res = await apiClient.get('/api/settings')
        const data = res.data
        if (mounted && data && data.data) {
          const s = data.data
          setSettings((prev) => ({ ...prev, ...s }))
        }
      } catch (e) {
        // ignore
      }
    })()
    return () => {
      mounted = false
    }
  }, [])

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-6">
        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-white">System</h3>

          <div>
            <label className="block text-sm text-gray-400 mb-1">System Name</label>
            <input
              type="text"
              value={settings.systemName}
              onChange={(e) => setSettings({ ...settings, systemName: e.target.value })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Timezone</label>
            <select
              value={settings.timezone}
              onChange={(e) => setSettings({ ...settings, timezone: e.target.value })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            >
              <option value="America/New_York">Eastern Time (ET)</option>
              <option value="America/Chicago">Central Time (CT)</option>
              <option value="America/Denver">Mountain Time (MT)</option>
              <option value="America/Los_Angeles">Pacific Time (PT)</option>
              <option value="UTC">UTC</option>
            </select>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Date Format</label>
            <select
              value={settings.dateFormat}
              onChange={(e) => setSettings({ ...settings, dateFormat: e.target.value })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            >
              <option value="MM/DD/YYYY">MM/DD/YYYY</option>
              <option value="DD/MM/YYYY">DD/MM/YYYY</option>
              <option value="YYYY-MM-DD">YYYY-MM-DD</option>
            </select>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Data Retention (days)</label>
            <input
              type="number"
              value={settings.dataRetentionDays}
              onChange={(e) => setSettings({ ...settings, dataRetentionDays: parseInt(e.target.value) })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-white">Security</h3>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Session Timeout (minutes)</label>
            <input
              type="number"
              value={settings.sessionTimeout}
              onChange={(e) => setSettings({ ...settings, sessionTimeout: parseInt(e.target.value) })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Max Login Attempts</label>
            <input
              type="number"
              value={settings.maxLoginAttempts}
              onChange={(e) => setSettings({ ...settings, maxLoginAttempts: parseInt(e.target.value) })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Password Policy</label>
            <select
              value={settings.passwordPolicy}
              onChange={(e) => setSettings({ ...settings, passwordPolicy: e.target.value })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            >
              <option value="basic">Basic (8+ characters)</option>
              <option value="medium">Medium (8+ chars, mixed case, number)</option>
              <option value="strong">Strong (12+ chars, mixed case, number, symbol)</option>
            </select>
          </div>

          <div className="flex items-center justify-between py-2">
            <span className="text-sm text-gray-300">Require MFA for all admins</span>
            <button
              onClick={() => setSettings({ ...settings, mfaRequired: !settings.mfaRequired })}
              className={`relative w-12 h-6 rounded-full transition-colors ${
                settings.mfaRequired ? 'bg-cyan-600' : 'bg-slate-600'
              }`}
            >
              <div
                className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
                  settings.mfaRequired ? 'left-7' : 'left-1'
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      <div className="flex justify-end pt-4 border-t border-slate-700">
        {saveError && <div className="text-red-400 text-sm mr-4 self-center">{saveError}</div>}
        {saveSuccess && <div className="text-green-400 text-sm mr-4 self-center">Settings saved</div>}
        <button onClick={async () => {
          try {
            await apiClient.put('/api/settings', settings)
            setSaveSuccess(true)
            setSaveError('')
          } catch (e) {
            console.error('Failed to save settings:', e)
            setSaveSuccess(false)
            setSaveError('Failed to save settings')
          }
        }} className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors">
          <Save className="w-4 h-4" />
          Save Changes
        </button>
      </div>
    </div>
  );
}

function ADConfigTab() {
  const [adConfig, setADConfig] = useState(initialADConfig);
  const [showPassword, setShowPassword] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [isSyncing, setIsSyncing] = useState(false);

  const handleTestConnection = async () => {
    setIsTesting(true);
    await new Promise((r) => setTimeout(r, 2000));
    setIsTesting(false);
  };

  const handleSync = async () => {
    setIsSyncing(true);
    await new Promise((r) => setTimeout(r, 3000));
    setADConfig({ ...adConfig, lastSync: new Date().toISOString(), syncStatus: 'success' });
    setIsSyncing(false);
  };

  return (
    <div className="space-y-6">
      {/* Connection Status */}
      <div className="bg-slate-700/50 border border-slate-600 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full ${adConfig.syncStatus === 'success' ? 'bg-green-500' : adConfig.syncStatus === 'failed' ? 'bg-red-500' : 'bg-gray-500'}`} />
            <div>
              <p className="text-white font-medium">
                {adConfig.syncStatus === 'success' ? 'Connected' : adConfig.syncStatus === 'failed' ? 'Connection Failed' : 'Not Configured'}
              </p>
              {adConfig.lastSync && (
                <p className="text-sm text-gray-400">
                  Last sync: {new Date(adConfig.lastSync).toLocaleString()}
                </p>
              )}
            </div>
          </div>
          <button
            onClick={handleSync}
            disabled={isSyncing}
            className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-sm rounded-lg transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${isSyncing ? 'animate-spin' : ''}`} />
            {isSyncing ? 'Syncing...' : 'Sync Now'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-white">Server Configuration</h3>

          <div>
            <label className="block text-sm text-gray-400 mb-1">LDAP Server</label>
            <input
              type="text"
              value={adConfig.server}
              onChange={(e) => setADConfig({ ...adConfig, server: e.target.value })}
              placeholder="ldap://dc.company.local"
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Port</label>
            <input
              type="number"
              value={adConfig.port}
              onChange={(e) => setADConfig({ ...adConfig, port: parseInt(e.target.value) })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Base DN</label>
            <input
              type="text"
              value={adConfig.baseDN}
              onChange={(e) => setADConfig({ ...adConfig, baseDN: e.target.value })}
              placeholder="DC=company,DC=local"
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center justify-between py-2">
            <span className="text-sm text-gray-300">Use TLS/SSL</span>
            <button
              onClick={() => setADConfig({ ...adConfig, useTLS: !adConfig.useTLS })}
              className={`relative w-12 h-6 rounded-full transition-colors ${
                adConfig.useTLS ? 'bg-cyan-600' : 'bg-slate-600'
              }`}
            >
              <div
                className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
                  adConfig.useTLS ? 'left-7' : 'left-1'
                }`}
              />
            </button>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-white">Authentication</h3>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Bind User DN</label>
            <input
              type="text"
              value={adConfig.bindUser}
              onChange={(e) => setADConfig({ ...adConfig, bindUser: e.target.value })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Bind Password</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={adConfig.bindPassword}
                onChange={(e) => setADConfig({ ...adConfig, bindPassword: e.target.value })}
                className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 pr-10 rounded-lg focus:outline-none focus:border-cyan-500"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Sync Interval (minutes)</label>
            <input
              type="number"
              value={adConfig.syncInterval}
              onChange={(e) => setADConfig({ ...adConfig, syncInterval: parseInt(e.target.value) })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>
      </div>

      <div className="flex justify-between pt-4 border-t border-slate-700">
        <button
          onClick={handleTestConnection}
          disabled={isTesting}
          className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 disabled:opacity-50 text-white rounded-lg transition-colors"
        >
          <Network className={`w-4 h-4 ${isTesting ? 'animate-pulse' : ''}`} />
          {isTesting ? 'Testing...' : 'Test Connection'}
        </button>
        <button className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors">
          <Save className="w-4 h-4" />
          Save Configuration
        </button>
      </div>
    </div>
  );
}

function NotificationsTab() {
  const [channels, setChannels] = useState(initialNotificationChannels);
  const [showAddModal, setShowAddModal] = useState(false);

  const toggleChannel = (id: string) => {
    setChannels(channels.map((c) => (c.id === id ? { ...c, enabled: !c.enabled } : c)));
  };

  const getChannelIcon = (type: string) => {
    switch (type) {
      case 'email':
        return <Mail className="w-5 h-5" />;
      case 'slack':
        return <Slack className="w-5 h-5" />;
      case 'webhook':
        return <Webhook className="w-5 h-5" />;
      default:
        return <Bell className="w-5 h-5" />;
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Notification Channels</h3>
        <button
          onClick={() => setShowAddModal(true)}
          className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-sm rounded-lg transition-colors"
        >
          <Plus className="w-4 h-4" />
          Add Channel
        </button>
      </div>

      <div className="space-y-3">
        {channels.map((channel) => (
          <div
            key={channel.id}
            className="bg-slate-700/50 border border-slate-600 rounded-lg p-4"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className={`p-2 rounded-lg ${channel.enabled ? 'bg-cyan-500/20 text-cyan-400' : 'bg-slate-600 text-gray-400'}`}>
                  {getChannelIcon(channel.type)}
                </div>
                <div>
                  <p className="font-medium text-white">{channel.name}</p>
                  <p className="text-sm text-gray-400 capitalize">{channel.type}</p>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <div className="flex gap-1">
                  {channel.events.slice(0, 2).map((e) => (
                    <span key={e} className="text-xs bg-slate-600 text-gray-300 px-2 py-0.5 rounded">
                      {e.replace('_', ' ')}
                    </span>
                  ))}
                  {channel.events.length > 2 && (
                    <span className="text-xs text-gray-500">+{channel.events.length - 2}</span>
                  )}
                </div>

                <button
                  onClick={() => toggleChannel(channel.id)}
                  className={`relative w-12 h-6 rounded-full transition-colors ${
                    channel.enabled ? 'bg-cyan-600' : 'bg-slate-600'
                  }`}
                >
                  <div
                    className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
                      channel.enabled ? 'left-7' : 'left-1'
                    }`}
                  />
                </button>

                <div className="flex gap-1">
                  <button className="p-1.5 text-gray-400 hover:text-white rounded transition-colors">
                    <Edit2 className="w-4 h-4" />
                  </button>
                  <button className="p-1.5 text-gray-400 hover:text-red-400 rounded transition-colors">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Event Types */}
      <div className="pt-4 border-t border-slate-700">
        <h3 className="text-lg font-semibold text-white mb-4">Event Types</h3>
        <div className="grid grid-cols-2 gap-4">
          {[
            { id: 'critical_incident', name: 'Critical Incidents', icon: <AlertTriangle className="w-4 h-4 text-red-400" /> },
            { id: 'high_incident', name: 'High Severity Incidents', icon: <AlertTriangle className="w-4 h-4 text-orange-400" /> },
            { id: 'blocked_transfer', name: 'Blocked Transfers', icon: <XCircle className="w-4 h-4 text-red-400" /> },
            { id: 'approval_pending', name: 'Approval Requests', icon: <Clock className="w-4 h-4 text-yellow-400" /> },
            { id: 'endpoint_offline', name: 'Endpoint Offline', icon: <Server className="w-4 h-4 text-gray-400" /> },
            { id: 'policy_violation', name: 'Policy Violations', icon: <Shield className="w-4 h-4 text-purple-400" /> },
          ].map((event) => (
            <div
              key={event.id}
              className="flex items-center gap-3 p-3 bg-slate-700/30 border border-slate-600 rounded-lg"
            >
              {event.icon}
              <span className="text-sm text-gray-300">{event.name}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Add Channel Modal (simplified) */}
      {showAddModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 w-[500px]">
            <h3 className="text-lg font-semibold text-white mb-4">Add Notification Channel</h3>
            <div className="grid grid-cols-2 gap-3 mb-4">
              {['email', 'slack', 'webhook', 'teams'].map((type) => (
                <button
                  key={type}
                  className="flex items-center gap-3 p-4 bg-slate-700/50 hover:bg-slate-700 border border-slate-600 hover:border-cyan-500 rounded-lg transition-colors"
                >
                  {getChannelIcon(type)}
                  <span className="capitalize text-white">{type}</span>
                </button>
              ))}
            </div>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowAddModal(false)}
                className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function AgentConfigTab() {
  const [config, setConfig] = useState(initialAgentConfig);

  return (
    <div className="space-y-6">
      {/* Current Version */}
      <div className="bg-slate-700/50 border border-slate-600 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-white font-medium">Agent Version</p>
            <p className="text-sm text-gray-400">Current: v{config.version} (Stable)</p>
          </div>
          <div className="flex gap-2">
            <button className="flex items-center gap-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white text-sm rounded-lg transition-colors">
              <Download className="w-4 h-4" />
              Download Agent
            </button>
            <button className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-sm rounded-lg transition-colors">
              <Upload className="w-4 h-4" />
              Push Update
            </button>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-white">Update Settings</h3>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Update Channel</label>
            <select
              value={config.updateChannel}
              onChange={(e) => setConfig({ ...config, updateChannel: e.target.value as AgentConfig['updateChannel'] })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            >
              <option value="stable">Stable (Recommended)</option>
              <option value="beta">Beta</option>
              <option value="dev">Development</option>
            </select>
          </div>

          <div className="flex items-center justify-between py-2">
            <span className="text-sm text-gray-300">Auto-update agents</span>
            <button
              onClick={() => setConfig({ ...config, autoUpdate: !config.autoUpdate })}
              className={`relative w-12 h-6 rounded-full transition-colors ${
                config.autoUpdate ? 'bg-cyan-600' : 'bg-slate-600'
              }`}
            >
              <div
                className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
                  config.autoUpdate ? 'left-7' : 'left-1'
                }`}
              />
            </button>
          </div>

          <div className="flex items-center justify-between py-2">
            <span className="text-sm text-gray-300">Sync on agent startup</span>
            <button
              onClick={() => setConfig({ ...config, syncOnStartup: !config.syncOnStartup })}
              className={`relative w-12 h-6 rounded-full transition-colors ${
                config.syncOnStartup ? 'bg-cyan-600' : 'bg-slate-600'
              }`}
            >
              <div
                className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
                  config.syncOnStartup ? 'left-7' : 'left-1'
                }`}
              />
            </button>
          </div>
        </div>

        <div className="space-y-4">
          <h3 className="text-lg font-semibold text-white">Agent Behavior</h3>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Scan Interval (seconds)</label>
            <input
              type="number"
              value={config.scanInterval}
              onChange={(e) => setConfig({ ...config, scanInterval: parseInt(e.target.value) })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1">Max Log Size (MB)</label>
            <input
              type="number"
              value={config.maxLogSize}
              onChange={(e) => setConfig({ ...config, maxLogSize: parseInt(e.target.value) })}
              className="w-full bg-slate-700 border border-slate-600 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center justify-between py-2">
            <div>
              <span className="text-sm text-gray-300">Debug Mode</span>
              <p className="text-xs text-gray-500">Enables verbose logging</p>
            </div>
            <button
              onClick={() => setConfig({ ...config, debugMode: !config.debugMode })}
              className={`relative w-12 h-6 rounded-full transition-colors ${
                config.debugMode ? 'bg-yellow-600' : 'bg-slate-600'
              }`}
            >
              <div
                className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
                  config.debugMode ? 'left-7' : 'left-1'
                }`}
              />
            </button>
          </div>

          <div className="flex items-center justify-between py-2">
            <div>
              <span className="text-sm text-gray-300">Offline Mode</span>
              <p className="text-xs text-gray-500">Queue events when disconnected</p>
            </div>
            <button
              onClick={() => setConfig({ ...config, offlineMode: !config.offlineMode })}
              className={`relative w-12 h-6 rounded-full transition-colors ${
                config.offlineMode ? 'bg-cyan-600' : 'bg-slate-600'
              }`}
            >
              <div
                className={`absolute top-1 w-4 h-4 bg-white rounded-full transition-transform ${
                  config.offlineMode ? 'left-7' : 'left-1'
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      <div className="flex justify-end pt-4 border-t border-slate-700">
        <button className="flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg transition-colors">
          <Save className="w-4 h-4" />
          Save Configuration
        </button>
      </div>
    </div>
  );
}

function RBACTab() {
  const [roles] = useState(initialRoles);
  const [selectedRole, setSelectedRole] = useState<string | null>(null);

  const allPermissions = [
    { category: 'Policies', perms: ['policies:read', 'policies:create', 'policies:update', 'policies:delete'] },
    { category: 'Keywords', perms: ['keywords:read', 'keywords:create', 'keywords:update', 'keywords:delete'] },
    { category: 'Incidents', perms: ['incidents:read', 'incidents:update', 'incidents:resolve'] },
    { category: 'Endpoints', perms: ['endpoints:read', 'endpoints:manage', 'endpoints:delete'] },
    { category: 'Reports', perms: ['reports:read', 'reports:generate', 'reports:schedule'] },
    { category: 'Settings', perms: ['settings:read', 'settings:update'] },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Roles & Permissions</h3>
        <button className="flex items-center gap-2 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-sm rounded-lg transition-colors">
          <Plus className="w-4 h-4" />
          Create Role
        </button>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Roles List */}
        <div className="col-span-1 space-y-2">
          {roles.map((role) => (
            <button
              key={role.id}
              onClick={() => setSelectedRole(role.id)}
              className={`w-full text-left p-3 rounded-lg border transition-colors ${
                selectedRole === role.id
                  ? 'bg-cyan-500/20 border-cyan-500'
                  : 'bg-slate-700/50 border-slate-600 hover:border-slate-500'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-medium text-white">{role.name}</span>
                {role.isSystem && (
                  <span className="text-xs bg-slate-600 text-gray-300 px-1.5 py-0.5 rounded">System</span>
                )}
              </div>
              <p className="text-xs text-gray-400">{role.description}</p>
              <p className="text-xs text-gray-500 mt-1">{role.userCount} users</p>
            </button>
          ))}
        </div>

        {/* Permissions Editor */}
        <div className="col-span-2 bg-slate-700/50 border border-slate-600 rounded-lg p-4">
          {selectedRole ? (
            <>
              <div className="flex items-center justify-between mb-4">
                <h4 className="font-medium text-white">
                  {roles.find((r) => r.id === selectedRole)?.name} Permissions
                </h4>
                {!roles.find((r) => r.id === selectedRole)?.isSystem && (
                  <button className="text-red-400 hover:text-red-300 text-sm">
                    Delete Role
                  </button>
                )}
              </div>

              <div className="space-y-4">
                {allPermissions.map((category) => (
                  <div key={category.category}>
                    <p className="text-sm font-medium text-gray-300 mb-2">{category.category}</p>
                    <div className="flex flex-wrap gap-2">
                      {category.perms.map((perm) => {
                        const role = roles.find((r) => r.id === selectedRole);
                        const hasPermission = role?.permissions.includes('*') || role?.permissions.includes(perm) || role?.permissions.includes('*:read') && perm.endsWith(':read');
                        return (
                          <button
                            key={perm}
                            className={`px-2 py-1 text-xs rounded border transition-colors ${
                              hasPermission
                                ? 'bg-cyan-500/20 border-cyan-500 text-cyan-400'
                                : 'bg-slate-600/50 border-slate-500 text-gray-400 hover:border-cyan-500'
                            }`}
                          >
                            {perm.split(':')[1]}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-64 text-gray-500">
              Select a role to view permissions
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function AuditLogsTab() {
  const [logs] = useState(initialAuditLogs);
  const [filter, setFilter] = useState('all');

  const getActionColor = (action: string) => {
    if (action.includes('CREATE')) return 'text-green-400';
    if (action.includes('UPDATE')) return 'text-yellow-400';
    if (action.includes('DELETE')) return 'text-red-400';
    return 'text-cyan-400';
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-white">Audit Logs</h3>
        <div className="flex gap-2">
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="bg-slate-700 border border-slate-600 text-white px-3 py-1.5 rounded-lg text-sm focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Actions</option>
            <option value="policy">Policy Changes</option>
            <option value="keyword">Keyword Changes</option>
            <option value="incident">Incident Updates</option>
            <option value="system">System Events</option>
          </select>
          <button className="flex items-center gap-2 px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white text-sm rounded-lg transition-colors">
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </div>

      <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-slate-900/50">
            <tr>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Timestamp</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Admin</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Action</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Resource</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">Details</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase">IP Address</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-700">
            {logs.map((log) => (
              <tr key={log.id} className="hover:bg-slate-700/30">
                <td className="px-4 py-3 text-sm text-gray-300">
                  {new Date(log.timestamp).toLocaleString()}
                </td>
                <td className="px-4 py-3 text-sm text-white">{log.admin}</td>
                <td className="px-4 py-3">
                  <span className={`text-sm font-medium ${getActionColor(log.action)}`}>
                    {log.action}
                  </span>
                </td>
                <td className="px-4 py-3 text-sm text-gray-300">
                  {log.resourceType} ({log.resourceId})
                </td>
                <td className="px-4 py-3 text-sm text-gray-400 max-w-xs truncate">
                  {log.details}
                </td>
                <td className="px-4 py-3 text-sm text-gray-500 font-mono">
                  {log.ipAddress}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-400">Showing 1-{logs.length} of 156 entries</p>
        <div className="flex gap-1">
          <button className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-white text-sm rounded transition-colors">
            Previous
          </button>
          <button className="px-3 py-1 bg-cyan-600 text-white text-sm rounded">1</button>
          <button className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-white text-sm rounded transition-colors">2</button>
          <button className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-white text-sm rounded transition-colors">3</button>
          <button className="px-3 py-1 bg-slate-700 hover:bg-slate-600 text-white text-sm rounded transition-colors">
            Next
          </button>
        </div>
      </div>
    </div>
  );
}

// Main Component
type TabType = 'general' | 'ad' | 'notifications' | 'agent' | 'rbac' | 'audit';

export default function EnhancedSettingsPage() {
  const [activeTab, setActiveTab] = useState<TabType>('general');

  const tabs: { id: TabType; label: string; icon: React.ReactNode }[] = [
    { id: 'general', label: 'General', icon: <Settings className="w-4 h-4" /> },
    { id: 'ad', label: 'Active Directory', icon: <Server className="w-4 h-4" /> },
    { id: 'notifications', label: 'Notifications', icon: <Bell className="w-4 h-4" /> },
    { id: 'agent', label: 'Agent Config', icon: <Key className="w-4 h-4" /> },
    { id: 'rbac', label: 'Roles & Access', icon: <Users className="w-4 h-4" /> },
    { id: 'audit', label: 'Audit Logs', icon: <ScrollText className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen bg-white p-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-900 flex items-center gap-3">
          <Settings className="w-8 h-8 text-brand" />
          Settings
        </h1>
        <p className="text-gray-600 mt-1">Configure system settings and integrations</p>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 mb-6 bg-gray-50 p-1 rounded-lg w-fit border border-gray-200">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-brand text-white'
                : 'text-gray-700 hover:text-gray-900 hover:bg-gray-100'
            }`}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="bg-white border border-gray-200 rounded-lg p-6 shadow-sm">
        {activeTab === 'general' && <GeneralSettingsTab />}
        {activeTab === 'ad' && <ADConfigTab />}
        {activeTab === 'notifications' && <NotificationsTab />}
        {activeTab === 'agent' && <AgentConfigTab />}
        {activeTab === 'rbac' && <RBACTab />}
        {activeTab === 'audit' && <AuditLogsTab />}
      </div>
    </div>
  );
}
