import React, { useEffect } from 'react';
import { Monitor, FileText, AlertTriangle, Folder } from 'lucide-react';
import { useDashboardStore } from '../store/dashboardStore';
import { StatsCard } from '../components/StatsCard';
import { SeverityBadge } from '../components/SeverityBadge';
import { ClassificationBadge } from '../components/ClassificationBadge';

// Icons
const DeviceIcon = () => <Monitor className="w-6 h-6" />;
const PolicyIcon = () => <FileText className="w-6 h-6" />;
const AlertIcon = () => <AlertTriangle className="w-6 h-6" />;
const FileIcon = () => <Folder className="w-6 h-6" />;

const DashboardPage: React.FC = () => {
  const {
    stats,
    incidentsTrend,
    topViolators,
    topDestinations,
    classificationDistribution,
    recentActivity,
    loading,
    fetchAll,
  } = useDashboardStore();

  useEffect(() => {
    fetchAll();

    // Refresh every 60 seconds
    const interval = setInterval(() => {
      fetchAll();
    }, 60000);

    return () => clearInterval(interval);
  }, []);
  const formatTimestamp = (timestamp: string) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();

    if (diff < 60000) return 'Just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className="p-6 space-y-6 bg-white min-h-screen">
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Dashboard</h1>
          <p className="text-gray-600 text-sm mt-1">
            Enterprise DLP Security Overview
          </p>
        </div>
        <div className="text-gray-600 text-sm">
          Last updated: {new Date().toLocaleTimeString()}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Endpoints"
          value={stats?.endpoints?.total || 0}
          subtitle={`${stats?.endpoints?.online || 0} online, ${stats?.endpoints?.offline || 0} offline`}
          icon={<DeviceIcon />}
          color="blue"
        />
        <StatsCard
          title="Active Policies"
          value={stats?.policies?.active || 0}
          subtitle={`${stats?.policies?.total || 0} total policies`}
          icon={<PolicyIcon />}
          color="green"
        />
        <StatsCard
          title="Today's Incidents"
          value={stats?.incidents?.today || 0}
          subtitle={`${stats?.incidents?.critical || 0} critical`}
          icon={<AlertIcon />}
          color={stats?.incidents?.critical ? 'red' : 'yellow'}
          trend={stats?.incidents?.trend}
          trendLabel="vs yesterday"
        />
        <StatsCard
          title="Files Classified"
          value={stats?.files_classified || 0}
          subtitle="Last 24 hours"
          icon={<FileIcon />}
          color="purple"
        />
      </div>

      {/* Quick Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-white rounded-lg p-4 border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-gray-600">Open Incidents</span>
            <span className="text-2xl font-bold text-gray-900">{stats?.open_incidents || 0}</span>
          </div>
        </div>
        <div className="bg-white rounded-lg p-4 border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-gray-600">Pending Approvals</span>
            <span className="text-2xl font-bold text-brand">{stats?.pending_approvals || 0}</span>
          </div>
        </div>
        <div className="bg-white rounded-lg p-4 border border-gray-200 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-gray-600">Online Endpoints</span>
            <div className="flex items-center gap-2">
              <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-2xl font-bold text-green-600">{stats?.endpoints?.online || 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Incidents Trend */}
        <div className="bg-white rounded-lg p-4 border border-gray-200 shadow-sm">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Incidents Trend (7 Days)</h3>
          <div className="space-y-2">
            <div className="flex justify-between text-sm text-gray-600 mb-2 font-medium">
              <span>Date</span>
              <div className="flex gap-4">
                <span className="text-red-600">Blocked</span>
                <span className="text-green-600">Allowed</span>
                <span className="text-gray-900">Total</span>
              </div>
            </div>
            {incidentsTrend.length > 0 ? incidentsTrend.map((day) => (
              <div key={day.date} className="flex items-center justify-between py-2 border-b border-gray-200">
                <span className="text-gray-700">{day.date}</span>
                <div className="flex gap-4 text-sm">
                  <span className="text-red-600 w-12 text-right font-medium">{day.blocked}</span>
                  <span className="text-green-600 w-12 text-right font-medium">{day.allowed}</span>
                  <span className="text-gray-900 font-semibold w-12 text-right">{day.total}</span>
                </div>
              </div>
            )) : (
              <div className="text-center py-8 text-gray-500">No data available</div>
            )}
          </div>
        </div>

        {/* Real-time Activity Feed */}
        <div className="bg-white rounded-lg p-4 border border-gray-200 shadow-sm">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent Activity</h3>
          <div className="space-y-3 max-h-80 overflow-y-auto">
            {recentActivity.length > 0 ? recentActivity.slice(0, 10).map((activity, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-3 p-2 rounded hover:bg-gray-50 transition-colors"
                >
                  <div className="flex-shrink-0 mt-1">
                    <SeverityBadge severity={activity.severity} size="sm" showIcon={false} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-gray-900 font-medium truncate">{activity.username}</span>
                      <span className={`text-xs font-semibold ${
                        activity.decision === 'BLOCK' ? 'text-red-600' :
                        activity.decision === 'ALLOW' ? 'text-green-600' : 'text-yellow-600'
                      }`}>
                        {activity.decision === 'BLOCK' ? 'BLOCKED' : activity.decision === 'ALLOW' ? 'ALLOWED' : 'PENDING'}
                      </span>
                    </div>
                    <p className="text-gray-600 text-sm truncate">
                      {activity.action} - {activity.file_name || 'Unknown file'}
                    </p>
                    {activity.hostname && (
                      <p className="text-gray-500 text-xs">{activity.hostname}</p>
                    )}
                  </div>
                  <div className="text-gray-500 text-xs flex-shrink-0">
                    {formatTimestamp(activity.timestamp)}
                  </div>
                </div>
              )) : (
                <div className="text-center py-8 text-gray-500">No recent activity</div>
              )}
          </div>
        </div>

        {/* Top Violators */}
        <div className="bg-white rounded-lg p-4 border border-gray-200 shadow-sm">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Violators (7 Days)</h3>
          {topViolators.length > 0 ? topViolators.slice(0, 5).map((violator, idx) => (
                <div key={idx} className="flex items-center justify-between py-2 border-b border-gray-200">
                  <div className="flex items-center gap-3">
                    <span className="text-gray-500 text-sm w-6">#{idx + 1}</span>
                    <span className="text-gray-900 font-medium">{violator.username}</span>
                  </div>
                  <div className="flex items-center gap-4">
                    {violator.critical_count > 0 && (
                      <span className="text-red-600 text-sm font-semibold">
                        {violator.critical_count} critical
                      </span>
                    )}
                    <span className="text-brand font-semibold">
                      {violator.violations} violations
                    </span>
                  </div>
                </div>
              )) : (
                <div className="text-center py-8 text-gray-500">No data available</div>
              )}
        </div>

        {/* Top Blocked Destinations */}
        <div className="bg-white rounded-lg p-4 border border-gray-200 shadow-sm">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Top Blocked Destinations</h3>
          {topDestinations.length > 0 ? topDestinations.slice(0, 5).map((dest, idx) => (
                <div key={idx} className="flex items-center justify-between py-2 border-b border-gray-200">
                  <div className="flex items-center gap-3">
                    <span className="text-gray-500 text-sm w-6">#{idx + 1}</span>
                    <code className="text-gray-900 bg-gray-100 px-2 py-1 rounded text-sm truncate max-w-xs font-mono">
                      {dest.destination}
                    </code>
                  </div>
                  <span className="text-red-600 font-semibold">{dest.count}</span>
                </div>
              )) : (
                <div className="text-center py-8 text-gray-500">No data available</div>
              )}
        </div>

        {/* Classification Distribution */}
        <div className="bg-white rounded-lg p-4 border border-gray-200 shadow-sm lg:col-span-2">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">File Classification Distribution</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {classificationDistribution.length > 0 ? classificationDistribution.map((item) => (
                <div key={item.classification} className="bg-gray-50 rounded-lg p-4 text-center border border-gray-200">
                  <ClassificationBadge classification={item.classification} size="lg" />
                  <p className="text-3xl font-bold text-gray-900 mt-2">{item.count}</p>
                  <p className="text-gray-600 text-sm">files</p>
                </div>
              )) : (
                <div className="col-span-full text-center py-8 text-gray-500">No data available</div>
              )}
          </div>
        </div>
      </div>

      {loading && (
        <div className="fixed bottom-4 right-4 bg-white border border-gray-200 px-4 py-2 rounded-lg text-gray-600 text-sm shadow-lg">
          Refreshing data...
        </div>
      )}
    </div>
  );
};

export default DashboardPage;
