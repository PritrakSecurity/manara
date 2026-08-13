import { create } from 'zustand';
import { apiClient } from '../api/client';

export interface DashboardStats {
  endpoints: {
    total: number;
    online: number;
    offline: number;
  };
  policies: {
    active: number;
    total: number;
  };
  incidents: {
    today: number;
    critical: number;
    trend: number;
  };
  files_classified: number;
  open_incidents: number;
  pending_approvals: number;
}

export interface TrendData {
  date: string;
  total: number;
  blocked: number;
  allowed: number;
}

export interface Violator {
  username: string;
  violations: number;
  critical_count: number;
}

export interface DestinationData {
  destination: string;
  count: number;
}

export interface ClassificationData {
  classification: string;
  count: number;
}

export interface ActivityItem {
  incident_id: string;
  timestamp: string;
  severity: string;
  username: string;
  hostname?: string;
  file_name?: string;
  action?: string;
  decision?: string;
  block_reason?: string;
}

interface DashboardState {
  stats: DashboardStats | null;
  incidentsTrend: TrendData[];
  topViolators: Violator[];
  topDestinations: DestinationData[];
  classificationDistribution: ClassificationData[];
  recentActivity: ActivityItem[];
  loading: boolean;
  error: string | null;

  // Actions
  fetchStats: () => Promise<void>;
  fetchIncidentsTrend: (days?: number) => Promise<void>;
  fetchTopViolators: (limit?: number) => Promise<void>;
  fetchTopDestinations: (limit?: number) => Promise<void>;
  fetchClassificationDistribution: () => Promise<void>;
  fetchRecentActivity: (limit?: number) => Promise<void>;
  fetchAll: () => Promise<void>;
}

export const useDashboardStore = create<DashboardState>((set) => ({
  stats: null,
  incidentsTrend: [],
  topViolators: [],
  topDestinations: [],
  classificationDistribution: [],
  recentActivity: [],
  loading: false,
  error: null,

  fetchStats: async () => {
    try {
      const response = await apiClient.get('/api/dashboard/stats');
      set({ stats: response.data });
    } catch (error) {
      console.error('Failed to fetch dashboard stats:', error);
    }
  },

  fetchIncidentsTrend: async (days = 7) => {
    try {
      const response = await apiClient.get('/api/dashboard/incidents-trend', { params: { days } });
      const data = response.data;
      set({ incidentsTrend: data.trend || [] });
    } catch (error) {
      console.error('Failed to fetch incidents trend:', error);
    }
  },

  fetchTopViolators: async (limit = 10) => {
    try {
      const response = await apiClient.get('/api/dashboard/top-violators', { params: { limit } });
      const data = response.data;
      set({ topViolators: data.violators || [] });
    } catch (error) {
      console.error('Failed to fetch top violators:', error);
    }
  },

  fetchTopDestinations: async (limit = 10) => {
    try {
      const response = await apiClient.get('/api/dashboard/top-destinations', { params: { limit } });
      const data = response.data;
      set({ topDestinations: data.destinations || [] });
    } catch (error) {
      console.error('Failed to fetch top destinations:', error);
    }
  },

  fetchClassificationDistribution: async () => {
    try {
      const response = await apiClient.get('/api/dashboard/classification-distribution');
      const data = response.data;
      set({ classificationDistribution: data.distribution || [] });
    } catch (error) {
      console.error('Failed to fetch classification distribution:', error);
    }
  },

  fetchRecentActivity: async (limit = 20) => {
    try {
      const response = await apiClient.get('/api/dashboard/recent-activity', { params: { limit } });
      const data = response.data;
      set({ recentActivity: data.activities || [] });
    } catch (error) {
      console.error('Failed to fetch recent activity:', error);
    }
  },

  fetchAll: async () => {
    set({ loading: true, error: null });
    try {
      await Promise.all([
        useDashboardStore.getState().fetchStats(),
        useDashboardStore.getState().fetchIncidentsTrend(),
        useDashboardStore.getState().fetchTopViolators(),
        useDashboardStore.getState().fetchTopDestinations(),
        useDashboardStore.getState().fetchClassificationDistribution(),
        useDashboardStore.getState().fetchRecentActivity(),
      ]);
      set({ loading: false });
    } catch (error) {
      set({ error: (error as Error).message, loading: false });
    }
  },
}));
