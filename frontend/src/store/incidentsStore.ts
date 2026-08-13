import { create } from 'zustand';
import { apiClient } from '../api/client';

export interface Incident {
  id: number;
  incident_id: string;
  timestamp: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string;
  device_id: string;
  hostname: string;
  ip_address: string;
  user_sid: string;
  username: string;
  user_email: string;
  user_department: string;
  file_hash: string;
  file_name: string;
  file_path: string;
  file_size: number;
  file_type: string;
  file_classification: string;
  action_attempted: string;
  destination_type: string;
  destination_detail: string;
  decision: 'ALLOW' | 'BLOCK' | 'PENDING_APPROVAL';
  block_reason: string;
  matched_keywords: string[];
  policy_id: string;
  policy_name: string;
  rule_id: string;
  rule_name: string;
  approval_request_id: string;
  status: 'OPEN' | 'INVESTIGATING' | 'ESCALATED' | 'RESOLVED' | 'FALSE_POSITIVE' | 'ACKNOWLEDGED';
  assigned_to: string;
  assigned_at: string;
  escalated_to: string;
  escalated_at: string;
  investigation_notes: string;
  resolution_notes: string;
  resolved_at: string;
  resolved_by: string;
  tags: string[];
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface IncidentNote {
  id: number;
  incident_id: number;
  author_username: string;
  note_type: string;
  content: string;
  previous_status: string;
  new_status: string;
  created_at: string;
}

export interface IncidentStats {
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_decision: Record<string, number>;
  daily_trend: Array<{ date: string; count: number }>;
  open_count: number;
}

interface IncidentFilters {
  severity?: string;
  status?: string;
  decision?: string;
  user_sid?: string;
  device_id?: string;
  policy_id?: string;
  assigned_to?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

interface IncidentsState {
  incidents: Incident[];
  total: number;
  stats: IncidentStats | null;
  loading: boolean;
  error: string | null;
  filters: IncidentFilters;

  // Actions
  fetchIncidents: (filters?: IncidentFilters) => Promise<void>;
  fetchStats: (days?: number) => Promise<void>;
  getIncident: (id: number) => Promise<Incident>;
  updateStatus: (id: number, status: string, username: string) => Promise<void>;
  assignIncident: (id: number, assignTo: string, assignedBy: string) => Promise<void>;
  escalateIncident: (id: number, escalateTo: string, escalatedBy: string) => Promise<void>;
  resolveIncident: (id: number, notes: string, resolvedBy: string) => Promise<void>;
  markFalsePositive: (id: number, notes: string, markedBy: string) => Promise<void>;
  addNote: (id: number, author: string, content: string) => Promise<void>;
  getNotes: (id: number) => Promise<IncidentNote[]>;
  setFilters: (filters: Partial<IncidentFilters>) => void;
}

export const useIncidentsStore = create<IncidentsState>((set, get) => ({
  incidents: [],
  total: 0,
  stats: null,
  loading: false,
  error: null,
  filters: { limit: 50, offset: 0 },

  fetchIncidents: async (filters?: IncidentFilters) => {
    const currentFilters = { ...get().filters, ...filters };
    set({ loading: true, error: null, filters: currentFilters });

    try {
      const params = new URLSearchParams();
      Object.entries(currentFilters).forEach(([key, value]) => {
        if (value !== undefined && value !== '') {
          params.append(key, String(value));
        }
      });

      const response = await apiClient.get(`/api/incidents/enhanced?${params}`);
      const data = response.data;
      set({
        incidents: data.incidents || [],
        total: data.total || 0,
        loading: false
      });
    } catch (error) {
      set({ error: (error as Error).message, loading: false });
    }
  },

  fetchStats: async (days = 7) => {
    try {
      const response = await apiClient.get('/api/incidents/stats', { params: { days } });
      set({ stats: response.data });
    } catch (error) {
      console.error('Failed to fetch incident stats:', error);
    }
  },

  getIncident: async (id: number) => {
    const response = await apiClient.get('/api/incidents/enhanced', { params: { id } });
    return response.data;
  },

  updateStatus: async (id: number, status: string, username: string) => {
    await apiClient.put('/api/incidents/enhanced', { status, username }, { params: { id } });
    await get().fetchIncidents();
  },

  assignIncident: async (id: number, assignTo: string, assignedBy: string) => {
    await apiClient.put(
      '/api/incidents/enhanced',
      { assign_to: assignTo, assigned_by: assignedBy },
      { params: { id } }
    );
    await get().fetchIncidents();
  },

  escalateIncident: async (id: number, escalateTo: string, escalatedBy: string) => {
    await apiClient.put(
      '/api/incidents/enhanced',
      { escalate_to: escalateTo, escalated_by: escalatedBy },
      { params: { id } }
    );
    await get().fetchIncidents();
  },

  resolveIncident: async (id: number, notes: string, resolvedBy: string) => {
    await apiClient.put(
      '/api/incidents/enhanced',
      { resolution_notes: notes, resolved_by: resolvedBy },
      { params: { id } }
    );
    await get().fetchIncidents();
  },

  markFalsePositive: async (id: number, notes: string, markedBy: string) => {
    await apiClient.put(
      '/api/incidents/enhanced',
      { notes, marked_by: markedBy, status: 'FALSE_POSITIVE' },
      { params: { id } }
    );
    await get().fetchIncidents();
  },

  addNote: async (id: number, author: string, content: string) => {
    await apiClient.post(
      '/api/incidents/enhanced',
      { author, content },
      { params: { id } }
    );
  },

  getNotes: async (id: number) => {
    const response = await apiClient.get('/api/incidents/enhanced', { params: { id, notes: true } });
    const data = response.data;
    return data.notes || [];
  },

  setFilters: (filters: Partial<IncidentFilters>) => {
    set(state => ({ filters: { ...state.filters, ...filters } }));
  },
}));
