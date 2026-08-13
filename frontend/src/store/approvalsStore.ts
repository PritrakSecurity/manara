import { create } from 'zustand';
import { apiClient } from '../api/client';

export interface ApprovalRequest {
  request_id: string;
  file_hash: string;
  file_name: string;
  file_path: string;
  file_classification: string;
  requester_sid: string;
  requester_username: string;
  requester_email: string;
  requester_device_id: string;
  requester_hostname: string;
  owner_sid: string;
  owner_username: string;
  owner_email: string;
  action_type: string;
  destination_type: string;
  destination_detail: string;
  status: 'PENDING' | 'APPROVED' | 'DENIED' | 'TIMEOUT' | 'CANCELLED';
  decision_comment: string;
  allow_permanent: boolean;
  created_at: string;
  decided_at: string;
  timeout_at: string;
  notified_at: string;
  reminder_sent: boolean;
  policy_id: string;
  rule_id: string;
  seconds_remaining: number;
}

interface ApprovalsState {
  pendingRequests: ApprovalRequest[];
  history: ApprovalRequest[];
  pendingCount: number;
  loading: boolean;
  error: string | null;

  // Actions
  fetchPending: (ownerSID?: string) => Promise<void>;
  fetchHistory: (ownerSID?: string, requesterSID?: string) => Promise<void>;
  fetchPendingCount: (ownerSID?: string) => Promise<number>;
  approveRequest: (requestId: string, comment?: string, permanent?: boolean) => Promise<void>;
  denyRequest: (requestId: string, comment?: string) => Promise<void>;
  cancelRequest: (requestId: string) => Promise<void>;
  createRequest: (request: Partial<ApprovalRequest>) => Promise<ApprovalRequest>;
}

export const useApprovalsStore = create<ApprovalsState>((set, _get) => ({
  pendingRequests: [],
  history: [],
  pendingCount: 0,
  loading: false,
  error: null,

  fetchPending: async (ownerSID?: string) => {
    set({ loading: true, error: null });
    try {
      const response = await apiClient.get('/api/approvals/pending', {
        params: ownerSID ? { owner_sid: ownerSID } : undefined,
      });

      const data = response.data;
      set({
        pendingRequests: data.requests || [],
        pendingCount: data.count || 0,
        loading: false
      });
    } catch (error) {
      set({ error: (error as Error).message, loading: false });
    }
  },

  fetchHistory: async (ownerSID?: string, requesterSID?: string) => {
    set({ loading: true, error: null });
    try {
      const response = await apiClient.get('/api/approvals/history', {
        params: { owner_sid: ownerSID, requester_sid: requesterSID },
      });

      const data = response.data;
      set({ history: data.requests || [], loading: false });
    } catch (error) {
      set({ error: (error as Error).message, loading: false });
    }
  },

  fetchPendingCount: async (ownerSID?: string) => {
    try {
      const response = await apiClient.get('/api/approvals/pending/count', {
        params: ownerSID ? { owner_sid: ownerSID } : undefined,
      });

      const data = response.data;
      const count = data.count || 0;
      set({ pendingCount: count });
      return count;
    } catch (error) {
      console.error('Failed to fetch pending count:', error);
      return 0;
    }
  },

  approveRequest: async (requestId: string, comment = '', permanent = false) => {
    set({ loading: true, error: null });
    try {
      await apiClient.post(
        `/api/approvals/${encodeURIComponent(requestId)}/approve`,
        { comment, permanent },
        { params: { id: requestId } }
      );

      // Update local state
      set(state => ({
        pendingRequests: state.pendingRequests.filter(r => r.request_id !== requestId),
        pendingCount: Math.max(0, state.pendingCount - 1),
        loading: false,
      }));
    } catch (error) {
      set({ error: (error as Error).message, loading: false });
      throw error;
    }
  },

  denyRequest: async (requestId: string, comment = '') => {
    set({ loading: true, error: null });
    try {
      await apiClient.post(
        `/api/approvals/${encodeURIComponent(requestId)}/deny`,
        { comment },
        { params: { id: requestId } }
      );

      set(state => ({
        pendingRequests: state.pendingRequests.filter(r => r.request_id !== requestId),
        pendingCount: Math.max(0, state.pendingCount - 1),
        loading: false,
      }));
    } catch (error) {
      set({ error: (error as Error).message, loading: false });
      throw error;
    }
  },

  cancelRequest: async (requestId: string) => {
    set({ loading: true, error: null });
    try {
      await apiClient.post(
        `/api/approvals/${encodeURIComponent(requestId)}/cancel`,
        null,
        { params: { id: requestId } }
      );

      set(state => ({
        pendingRequests: state.pendingRequests.filter(r => r.request_id !== requestId),
        pendingCount: Math.max(0, state.pendingCount - 1),
        loading: false,
      }));
    } catch (error) {
      set({ error: (error as Error).message, loading: false });
      throw error;
    }
  },

  createRequest: async (request: Partial<ApprovalRequest>) => {
    const response = await apiClient.post('/api/approvals', request);
    return response.data;
  },
}));
