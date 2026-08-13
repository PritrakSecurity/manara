import { create } from 'zustand';
import { apiClient } from '../api/client';

export interface Keyword {
  id: string;
  keyword: string;
  match_type: 'EXACT' | 'PARTIAL' | 'REGEX';
  case_sensitive: boolean;
  classification: 'PUBLIC' | 'PRIVATE' | 'CONFIDENTIAL' | 'RESTRICTED';
  priority: number;
  hard_block: boolean;
  description: string;
  tags: string[];
  group_id?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface KeywordGroup {
  id: string;
  name: string;
  description: string;
  default_classification: string;
  enabled: boolean;
}

export interface KeywordMatch {
  keyword_id: string;
  keyword: string;
  match_type: string;
  classification: string;
  priority: number;
  hard_block: boolean;
  matched_text: string;
  position: number;
}

interface KeywordsState {
  keywords: Keyword[];
  groups: KeywordGroup[];
  total: number;
  loading: boolean;
  error: string | null;

  // Actions
  fetchKeywords: (filters?: KeywordFilters) => Promise<void>;
  fetchGroups: () => Promise<void>;
  createKeyword: (keyword: Partial<Keyword>) => Promise<void>;
  updateKeyword: (id: string, keyword: Partial<Keyword>) => Promise<void>;
  deleteKeyword: (id: string) => Promise<void>;
  testKeywords: (content: string) => Promise<{ matches: KeywordMatch[]; classification: string; has_hard_block: boolean }>;
  validateRegex: (pattern: string) => Promise<{ valid: boolean; error: string }>;
  importCSV: (file: File) => Promise<{ imported: number; skipped: number }>;
  exportCSV: () => Promise<void>;
}

interface KeywordFilters {
  classification?: string;
  match_type?: string;
  hard_block?: boolean;
  enabled?: boolean;
  group_id?: string;
  search?: string;
  limit?: number;
  offset?: number;
}

export const useKeywordsStore = create<KeywordsState>((set, get) => ({
  keywords: [],
  groups: [],
  total: 0,
  loading: false,
  error: null,

  fetchKeywords: async (filters?: KeywordFilters) => {
    set({ loading: true, error: null });
    try {
      const params = new URLSearchParams();
      if (filters) {
        Object.entries(filters).forEach(([key, value]) => {
          if (value !== undefined) {
            params.append(key, String(value));
          }
        });
      }

      const response = await apiClient.get(`/api/keywords?${params}`);
      const data = response.data;
      set({
        keywords: data.keywords || [],
        total: data.total || 0,
        loading: false
      });
    } catch (error) {
      set({ error: (error as Error).message, loading: false });
    }
  },

  fetchGroups: async () => {
    try {
      const response = await apiClient.get('/api/keywords/groups');
      const data = response.data;
      set({ groups: data.groups || [] });
    } catch (error) {
      console.error('Failed to fetch groups:', error);
    }
  },

  createKeyword: async (keyword: Partial<Keyword>) => {
    set({ loading: true, error: null });
    try {
      await apiClient.post('/api/keywords', keyword);
      await get().fetchKeywords();
    } catch (error) {
      set({ error: (error as Error).message, loading: false });
      throw error;
    }
  },

  updateKeyword: async (id: string, keyword: Partial<Keyword>) => {
    set({ loading: true, error: null });
    try {
      await apiClient.put('/api/keywords', { ...keyword, id }, { params: { id } });
      await get().fetchKeywords();
    } catch (error) {
      set({ error: (error as Error).message, loading: false });
      throw error;
    }
  },

  deleteKeyword: async (id: string) => {
    set({ loading: true, error: null });
    try {
      await apiClient.delete('/api/keywords', { params: { id } });
      await get().fetchKeywords();
    } catch (error) {
      set({ error: (error as Error).message, loading: false });
      throw error;
    }
  },

  testKeywords: async (content: string) => {
    const response = await apiClient.post('/api/keywords/test', { content });
    return response.data;
  },

  validateRegex: async (pattern: string) => {
    const response = await apiClient.post('/api/keywords/validate-regex', { pattern });
    return response.data;
  },

  importCSV: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);

    const response = await apiClient.post('/api/keywords/import', formData);
    const result = response.data;
    await get().fetchKeywords();
    return result;
  },

  exportCSV: async () => {
    const response = await apiClient.get('/api/keywords/export', { responseType: 'blob' });

    const blob = response.data as Blob;
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'keywords.csv';
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  },
}));
