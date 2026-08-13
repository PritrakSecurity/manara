import { useState, useEffect } from 'react';
import { apiClient } from '../api/client';

export interface ClassificationType {
  name: string;
  priority: number;
  color: string;
  description: string;
}

export const useClassifications = () => {
  const [classifications, setClassifications] = useState<ClassificationType[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchClassifications = async () => {
      try {
        const response = await apiClient.get('/api/classifications');
        const data = response.data.classifications || response.data;
        if (data && data.length > 0) {
          setClassifications(data);
        } else {
          // Trigger fallback if data is empty
          throw new Error('No classifications returned');
        }
      } catch (err) {
        console.error('Failed to fetch classifications:', err);
        // Fallback to defaults if API fails or returns empty
        setClassifications([
          { name: 'PUBLIC', priority: 0, color: '#28a745', description: 'Publicly accessible' },
          { name: 'PRIVATE', priority: 1, color: '#17a2b8', description: 'Internal use only' },
          { name: 'CONFIDENTIAL', priority: 2, color: '#ffc107', description: 'Sensitive business information' },
          { name: 'RESTRICTED', priority: 3, color: '#dc3545', description: 'Highly sensitive data' },
        ]);
        setError('Using local classification defaults');
      } finally {
        setLoading(false);
      }
    };

    fetchClassifications();
  }, []);

  return { classifications, loading, error };
};