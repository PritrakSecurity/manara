// Centralized mock/simulation data.
//
// All mock data is gated behind the VITE_USE_MOCKS environment variable so it
// can never execute in a production build. When the flag is not set, mock
// sources resolve to empty/default values and pages rely on real APIs.

export const USE_MOCKS: boolean = import.meta.env.VITE_USE_MOCKS === 'true';

export const mockRiskiestAssets: string[] = USE_MOCKS
  ? [
      'C:\\finance\\salary-master.xlsx',
      'C:\\hr\\employee-ssn.csv',
      'C:\\legal\\nda-drafts.pdf',
      'C:\\executive\\board-minutes.docx',
      'C:\\db\\production-credentials.sql',
    ]
  : [];
