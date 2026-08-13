//  CORRECT CLASSIFICATIONS
export const CLASSIFICATIONS = [
  { id: 'PUBLIC', name: 'Public', icon: '', color: '#10B981', badge: 'bg-green-500/20 text-green-400', description: 'Publicly available information' },
  { id: 'INTERNAL', name: 'Internal', icon: '', color: '#3B82F6', badge: 'bg-blue-500/20 text-blue-400', description: 'Internal use only' },
  { id: 'SENSITIVE', name: 'Sensitive', icon: '', color: '#F59E0B', badge: 'bg-yellow-500/20 text-yellow-400', description: 'Sensitive company data' },
  { id: 'CLASSIFIED', name: 'Classified', icon: '', color: '#EF4444', badge: 'bg-orange-500/20 text-orange-400', description: 'Classified information' }
];

export const DESTINATIONS = [
  { id: 'usb', name: 'USB Storage', icon: '', description: 'USB drives and portable storage' },
  { id: 'removable', name: 'Removable Media', icon: '', description: 'DVD, CD, and external drives' },
  { id: 'cloud', name: 'Cloud Storage', icon: '', description: 'Google Drive, OneDrive, Dropbox' },
  { id: 'web', name: 'Web Upload', icon: '', description: 'Web-based file upload services' },
  { id: 'email', name: 'External Email', icon: '', description: 'Email to external recipients' },
  { id: 'print', name: 'Print', icon: '', description: 'Physical printer output' }
];
