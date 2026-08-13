/**
 * Get the backend URL based on the current window location
 * This ensures the frontend can communicate with backend on any network
 * NOT just localhost
 */
export function getBackendUrl(): string {
  // Get current host/IP
  const host = window.location.hostname;
  // Backend is on port 8080
  const port = '8080';

  // Return full URL
  return `http://${host}:${port}`;
}

export function getBackendUrlWithPath(path: string): string {
  return `${getBackendUrl()}${path}`;
}
