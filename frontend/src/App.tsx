import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from './lib/queryClient'
import { ThemeProvider } from './components/ThemeProvider'
import { ErrorBoundary } from './components/ErrorBoundary'
import { ProtectedRoute } from './components/ProtectedRoute'
import { TierProtectedRoute } from './components/TierProtectedRoute'
import MainLayout from './components/MainLayout'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import { EndpointsPage } from './pages/EndpointsPage'
import { IncidentsPage } from './pages/IncidentsPage'
import KeywordsPage from './pages/KeywordsPage'
import ApprovalsPage from './pages/ApprovalsPage'
import EnhancedIncidentsPage from './pages/EnhancedIncidentsPage'
import FilesClassificationPage from './pages/FilesClassificationPage'
import ClassificationRules from './components/ClassificationRules'
import ReportsPage from './pages/ReportsPage'
import EnhancedSettingsPage from './pages/EnhancedSettingsPage'
import EnhancedPoliciesPage from './pages/EnhancedPoliciesPage'
import ThreatDetection from './pages/ThreatDetection'
import EventLogs from './pages/EventLogsPage'
import UsersRoles from './pages/UsersRolesPage'
import ComingSoonPage from './pages/ComingSoonPage'
import InventoryAssetMap from './pages/InventoryAssetMap'
import ExecutiveOverview from './pages/ExecutiveOverview'
import PostureRiskScorecard from './pages/PostureRiskScorecard'
import ThreatIncidentPulse from './pages/ThreatIncidentPulse'
import ComplianceSnapshot from './pages/ComplianceSnapshot'
import IncidentQueueTriage from './pages/IncidentQueueTriage'
import FrameworkMapping from './pages/FrameworkMapping'
import SensorHealth from './pages/SensorHealth'
import LicenseUsage from './pages/LicenseUsage'

const comingSoonRoutes = [
  // Data Posture (DSPM)
  { path: '/data-posture/classification-labels', title: 'Classification & Sensitivity Labels' },
  { path: '/data-posture/data-flow-lineage', title: 'Data Flow & Lineage' },
  { path: '/data-posture/access-exposure', title: 'Access & Exposure Analysis' },
  { path: '/data-posture/shadow-unmanaged-data', title: 'Shadow & Unmanaged Data' },
  { path: '/data-posture/posture-findings', title: 'Posture Findings & Misconfigurations' },
  // Detection & Investigation
  { path: '/detection/alert-analytics-tuning', title: 'Alert Analytics & Tuning' },
  { path: '/detection/user-entity-risk', title: 'User & Entity Risk (UEBA)' },
  { path: '/detection/case-management', title: 'Case Management' },
  { path: '/detection/response-playbooks', title: 'Response Playbooks & Remediation' },
  // Policy Studio
  { path: '/policy-studio/policy-simulation', title: 'Policy Simulation & Impact Testing' },
  { path: '/policy-studio/exceptions-overrides', title: 'Exceptions & Overrides' },
  { path: '/policy-studio/change-review-versioning', title: 'Change Review & Versioning' },
  // Compliance & Audit
  { path: '/compliance/audit-reports', title: 'Audit Evidence & Reports' },
  { path: '/compliance/dsar', title: 'Data Subject Requests (DSAR)' },
  { path: '/compliance/retention-residency', title: 'Retention & Residency Controls' },
  { path: '/compliance/attestation-signoff', title: 'Attestation & Sign-off' },
  // Coverage & Integrations
  { path: '/coverage/cloud-saas', title: 'Cloud & SaaS Connectors' },
  { path: '/coverage/network-email', title: 'Network & Email Gateways' },
  { path: '/coverage/identity-sync', title: 'Identity (IAM/IdP) Sync' },
  { path: '/coverage/siem-soar-exports', title: 'SIEM, SOAR & Ticketing Exports' },
  // Administration
  { path: '/administration/notifications', title: 'Notifications & Escalations' },
  { path: '/administration/api-keys', title: 'API Keys & Automation' },
  { path: '/administration/audit-log', title: 'Platform Audit Log' },
]

function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <ThemeProvider>
          <BrowserRouter>
          <Routes>
            <Route
              path="/login"
              element={
                <TierProtectedRoute>
                  <LoginPage />
                </TierProtectedRoute>
              }
            />
            <Route
              path="/dashboard"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <DashboardPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/policies"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <EnhancedPoliciesPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/devices"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <EndpointsPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/incidents"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <IncidentsPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/settings"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <EnhancedSettingsPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/keywords"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <KeywordsPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/approvals"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <ApprovalsPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/incidents-enhanced"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <EnhancedIncidentsPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/files"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <FilesClassificationPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/classification-rules"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <ClassificationRules />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/reports"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <ReportsPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/threat-detection"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <ThreatDetection />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/event-logs"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <EventLogs />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/dashboard/users"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <UsersRoles />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />

            {/* Mapped enterprise navigation routes (existing pages) */}
            <Route
              path="/coverage/endpoints"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <EndpointsPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/detection/event-explorer"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <EventLogs />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/detection/incident-queue-triage"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <IncidentQueueTriage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/policy-studio/policy-builder"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <EnhancedPoliciesPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/policy-studio/classifiers-rules"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <ClassificationRules />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/policy-studio/dictionaries-edm"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <KeywordsPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/administration/users-rbac"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <UsersRoles />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/administration/workspace"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <EnhancedSettingsPage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />

            <Route
              path="/data-posture/inventory-asset-map"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <InventoryAssetMap />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />

            {/* Command Center dashboards */}
            <Route
              path="/command-center/executive-overview"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <ExecutiveOverview />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/command-center/posture-risk-scorecard"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <PostureRiskScorecard />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/command-center/threat-incident-pulse"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <ThreatIncidentPulse />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/command-center/compliance-snapshot"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <ComplianceSnapshot />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/compliance/framework-mapping"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <FrameworkMapping />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/coverage/sensor-health"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <SensorHealth />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />
            <Route
              path="/administration/license-usage"
              element={
                <ProtectedRoute>
                  <TierProtectedRoute>
                    <MainLayout>
                      <LicenseUsage />
                    </MainLayout>
                  </TierProtectedRoute>
                </ProtectedRoute>
              }
            />

            {/* New enterprise navigation placeholder routes */}
            {comingSoonRoutes.map((route) => (
              <Route
                key={route.path}
                path={route.path}
                element={
                  <ProtectedRoute>
                    <TierProtectedRoute>
                      <MainLayout>
                        <ComingSoonPage title={route.title} />
                      </MainLayout>
                    </TierProtectedRoute>
                  </ProtectedRoute>
                }
              />
            ))}

            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
    </ErrorBoundary>
  )
}

export default App
