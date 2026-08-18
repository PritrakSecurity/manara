import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import React from 'react'
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
import CloudSaaS from './pages/CloudSaaS'

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
  { path: '/coverage/network-email', title: 'Network & Email Gateways' },
  { path: '/coverage/identity-sync', title: 'Identity (IAM/IdP) Sync' },
  { path: '/coverage/siem-soar-exports', title: 'SIEM, SOAR & Ticketing Exports' },
  // Administration
  { path: '/administration/notifications', title: 'Notifications & Escalations' },
  { path: '/administration/api-keys', title: 'API Keys & Automation' },
  { path: '/administration/audit-log', title: 'Platform Audit Log' },
]

const layout = (node: React.ReactNode) => (
  <ProtectedRoute>
    <TierProtectedRoute>
      <MainLayout>{node}</MainLayout>
    </TierProtectedRoute>
  </ProtectedRoute>
)

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

              {/* Command Center */}
              <Route path="/command-center/dashboard" element={layout(<DashboardPage />)} />
              <Route path="/command-center/executive-overview" element={layout(<ExecutiveOverview />)} />
              <Route path="/command-center/posture-risk-scorecard" element={layout(<PostureRiskScorecard />)} />
              <Route path="/command-center/threat-incident-pulse" element={layout(<ThreatIncidentPulse />)} />
              <Route path="/command-center/compliance-snapshot" element={layout(<ComplianceSnapshot />)} />

              {/* Data Posture (DSPM) */}
              <Route path="/data-posture/inventory-asset-map" element={layout(<InventoryAssetMap />)} />
              <Route path="/data-posture/files-classification" element={layout(<FilesClassificationPage />)} />

              {/* Detection & Investigation */}
              <Route path="/detection/event-explorer" element={layout(<EventLogs />)} />
              <Route path="/detection/incident-queue-triage" element={layout(<IncidentQueueTriage />)} />
              <Route path="/detection/incidents-enhanced" element={layout(<EnhancedIncidentsPage />)} />
              <Route path="/detection/approvals" element={layout(<ApprovalsPage />)} />
              <Route path="/detection/threat-detection" element={layout(<ThreatDetection />)} />

              {/* Policy Studio */}
              <Route path="/policy-studio/policy-builder" element={layout(<EnhancedPoliciesPage />)} />
              <Route path="/policy-studio/classifiers-rules" element={layout(<ClassificationRules />)} />
              <Route path="/policy-studio/dictionaries-edm" element={layout(<KeywordsPage />)} />

              {/* Compliance & Audit */}
              <Route path="/compliance/framework-mapping" element={layout(<FrameworkMapping />)} />
              <Route path="/compliance/reports" element={layout(<ReportsPage />)} />

              {/* Coverage & Integrations */}
              <Route path="/coverage/endpoints" element={layout(<EndpointsPage />)} />
              <Route path="/coverage/sensor-health" element={layout(<SensorHealth />)} />
              <Route path="/coverage/cloud-saas" element={layout(<CloudSaaS />)} />

              {/* Administration */}
              <Route path="/administration/users-rbac" element={layout(<UsersRoles />)} />
              <Route path="/administration/workspace" element={layout(<EnhancedSettingsPage />)} />
              <Route path="/administration/license-usage" element={layout(<LicenseUsage />)} />

              {/* New enterprise navigation placeholder routes */}
              {comingSoonRoutes.map((route) => (
                <Route
                  key={route.path}
                  path={route.path}
                  element={layout(<ComingSoonPage title={route.title} />)}
                />
              ))}

              <Route path="/" element={<Navigate to="/command-center/executive-overview" replace />} />
              <Route path="*" element={<Navigate to="/command-center/executive-overview" replace />} />
            </Routes>
          </BrowserRouter>
        </ThemeProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  )
}

export default App
