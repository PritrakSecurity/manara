import { useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard, Gauge, ShieldCheck, Activity, ClipboardCheck,
  Database, Map, Tags, Workflow, KeyRound, Ghost, AlertTriangle,
  Search, ListChecks, SlidersHorizontal, FileSearch, UserSearch, Briefcase, PlayCircle,
  BookOpenCheck, Wand2, FingerprintPattern, Library, FlaskConical, Ban, History,
  ScrollText, GanttChartSquare, FileBarChart, MailCheck, Archive, Stamp,
  Radar, MonitorSmartphone, Cloud, Network, UsersRound, Share2, HeartPulse,
  Settings, Shield, Building2, Bell, Key, FileText, Tag, ChevronDown, Lock,
  User as UserIcon
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useAuthStore } from '../../store/authStore';
import { useTier, routeTiers, isRouteLocked } from '../../config/tiers';
import { useUIStore } from '../../store/uiStore';

interface NavItem {
  path: string;
  icon: LucideIcon;
  label: string;
}

interface NavSection {
  id: string;
  label: string;
  icon: LucideIcon;
  items: NavItem[];
}

const navSections: NavSection[] = [
  {
    id: 'command-center',
    label: 'Command Center',
    icon: LayoutDashboard,
    items: [
      { path: '/command-center/executive-overview', icon: Gauge, label: 'Executive Overview' },
      { path: '/command-center/posture-risk-scorecard', icon: ShieldCheck, label: 'Posture & Risk Scorecard' },
      { path: '/command-center/threat-incident-pulse', icon: Activity, label: 'Threat & Incident Pulse' },
      { path: '/command-center/compliance-snapshot', icon: ClipboardCheck, label: 'Compliance Snapshot' },
    ],
  },
  {
    id: 'data-posture',
    label: 'Data Posture (DSPM)',
    icon: Database,
    items: [
      { path: '/data-posture/inventory-asset-map', icon: Map, label: 'Data Inventory & Asset Map' },
      { path: '/data-posture/classification-labels', icon: Tags, label: 'Classification & Sensitivity Labels' },
      { path: '/data-posture/data-flow-lineage', icon: Workflow, label: 'Data Flow & Lineage' },
      { path: '/data-posture/access-exposure', icon: KeyRound, label: 'Access & Exposure Analysis' },
      { path: '/data-posture/shadow-unmanaged-data', icon: Ghost, label: 'Shadow & Unmanaged Data' },
      { path: '/data-posture/posture-findings', icon: AlertTriangle, label: 'Posture Findings & Misconfigurations' },
    ],
  },
  {
    id: 'detection-investigation',
    label: 'Detection & Investigation',
    icon: Search,
    items: [
      { path: '/detection/incident-queue-triage', icon: ListChecks, label: 'Incident Queue & Triage' },
      { path: '/detection/alert-analytics-tuning', icon: SlidersHorizontal, label: 'Alert Analytics & Tuning' },
      { path: '/detection/event-explorer', icon: FileSearch, label: 'Event Explorer (Forensic Search)' },
      { path: '/detection/user-entity-risk', icon: UserSearch, label: 'User & Entity Risk (UEBA)' },
      { path: '/detection/case-management', icon: Briefcase, label: 'Case Management' },
      { path: '/detection/response-playbooks', icon: PlayCircle, label: 'Response Playbooks & Remediation' },
    ],
  },
  {
    id: 'policy-studio',
    label: 'Policy Studio',
    icon: BookOpenCheck,
    items: [
      { path: '/policy-studio/policy-builder', icon: Wand2, label: 'Policy Builder & Lifecycle' },
      { path: '/policy-studio/classifiers-rules', icon: FingerprintPattern, label: 'Classifiers & Detection Rules' },
      { path: '/policy-studio/dictionaries-edm', icon: Library, label: 'Dictionaries, EDM & Fingerprints' },
      { path: '/policy-studio/policy-simulation', icon: FlaskConical, label: 'Policy Simulation & Impact Testing' },
      { path: '/policy-studio/exceptions-overrides', icon: Ban, label: 'Exceptions & Overrides' },
      { path: '/policy-studio/change-review-versioning', icon: History, label: 'Change Review & Versioning' },
    ],
  },
  {
    id: 'compliance-audit',
    label: 'Compliance & Audit',
    icon: ScrollText,
    items: [
      { path: '/compliance/framework-mapping', icon: GanttChartSquare, label: 'Framework Mapping (GDPR, HIPAA, PCI)' },
      { path: '/compliance/audit-reports', icon: FileBarChart, label: 'Audit Evidence & Reports' },
      { path: '/compliance/dsar', icon: MailCheck, label: 'Data Subject Requests (DSAR)' },
      { path: '/compliance/retention-residency', icon: Archive, label: 'Retention & Residency Controls' },
      { path: '/compliance/attestation-signoff', icon: Stamp, label: 'Attestation & Sign-off' },
    ],
  },
  {
    id: 'coverage-integrations',
    label: 'Coverage & Integrations',
    icon: Radar,
    items: [
      { path: '/coverage/endpoints', icon: MonitorSmartphone, label: 'Endpoints & Agents' },
      { path: '/coverage/cloud-saas', icon: Cloud, label: 'Cloud & SaaS Connectors' },
      { path: '/coverage/network-email', icon: Network, label: 'Network & Email Gateways' },
      { path: '/coverage/identity-sync', icon: UsersRound, label: 'Identity (IAM/IdP) Sync' },
      { path: '/coverage/siem-soar-exports', icon: Share2, label: 'SIEM, SOAR & Ticketing Exports' },
      { path: '/coverage/sensor-health', icon: HeartPulse, label: 'Sensor Health & Telemetry' },
    ],
  },
  {
    id: 'administration',
    label: 'Administration',
    icon: Settings,
    items: [
      { path: '/administration/users-rbac', icon: Shield, label: 'Users, Roles & RBAC' },
      { path: '/administration/workspace', icon: Building2, label: 'Tenant & Workspace Settings' },
      { path: '/administration/notifications', icon: Bell, label: 'Notifications & Escalations' },
      { path: '/administration/api-keys', icon: Key, label: 'API Keys & Automation' },
      { path: '/administration/audit-log', icon: FileText, label: 'Platform Audit Log' },
      { path: '/administration/license-usage', icon: Tag, label: 'License & Usage' },
    ],
  },
];

export default function Sidebar({
  mobileOpen = false,
  onClose,
}: {
  mobileOpen?: boolean;
  onClose?: () => void;
}) {
  const { user } = useAuthStore();
  const [openSection, setOpenSection] = useState<string>('command-center');
  const tier = useTier();
  const openUpgradeModal = useUIStore((s) => s.openUpgradeModal);

  const toggleSection = (id: string) => {
    setOpenSection((prev) => (prev === id ? '' : id));
  };

  return (
    <>
      {mobileOpen && (
        <div className="fixed inset-0 z-40 bg-black/50 lg:hidden" onClick={onClose} />
      )}
      <aside
        className={`app-sidebar fixed lg:static top-0 left-0 z-50 h-full transition-transform duration-300 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        } lg:translate-x-0`}
      >
      <nav className="sidebar-nav">
        {navSections.map((section) => {
          const isOpen = openSection === section.id;
          return (
            <div key={section.id} className="sidebar-section">
              <button
                type="button"
                onClick={() => toggleSection(section.id)}
                className={`section-header ${isOpen ? 'open' : ''}`}
              >
                <section.icon size={18} className="section-icon" />
                <span className="section-label">{section.label}</span>
                <ChevronDown size={16} className={`section-chevron ${isOpen ? 'rotated' : ''}`} />
              </button>
              {isOpen && (
                <div className="sub-nav">
                  {section.items.map((item) => {
                    const requiredTier = routeTiers[item.path];
                    const locked = isRouteLocked(item.path, tier);
                    return (
                      <NavLink
                        key={item.path}
                        to={item.path}
                        onClick={(e) => {
                          if (locked) {
                            e.preventDefault();
                            openUpgradeModal(
                              item.label,
                              requiredTier,
                              `${item.label} is a ${requiredTier} feature in the Pritrak DLP platform.`
                            );
                          }
                        }}
                        className={({ isActive }) =>
                          `manara-nav-item nav-item sub-item ${isActive ? 'manara-nav-item-active active' : ''}`
                        }
                      >
                        <item.icon size={16} />
                        <span>{item.label}</span>
                        {locked && <Lock size={14} className="sub-lock" />}
                      </NavLink>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      <div
        className="user-profile"
        title={`${user?.name || user?.email || 'Logged user'}${user?.email ? ' · ' + user.email : ''}${user?.role ? ' · ' + user.role : ''}`}
      >
        <div className="avatar">
          {user?.name?.[0]?.toUpperCase() || user?.email?.[0]?.toUpperCase() || <UserIcon size={16} />}
        </div>
        <div className="user-meta">
          <div className="name" title={user?.name || user?.email || ''}>{user?.name || user?.email || 'Current User'}</div>
          <div className="role">{user?.role ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : 'Member'}</div>
        </div>
      </div>

      <style>{`
        .app-sidebar {
          width: 260px;
          background: #181a1b;
          border-right: 1px solid #262a2c;
          height: 100%;
          overflow: hidden;
          display: flex;
          flex-direction: column;
        }

        .sidebar-nav {
          padding: 12px 0;
          flex: 1;
          overflow-y: auto;
          overflow-x: hidden;
        }

        .nav-item {
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 24px;
          color: #e5e7eb;
          text-decoration: none;
          transition: all 0.2s;
          border-left: 3px solid transparent;
          border-radius: 6px;
          margin: 4px 12px;
        }

        .nav-item:hover {
          background: #202325;
        }

        .nav-item.active {
          background: #262a2c;
          color: #ffffff;
          border-left-color: var(--color-brand-primary);
          font-weight: 600;
          box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.1);
        }

        .sidebar-section {
          margin-bottom: 2px;
        }

        .section-header {
          display: flex;
          align-items: center;
          gap: 12px;
          width: 100%;
          padding: 12px 24px;
          background: transparent;
          border: none;
          color: #e5e7eb;
          cursor: pointer;
          text-align: left;
          font-size: 12px;
          font-weight: 600;
          letter-spacing: 0.4px;
          text-transform: uppercase;
          transition: all 0.2s;
        }

        .section-header:hover {
          background: #202325;
          color: #ffffff;
        }

        .section-header.open {
          color: var(--color-brand-primary);
        }

        .section-icon {
          color: #9ca3af;
          flex-shrink: 0;
        }

        .section-header.open .section-icon {
          color: var(--color-brand-primary);
        }

        .section-label {
          flex: 1;
        }

        .section-chevron {
          transition: transform 0.2s;
          color: #6b7280;
          flex-shrink: 0;
        }

        .section-chevron.rotated {
          transform: rotate(180deg);
        }

        .sub-nav {
          padding: 0 0 6px;
        }

        .nav-item.sub-item {
          padding: 8px 16px 8px 46px;
          margin: 2px 12px;
          font-size: 13px;
          text-transform: none;
          letter-spacing: 0;
          font-weight: 400;
        }

        .nav-item.sub-item svg {
          color: #9ca3af;
        }

        .nav-item.sub-item.active svg {
          color: var(--color-brand-primary);
        }

        .nav-item.sub-item .sub-lock {
          margin-left: auto;
          flex-shrink: 0;
          color: var(--color-brand-primary);
        }

        .user-profile {
          position: sticky;
          bottom: 0;
          left: 0;
          right: 0;
          display: flex;
          align-items: center;
          gap: 12px;
          padding: 12px 16px;
          border-top: 1px solid #262a2c;
          background: #1f2123;
          transition: background 0.2s ease;
          z-index: 1;
        }

        .user-profile:hover {
          background: #202325;
        }

        .avatar {
          width: 36px;
          height: 36px;
          border-radius: 50%;
          display: flex;
          align-items: center;
          justify-content: center;
          background: var(--color-brand-primary);
          color: white;
          font-weight: 700;
          font-size: 14px;
          flex-shrink: 0;
        }

        .user-meta {
          min-width: 0;
        }

        .user-meta .name {
          font-size: 13px;
          font-weight: 600;
          color: #f3f4f6;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }

        .user-meta .role {
          font-size: 12px;
          color: #9ca3af;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }
      `}</style>
      </aside>
    </>
  );
}
