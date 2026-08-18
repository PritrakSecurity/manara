import React, { useState } from 'react';
import Header from './layout/Header';
import Sidebar from './layout/Sidebar';
import UpgradeGateModal from './UpgradeGateModal';

export default function MainLayout({ children }: { children: React.ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <>
      <div className="flex flex-col h-screen bg-white">
        <Header onMenuClick={() => setMobileOpen(true)} />
        <div className="flex flex-1 overflow-hidden">
          <Sidebar mobileOpen={mobileOpen} onClose={() => setMobileOpen(false)} />
          <main className="flex-1 overflow-y-auto bg-white">
            {children}
          </main>
        </div>
      </div>
      <UpgradeGateModal />
    </>
  );
}
