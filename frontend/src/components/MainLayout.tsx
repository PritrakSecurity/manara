import React from 'react';
import Header from './layout/Header';
import Sidebar from './layout/Sidebar';
import UpgradeGateModal from './UpgradeGateModal';

export default function MainLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <div className="flex flex-col h-screen bg-white">
        <Header />
        <div className="flex flex-1 overflow-hidden">
          <Sidebar />
          <main className="flex-1 overflow-y-auto bg-white">
            {children}
          </main>
        </div>
      </div>
      <UpgradeGateModal />
    </>
  );
}
