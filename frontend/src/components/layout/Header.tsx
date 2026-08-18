import { Bell, Settings, LogOut, Menu } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useState } from 'react';
import PritrakLogo from '../../assets/pritrak-dashboard-logo.png';
import { useAuthStore } from '../../store/authStore';

interface HeaderProps {
  onMenuClick?: () => void;
}

export default function Header({ onMenuClick }: HeaderProps) {
  const navigate = useNavigate();
  const { logout } = useAuthStore();
  const [showNotifications, setShowNotifications] = useState(false);

  const handleLogout = () => {
    logout();
    localStorage.removeItem('auth_token');
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login';
  };

  const notifications = [
    { id: 1, message: 'New security incident detected', time: '2 minutes ago', type: 'alert' },
    { id: 2, message: 'Policy update completed', time: '15 minutes ago', type: 'info' },
    { id: 3, message: 'Device sync from AD completed', time: '1 hour ago', type: 'success' },
  ];

  return (
    <header className="bg-brand h-[80px] w-full flex items-center justify-between px-6 shadow-md relative z-50">
      <div className="flex items-center">
        <img
          src={PritrakLogo}
          alt="Pritrak"
          className="h-[80px] w-auto object-contain mr-4"
        />
      </div>

      <div className="flex gap-3 items-center">
        <button
          className="w-10 h-10 border-none bg-transparent text-white rounded-lg flex items-center justify-center cursor-pointer transition-colors hover:bg-white/15 lg:hidden"
          onClick={onMenuClick}
          aria-label="Open menu"
        >
          <Menu size={20} className="text-white" />
        </button>
        <div className="relative">
          <button
            className="w-10 h-10 border-none bg-transparent text-white rounded-lg flex items-center justify-center cursor-pointer transition-colors hover:bg-white/15 relative"
            onClick={() => setShowNotifications(!showNotifications)}
          >
            <Bell size={20} className="text-white" />
            {notifications.length > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-yellow-400 rounded-full border border-white"></span>
            )}
          </button>
          {showNotifications && (
            <div className="absolute top-[calc(100%+8px)] right-0 w-80 bg-white border border-gray-200 rounded-lg shadow-lg z-50">
              <div className="flex justify-between items-center px-4 py-3 border-b border-gray-200">
                <span className="font-semibold text-gray-800">Notifications</span>
                <button
                  onClick={() => setShowNotifications(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ×
                </button>
              </div>
              <div className="max-h-[400px] overflow-y-auto">
                {notifications.map((notif) => (
                  <div key={notif.id} className="px-4 py-3 border-b border-gray-100 cursor-pointer transition-colors hover:bg-gray-50">
                    <div className="flex flex-col gap-1">
                      <p className="text-sm text-gray-800">{notif.message}</p>
                      <span className="text-xs text-gray-500">{notif.time}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        <button
          className="w-10 h-10 border-none bg-transparent text-white rounded-lg flex items-center justify-center cursor-pointer transition-colors hover:bg-white/15"
          onClick={() => navigate('/administration/workspace')}
        >
          <Settings size={20} className="text-white" />
        </button>
        <button
          className="flex items-center gap-2 px-4 py-2 bg-white/10 border border-white/30 rounded-md text-white text-sm cursor-pointer transition-all hover:bg-white/20"
          onClick={handleLogout}
        >
          <LogOut className="text-white" size={20} />
          <span>Logout</span>
        </button>
      </div>
    </header>
  );
}
