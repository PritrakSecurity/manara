import { Bell, Settings, LogOut } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useState } from 'react';
import PritrakLogo from '../../assets/pritrak-dashboard-logo.png';
import { useAuthStore } from '../../store/authStore';

export default function Header() {
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
    <header className="app-header">
      <div className="header-left">
        <img 
          src={PritrakLogo} 
          alt="Pritrak" 
          className="header-logo-large" 
          style={{ height: '80px', width: 'auto' }}
        />
      </div>
      
      <div className="header-right">
        <div className="relative">
          <button 
            className="icon-btn relative"
            onClick={() => setShowNotifications(!showNotifications)}
          >
            <Bell size={20} className="text-white" />
            {notifications.length > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 bg-yellow-400 rounded-full border border-white"></span>
            )}
          </button>
          {showNotifications && (
            <div className="notification-dropdown">
              <div className="notification-header">
                <span className="font-semibold text-gray-800">Notifications</span>
                <button 
                  onClick={() => setShowNotifications(false)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ×
                </button>
              </div>
              <div className="notification-list">
                {notifications.map((notif) => (
                  <div key={notif.id} className="notification-item">
                    <div className="notification-content">
                      <p className="notification-message">{notif.message}</p>
                      <span className="notification-time">{notif.time}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
        <button 
          className="icon-btn"
          onClick={() => navigate('/dashboard/settings')}
        >
          <Settings size={20} className="text-white" />
        </button>
        <button 
          className="logout-btn"
          onClick={handleLogout}
        >
          <LogOut className="icon text-white" size={20} />
          <span>Logout</span>
        </button>
      </div>

      <style>{`
        .app-header {
          height: 80px;
          background: #fd382f;
          border-bottom: none;
          display: flex;
          justify-content: space-between;
          align-items: center;
          padding: 0 24px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.15);
          position: relative;
          z-index: 100;
        }

        .header-logo-large {
          height: 80px !important;
          width: auto;
          object-fit: contain;
          margin-right: 16px;
        }

        .header-right {
          display: flex;
          gap: 12px;
          align-items: center;
        }

        .icon-btn {
          width: 40px;
          height: 40px;
          border: none;
          background: transparent;
          color: white;
          border-radius: 8px;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          transition: background 0.2s;
          position: relative;
        }

        .icon-btn:hover {
          background: rgba(255, 255, 255, 0.15);
        }

        .notification-dropdown {
          position: absolute;
          top: calc(100% + 8px);
          right: 0;
          width: 320px;
          background: white;
          border: 1px solid #e1e4e8;
          border-radius: 8px;
          box-shadow: 0 4px 12px rgba(0,0,0,0.15);
          z-index: 1000;
        }

        .notification-header {
          padding: 12px 16px;
          border-bottom: 1px solid #e1e4e8;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .notification-list {
          max-height: 400px;
          overflow-y: auto;
        }

        .notification-item {
          padding: 12px 16px;
          border-bottom: 1px solid #f1f3f5;
          cursor: pointer;
          transition: background 0.2s;
        }

        .notification-item:hover {
          background: #f8f9fa;
        }

        .notification-content {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .notification-message {
          font-size: 14px;
          color: #2c3e50;
        }

        .notification-time {
          font-size: 12px;
          color: #7f8c8d;
        }

        .logout-btn {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 8px 16px;
          background: rgba(255, 255, 255, 0.1);
          border: 1px solid rgba(255, 255, 255, 0.3);
          border-radius: 6px;
          color: white;
          font-size: 14px;
          cursor: pointer;
          transition: all 0.2s;
        }

        .logout-btn:hover {
          background: rgba(255, 255, 255, 0.2);
          border-color: rgba(255, 255, 255, 0.5);
        }

        .logout-btn .icon {
          color: white;
        }
      `}</style>
    </header>
  );
}
