import React, { useEffect } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}

export default function Modal({ isOpen, onClose, title, children, size = 'md' }: ModalProps) {
  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      document.addEventListener('keydown', handleEsc);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.removeEventListener('keydown', handleEsc);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className={`modal-content modal-${size}`} onClick={(e) => e.stopPropagation()}>
        {title && (
          <div className="modal-header">
            <h2>{title}</h2>
            <button className="close-btn" onClick={onClose}>
              <X size={20} />
            </button>
          </div>
        )}
        {!title && (
          <button className="close-btn-absolute" onClick={onClose}>
            <X size={20} />
          </button>
        )}
        <div className="modal-body">{children}</div>
      </div>

      <style>{`
        .modal-overlay {
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.5);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
          animation: fadeIn 0.2s;
        }

        .modal-content {
          background: white;
          border-radius: 12px;
          box-shadow: 0 4px 16px rgba(0,0,0,0.12);
          position: relative;
          animation: slideUp 0.2s;
        }

        .modal-sm { max-width: 400px; width: 90%; }
        .modal-md { max-width: 600px; width: 90%; }
        .modal-lg { max-width: 800px; width: 90%; }
        .modal-xl { max-width: 1200px; width: 90%; }

        .modal-header {
          padding: 20px 24px;
          border-bottom: 1px solid #e1e4e8;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .modal-header h2 {
          font-size: 18px;
          font-weight: 600;
          color: #2c3e50;
          margin: 0;
        }

        .close-btn, .close-btn-absolute {
          width: 32px;
          height: 32px;
          border: none;
          background: transparent;
          color: #7f8c8d;
          border-radius: 6px;
          display: flex;
          align-items: center;
          justify-content: center;
          cursor: pointer;
          transition: all 0.2s;
        }

        .close-btn-absolute {
          position: absolute;
          top: 16px;
          right: 16px;
          z-index: 1;
        }

        .close-btn:hover, .close-btn-absolute:hover {
          background: #f0f0f0;
          color: #2c3e50;
        }

        .modal-body {
          padding: 24px;
          max-height: calc(90vh - 100px);
          overflow-y: auto;
        }

        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }

        @keyframes slideUp {
          from { transform: translateY(20px); opacity: 0; }
          to { transform: translateY(0); opacity: 1; }
        }
      `}</style>
    </div>
  );
}
