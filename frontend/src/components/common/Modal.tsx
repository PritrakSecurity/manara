import React, { useEffect } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title?: string;
  children: React.ReactNode;
  size?: 'sm' | 'md' | 'lg' | 'xl';
}

const sizeClasses: Record<string, string> = {
  sm: 'max-w-[400px]',
  md: 'max-w-[600px]',
  lg: 'max-w-[800px]',
  xl: 'max-w-[1200px]',
};

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
    <div
      className="fixed inset-0 z-[1000] bg-black/50 flex items-center justify-center p-4 animate-[manaraFadeIn_0.2s]"
      onClick={onClose}
    >
      <div
        className={`manara-card w-full ${sizeClasses[size]} max-h-[calc(90vh-100px)] overflow-y-auto relative animate-[manaraSlideUp_0.2s]`}
        onClick={(e) => e.stopPropagation()}
      >
        {title ? (
          <div className="flex justify-between items-center pb-4 mb-4 border-b border-gray-100">
            <h2 className="text-lg font-semibold text-primary">{title}</h2>
            <button
              className="p-1.5 hover:bg-gray-100 rounded-lg text-gray-400 transition-colors"
              onClick={onClose}
              aria-label="Close"
            >
              <X size={20} />
            </button>
          </div>
        ) : (
          <button
            className="absolute top-4 right-4 p-1.5 hover:bg-gray-100 rounded-lg text-gray-400 transition-colors"
            onClick={onClose}
            aria-label="Close"
          >
            <X size={20} />
          </button>
        )}
        {children}
      </div>
    </div>
  );
}
