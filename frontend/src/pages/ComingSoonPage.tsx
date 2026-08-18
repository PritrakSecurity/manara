import { Rocket } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

interface ComingSoonPageProps {
  title: string;
  description?: string;
}

export default function ComingSoonPage({ title, description }: ComingSoonPageProps) {
  const navigate = useNavigate();

  return (
    <div className="flex items-center justify-center min-h-full p-8 bg-gray-50">
      <div className="bg-white rounded-2xl border border-gray-200 shadow-sm max-w-md w-full p-10 text-center">
        <div className="w-20 h-20 rounded-full bg-brand/10 flex items-center justify-center mx-auto mb-6">
          <Rocket className="h-9 w-9 text-brand" />
        </div>
        <h1 className="text-3xl font-bold text-gray-900 mb-3">{title}</h1>
        <p className="text-gray-600 leading-relaxed mb-8">
          {description ||
            'This module is currently under active development and will be available soon in the Community Edition.'}
        </p>
        <button
          onClick={() => navigate('/command-center/executive-overview')}
          className="inline-flex items-center gap-2 px-6 py-2.5 bg-brand hover:bg-brand-hover text-white rounded-lg font-medium transition-colors"
        >
          Back to Command Center
        </button>
      </div>
    </div>
  );
}
