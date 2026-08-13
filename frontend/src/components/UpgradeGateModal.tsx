import { Lock, X } from 'lucide-react'
import { useUIStore } from '../stores/uiStore'

export default function UpgradeGateModal() {
  const { isUpgradeModalOpen, modalContent, closeUpgradeModal } = useUIStore()

  if (!isUpgradeModalOpen || !modalContent) return null

  const tierLabel =
    modalContent.requiredTier.charAt(0).toUpperCase() + modalContent.requiredTier.slice(1)

  const handleStartTrial = () => {
    console.log(
      `[UpgradeGateModal] Start Free Trial requested for: ${modalContent.featureName} (${modalContent.requiredTier} tier)`
    )
    closeUpgradeModal()
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-[150] p-4">
      <div className="bg-white rounded-2xl border border-gray-200 shadow-xl max-w-md w-full overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b border-gray-100 flex items-start gap-4">
          <div className="w-12 h-12 bg-[#fd382f]/10 rounded-full flex items-center justify-center flex-shrink-0">
            <Lock className="h-6 w-6 text-[#fd382f]" />
          </div>
          <div className="flex-1">
            <h2 className="text-xl font-bold text-gray-900 leading-tight">
              {modalContent.featureName}
            </h2>
            <p className="text-sm font-semibold text-[#fd382f] mt-1 capitalize">
              {tierLabel} Feature
            </p>
          </div>
          <button
            onClick={closeUpgradeModal}
            className="p-1.5 hover:bg-gray-100 rounded-lg transition-colors text-gray-400"
            aria-label="Close"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6">
          <p className="text-gray-700 leading-relaxed">{modalContent.description}</p>
          <p className="text-gray-500 text-sm mt-4 leading-relaxed">
            This feature requires an upgrade to automate remediation and secure your data at
            scale.
          </p>
        </div>

        {/* Footer */}
        <div className="p-6 pt-0 flex gap-3">
          <button
            onClick={closeUpgradeModal}
            className="flex-1 px-4 py-2.5 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors font-medium"
          >
            Maybe later
          </button>
          <button
            onClick={handleStartTrial}
            className="flex-1 px-4 py-2.5 bg-[#fd382f] hover:bg-[#e02f26] text-white rounded-lg transition-colors font-medium"
          >
            Start Free Trial
          </button>
        </div>
      </div>
    </div>
  )
}
