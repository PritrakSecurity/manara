import { Lock } from 'lucide-react'
import { useUIStore } from '../store/uiStore'
import Modal from './common/Modal'

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
    <Modal
      isOpen={isUpgradeModalOpen}
      onClose={closeUpgradeModal}
      title={modalContent.featureName}
      size="sm"
    >
      <div className="flex items-center gap-3 mb-4">
        <div className="w-11 h-11 bg-brand/10 rounded-full flex items-center justify-center flex-shrink-0">
          <Lock className="h-5 w-5 text-brand" />
        </div>
        <p className="text-sm font-semibold text-brand capitalize">{tierLabel} Feature</p>
      </div>

      <p className="text-gray-700 leading-relaxed">{modalContent.description}</p>
      <p className="text-gray-500 text-sm mt-4 leading-relaxed">
        This feature requires an upgrade to automate remediation and secure your data at scale.
      </p>

      <div className="mt-6 flex gap-3">
        <button
          onClick={closeUpgradeModal}
          className="flex-1 px-4 py-2.5 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors font-medium"
        >
          Maybe later
        </button>
        <button
          onClick={handleStartTrial}
          className="flex-1 px-4 py-2.5 bg-brand hover:bg-brand-hover text-white rounded-lg transition-colors font-medium"
        >
          Start Free Trial
        </button>
      </div>
    </Modal>
  )
}
