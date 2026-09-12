package service

func ProvideTLSFingerprintProfileService(repo TLSFingerprintProfileRepository, cache TLSFingerprintProfileCache, settings SettingRepository) *TLSFingerprintProfileService {
	return newTLSFingerprintProfileService(repo, cache, settings)
}
