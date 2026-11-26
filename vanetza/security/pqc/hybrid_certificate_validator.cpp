#include <vanetza/security/pqc/hybrid_certificate_validator.hpp>
#include <vanetza/security/pqc/hybrid_certificate.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/issuer_lookup.hpp>
#include <vanetza/security/v3/trust_store.hpp>
#include <venit_metrics_handler/metrics.hpp>

namespace vanetza
{
namespace security
{
namespace pqc
{

auto HybridCertificateValidator::valid_for_signing(
    const v3::CertificateView& certificate, ItsAid aid) -> Verdict
{
    const Verdict policy_verdict = m_policy_validator.valid_for_signing(certificate, aid);
    if (policy_verdict != Verdict::Valid) {
        return policy_verdict;
    }
    if (!m_issuer_lookup || !m_trust_store || !m_ecc_backend ||
            (m_verification_policy != VerificationPolicy::ClassicalOnly && !m_pqc_backend)) {
        return Verdict::Misconfiguration;
    }
    return chain_is_authentic(certificate) ? Verdict::Valid : Verdict::Untrusted;
}

void HybridCertificateValidator::use_runtime(const Runtime* runtime)
{
    m_policy_validator.use_runtime(runtime);
}

void HybridCertificateValidator::use_position_provider(PositionProvider* provider)
{
    m_policy_validator.use_position_provider(provider);
}

void HybridCertificateValidator::use_issuer_lookup(const v3::IssuerLookup* lookup)
{
    m_issuer_lookup = lookup;
    m_policy_validator.use_issuer_lookup(lookup);
}

void HybridCertificateValidator::use_location_checker(const v3::LocationChecker* checker)
{
    m_policy_validator.use_location_checker(checker);
}

void HybridCertificateValidator::use_revocation_lookup(const v3::RevocationLookup* lookup)
{
    m_policy_validator.use_revocation_lookup(lookup);
}

void HybridCertificateValidator::use_trust_store(const v3::TrustStore* store)
{
    m_trust_store = store;
    m_policy_validator.use_trust_store(store);
}

void HybridCertificateValidator::use_backends(
    ::vanetza::security::Backend* ecc, Backend* pqc_backend)
{
    m_ecc_backend = ecc;
    m_pqc_backend = pqc_backend;
}

void HybridCertificateValidator::use_verification_policy(VerificationPolicy policy)
{
    m_verification_policy = policy;
}

#ifdef VENIT_WITH_HYBRID_METRICS
void HybridCertificateValidator::use_metrics_direction(venit::metrics::Direction direction)
{
    m_metrics_direction = direction;
}
#endif

void HybridCertificateValidator::disable_time_checks(bool disable)
{
    m_policy_validator.disable_time_checks(disable);
}

void HybridCertificateValidator::disable_location_checks(bool disable)
{
    m_policy_validator.disable_location_checks(disable);
}

void HybridCertificateValidator::disable_chain_consistency_checks(bool disable)
{
    m_policy_validator.disable_chain_consistency_checks(disable);
}

void HybridCertificateValidator::disable_region_consistency_checks(bool disable)
{
    m_policy_validator.disable_region_consistency_checks(disable);
}

bool HybridCertificateValidator::alternative_signature_is_accepted(
    const v3::CertificateView& subject, const v3::CertificateView* issuer) const
{
    if (m_verification_policy == VerificationPolicy::ClassicalOnly) {
        return true;
    }

    const auto state = alternative_material_state(subject);
    if (state == MaterialState::Inconsistent) {
        return false;
    }
    if (state == MaterialState::None) {
        return m_verification_policy == VerificationPolicy::HybridIfPresent;
    }

    VENIT_HYBRID_METRIC_SCOPE(m_metrics_direction, PQC_CERTIFICATE_VERIFICATION_TIME);
    return m_pqc_backend && verify_alternative_certificate(
        subject, issuer, *m_ecc_backend, *m_pqc_backend);
}

#ifdef VENIT_WITH_HYBRID_METRICS
bool HybridCertificateValidator::primary_signature_is_valid(
    const v3::CertificateView& subject, const v3::CertificateView* issuer) const
{
    VENIT_HYBRID_METRIC_SCOPE(m_metrics_direction, ECC_CERTIFICATE_VERIFICATION_TIME);
    return verify_primary_certificate(subject, issuer, *m_ecc_backend);
}
#endif

bool HybridCertificateValidator::chain_is_authentic(
    const v3::CertificateView& signing_certificate) const
{
    VENIT_HYBRID_METRIC_SCOPE(m_metrics_direction, HYBRID_CHAIN_VERIFICATION_TIME);
    constexpr int maximum_chain_depth = 8;
    const v3::CertificateView* subject = &signing_certificate;

    for (int depth = 0; depth < maximum_chain_depth; ++depth) {
        if (subject->issuer_is_self()) {
            const auto root_digest = subject->calculate_digest();
            if (!root_digest || m_trust_store->lookup(*root_digest).empty()) {
                return false;
            }
#ifdef VENIT_WITH_HYBRID_METRICS
            return primary_signature_is_valid(*subject, nullptr) &&
#else
            return verify_primary_certificate(*subject, nullptr, *m_ecc_backend) &&
#endif
                alternative_signature_is_accepted(*subject, nullptr);
        }

        const auto expected_issuer_digest = subject->issuer_digest();
        if (!expected_issuer_digest) {
            return false;
        }
        const v3::Certificate* issuer = m_issuer_lookup->find_issuer(*expected_issuer_digest);
        if (!issuer) {
            return false;
        }
        const auto actual_issuer_digest = issuer->calculate_digest();
        if (!actual_issuer_digest || *actual_issuer_digest != *expected_issuer_digest) {
            return false;
        }

#ifdef VENIT_WITH_HYBRID_METRICS
        if (!primary_signature_is_valid(*subject, issuer) ||
#else
        if (!verify_primary_certificate(*subject, issuer, *m_ecc_backend) ||
#endif
                !alternative_signature_is_accepted(*subject, issuer)) {
            return false;
        }
        subject = issuer;
    }

    return false;
}

} // namespace pqc
} // namespace security
} // namespace vanetza
