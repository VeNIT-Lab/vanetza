#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/sign_service.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <venit_metrics_handler/metrics.hpp>
#ifdef VANETZA_WITH_PQC
#include <string>

// alternative (PQC) signature algorithm of the hybrid-PQC certificates, the messages are signed with ECDSA
#define VENIT_ALTERNATIVE_ALGORITHM_NAME "FN-DSA-512"
#endif

namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{

/// name of the signature algorithm reported to the metrics handler
[[maybe_unused]] const char* algorithm_name(KeyType type)
{
    switch (type) {
        case KeyType::NistP256:
            return "ECDSA-NistP256";
        case KeyType::BrainpoolP256r1:
            return "ECDSA-BrainpoolP256r1";
        case KeyType::BrainpoolP384r1:
            return "ECDSA-BrainpoolP384r1";
        default:
            return "unspecified";
    }
}

} // namespace

StraightSignService::StraightSignService(CertificateProvider& provider, Backend& backend, SignHeaderPolicy& policy, CertificateValidator& validator) :
    m_certificates(provider), m_backend(backend), m_policy(policy), m_validator(validator)
{
}

SignConfirm StraightSignService::sign(SignRequest&& request)
{
    const auto& signing_cert = m_certificates.own_certificate();
    const auto hash_algo = specified_hash_algorithm(signing_cert.get_verification_key_type());

    SecuredMessage secured_message = SecuredMessage::with_signed_data();
    secured_message.set_hash_id(hash_algo);
    secured_message.set_payload(convert_to_payload(request.plain_message));
    m_policy.prepare_header(request, secured_message);

    auto verdict = [&] {
        VENIT_METRIC_SCOPE(SENT_MESSAGE_CERTIFICATE_VALIDATION_TIME);
        return m_validator.valid_for_signing(signing_cert, request.its_aid);
    }();
    if (verdict != CertificateValidator::Verdict::Valid) {
        return SignConfirm::failure(SignConfirmError::No_Certificate);
    }

    ByteBuffer digest = calculate_message_hash(m_backend, hash_algo, secured_message.signing_payload(), signing_cert);
#ifdef VANETZA_WITH_PQC
    // hybrid-PQC stack: the algorithm of the messages along with the alternative one of the certificates
    VENIT_METRIC_ALGORITHM((std::string(algorithm_name(signing_cert.get_verification_key_type())) + "+" +
        VENIT_ALTERNATIVE_ALGORITHM_NAME).c_str());
#else
    VENIT_METRIC_ALGORITHM(algorithm_name(signing_cert.get_verification_key_type()));
#endif
    Signature signature = [&] {
        VENIT_METRIC_SCOPE(SIGNATURE_TIME);
        return m_backend.sign_digest(m_certificates.own_private_key(), digest);
    }();
    secured_message.set_signature(signature);
    return SignConfirm::success(std::move(secured_message));
}

DummySignService::DummySignService(const Runtime& runtime) :
    m_runtime(runtime)
{
}

SignConfirm DummySignService::sign(SignRequest&& request)
{
    SecuredMessage secured_message = SecuredMessage::with_signed_data();
    ByteBuffer payload;
    payload = convert_to_payload(request.plain_message);
    secured_message.set_payload(payload);
    secured_message.set_dummy_signature();
    secured_message.set_its_aid(request.its_aid);
    secured_message.set_generation_time(vanetza::security::v2::convert_time64(m_runtime.now()));
    secured_message->content->choice.signedData->signer.present = Vanetza_Security_SignerIdentifier_PR_self;

    return SignConfirm::success(std::move(secured_message));
}

} // namespace v3
} // namespace security
} // namespace vanetza
