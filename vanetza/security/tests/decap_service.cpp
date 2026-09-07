#include <gtest/gtest.h>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/decap_service.hpp>
#include <vanetza/security/v3/secured_message.hpp>

#include "printer.hpp"

using namespace vanetza;
using namespace vanetza::security;

TEST(DecapService, confirm_from_verify_confirm)
{
    v3::SecuredMessage v3_msg = v3::SecuredMessage::with_signed_data();
    v3_msg.set_payload(ByteBuffer { 0xca, 0xfe });
    SecuredMessage msg { std::move(v3_msg) };

    const HashedId8 signer { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    VerifyConfirm verify;
    verify.report = VerificationReport::Success;
    verify.its_aid = aid::CA;
    verify.permissions = ByteBuffer { 0x01, 0x02 };
    verify.certificate_validity = CertificateValidity::valid();
    verify.certificate_id = signer;

    DecapConfirm decap = DecapConfirm::from(std::move(verify), SecuredMessageView { msg });
    EXPECT_EQ(VerificationReport::Success, decap.report);
    EXPECT_EQ(aid::CA, decap.its_aid);
    EXPECT_EQ(ByteBuffer({ 0x01, 0x02 }), decap.permissions);
    EXPECT_TRUE(decap.certificate_validity);
    ASSERT_TRUE(decap.certificate_id);
    EXPECT_EQ(signer, *decap.certificate_id);
    EXPECT_EQ(2, boost::apply_visitor([](const auto& packet) { return packet.size(); }, decap.plaintext_payload));
}
