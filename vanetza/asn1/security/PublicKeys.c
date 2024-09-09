/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "EtsiTs102941BaseTypes"
 * 	found in "asn1/TS102941v131-BaseTypes.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security_ -R`
 */

#include "PublicKeys.h"

asn_TYPE_member_t asn_MBR_Vanetza_Security_PublicKeys_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Vanetza_Security_PublicKeys, verificationKey),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_Vanetza_Security_PublicVerificationKey,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"verificationKey"
		},
	{ ATF_POINTER, 1, offsetof(struct Vanetza_Security_PublicKeys, encryptionKey),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Vanetza_Security_PublicEncryptionKey,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"encryptionKey"
		},
};
static const int asn_MAP_Vanetza_Security_PublicKeys_oms_1[] = { 1 };
static const ber_tlv_tag_t asn_DEF_Vanetza_Security_PublicKeys_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_Vanetza_Security_PublicKeys_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* verificationKey */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* encryptionKey */
};
asn_SEQUENCE_specifics_t asn_SPC_Vanetza_Security_PublicKeys_specs_1 = {
	sizeof(struct Vanetza_Security_PublicKeys),
	offsetof(struct Vanetza_Security_PublicKeys, _asn_ctx),
	asn_MAP_Vanetza_Security_PublicKeys_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_Vanetza_Security_PublicKeys_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* First extension addition */
};
asn_TYPE_descriptor_t asn_DEF_Vanetza_Security_PublicKeys = {
	"PublicKeys",
	"PublicKeys",
	&asn_OP_SEQUENCE,
	asn_DEF_Vanetza_Security_PublicKeys_tags_1,
	sizeof(asn_DEF_Vanetza_Security_PublicKeys_tags_1)
		/sizeof(asn_DEF_Vanetza_Security_PublicKeys_tags_1[0]), /* 1 */
	asn_DEF_Vanetza_Security_PublicKeys_tags_1,	/* Same as above */
	sizeof(asn_DEF_Vanetza_Security_PublicKeys_tags_1)
		/sizeof(asn_DEF_Vanetza_Security_PublicKeys_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		SEQUENCE_constraint
	},
	asn_MBR_Vanetza_Security_PublicKeys_1,
	2,	/* Elements count */
	&asn_SPC_Vanetza_Security_PublicKeys_specs_1	/* Additional specs */
};
