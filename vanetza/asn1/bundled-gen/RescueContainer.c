/*
 * Generated by asn1c-0.9.27 (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "/home/rieblr/work/car2x/vanetza/vanetza/asn1/cam_en302637-2v1.3.0.asn1"
 * 	`asn1c -fcompound-names -gen-PER`
 */

#include "RescueContainer.h"

static asn_TYPE_member_t asn_MBR_RescueContainer_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct RescueContainer, lightBarSirenInUse),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LightBarSirenInUse,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"lightBarSirenInUse"
		},
	{ ATF_POINTER, 1, offsetof(struct RescueContainer, emergencyPriority),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_EmergencyPriority,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"emergencyPriority"
		},
};
static int asn_MAP_RescueContainer_oms_1[] = { 1 };
static ber_tlv_tag_t asn_DEF_RescueContainer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_RescueContainer_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* lightBarSirenInUse */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* emergencyPriority */
};
static asn_SEQUENCE_specifics_t asn_SPC_RescueContainer_specs_1 = {
	sizeof(struct RescueContainer),
	offsetof(struct RescueContainer, _asn_ctx),
	asn_MAP_RescueContainer_tag2el_1,
	2,	/* Count of tags in the map */
	asn_MAP_RescueContainer_oms_1,	/* Optional members */
	1, 0,	/* Root/Additions */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_RescueContainer = {
	"RescueContainer",
	"RescueContainer",
	SEQUENCE_free,
	SEQUENCE_print,
	SEQUENCE_constraint,
	SEQUENCE_decode_ber,
	SEQUENCE_encode_der,
	SEQUENCE_decode_xer,
	SEQUENCE_encode_xer,
	SEQUENCE_decode_uper,
	SEQUENCE_encode_uper,
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_RescueContainer_tags_1,
	sizeof(asn_DEF_RescueContainer_tags_1)
		/sizeof(asn_DEF_RescueContainer_tags_1[0]), /* 1 */
	asn_DEF_RescueContainer_tags_1,	/* Same as above */
	sizeof(asn_DEF_RescueContainer_tags_1)
		/sizeof(asn_DEF_RescueContainer_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RescueContainer_1,
	2,	/* Elements count */
	&asn_SPC_RescueContainer_specs_1	/* Additional specs */
};

