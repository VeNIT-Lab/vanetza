/*
 * Generated by asn1c-0.9.27 (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "/home/rieblr/work/car2x/vanetza/vanetza/asn1/cdd_ts102894-2v1.1.1.asn1"
 * 	`asn1c -fcompound-names -gen-PER`
 */

#include "Heading.h"

static asn_TYPE_member_t asn_MBR_Heading_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct Heading, headingValue),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HeadingValue,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"headingValue"
		},
	{ ATF_NOFLAGS, 0, offsetof(struct Heading, headingConfidence),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_HeadingConfidence,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"headingConfidence"
		},
};
static ber_tlv_tag_t asn_DEF_Heading_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_Heading_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* headingValue */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 } /* headingConfidence */
};
static asn_SEQUENCE_specifics_t asn_SPC_Heading_specs_1 = {
	sizeof(struct Heading),
	offsetof(struct Heading, _asn_ctx),
	asn_MAP_Heading_tag2el_1,
	2,	/* Count of tags in the map */
	0, 0, 0,	/* Optional elements (not needed) */
	-1,	/* Start extensions */
	-1	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_Heading = {
	"Heading",
	"Heading",
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
	asn_DEF_Heading_tags_1,
	sizeof(asn_DEF_Heading_tags_1)
		/sizeof(asn_DEF_Heading_tags_1[0]), /* 1 */
	asn_DEF_Heading_tags_1,	/* Same as above */
	sizeof(asn_DEF_Heading_tags_1)
		/sizeof(asn_DEF_Heading_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_Heading_1,
	2,	/* Elements count */
	&asn_SPC_Heading_specs_1	/* Additional specs */
};

