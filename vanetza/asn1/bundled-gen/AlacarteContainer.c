/*
 * Generated by asn1c-0.9.27 (http://lionet.info/asn1c)
 * From ASN.1 module "DENM-PDU-Descriptions"
 * 	found in "/home/rieblr/work/car2x/vanetza/vanetza/asn1/denm_en302637-3v1.2.0.asn1"
 * 	`asn1c -fcompound-names -gen-PER`
 */

#include "AlacarteContainer.h"

static asn_TYPE_member_t asn_MBR_AlacarteContainer_1[] = {
	{ ATF_POINTER, 6, offsetof(struct AlacarteContainer, laneNumber),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_LaneNumber,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"laneNumber"
		},
	{ ATF_POINTER, 5, offsetof(struct AlacarteContainer, impactReduction),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_ImpactReductionContainer,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"impactReduction"
		},
	{ ATF_POINTER, 4, offsetof(struct AlacarteContainer, externalTemperature),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_Temperature,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"externalTemperature"
		},
	{ ATF_POINTER, 3, offsetof(struct AlacarteContainer, roadWorks),
		(ASN_TAG_CLASS_CONTEXT | (3 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_RoadWorksContainerExtended,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"roadWorks"
		},
	{ ATF_POINTER, 2, offsetof(struct AlacarteContainer, positioningSolution),
		(ASN_TAG_CLASS_CONTEXT | (4 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_PositioningSolutionType,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"positioningSolution"
		},
	{ ATF_POINTER, 1, offsetof(struct AlacarteContainer, stationaryVehicle),
		(ASN_TAG_CLASS_CONTEXT | (5 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_StationaryVehicleContainer,
		0,	/* Defer constraints checking to the member type */
		0,	/* No PER visible constraints */
		0,
		"stationaryVehicle"
		},
};
static int asn_MAP_AlacarteContainer_oms_1[] = { 0, 1, 2, 3, 4, 5 };
static ber_tlv_tag_t asn_DEF_AlacarteContainer_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (16 << 2))
};
static asn_TYPE_tag2member_t asn_MAP_AlacarteContainer_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* laneNumber */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* impactReduction */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 }, /* externalTemperature */
    { (ASN_TAG_CLASS_CONTEXT | (3 << 2)), 3, 0, 0 }, /* roadWorks */
    { (ASN_TAG_CLASS_CONTEXT | (4 << 2)), 4, 0, 0 }, /* positioningSolution */
    { (ASN_TAG_CLASS_CONTEXT | (5 << 2)), 5, 0, 0 } /* stationaryVehicle */
};
static asn_SEQUENCE_specifics_t asn_SPC_AlacarteContainer_specs_1 = {
	sizeof(struct AlacarteContainer),
	offsetof(struct AlacarteContainer, _asn_ctx),
	asn_MAP_AlacarteContainer_tag2el_1,
	6,	/* Count of tags in the map */
	asn_MAP_AlacarteContainer_oms_1,	/* Optional members */
	6, 0,	/* Root/Additions */
	5,	/* Start extensions */
	7	/* Stop extensions */
};
asn_TYPE_descriptor_t asn_DEF_AlacarteContainer = {
	"AlacarteContainer",
	"AlacarteContainer",
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
	asn_DEF_AlacarteContainer_tags_1,
	sizeof(asn_DEF_AlacarteContainer_tags_1)
		/sizeof(asn_DEF_AlacarteContainer_tags_1[0]), /* 1 */
	asn_DEF_AlacarteContainer_tags_1,	/* Same as above */
	sizeof(asn_DEF_AlacarteContainer_tags_1)
		/sizeof(asn_DEF_AlacarteContainer_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_AlacarteContainer_1,
	6,	/* Elements count */
	&asn_SPC_AlacarteContainer_specs_1	/* Additional specs */
};

