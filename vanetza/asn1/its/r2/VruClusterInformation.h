/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/release2/TS102894-2v221-CDD.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_ITS2_ -R`
 */

#ifndef	_Vanetza_ITS2_VruClusterInformation_H_
#define	_Vanetza_ITS2_VruClusterInformation_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Identifier1B.h"
#include "CardinalNumber1B.h"
#include "VruClusterProfiles.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Vanetza_ITS2_Shape;

/* Vanetza_ITS2_VruClusterInformation */
typedef struct Vanetza_ITS2_VruClusterInformation {
	Vanetza_ITS2_Identifier1B_t	*clusterId;	/* OPTIONAL */
	struct Vanetza_ITS2_Shape	*clusterBoundingBoxShape;	/* OPTIONAL */
	Vanetza_ITS2_CardinalNumber1B_t	 clusterCardinalitySize;
	Vanetza_ITS2_VruClusterProfiles_t	*clusterProfiles;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_ITS2_VruClusterInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_ITS2_VruClusterInformation;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_ITS2_VruClusterInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_ITS2_VruClusterInformation_1[4];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Shape.h"

#endif	/* _Vanetza_ITS2_VruClusterInformation_H_ */
#include "asn_internal.h"