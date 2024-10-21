/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "ETSI-ITS-CDD"
 * 	found in "asn1/release2/TS102894-2v221-CDD.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_ITS2_ -R`
 */

#ifndef	_Vanetza_ITS2_MetaInformation_H_
#define	_Vanetza_ITS2_MetaInformation_H_


#include "asn_application.h"

/* Including external dependencies */
#include "SensorTypes.h"
#include "StoredInformationType.h"
#include "ConfidenceLevel.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Vanetza_ITS2_MetaInformation */
typedef struct Vanetza_ITS2_MetaInformation {
	Vanetza_ITS2_SensorTypes_t	 usedDetectionInformation;
	Vanetza_ITS2_StoredInformationType_t	 usedStoredInformation;
	Vanetza_ITS2_ConfidenceLevel_t	*confidenceValue;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_ITS2_MetaInformation_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_ITS2_MetaInformation;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_ITS2_MetaInformation_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_ITS2_MetaInformation_1[3];

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_ITS2_MetaInformation_H_ */
#include "asn_internal.h"