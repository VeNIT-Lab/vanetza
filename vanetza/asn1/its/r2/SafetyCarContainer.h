/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/release2/TS103900v211-CAM.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_ITS2_ -R`
 */

#ifndef	_Vanetza_ITS2_SafetyCarContainer_H_
#define	_Vanetza_ITS2_SafetyCarContainer_H_


#include "asn_application.h"

/* Including external dependencies */
#include "LightBarSirenInUse.h"
#include "TrafficRule.h"
#include "SpeedLimit.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Vanetza_ITS2_CauseCodeV2;

/* Vanetza_ITS2_SafetyCarContainer */
typedef struct Vanetza_ITS2_SafetyCarContainer {
	Vanetza_ITS2_LightBarSirenInUse_t	 lightBarSirenInUse;
	struct Vanetza_ITS2_CauseCodeV2	*incidentIndication;	/* OPTIONAL */
	Vanetza_ITS2_TrafficRule_t	*trafficRule;	/* OPTIONAL */
	Vanetza_ITS2_SpeedLimit_t	*speedLimit;	/* OPTIONAL */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_ITS2_SafetyCarContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_ITS2_SafetyCarContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_ITS2_SafetyCarContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_ITS2_SafetyCarContainer_1[4];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "CauseCodeV2.h"

#endif	/* _Vanetza_ITS2_SafetyCarContainer_H_ */
#include "asn_internal.h"