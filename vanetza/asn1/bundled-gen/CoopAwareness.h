/*
 * Generated by asn1c-0.9.27 (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "/home/rieblr/work/car2x/vanetza/vanetza/asn1/cam_en302637-2v1.3.0.asn1"
 * 	`asn1c -fcompound-names -gen-PER`
 */

#ifndef	_CoopAwareness_H_
#define	_CoopAwareness_H_


#include <asn_application.h>

/* Including external dependencies */
#include "GenerationDeltaTime.h"
#include "CamParameters.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CoopAwareness */
typedef struct CoopAwareness {
	GenerationDeltaTime_t	 generationDeltaTime;
	CamParameters_t	 camParameters;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CoopAwareness_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CoopAwareness;

#ifdef __cplusplus
}
#endif

#endif	/* _CoopAwareness_H_ */
#include <asn_internal.h>
