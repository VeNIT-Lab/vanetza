/*
 * Generated by asn1c-0.9.27 (http://lionet.info/asn1c)
 * From ASN.1 module "DENM-PDU-Descriptions"
 * 	found in "/home/rieblr/work/car2x/vanetza/vanetza/asn1/denm_en302637-3v1.2.0.asn1"
 * 	`asn1c -fcompound-names -gen-PER`
 */

#ifndef	_PositionOfPillars_H_
#define	_PositionOfPillars_H_


#include <asn_application.h>

/* Including external dependencies */
#include "PosPillar.h"
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PositionOfPillars */
typedef struct PositionOfPillars {
	A_SEQUENCE_OF(PosPillar_t) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PositionOfPillars_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PositionOfPillars;

#ifdef __cplusplus
}
#endif

#endif	/* _PositionOfPillars_H_ */
#include <asn_internal.h>
