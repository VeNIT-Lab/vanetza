/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CAM-PDU-Descriptions"
 * 	found in "asn1/release2/TS103900v211-CAM.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_ITS2_ -R`
 */

#ifndef	_Vanetza_ITS2_DangerousGoodsContainer_H_
#define	_Vanetza_ITS2_DangerousGoodsContainer_H_


#include "asn_application.h"

/* Including external dependencies */
#include "DangerousGoodsBasic.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Vanetza_ITS2_DangerousGoodsContainer */
typedef struct Vanetza_ITS2_DangerousGoodsContainer {
	Vanetza_ITS2_DangerousGoodsBasic_t	 dangerousGoodsBasic;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_ITS2_DangerousGoodsContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_ITS2_DangerousGoodsContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_ITS2_DangerousGoodsContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_ITS2_DangerousGoodsContainer_1[1];

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_ITS2_DangerousGoodsContainer_H_ */
#include "asn_internal.h"