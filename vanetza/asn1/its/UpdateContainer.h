/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "CBM-PDU-Descriptions"
 * 	found in "asn1/VeNIT-v100-CBM.asn"
 * 	`asn1c -fcompound-names -fno-include-deps -fincludes-quoted -no-gen-example -R`
 */

#ifndef	_UpdateContainer_H_
#define	_UpdateContainer_H_


#include "asn_application.h"

/* Including external dependencies */
#include "PlatoonID.h"
#include "Gap.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Speed;
struct ItineraryPath;

/* UpdateContainer */
typedef struct UpdateContainer {
	PlatoonID_t	 platoonId;
	struct Speed	*speed;	/* OPTIONAL */
	Gap_t	*gap;	/* OPTIONAL */
	struct ItineraryPath	*itineraryPath;	/* OPTIONAL */
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} UpdateContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_UpdateContainer;
extern asn_SEQUENCE_specifics_t asn_SPC_UpdateContainer_specs_1;
extern asn_TYPE_member_t asn_MBR_UpdateContainer_1[4];

#ifdef __cplusplus
}
#endif

#endif	/* _UpdateContainer_H_ */
#include "asn_internal.h"
