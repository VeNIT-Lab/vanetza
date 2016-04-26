/*
 * Generated by asn1c-0.9.27 (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "/home/rieblr/work/car2x/vanetza/vanetza/asn1/cdd_ts102894-2v1.1.1.asn1"
 * 	`asn1c -fcompound-names -gen-PER`
 */

#ifndef	_PosConfidenceEllipse_H_
#define	_PosConfidenceEllipse_H_


#include <asn_application.h>

/* Including external dependencies */
#include "SemiAxisLength.h"
#include "Heading.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PosConfidenceEllipse */
typedef struct PosConfidenceEllipse {
	SemiAxisLength_t	 semiMajorConfidence;
	SemiAxisLength_t	 semiMinorConfidence;
	Heading_t	 semiMajorOrientation;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} PosConfidenceEllipse_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_PosConfidenceEllipse;

#ifdef __cplusplus
}
#endif

#endif	/* _PosConfidenceEllipse_H_ */
#include <asn_internal.h>
