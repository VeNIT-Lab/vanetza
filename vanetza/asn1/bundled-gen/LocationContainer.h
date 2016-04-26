/*
 * Generated by asn1c-0.9.27 (http://lionet.info/asn1c)
 * From ASN.1 module "DENM-PDU-Descriptions"
 * 	found in "/home/rieblr/work/car2x/vanetza/vanetza/asn1/denm_en302637-3v1.2.0.asn1"
 * 	`asn1c -fcompound-names -gen-PER`
 */

#ifndef	_LocationContainer_H_
#define	_LocationContainer_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Traces.h"
#include "RoadType.h"
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct Speed;
struct Heading;

/* LocationContainer */
typedef struct LocationContainer {
	struct Speed	*eventSpeed	/* OPTIONAL */;
	struct Heading	*eventPositionHeading	/* OPTIONAL */;
	Traces_t	 traces;
	RoadType_t	*roadClass	/* OPTIONAL */;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} LocationContainer_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_LocationContainer;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Speed.h"
#include "Heading.h"

#endif	/* _LocationContainer_H_ */
#include <asn_internal.h>
