/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "Ieee1609Dot2Dot1Protocol"
 * 	found in "build.asn1/ieee/IEEE1609dot2dot1Protocol.asn"
 * 	`asn1c -fcompound-names -fincludes-quoted -no-gen-example -fprefix=Vanetza_Security2_ -R`
 */

#ifndef	_Vanetza_Security2_ScmsPdu_H_
#define	_Vanetza_Security2_ScmsPdu_H_


#include "asn_application.h"

/* Including external dependencies */
#include "Uint8.h"
#include "AcaEeInterfacePdu.h"
#include "AcaLaInterfacePdu.h"
#include "AcaMaInterfacePdu.h"
#include "AcaRaInterfacePdu.h"
#include "CertManagementPdu.h"
#include "EcaEeInterfacePdu.h"
#include "EeMaInterfacePdu.h"
#include "EeRaInterfacePdu.h"
#include "LaMaInterfacePdu.h"
#include "LaRaInterfacePdu.h"
#include "MaRaInterfacePdu.h"
#include "constr_CHOICE.h"
#include "constr_SEQUENCE.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum Vanetza_Security2_ScmsPdu__content_PR {
	Vanetza_Security2_ScmsPdu__content_PR_NOTHING,	/* No components present */
	Vanetza_Security2_ScmsPdu__content_PR_aca_ee,
	Vanetza_Security2_ScmsPdu__content_PR_aca_la,
	Vanetza_Security2_ScmsPdu__content_PR_aca_ma,
	Vanetza_Security2_ScmsPdu__content_PR_aca_ra,
	Vanetza_Security2_ScmsPdu__content_PR_cert,
	Vanetza_Security2_ScmsPdu__content_PR_eca_ee,
	Vanetza_Security2_ScmsPdu__content_PR_ee_ma,
	Vanetza_Security2_ScmsPdu__content_PR_ee_ra,
	Vanetza_Security2_ScmsPdu__content_PR_la_ma,
	Vanetza_Security2_ScmsPdu__content_PR_la_ra,
	Vanetza_Security2_ScmsPdu__content_PR_ma_ra
	/* Extensions may appear below */
	
} Vanetza_Security2_ScmsPdu__content_PR;

/* Vanetza_Security2_ScmsPdu */
typedef struct Vanetza_Security2_ScmsPdu {
	Vanetza_Security2_Uint8_t	 version;
	struct Vanetza_Security2_ScmsPdu__content {
		Vanetza_Security2_ScmsPdu__content_PR present;
		union Vanetza_Security2_ScmsPdu__Vanetza_Security2_content_u {
			Vanetza_Security2_AcaEeInterfacePdu_t	 aca_ee;
			Vanetza_Security2_AcaLaInterfacePdu_t	 aca_la;
			Vanetza_Security2_AcaMaInterfacePdu_t	 aca_ma;
			Vanetza_Security2_AcaRaInterfacePdu_t	 aca_ra;
			Vanetza_Security2_CertManagementPdu_t	 cert;
			Vanetza_Security2_EcaEeInterfacePdu_t	 eca_ee;
			Vanetza_Security2_EeMaInterfacePdu_t	 ee_ma;
			Vanetza_Security2_EeRaInterfacePdu_t	 ee_ra;
			Vanetza_Security2_LaMaInterfacePdu_t	 la_ma;
			Vanetza_Security2_LaRaInterfacePdu_t	 la_ra;
			Vanetza_Security2_MaRaInterfacePdu_t	 ma_ra;
			/*
			 * This type is extensible,
			 * possible extensions are below.
			 */
		} choice;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} content;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Vanetza_Security2_ScmsPdu_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Vanetza_Security2_ScmsPdu;
extern asn_SEQUENCE_specifics_t asn_SPC_Vanetza_Security2_ScmsPdu_specs_1;
extern asn_TYPE_member_t asn_MBR_Vanetza_Security2_ScmsPdu_1[2];

#ifdef __cplusplus
}
#endif

#endif	/* _Vanetza_Security2_ScmsPdu_H_ */
#include "asn_internal.h"