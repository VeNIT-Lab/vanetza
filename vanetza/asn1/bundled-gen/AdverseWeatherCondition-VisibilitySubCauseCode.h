/*
 * Generated by asn1c-0.9.27 (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "/home/rieblr/work/car2x/vanetza/vanetza/asn1/cdd_ts102894-2v1.1.1.asn1"
 * 	`asn1c -fcompound-names -gen-PER`
 */

#ifndef	_AdverseWeatherCondition_VisibilitySubCauseCode_H_
#define	_AdverseWeatherCondition_VisibilitySubCauseCode_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AdverseWeatherCondition_VisibilitySubCauseCode {
	AdverseWeatherCondition_VisibilitySubCauseCode_unavailable	= 0,
	AdverseWeatherCondition_VisibilitySubCauseCode_fog	= 1,
	AdverseWeatherCondition_VisibilitySubCauseCode_smoke	= 2,
	AdverseWeatherCondition_VisibilitySubCauseCode_heavySnowfall	= 3,
	AdverseWeatherCondition_VisibilitySubCauseCode_heavyRain	= 4,
	AdverseWeatherCondition_VisibilitySubCauseCode_heavyHail	= 5,
	AdverseWeatherCondition_VisibilitySubCauseCode_lowSunGlare	= 6,
	AdverseWeatherCondition_VisibilitySubCauseCode_sandstorms	= 7,
	AdverseWeatherCondition_VisibilitySubCauseCode_swarmsOfInsects	= 8
} e_AdverseWeatherCondition_VisibilitySubCauseCode;

/* AdverseWeatherCondition-VisibilitySubCauseCode */
typedef long	 AdverseWeatherCondition_VisibilitySubCauseCode_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AdverseWeatherCondition_VisibilitySubCauseCode;
asn_struct_free_f AdverseWeatherCondition_VisibilitySubCauseCode_free;
asn_struct_print_f AdverseWeatherCondition_VisibilitySubCauseCode_print;
asn_constr_check_f AdverseWeatherCondition_VisibilitySubCauseCode_constraint;
ber_type_decoder_f AdverseWeatherCondition_VisibilitySubCauseCode_decode_ber;
der_type_encoder_f AdverseWeatherCondition_VisibilitySubCauseCode_encode_der;
xer_type_decoder_f AdverseWeatherCondition_VisibilitySubCauseCode_decode_xer;
xer_type_encoder_f AdverseWeatherCondition_VisibilitySubCauseCode_encode_xer;
per_type_decoder_f AdverseWeatherCondition_VisibilitySubCauseCode_decode_uper;
per_type_encoder_f AdverseWeatherCondition_VisibilitySubCauseCode_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _AdverseWeatherCondition_VisibilitySubCauseCode_H_ */
#include <asn_internal.h>
