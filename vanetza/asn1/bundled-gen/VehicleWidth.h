/*
 * Generated by asn1c-0.9.27 (http://lionet.info/asn1c)
 * From ASN.1 module "ITS-Container"
 * 	found in "/home/rieblr/work/car2x/vanetza/vanetza/asn1/cdd_ts102894-2v1.1.1.asn1"
 * 	`asn1c -fcompound-names -gen-PER`
 */

#ifndef	_VehicleWidth_H_
#define	_VehicleWidth_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum VehicleWidth {
	VehicleWidth_tenCentimeters	= 1,
	VehicleWidth_outOfRange	= 61,
	VehicleWidth_unavailable	= 62
} e_VehicleWidth;

/* VehicleWidth */
typedef long	 VehicleWidth_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_VehicleWidth;
asn_struct_free_f VehicleWidth_free;
asn_struct_print_f VehicleWidth_print;
asn_constr_check_f VehicleWidth_constraint;
ber_type_decoder_f VehicleWidth_decode_ber;
der_type_encoder_f VehicleWidth_encode_der;
xer_type_decoder_f VehicleWidth_decode_xer;
xer_type_encoder_f VehicleWidth_encode_xer;
per_type_decoder_f VehicleWidth_decode_uper;
per_type_encoder_f VehicleWidth_encode_uper;

#ifdef __cplusplus
}
#endif

#endif	/* _VehicleWidth_H_ */
#include <asn_internal.h>
