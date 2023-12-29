#ifndef CBM_HPP_ZAYZK69S
#define CBM_HPP_ZAYZK69S

#include <vanetza/asn1/asn1c_conversion.hpp>
#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/asn1/its/CBM.h>

namespace vanetza
{
namespace asn1
{

class Cbm : public asn1c_per_wrapper<CBM_t>
{
public:
	using wrapper = asn1c_per_wrapper<CBM_t>;
	Cbm() : wrapper(asn_DEF_CBM) {}
};

} // namespace asn1
} // namespace vanetza

#endif /* CBM_HPP_ZAYZK69S */

