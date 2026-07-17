#pragma once
#include <vanetza/facilities/path_history.hpp>
#include <vanetza/facilities/path_point.hpp>
#include <chrono>
#include <type_traits>

namespace vanetza
{
namespace facilities
{

// C2C-CC BSP CAM trace limits (RS_BSP_318)
static const units::Length cCamTraceMinLength = 200.0 * units::si::meter;
static constexpr std::size_t cCamTraceMaxPoints = 23;

template<typename SomePathSequence, typename SomePathPoint>
void copy(const facilities::PathHistory& src, SomePathSequence& dest,
        units::Length min_distance = cCamTraceMinLength, std::size_t max_points = cCamTraceMaxPoints)
{
    using SomePathDeltaTime = typename std::remove_pointer<decltype(SomePathPoint::pathDeltaTime)>::type;

    static const auto scDeltaTimeStepLength = boost::posix_time::milliseconds(10);
    static const auto scMaxDeltaTime = scDeltaTimeStepLength * 65535;

    const facilities::PathPoint& ref = src.getReferencePoint();

    for (const PathPoint& point : src.getConcisePointsMinLength(min_distance, max_points)) {
        auto delta_time = ref.time - point.time; // positive: point is in past
        auto delta_latitude = round(point.latitude - ref.latitude, tenth_microdegree); // positive: point is north
        auto delta_longitude = round(point.longitude - ref.longitude, tenth_microdegree); // positive: point is east

        if (delta_latitude < -131071 || delta_latitude > 131071) {
            continue; // delta latitude not encodable
        } else if (delta_longitude < -131071 || delta_longitude > 131071) {
            continue; // delta longitude not encodable
        } else if (delta_time >= scDeltaTimeStepLength && delta_time <= scMaxDeltaTime) {
            SomePathPoint* path_point = asn1::allocate<SomePathPoint>();
            path_point->pathPosition.deltaLatitude = delta_latitude;
            path_point->pathPosition.deltaLongitude = delta_longitude;
            path_point->pathPosition.deltaAltitude = DeltaAltitude::DeltaAltitude_unavailable;

            path_point->pathDeltaTime = asn1::allocate<SomePathDeltaTime>();
            *(path_point->pathDeltaTime) = delta_time.total_milliseconds() / scDeltaTimeStepLength.total_milliseconds();

            ASN_SEQUENCE_ADD(&dest, path_point);
        }
    }
}

} // namespace facilities
} // namespace vanetza
