#ifndef PATH_HISTORY_HPP_1ITSMS5I
#define PATH_HISTORY_HPP_1ITSMS5I

#include <vanetza/facilities/path_point.hpp>
#include <boost/circular_buffer.hpp>
#include <boost/range/iterator_range.hpp>
#include <cstddef>
#include <list>

namespace vanetza
{
namespace facilities
{

// C2C-CC BSP RS_BSP_318 path history (Method One) parameters
extern const units::Length cTraceAllowableError;
extern const units::Length cTraceMaxDeltaDistance;
extern const units::Angle cTraceDeltaPhi;

/**
 * Implementation of Path History Reference Design (Method One)
 * \see NHTSA Document "VSC-A Final Report: Appendix B-2" from September 2011
 */
class PathHistory
{
public:
    struct Parameters
    {
        units::Length allowable_error = cTraceAllowableError;
        units::Length chord_length_threshold = cTraceMaxDeltaDistance;
        units::Angle small_delta_phi = cTraceDeltaPhi;
        units::Length retention_distance = 500.0 * units::si::meter;
    };

    PathHistory();
    explicit PathHistory(const Parameters& params);

    /**
     * Consider one further path point for inclusion into path history
     * \param a path point, expected to be newer than any previously given point
     */
    void addSample(const PathPoint&);

    /**
     * Get current reference point, i.e. last provided path point
     * \return current reference point (fallback is a default constructed PathPoint)
     */
    const PathPoint& getReferencePoint() const;

    /**
     * Get concise list of path points
     * \note previously given path points are only included if the algorithm
     *       presented in above mentioned document as "Method One" selects them
     * \return list of path points, some given points might be omitted
     */
    const std::list<PathPoint>& getConcisePoints() const { return m_concise; }

    /**
     * Newest concise points covering at least a distance (crossing point included)
     * \param distance minimum distance to cover
     * \return view of the newest concise points
     */
    boost::iterator_range<std::list<PathPoint>::const_iterator>
    getConcisePointsMinLength(units::Length distance) const;

    /// As above but capped at max_points
    boost::iterator_range<std::list<PathPoint>::const_iterator>
    getConcisePointsMinLength(units::Length distance, std::size_t max_points) const;

    /**
     * Newest concise points covering at most a distance (crossing point excluded)
     * \param distance maximum distance to cover
     * \return view of the newest concise points
     */
    boost::iterator_range<std::list<PathPoint>::const_iterator>
    getConcisePointsMaxLength(units::Length distance) const;

    /// As above but capped at max_points
    boost::iterator_range<std::list<PathPoint>::const_iterator>
    getConcisePointsMaxLength(units::Length distance, std::size_t max_points) const;

private:
    void updateConcisePoints();
    void truncateConcisePoints();
    const PathPoint& starting() const;
    const PathPoint& previous() const;
    const PathPoint& next() const;

    Parameters m_params;
    boost::circular_buffer<PathPoint> m_samples;
    std::list<PathPoint> m_concise;
};

} // namespace facilities
} // namespace vanetza

#endif /* PATH_HISTORY_HPP_1ITSMS5I */

