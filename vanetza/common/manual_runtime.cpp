#include "manual_runtime.hpp"
#include <cassert>

namespace vanetza
{

ManualRuntime::ManualRuntime(Clock::time_point init) : m_now(init)
{
}

void ManualRuntime::schedule(Clock::time_point tp, const Callback& cb, const void* scope)
{
	std::lock_guard<std::mutex> lock(m_mutex);
    m_queue.emplace(queue_type::value_type { tp, cb, scope });
}

void ManualRuntime::schedule(Clock::duration d, const Callback& cb, const void* scope)
{
    schedule(m_now + d, cb, scope);
}

void ManualRuntime::cancel(const void* scope)
{
    if (scope) {
    	std::lock_guard<std::mutex> lock(m_mutex);
        auto scope_match_range = m_queue.get<by_scope>().equal_range(scope);
        m_queue.get<by_scope>().erase(scope_match_range.first, scope_match_range.second);
    }
}

Clock::time_point ManualRuntime::next()
{
    Clock::time_point next_tp = Clock::time_point::max();
	{
    	std::lock_guard<std::mutex> lock(m_mutex);
    	if (!m_queue.empty()) {
			next_tp = m_queue.get<by_deadline>().begin()->deadline;
		}
	}
    return next_tp;
}

Clock::time_point ManualRuntime::now() const
{
	std::lock_guard<std::mutex> lock(m_mutex);
    return m_now;
}

void ManualRuntime::trigger(Clock::time_point tp)
{
	{
    	std::lock_guard<std::mutex> lock(m_mutex);
		if (tp >= m_now) { // This is needed for thread-safe usage in high load
			m_now = tp;
		}
	}
    trigger();
}

void ManualRuntime::trigger(Clock::duration d)
{
  {
   		std::lock_guard<std::mutex> lock(m_mutex);
   		m_now += d;
   }
    trigger();
}

void ManualRuntime::trigger()
{
    while (true) {
        Callback cb;
        Clock::time_point deadline;

        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_queue.empty()) {
                break;
            }

            auto top = m_queue.get<by_deadline>().begin();
            deadline = top->deadline;

            if (deadline <= m_now) {
                cb = top->callback;
                m_queue.get<by_deadline>().erase(top);
            } else {
                break;
            }
        }

        if (cb) {
            cb(deadline);
        }
    }
}

void ManualRuntime::reset(Clock::time_point tp)
{
    m_now = tp;
    queue_type queue;
    swap(queue, m_queue);

    // invoke all callbacks once so they can re-schedule
    for (auto& item : queue) {
        const auto& deadline = item.deadline;
        auto& callback = item.callback;
        // callback might modify m_queue
        callback(deadline);
    }
}

} // namespace vanetza
