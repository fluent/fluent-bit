#ifndef VSOMEIP_V3_PROTOCOL_REGISTER_EVENT_HPP_
#define VSOMEIP_V3_PROTOCOL_REGISTER_EVENT_HPP_

#include <set>
#include <vector>
#include <vsomeip/constants.hpp>
#include <cstring>

#include "protocol.hpp"
#include <vsomeip/enumeration_types.hpp>
#include <vsomeip/primitive_types.hpp>

namespace vsomeip_v3 {
namespace protocol {

class register_event {
public:
    register_event(service_t service = ANY_SERVICE, instance_t instance = ANY_INSTANCE,
                    event_t event = ANY_EVENT, event_type_e event_type = event_type_e::ET_UNKNOWN,
                    bool is_provided = false, reliability_type_e reliability = reliability_type_e::RT_UNKNOWN,
                    bool is_cyclic = false, uint16_t num_eventg = 0,
                    const std::set<eventgroup_t> &eventgroups = std::set<eventgroup_t>());
    void serialize(std::vector<byte_t> &_buffer, size_t &_offset, error_e &_error) const;
    void deserialize(const std::vector<byte_t> &_buffer, size_t &_offset, error_e &_error);

    service_t get_service() const  { return service_; }
    void set_service(service_t _service) { service_ = _service; }

    instance_t get_instance() const  { return instance_; }
    void set_instance(instance_t _instance) { instance_ = _instance; }

    event_t get_event() const  { return event_; }
    void set_event(event_t _event) { event_ = _event; }

    event_type_e get_event_type() const  { return event_type_; }
    void set_event_type(event_type_e _event_type) { event_type_ = _event_type; }

    bool is_provided() const { return is_provided_; }
    void set_provided(bool _is_provided) { is_provided_ = _is_provided; }

    reliability_type_e get_reliability() const { return reliability_; }
    void set_reliability(reliability_type_e _reliability) { reliability_ = _reliability; }

    bool is_cyclic() const { return is_cyclic_; }
    void set_cyclic(bool _cyclic) { is_cyclic_ = _cyclic; }

    uint16_t get_num_eventgroups() const { return num_eventg_; }

    std::set<eventgroup_t> get_eventgroups() const { return eventgroups_; }
    void set_eventgroups(const std::set<eventgroup_t> &_eventgroups);

private:
    service_t service_;
    instance_t instance_;
    event_t event_;
    event_type_e event_type_;
    bool is_provided_;
    reliability_type_e reliability_;
    bool is_cyclic_;
    uint16_t num_eventg_;
    std::set<eventgroup_t> eventgroups_;
};

} // namespace protocol
} // namespace vsomeip_v3

#endif // VSOMEIP_V3_PROTOCOL_REGISTER_EVENT_HPP_
