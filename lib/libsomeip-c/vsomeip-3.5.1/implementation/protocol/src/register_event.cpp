#include "../include/register_event.hpp"
#include <vsomeip/internal/logger.hpp>

namespace vsomeip_v3 {
namespace protocol {

register_event::register_event(service_t service, instance_t instance,
                    event_t event, event_type_e event_type,
                    bool is_provided, reliability_type_e reliability,
                    bool is_cyclic, uint16_t num_eventg,
                    const std::set<eventgroup_t> &eventgroups):
            service_(service), instance_(instance), event_(event),
            event_type_(event_type), is_provided_(is_provided),
            reliability_(reliability), is_cyclic_(is_cyclic),
            num_eventg_(num_eventg), eventgroups_(eventgroups) {
}

void
register_event::serialize(std::vector<byte_t> &_buffer, size_t &_offset, error_e &_error) const {

    size_t its_size(_offset
                    + sizeof(service_) + sizeof(instance_)
                    + sizeof(event_) + sizeof(event_type_)
                    + sizeof(is_provided_) + sizeof(reliability_)
                    + sizeof(is_cyclic_) + sizeof(num_eventg_));

    // First check: Does the static part of the data fit into the buffer?
    if (_buffer.size() < its_size) {
        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    std::memcpy(&_buffer[_offset], &service_, sizeof(service_));
    _offset += sizeof(service_);
    std::memcpy(&_buffer[_offset], &instance_, sizeof(instance_));
    _offset += sizeof(instance_);
    std::memcpy(&_buffer[_offset], &event_, sizeof(event_));
    _offset += sizeof(event_);
    _buffer[_offset] = static_cast<byte_t>(event_type_);
    _offset += sizeof(event_type_);
    _buffer[_offset] = static_cast<byte_t>(is_provided_);
    _offset += sizeof(is_provided_);
    _buffer[_offset] = static_cast<byte_t>(reliability_);
    _offset += sizeof(reliability_);
    _buffer[_offset] = static_cast<byte_t>(is_cyclic_);
    _offset += sizeof(is_cyclic_);
    std::memcpy(&_buffer[_offset], &num_eventg_, sizeof(num_eventg_));
    _offset += sizeof(num_eventg_);

    // Second check: Does the dynamic part of the data fit into the buffer?
    if (_buffer.size() < _offset + (num_eventg_ * sizeof(eventgroup_t))) {
        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    for (const auto g : eventgroups_) {
        std::memcpy(&_buffer[_offset], &g, sizeof(g));
        _offset += sizeof(g);
    }
}

void
register_event::deserialize(const std::vector<byte_t> &_buffer, size_t &_offset, error_e &_error) {

    size_t its_size(_offset
                    + sizeof(service_) + sizeof(instance_)
                    + sizeof(event_) + sizeof(event_type_)
                    + sizeof(is_provided_) + sizeof(reliability_)
                    + sizeof(is_cyclic_) + sizeof(num_eventg_));

    // First check: Does the buffer contain the full static part of the data?
    if (_buffer.size() < its_size) {
        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    std::memcpy(&service_, &_buffer[_offset], sizeof(service_));
    _offset += sizeof(service_);
    std::memcpy(&instance_, &_buffer[_offset], sizeof(instance_));
    _offset += sizeof(instance_);
    std::memcpy(&event_, &_buffer[_offset], sizeof(event_));
    _offset += sizeof(event_);
    event_type_ = static_cast<event_type_e>(_buffer[_offset]);
    _offset += sizeof(event_type_);
    is_provided_ = static_cast<bool>(_buffer[_offset]);
    _offset += sizeof(is_provided_);
    reliability_ = static_cast<reliability_type_e>(_buffer[_offset]);
    _offset += sizeof(reliability_);
    is_cyclic_ = static_cast<bool>(_buffer[_offset]);
    _offset += sizeof(is_cyclic_);
    std::memcpy(&num_eventg_, &_buffer[_offset], sizeof(num_eventg_));
    _offset += sizeof(num_eventg_);

    // Second check: Does the buffer contain the full dynamic part of the data?
    if (_buffer.size() < _offset + (num_eventg_ * sizeof(eventgroup_t))) {
        _error = error_e::ERROR_NOT_ENOUGH_BYTES;
        return;
    }

    eventgroups_.clear();
    for (size_t i = 0; i < num_eventg_; i++) {
        eventgroup_t its_g;
        std::memcpy(&its_g, &_buffer[_offset], sizeof(its_g));
        _offset += sizeof(its_g);

        eventgroups_.insert(its_g);
    }
}

void
register_event::set_eventgroups(const std::set<eventgroup_t> &_eventgroups) {

    eventgroups_ = _eventgroups;
    num_eventg_ = (uint16_t)eventgroups_.size();
}

} // namespace protocol
} // namespace vsomeip_v3
