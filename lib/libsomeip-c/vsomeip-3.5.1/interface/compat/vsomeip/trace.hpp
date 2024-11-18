// Copyright (C) 2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#ifndef VSOMEIP_TRACE_HPP_
#define VSOMEIP_TRACE_HPP_

#include <memory>
#include <vector>

#include "../../compat/vsomeip/constants.hpp"
#include "../../compat/vsomeip/primitive_types.hpp"

namespace vsomeip {
/**
 * \defgroup vsomeip
 *
 * @{
 */
namespace trace {

/**
 * \brief Unique identifier for trace filters.
 */
typedef uint32_t filter_id_t;

/**
 * \brief Error value.
 */
extern const filter_id_t FILTER_ID_ERROR;

/**
 * \brief The default channel id "TC".
 */
extern const char *VSOMEIP_TC_DEFAULT_CHANNEL_ID;

/**
 * \brief Filters contain at least one match that specified
 * which messages are filtered.
 */
typedef std::tuple<service_t, instance_t, method_t> match_t;

/**
 * \brief Representation of a DLT trace channel.
 *
 * A trace channel contains one or more filters that specify the
 * messages that are forwarded to the trace.
 */
class channel {
public:
    virtual ~channel() {};

    /**
     * \brief Get the identifier of the channel.
     *
     * \return Channel identifier.
     */
    virtual std::string get_id() const = 0;

    /**
     * \brief Get the name of the channel.
     *
     * \return Channel name.
     */
    virtual std::string get_name() const = 0;

    /**
     * \brief Add a filter to the channel.
     *
     * Add a simple filter containing a single match.
     *
     * Note: The match is allowed to contain wildcards
     * (ANY_INSTANCE, ANY_SERVICE, ANY_METHOD).
     *
     * \param _match The tuple specifying the matching messages.
     * \param _is_positive True for positive filters,
     * false for negative filters. Default value is true.
     *
     * \return Filter identifier of the added filter or
     * FILTER_ID_ERROR if adding failed.
     */
    virtual filter_id_t add_filter(
            const match_t &_match,
            bool _is_positive = true) = 0;

    /**
     * \brief Add a filter to the channel.
     *
     * Add a filter containing a list of matches to the
     * channel. The filter matches if at least on of the
     * matches corresponds to a message.
     *
     * Note: The matches are allowed to contain wildcards
     * (ANY_INSTANCE, ANY_SERVICE, ANY_METHOD).
     *
     * \param _matches List of tuples specifying the matching messages.
     * \param _is_positive True for positive filters,
     * false for negative filters. Default value is true.
     *
     * \return Filter identifier of the added filter or
     * FILTER_ID_ERROR if adding failed.
     */
    virtual filter_id_t add_filter(
            const std::vector<match_t> &_matches,
            bool _is_positive = true) = 0;

    /**
     * \brief Add a filter to the channel.
     *
     * Add a filter containing a matches range to the
     * channel. The filter matches if the message identifiers
     * lie within the range specified by from and to. Thus,
     * the messages service identifier is greater equal than
     * the service identifier specified in from and less equal
     * than the service identifier specified in to.
     *
     * Note: from and to must not contain wildcards
     * (ANY_INSTANCE, ANY_SERVICE, ANY_METHOD).
     *
     * \param _from Tuples specifying the matching message with
     * the smallest identifiers.
     * \param _from Tuples specifying the matching message with
     * the greatest identifiers.
     * \param _is_positive True for positive filters,
     * false for negative filters. Default value is true.
     *
     * \return Filter identifier of the added filter or
     * FILTER_ID_ERROR if adding failed.
     */
    virtual filter_id_t add_filter(
            const match_t &_from, const match_t &_to,
            bool _is_positive = true) = 0;

    /**
     * \brief Remove a filter from the channel.
     *
     * Remove the filter with the given filter identifier
     * from the channel.
     *
     * \param _id Filter identifier of the filter that shall
     * be removed.
     */
    virtual void remove_filter(
            filter_id_t _id) = 0;
};

/**
 * \brief Singleton class to connect to the DLT tracing.
 *
 * The main configuration class of the DLT tracing. It holds
 * the trace channels which determine the messages that are
 * forwarded to the trace.
 */
class connector {
public:
    /**
     * \brief Get access to the connector.
     *
     * \return Shared pointer to the singleton object.
     */
    static std::shared_ptr<connector> get();

    virtual ~connector() {};

    /**
     * \brief Add a trace channel to the connector.
     *
     * Creates a trace channel with the given identifier and name
     * and adds it to the connector.
     *
     * \param _id Id of the trace channel.
     * \param _name Name of the trace channel
     *
     * \return Shared pointer to the created trace channel or
     * nullptr if the trace channel could not be created because
     * another trace channel with the given identifier does
     * already exist.
     */
    virtual std::shared_ptr<channel> add_channel(
            const std::string &_id,
            const std::string &_name) = 0;

    /**
     * \brief Remove a trace channel from the connector.
     *
     *  Removes the trace channel with the given identifier from
     *  the connector.
     *
     *  \param _id Identifier of a trace channel.
     *
     *  \return True of the trace channel was removed, False if
     *  it could not be removed, because it is the default trace
     *  channel.
     */
    virtual bool remove_channel(
            const std::string &_id) = 0;

    /**
     * \brief Get a trace channel from the connector.
     *
     * \param _id Identifier of the trace channel to be returned.
     * Optional argument that is predefined with the identifier
     * of the default trace channel.
     *
     * \return Shared pointer to the created trace channel or
     * nullptr if the trace channel does not exist.
     */
    virtual std::shared_ptr<channel> get_channel(
            const std::string &_id = VSOMEIP_TC_DEFAULT_CHANNEL_ID) const = 0;
};

} // namespace trace

/** @} */

} // namespace vsomeip

#endif // VSOMEIP_CONSTANTS_HPP
