// Copyright (C) 2014-2017 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef VSOMEIP_APPLICATION_HPP
#define VSOMEIP_APPLICATION_HPP

#include <chrono>
#include <memory>
#include <set>
#include <map>
#include <vector>

#include "../../compat/vsomeip/constants.hpp"
#include "../../compat/vsomeip/enumeration_types.hpp"
#include "../../compat/vsomeip/function_types.hpp"
#include "../../compat/vsomeip/handler.hpp"
#include "../../compat/vsomeip/primitive_types.hpp"

namespace vsomeip {

class configuration;
class event;
class payload;
struct policy;

/**
 * \defgroup vsomeip
 *
 * @{
 */

/**
 *
 * \brief This class contains the public API of the vsomeip implementation.
 *
 * Due to its heavy resource footprint, it should exist once per client and can
 * be instantiated using the API of @ref runtime. It manages the lifecycle of
 * the vsomeip client and allocates all resources needed to communicate.
 *
 */
class application {
public:
    virtual ~application() {}

    /**
     *
     * \brief Returns the name of the application as given during creation
     *
     * The application name is used to identify the application. It is either
     * set explicitely when the application object is created or configured by
     * the environment variable VSOMEIP_APPLICATION_NAME.
     *
     * Note: A user application can use several vsomeip application objects in
     * parallel. The application names must be set explicitly in this case
     * because VSOMEIP_APPLICATION_NAME only allows to specify a single name.
     *
     *
     * \return Application name
     *
     */
    virtual const std::string & get_name() const = 0;

    /**
     *
     * \brief Returns the client identifier that was assigned to the
     * application object.
     *
     * Each request sent by and each response sent to the application contain
     * the client identifier as part of the request identifier within the
     * SOME/IP message header. The client identifier can either be configured
     * by the configured as part of the application node within a vsomeip
     * configuration file or is automatically set to an unused client
     * identifier by vsomeip. If the client identifier is automatically set,
     * its high byte will always match the diagnosis address of the device.
     *
     * \return Client ID of application
     *
     */
    virtual client_t get_client() const = 0;

    /**
     *
     * \brief Does nothing.
     *
     * This method exists for compatibility reasons only. It is a null
     * operation and will be removed with the next major vsomeip version.
     *
     */
    virtual void set_configuration(const std::shared_ptr<configuration> _configuration) = 0;

    /**
     *
     * \brief Initializes the application.
     *
     *  The init method must be called first after creating a vsomeip
     *  application and executes the following steps to initialize it:
     * - Loading the configuration from a dynamic module
     *   - Loading the configuration from a .json file or
     *   - Loading the configuration from compiled data (not yet available)
     * - Determining routing configuration and initialization of the routing
     *   itself
     * - Installing signal handlers
     *
     */
    virtual bool init() = 0;

    /**
     *
     * \brief Starts message processing.
     *
     * This method must be called after init to start message processing. It
     * will block until the message processing is terminated using the @ref
     * stop method or by receiving signals. It processes messages received
     * via the sockets and uses registered callbacks to pass them to the user
     * application.
     *
     */
    virtual void start() = 0;

    /**
     *
     * \brief Stops message processing.
     *
     * This method stops message processing. Thus, @ref start will return
     * after a call to stop.
     *
     */
    virtual void stop() = 0;

    /**
     *
     * \brief Offers a SOME/IP service instance.
     *
     * The user application must call this method for each service it offers
     * to register it at the vsomeip routing component, which makes the
     * service visible to interested clients. Dependent on the configuration
     * the service is available internally only or internally and externally.
     * To offer a service to the external network, the configuration must
     * contain a port for the offered service instance. If no such port
     * configuration is provided, the service is not visible outside the
     * device.
     *
     * \param _service Service identifier of the offered service interface.
     * \param _instance Instance identifier of the offered service instance.
     * \param _major Major service version (Default: 0).
     * \param _minor Minor service version (Default: 0).
     *
     */
    virtual void offer_service(service_t _service, instance_t _instance,
            major_version_t _major = DEFAULT_MAJOR, minor_version_t _minor =
                    DEFAULT_MINOR) = 0;

    /**
     *
     * \brief Stops offering a SOME/IP service instance.
     *
     * The user application must call this method to withdraw a service offer.
     *
     * \param _service Service identifier of the offered service interface.
     * \param _instance Instance identifer of the offered service instance.
     * \param _major Major service version (Default: 0).
     * \param _minor Minor service version (Default: 0).
     *
     */
    virtual void stop_offer_service(service_t _service, instance_t _instance,
            major_version_t _major = DEFAULT_MAJOR, minor_version_t _minor =
                    DEFAULT_MINOR) = 0;

    /**
     *
     * \brief Offers a SOME/IP event or field.
     *
     * A user application must call this method for each event/field it wants
     * to offer. The event is registered at the vsomeip routing component that
     * enables other applications to subscribe to the event/field as well as
     * to get and set the field value.
     *
     * \param _service Service identifier of the interface containing the
     * event.
     * \param _instance Instance identifier of the interface containing the
     * event.
     * \param _event Event identifier of the offered event.
     * \param _eventgroups List of eventgroup identifiers of the eventgroups
     * that contain the event.
     * \param _is_field Selector for event or field.
     *
     */
    virtual void offer_event(service_t _service,
            instance_t _instance, event_t _event,
            const std::set<eventgroup_t> &_eventgroups,
            bool _is_field) = 0;

    /**
     *
     * \brief Stops offering a SOME/IP event or field.
     *
     * A user application must call this method to withdraw the offer of an
     * event or field.
     *
     * \param _service Service identifier of the interface that contains the
     * event
     * \param _instance Instance identifier of the interface that contains the
     * event
     * \param _event Event identifier of the offered event.
     *
     */
    virtual void stop_offer_event(service_t _service,
            instance_t _instance, event_t _event) = 0;

    /**
     *
     * \brief Registers the application as client of a service instance.
     *
     * A user application must call this method for each service instance it
     * wants to use. The request is stored within the routing component and the
     * application is registered as client for the service as soon as the
     * service instance becomes available.
     *
     * \param _service Service identifier of the requested service interface.
     * \param _instance Instance identifier of the requested service instance.
     * \param _major Major service version (Default: 0xFF).
     * \param _minor Minor service version (Default: 0xFFFFFF).
     * \param _use_exclusive_proxy Create an IP endpoint that is exclusively
     * used for the communication of this application to the service instance.
     *
     */
    virtual void request_service(service_t _service, instance_t _instance,
            major_version_t _major = ANY_MAJOR,
            minor_version_t _minor = ANY_MINOR,
            bool _use_exclusive_proxy = false) = 0;

    /**
     *
     * \brief Unregister the application as client of a service instance.
     *
     * A user application should call this method if it does not request to
     * use the service instance any longer. The method unregisters the request
     * a the routing component, which removes the service instance from the
     * list of requested service instances if the call releases the last
     * existing request for the service instance. This is important for
     * external service instances, as the SOME/IP Service Discovery can avoid
     * to send unnecessary Find messages.
     *
     * \param _service Service identifier of the offered service interface.
     * \param _instance Instance identifier of the offered service instance.
     *
     */
    virtual void release_service(service_t _service, instance_t _instance) = 0;

    /**
     *
     * \brief Registers the application as user of an event or field.
     *
     * A user application must call this method before being able to receive
     * event or field data. The method registers the event or field at the
     * routing component.
     *
     * \param _service Service identifier of the interface that contains the
     * event.
     * \param _instance Instance identifier of the interface that contains the
     * event.
     * \param _event Event identifier of the event.
     * \param _eventgroups List of Eventgroup identifiers of the eventgroups
     * that contain the event.
     * \param _is_field Pure event (false) or field (true).
     *
     */
    virtual void request_event(service_t _service, instance_t _instance,
            event_t _event, const std::set<eventgroup_t> &_eventgroups,
            bool _is_field) = 0;
    /**
     *
     * \brief Unregister the application as user of an event or field.
     *
     *  Unregister the application as user of an event or field and completely
     *  removes the event/field if the application is the last existing user.
     *
     * \param _service Service identifier of the interface that contains the
     * event or field.
     * \param _instance Instance identifier of the instance that contains the
     * event or field.
     * \param _event Event identifier of the event or field.
     * .
     */
    virtual void release_event(service_t _service, instance_t _instance,
            event_t _event) = 0;

    /**
     *
     * \brief Subscribes to an eventgroup.
     *
     * A user application must call this function to subscribe to an eventgroup.
     * Before calling subscribe it must register all events it interested in by
     * calls to @ref request_event. The method additionally allows to specify
     * a specific event. If a specific event is specified, all other events of
     * the eventgroup are not received by the application.
     *
     * Note: For external services, providing a specific event does not change
     * anything regarding the message routing. The specific event is only used
     * to filter incoming events and to determine which initial events must be
     * sent.
     *
     * \param _service Service identifier of the service that contains the
     * eventgroup.
     * \param _instance Instance identifier of the service that contains the
     * eventgroup.
     * \param _eventgroup Eventgroup identifier of the eventgroup.
     * \param _major Major version number of the service.
     * \param _subscription_type Specifies how the events shall be received.
     * \param _event All (Default) or a specific event.
     *
     */
    virtual void subscribe(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, major_version_t _major = DEFAULT_MAJOR,
            subscription_type_e _subscription_type = subscription_type_e::SU_RELIABLE_AND_UNRELIABLE,
            event_t _event = ANY_EVENT) = 0;

    /**
     *
     * \brief Unsubscribes from an eventgroup.
     *
     * \param _service Service identifier of the service that contains the
     * eventgroup.
     * \param _instance Instance identifier of the service that contains the
     * eventgroup.
     * \param _eventgroup Eventgroup identifier of the eventgroup.
     *
     */
    virtual void unsubscribe(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup) = 0;

    /**
     *
     * \brief Retrieve for the availability of a service instance.
     *
     * If the version is also given, the result will only be true if the
     * service instance is available in that specific version.
     *
     * \param _service Service identifier of the service instance.
     * \param _instance Instance identifier of the service instance.
     * \param _major Major interface version. Use ANY_MAJOR to ignore the
     * major version.
     * \param _minor Minor interface version. Use ANY_MINOR to ignore the
     * minor version.
     *
     */
    virtual bool is_available(service_t _service, instance_t _instance,
            major_version_t _major = DEFAULT_MAJOR, minor_version_t _minor = DEFAULT_MINOR) const = 0;

    /**
     *
     * \brief Sends a message.
     *
     * Serializes the specified message object, determines the taget and sends
     * the message to the target. For requests, the request identifier is
     * automatically built from the client identifier and the session
     * identifier.
     *
     * \param _message Message object.
     * \param _flush If set to true, the message is immediately sent. Otherwise
     * the message might be deferred and sent together with other messages.
     *
     */
    virtual void send(std::shared_ptr<message> _message, bool _flush = true) = 0;

    /**
     *
     * \brief Fire an event or field notification.
     *
     * The specified event is updated with the specified payload data.
     * Dependent on the type of the event, the payload is distributed to all
     * notified clients (always for events, only if the payload has changed
     * for fields).
     *
     * Note: Prior to using this method, @ref offer_event has to be called by
     * the service provider.
     *
     * \param _service Service identifier of the service that contains the
     * event.
     * \param _instance Instance identifier of the service instance that
     * holds the event.
     * \param _event Event identifier of the event.
     * \param _payload Serialized payload of the event.
     *
     */
    virtual void notify(service_t _service, instance_t _instance,
                event_t _event, std::shared_ptr<payload> _payload) const = 0;

    /**
     *
     * \brief Fire an event to a specific client.
     *
     * The specified event is updated with the specified payload data.
     * Dependent on the type of the event, the payload is distributed to all
     * notified clients (always for events, only if the payload has changed
     * for fields).
     *
     * Note: Prior to using this method, @ref offer_event has to be called by
     * the service provider.
     *
     * \param _service Service identifier of the service that contains the
     * event.
     * \param _instance Instance identifier of the service instance that
     * holds the event.
     * \param _event Event identifier of the event.
     * \param _payload Serialized payload of the event.
     * \param _client Target client.
     *
     */
    virtual void notify_one(service_t _service, instance_t _instance,
                event_t _event, std::shared_ptr<payload> _payload,
                client_t _client) const = 0;

    /**
     *
     * \brief Register a state handler with the vsomeip runtime.
     *
     * The state handler tells if this client is successfully [de]registered
     * at the central vsomeip routing component. This is called during the
     * @ref start and @ref stop methods of this class to inform the user
     * application about the registration state.
     *
     * \param _handler Handler function to be called on state change.
     *
     */
    virtual void register_state_handler(state_handler_t _handler) = 0;

    /**
     *
     * \brief Unregister the state handler.
     *
     */
    virtual void unregister_state_handler() = 0;

    /**
     *
     * \brief Registers a handler for the specified method or event.
     *
     * A user application must call this method to register callbacks for
     * for messages that match the specified service, instance, method/event
     * pattern. It is possible to specify wildcard values for all three
     * identifiers arguments.
     *
     * Notes:
     * - Only a single handler can be registered per service, instance,
     *   method/event combination.
     * - A subsequent call will overwrite an existing registration.
     * - Handler registrations containing wildcards can be active in parallel
     *   to handler registrations for specific service, instance, method/event
     *   combinations.
     *
     * \param _service Service identifier of the service that contains the
     * method or event. Can be set to ANY_SERVICE to register a handler for
     * a message independent from a specific service.
     * \param _instance Instance identifier of the service instance that
     * contains the method or event. Can be set to ANY_INSTANCE to register
     * a handler for a message independent from a specific service.
     * \param _method Method/Event identifier of the method/event that is
     * to be handled. Can be set to ANY_METHOD to register a handler for
     * all methods and events.
     * \param _handler Callback that will be called if a message arrives
     * that matches the specified service, instance and method/event
     * parameters.
     *
     */
    virtual void register_message_handler(service_t _service,
            instance_t _instance, method_t _method,
            message_handler_t _handler) = 0;
    /**
     *
     * \brief Unregisters the message handler for the specified service
     * method/event notification.
     *
     * \param _service Service identifier of the service that contains the
     * method or event. Can be set to ANY_SERVICE to unregister a handler for
     * a message independent from a specific service.
     * \param _instance Instance identifier of the service instance that
     * contains the method or event. Can be set to ANY_INSTANCE to unregister
     * a handler for a message independent from a specific service.
     * \param _method Method/Event identifier of the method/event that is
     * to be handled. Can be set to ANY_METHOD to unregister a handler for
     * all methods and events.
     */
    virtual void unregister_message_handler(service_t _service,
            instance_t _instance, method_t _method) = 0;

    /**
     *
     * \brief Register a callback that is called when service instances
     * availability changes.
     *
     * This method allows for the registration of callbacks that are called
     * whenever a service appears or disappears. It is possible to specify
     * wildcards for service, instance and/or version. Additionally, the
     * version specification is optional and defaults to DEFAULT_MAJOR
     * /DEFAULT_MINOR.
     *
     * \param _service Service identifier of the service instance whose
     * availability shall be reported. Can be set to ANY_SERVICE.
     * \param _instance Instance identifier of the service instance whose
     * availability shall be reported. Can be set to ANY_INSTANCE.
     * \param _handler Callback to be called if availability changes.
     * \param _major Major service version. The parameter defaults to
     * DEFAULT_MAJOR and can be set to ANY_MAJOR.
     * \param _minor Minor service version. The parameter defaults to
     * DEFAULT_MINOR and can be set to ANY_MINOR.
     *
     */
    virtual void register_availability_handler(service_t _service,
            instance_t _instance, availability_handler_t _handler,
            major_version_t _major = DEFAULT_MAJOR, minor_version_t _minor = DEFAULT_MINOR) = 0;

    /**
     *
     * \brief Unregister an availability callback.
     *
     * \param _service Service identifier of the service instance whose
     * availability shall be reported. Can be set to ANY_SERVICE.
     * \param _instance Instance identifier of the service instance whose
     * availability shall be reported. Can be set to ANY_INSTANCE.
     * \param _handler Callback to be called if availability changes.
     * \param _major Major service version. The parameter defaults to
     * DEFAULT_MAJOR and can be set to ANY_MAJOR.
     * \param _minor Minor service version. The parameter defaults to
     * DEFAULT_MINOR and can be set to ANY_MINOR.     *
     */
    virtual void unregister_availability_handler(service_t _service,
            instance_t _instance,
            major_version_t _major = DEFAULT_MAJOR, minor_version_t _minor = DEFAULT_MINOR) = 0;

    /**
     *
     * \brief Registers a subscription handler.
     *
     * A subscription handler is called whenever the subscription state of an
     * eventgroup changes. The callback is called with the client identifier
     * and a boolean that indicates whether the client subscribed or
     * unsubscribed.
     *
     * \param _service Service identifier of service instance whose
     * subscription state is to be monitored.
     * \param _instance Instance identifier of service instance whose
     * subscription state is to be monitored.
     * \param _eventgroup Eventgroup identifier of eventgroup whose
     * subscription state is to be monitored.
     * \param _handler Callback that shall be called.
     *
     */
    virtual void register_subscription_handler(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup,
            subscription_handler_t _handler) = 0;

    /**
     *
     * \brief Unregister a subscription handler.
     *
     * \param _service Service identifier of service instance whose
     * subscription state is to be monitored.
     * \param _instance Instance identifier of service instance whose
     * subscription state is to be monitored.
     * \param _eventgroup Eventgroup identifier of eventgroup whose
     * subscription state is to be monitored.
     *
     */
    virtual void unregister_subscription_handler(service_t _service,
                instance_t _instance, eventgroup_t _eventgroup) = 0;

    // [Un]Register handler for subscription errors
    /**
     *
     * \brief Allows for the registration of a subscription error handler.
     *
     * This handler is called whenever a subscription request for an eventgroup
     * was either accepted or rejected. The respective callback is called with
     * ether OK (0x00) or REJECTED (0x07).
     *
     * \param _service Service identifier of service instance whose
     * subscription error state is to be monitored.
     * \param _instance Instance identifier of service instance whose
     * subscription error state is to be monitored.
     * \param _eventgroup Eventgroup identifier of eventgroup whose
     * subscription error state is to be monitored.
     * \param _handler Callback that shall be called.
     *
     */
    virtual void register_subscription_error_handler(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup,
            error_handler_t _handler) = 0;

    /**
     *
     * \brief Removes a registered subscription error callback.
     *
     * \param _service Service identifier of service instance whose
     * error callback shall be removed.
     * \param _instance Instance identifier of service instance whose
     * error callback shall be removed.
     * \param _eventgroup Eventgroup identifier of eventgroup whose
     * error callback shall be removed.
     *
     */
    virtual void unregister_subscription_error_handler(service_t _service,
                instance_t _instance, eventgroup_t _eventgroup) = 0;

    /**
     *
     * \brief Unregister all registered handlers.
     *
     */
    virtual void clear_all_handler() = 0;

    /**
     *
     * \brief This method tells whether or not this application controls the
     * message routing.
     *
     * The application that controls the routing hosts the routing manager
     * and (optionally) loads the Service Discovery component.
     *
     * \return true, if this is the central routing instance, and false
     * otherwise
     *
     */
    virtual bool is_routing() const = 0;

    /**
     *
     * \brief Offers a SOME/IP event or field.
     *
     * A user application must call this method for each event/field it wants
     * to offer. The event is registered at the vsomeip routing component that
     * enables other applications to subscribe to the event/field as well as
     * to get and set the field value.
     *
     * This version of offer_event adds some additional functionalities:
     * - It is possible to configure a cycle time. The notification message of
     *   this event is then resent cyclically.
     * - The parameter _change_resets_cycle is available to control how event
     *   notification works in case the data is updated by the application. If
     *   set to true, an update of the data immediately leads to a
     *   notification. Otherwise, the updated data is sent only after the
     *   expiration of the cycle time.
     * - It is possible to specify callback function that can be used to
     *   implement a predicate that determines whether or not two event values
     *   are considered different. Field notifications are only sent if the
     *   predicate evaluates to true (or if a notify method is called with the
     *   force flag being set).
     *
     * \param _service Service identifier of the interface containing the
     * event.
     * \param _instance Instance identifier of the interface containing the
     * event.
     * \param _event Event identifier of the offered event.
     * \param _eventgroups List of eventgroup identifiers of the eventgroups
     * that contain the event.
     * \param _is_field Selector for event or field.
     * \param _cycle Sets the cycle time of the event. If nonzero, data is
     * resent cyclically after the cycle time expired.
     * \param _change_resets_cycle Tells if a change immediately leads to
     * a notification.
     * \param _epsilon_change_func Predicate that determines if two given
     * payloads are considered different.
     *
     * Note: The different versions of offer_event exist for compatibility
     * reasons. They will be merged with the next major vsomeip version.
     */
    virtual void offer_event(service_t _service,
            instance_t _instance, event_t _event,
            const std::set<eventgroup_t> &_eventgroups,
            bool _is_field,
            std::chrono::milliseconds _cycle,
            bool _change_resets_cycle,
            const epsilon_change_func_t &_epsilon_change_func) = 0;

    /**
     *
     * \brief Fire an event or field notification.
     *
     * The specified event is updated with the specified payload data.
     * Dependent on the type of the event, the payload is distributed to all
     * notified clients (always for events, only if the payload has changed
     * for fields).
     *
     * Note: Prior to using this method, @ref offer_event has to be called by
     * the service provider.
     *
     * \param _service Service identifier of the service that contains the
     * event.
     * \param _instance Instance identifier of the service instance that
     * holds the event.
     * \param _event Event identifier of the event.
     * \param _payload Serialized payload of the event.
     * \param _force Forces the notification to be sent (even if the event
     * is a field and the value did not change).
     *
     * Note: The different versions of notify do exist for compatibility
     * reasons. They will be merged with the next major vsomeip release.
     */
    virtual void notify(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            bool _force) const = 0;

    /**
     *
     * \brief Fire an event or field notification.
     *
     * The specified event is updated with the specified payload data.
     * Dependent on the type of the event, the payload is distributed to all
     * notified clients (always for events, only if the payload has changed
     * for fields).
     *
     * Note: Prior to using this method, @ref offer_event has to be called by
     * the service provider.
     *
     * \param _service Service identifier of the service that contains the
     * event.
     * \param _instance Instance identifier of the service instance that
     * holds the event.
     * \param _event Event identifier of the event.
     * \param _payload Serialized payload of the event.
     * \param _client Target client.
     * \param _force Forces the notification to be sent (even if the event
     * is a field and the value did not change).
     *
     * Note: The different versions of notify_one do exist for compatibility
     * reasons. They will be merged with the next major vsomeip release.
     */
    virtual void notify_one(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            client_t _client, bool _force) const = 0;

    typedef std::map<service_t, std::map<instance_t, std::map<major_version_t, minor_version_t >>> available_t;
    /**
     * \brief Returns all available instances that match the given combination
     * of service, instance and version.
     *
     * This method checks the availability of the service instances that
     * match the specified combination of service, instance and version
     * parameters. If at least one matching service instance is available,
     * the method returns true, otherwise it returns false. All available
     * service instances are returned to the caller by filling the
     * _available parameter.
     *
     * \param _available Map that is filled with the available instances.
     * \param _service Service identifier that specifies which service(s)
     * are checked.
     * \param _instance Instance identifier that specifies which instance(s)
     * are checked.
     * \param _major_version Major version(s) of the service instances that
     * are checked
     * \param _minor_version Minor version(s) of the service instance that
     * are checked
     */
    virtual bool are_available(available_t &_available,
            service_t _service = ANY_SERVICE, instance_t _instance = ANY_INSTANCE,
            major_version_t _major = ANY_MAJOR, minor_version_t _minor = ANY_MINOR) const = 0;

    /**
     *
     * \brief Fire an event or field notification.
     *
     * The specified event is updated with the specified payload data.
     * Dependent on the type of the event, the payload is distributed to all
     * notified clients (always for events, only if the payload has changed
     * for fields).
     *
     * Note: Prior to using this method, @ref offer_event has to be called by
     * the service provider.
     *
     * \param _service Service identifier of the service that contains the
     * event.
     * \param _instance Instance identifier of the service instance that
     * holds the event.
     * \param _event Event identifier of the event.
     * \param _payload Serialized payload of the event.
     * \param _force Forces the notification to be sent (even if the event
     * is a field and the value did not change).
     * \param _flush Must be set to ensure the event is immediately fired.
     *
     * Note: The different versions of notify do exist for compatibility
     * reasons. They will be merged with the next major vsomeip release.
     */
    virtual void notify(service_t _service, instance_t _instance,
            event_t _event, std::shared_ptr<payload> _payload,
            bool _force, bool _flush) const = 0;

    /**
     *
     * \brief Fire an event or field notification.
     *
     * The specified event is updated with the specified payload data.
     * Dependent on the type of the event, the payload is distributed to all
     * notified clients (always for events, only if the payload has changed
     * for fields).
     *
     * Note: Prior to using this method, @ref offer_event has to be called by
     * the service provider.
     *
     * \param _service Service identifier of the service that contains the
     * event.
     * \param _instance Instance identifier of the service instance that
     * holds the event.
     * \param _event Event identifier of the event.
     * \param _payload Serialized payload of the event.
     * \param _client Target client.
     * \param _force Forces the notification to be sent (even if the event
     * is a field and the value did not change).
     * \param _flush Must be set to ensure the event is immediately fired.
     *
     * Note: The different versions of notify_one do exist for compatibility
     * reasons. They will be merged with the next major vsomeip release.
     */
    virtual void notify_one(service_t _service, instance_t _instance,
                event_t _event, std::shared_ptr<payload> _payload,
                client_t _client, bool _force, bool _flush) const = 0;

    /**
     * \brief Set the current routing state.
     *
     *  The routing state impacts the behavior of the SOME/IP Service Discovery component. It
     *  can be set to RUNNING, SUSPENDED, RESUMED, SHUTDOWN or UNKNOWN. Applications only need
     *  to set the routing state if they are responsible for controlling the routing manager.
     *  In most environments the vsomeip daemon is controlling the routing manager.
     *
     * \param _routing_state the current routing state
     */
    virtual  void set_routing_state(routing_state_e _routing_state) = 0;

    /**
     *
     * \brief Unsubscribes from an eventgroup.
     *
     * \param _service Service identifier of the service that contains the
     * eventgroup.
     * \param _instance Instance identifier of the service that contains the
     * eventgroup.
     * \param _eventgroup Eventgroup identifier of the eventgroup.
     * \param _event Event to unsubscribe (pass ANY_EVENT for all events of the eventgroup)
     */
    virtual void unsubscribe(service_t _service, instance_t _instance,
            eventgroup_t _eventgroup, event_t _event) = 0;


    /**
     *
     * \brief Registers a subscription status listener.
     *
     * When registered such a handler it will be called for
     * every application::subscribe call.
     *
     * This method is intended to replace the application::
     * register_subscription_error_handler call in future releases.
     *
     * \param _service Service identifier of the service that is subscribed to.
     * \param _instance Instance identifier of the service that is subscribed to.
     * \param _eventgroup Eventgroup identifier of the eventgroup is subscribed to.
     * \param _event Event indentifier of the event is subscribed to.
     * \param _handler A subscription status handler which will be called by vSomeIP
     * as a follow of application::subscribe.
     */
    virtual void register_subscription_status_handler(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event,
            subscription_status_handler_t _handler) = 0;

    /**
     *
     * \brief Registers a subscription status listener.
     *
     * When registered such a handler it will be called for
     * every application::subscribe call.
     *
     * This method is intended to replace the application::
     * register_subscription_error_handler call in future releases.
     *
     * \param _service Service identifier of the service that is subscribed to.
     * \param _instance Instance identifier of the service that is subscribed to.
     * \param _eventgroup Eventgroup identifier of the eventgroup is subscribed to.
     * \param _event Event indentifier of the event is subscribed to.
     * \param _handler A subscription status handler which will be called by vSomeIP
     * as a follow of application::subscribe.
     * \param _is_selective Flag to enable calling the provided handler if the
     * subscription is answered with a SUBSCRIBE_NACK.
     */
    virtual void register_subscription_status_handler(service_t _service,
            instance_t _instance, eventgroup_t _eventgroup, event_t _event,
            subscription_status_handler_t _handler, bool _is_selective) = 0;

    /**
     *
     * \brief Returns all registered services / instances on this node in an async callback.
     *
     * When called with a handler of type offered_services_handler_t,
     * all at the routing manager registered services on this node get returned in a vector of
     * service / instance pairs depending on the given _offer_type.
     *
     * \param _offer_type type of offered services to be returned (OT_LOCAL = 0x00, OT_REMOTE = 0x01, OT_ALL = 0x02)
     * \param offered_services_handler_t handler which gets called with a vector of service instance pairs that are currently offered
     */
    virtual void get_offered_services_async(offer_type_e _offer_type, offered_services_handler_t _handler) = 0;

    /**
     *
     * \brief Sets a handler to be called cyclically for watchdog monitoring.
     *
     * The handler shall be called in the given interval, but not before start()
     * has been called, and not after call to stop() returned.
     *
     * In case the application is running, i.e. start() succeeded, but the
     * handler will not be invoke within the (approximate) interval it may
     * be assumed that I/O or internal dispatcher threads are non-functional.
     *
     * \remark Accuracy of call interval is limited by clock/timer granularity
     *         or scheduling effects, thus it may underrun or overrun by small
     *         amount.
     *
     * \note Only one handler can be active at the time, thus last handler set
     *       by calling this function will be invoked.
     *
     * \note To disable calling an active handler, invoke this method again,
     *       passing nullptr as _handler and/or std::chrono::seconds::zero()
     *       as _interval.
     *
     * \param _handler A watchdog handler, pass nullptr to deactivate.
     * \param _interval Call interval in seconds, pass std::chrono::seconds::zero() to deactivate.
     */
    virtual void set_watchdog_handler(watchdog_handler_t _handler, std::chrono::seconds _interval) = 0;

   /**
     *
     * \brief Registers a subscription handler.
     *
     * A subscription handler is called whenever the subscription state of an
     * eventgroup changes. The callback is called with the client identifier
     * and a boolean that indicates whether the client subscribed or
     * unsubscribed.
     *
     * \param _service Service identifier of service instance whose
     * subscription state is to be monitored.
     * \param _instance Instance identifier of service instance whose
     * subscription state is to be monitored.
     * \param _eventgroup Eventgroup identifier of eventgroup whose
     * subscription state is to be monitored.
     * \param _handler Callback that shall be called.
     *
     */
    virtual void register_async_subscription_handler(
            service_t _service, instance_t _instance, eventgroup_t _eventgroup,
            async_subscription_handler_t _handler) = 0;

    /**
     *  \brief Enables or disables calling of registered offer acceptance
     *  handler for given IP address
     *
     * This method has only an effect when called on the application acting as
     * routing manager
     *
     *  \param _address IP address for which offer acceptance handler should be
     *  called
     *  \param _path Path which indicates need for offer acceptance
     *  \param _enable enable or disable calling of offer acceptance handler
     */
    virtual void set_offer_acceptance_required(ip_address_t _address,
                                               const std::string _path,
                                               bool _enable) = 0;

    /**
     * \brief Returns all configured IP addresses which require calling of
     * registered offer acceptance handler
     *
     * This method has only an effect when called on the application acting as
     * routing manager
     *
     * \return map with known IP addresses requiring offer acceptance handling
     */
    typedef std::map<ip_address_t, std::string> offer_acceptance_map_type_t;
    virtual offer_acceptance_map_type_t get_offer_acceptance_required() = 0;

    /**
     * \brief Registers a handler which will be called upon reception of
     * a remote offer with the offering ECU's IP address as parameter
     *
     * This method has only an effect when called on the application acting as
     * routing manager
     *
     * \param _handler The handler to be called
     */
    virtual void register_offer_acceptance_handler(
            offer_acceptance_handler_t _handler) = 0;

    /**
     * \brief Registers a handler which will be called upon detection of a
     * reboot of a remote ECU with the remote ECU's IP address as a parameter
     *
     * This method has only an effect when called on the application acting as
     * routing manager
     *
     * \param _handler The handler to be called
     */
    virtual void register_reboot_notification_handler(
            reboot_notification_handler_t _handler) = 0;

    /**
     * \brief Registers a handler which will be called when the routing reached
     * READY state.
     *
     * This method has only an effect when called on the application acting as
     * routing manager
     *
     * \param _handler The handler to be called
     */
    virtual void register_routing_ready_handler(
            routing_ready_handler_t _handler) = 0;

    /**
     * \brief Registers a handler which will be called when the routing state
     * changes.
     *
     * This method has only an effect when called on the application acting as
     * routing manager
     *
     * \param _handler The handler to be called
     */
    virtual void register_routing_state_handler(
            routing_state_handler_t _handler) = 0;

    /**
     * \brief Update service configuration to offer a local service on the
     *        network as well
     *
     *  This function is intended to take the necessary information to offer a
     *  service remotely if it was offered only locally beforehand.
     *  Precondition: The service must already be offered locally before
     *  calling this method.
     *  This function only has an effect if called on an application acting as
     *  routing manager.
     *
     * \param _service Service identifier
     * \param _instance Instance identifier
     * \param _port The port number on which the service should be offered
     * \param _reliable Offer via TCP or UDP
     * \param _magic_cookies_enabled Flag to enable magic cookies
     * \param _offer Offer the service or stop offering it remotely
     */
    virtual bool update_service_configuration(service_t _service,
                                              instance_t _instance,
                                              std::uint16_t _port,
                                              bool _reliable,
                                              bool _magic_cookies_enabled,
                                              bool _offer) = 0;

    /**
     * \brief Update security configuration of routing manager and all local clients
     *        The given handler gets called with "SU_SUCCESS" if the policy for UID
     *        and GID was updated or added successfully. If not all clients did confirm
     *        the update, SU_TIMEOUT is set.
     *
     * \param _uid UID of the policy
     * \param _gid GID of the policy
     * \param _policy The security policy to apply
     * \param _payload serialized security policy object
     * \param _handler handler which gets called after all clients have
     *                 confirmed the policy update
     */
    virtual void update_security_policy_configuration(uint32_t _uid,
                                                      uint32_t _gid,
                                                      std::shared_ptr<policy> _policy,
                                                      std::shared_ptr<payload> _payload,
                                                      security_update_handler_t _handler) = 0;

    /**
     * \brief Remove a security configuration for routing manager and all local clients
     *        The given handler gets called with "SU_SUCCESS" if the policy for UID
     *        and GID was removed successfully. SU_UNKNOWN_USER_ID is set if the
     *        UID and GID was not found. If not all clients did confirm the removal,
     *        SU_TIMEOUT is set.
     *
     * \param _uid UID of the policy to remove
     * \param _gid GID of the policy to remove
     * \param _handler handler which gets called after all clients have
     *                 confirmed the policy removal
     */
    virtual void remove_security_policy_configuration(uint32_t _uid,
                                                      uint32_t _gid,
                                                      security_update_handler_t _handler) = 0;
};

/** @} */

} // namespace vsomeip

#endif // VSOMEIP_APPLICATION_HPP
