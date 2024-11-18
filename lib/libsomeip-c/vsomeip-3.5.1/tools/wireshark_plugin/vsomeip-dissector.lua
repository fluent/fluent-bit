--[[
    Wireshark Lua vsomeip protocol dissector
    vsomeip-dissector.lua V0.0.1
--]]

protocol_name = 'vsomeip'

vsomeip_protocol = Proto(protocol_name, protocol_name:upper() .. ' Protocol')
vsomeip_command = ProtoField.uint8(protocol_name .. '.command' , "Command", base.HEX)
vsomeip_version = ProtoField.uint16(protocol_name .. '.version' , "Version", base.DEC)
vsomeip_client = ProtoField.uint16(protocol_name .. '.client' , "Client", base.HEX)
vsomeip_size = ProtoField.uint32(protocol_name .. '.size' , "Size", base.DEC)

vsomeip_name = ProtoField.string(protocol_name .. '.name' , "Name")

vsomeip_instance = ProtoField.uint16(protocol_name .. '.instance' , "Instance", base.HEX)
vsomeip_reliable = ProtoField.uint8(protocol_name .. '.reliable' , "Reliable", base.DEC)
vsomeip_crc = ProtoField.bytes(protocol_name .. '.crc' , "CRC", base_HEX)
vsomeip_dstClient = ProtoField.uint16(protocol_name .. '.dstClient' , "Dst Client", base.HEX)
vsomeip_payload = ProtoField.bytes(protocol_name .. '.payload' , "Payload", base_HEX)

vsomeip_service = ProtoField.uint16(protocol_name .. '.service' , "Service", base.HEX)
vsomeip_eventgroup = ProtoField.uint16(protocol_name .. '.eventgroup' , "Eventgroup", base.HEX)
vsomeip_subscriber = ProtoField.uint16(protocol_name .. '.subscriber' , "Subscriber", base.HEX)
vsomeip_notifier = ProtoField.uint16(protocol_name .. '.notifier' , "Notifier", base.HEX)
vsomeip_event = ProtoField.uint16(protocol_name .. '.event' , "Event", base.HEX)
vsomeip_id = ProtoField.uint16(protocol_name .. '.id' , "ID", base.HEX)

vsomeip_provided = ProtoField.uint8(protocol_name .. '.provided' , "Provided", base.DEC)

vsomeip_major = ProtoField.uint8(protocol_name .. '.major' , "Major", base.HEX)
vsomeip_minor = ProtoField.uint32(protocol_name .. '.minor' , "Minor", base.HEX)

vsomeip_offer_type = ProtoField.uint8(protocol_name .. '.offer_type' , "OfferType", base.DEC)

vsomeip_pending_offer_id = ProtoField.uint32(protocol_name .. '.pending_offer_id' , "PendingOfferId", base.HEX)

vsomeip_update_id = ProtoField.uint32(protocol_name .. '.update_id' , "UpdateId", base.HEX)
vsomeip_uid = ProtoField.uint32(protocol_name .. '.uid' , "UID", base.HEX)
vsomeip_gid = ProtoField.uint32(protocol_name .. '.gid' , "GID", base.HEX)
vsomeip_policy_count = ProtoField.uint32(protocol_name .. '.policy_count' , "PoliciesCount", base.HEX)
vsomeip_policy = ProtoField.bytes(protocol_name .. '.policy' , "Policy", base_HEX)

-- TODO Parse filter in VSOMEIP_SUBSCRIBE
vsomeip_filter = ProtoField.bytes(protocol_name .. '.filter' , "Filter", base_HEX)

-- TODO make this a subtree to list all entries in VSOMEIP_ROUTING_INFO
vsomeip_entries = ProtoField.bytes(protocol_name .. '.entries' , "Entries", base_HEX)

-- TODO make this a subtree to list all offered_services in VSOMEIP_OFFERED_SERVICES_RESPONSE
vsomeip_offered_services = ProtoField.bytes(protocol_name .. '.offered_services' , "OfferedServices", base_HEX)

-- TODO make this a subtree to list all configurations in VSOMEIP_CONFIG
vsomeip_configurations = ProtoField.bytes(protocol_name .. '.configurations' , "Configurations", base_HEX)

-- TODO make this a subtree to list all configurations in VSOMEIP_UPDATE_SECURITY_CREDENTIALS
vsomeip_credentials = ProtoField.bytes(protocol_name .. '.credentials' , "Credentials", base_HEX)

-- TODO make this a subtree to list all configurations in VSOMEIP_DISTRIBUTE_SECURITY_POLICIES
vsomeip_policies = ProtoField.bytes(protocol_name .. '.policies' , "Policies", base_HEX)

vsomeip_protocol.fields = {
    vsomeip_command, vsomeip_version,
    vsomeip_client, vsomeip_size,
    vsomeip_name,
    vsomeip_instance, vsomeip_reliable, vsomeip_crc, vsomeip_dstClient, vsomeip_payload,
    vsomeip_service, vsomeip_eventgroup, vsomeip_subscriber, vsomeip_notifier, vsomeip_event, vsomeip_id,
    vsomeip_provided,
    vsomeip_major, vsomeip_minor,
    vsomeip_filter,
    vsomeip_entries
}

function vsomeip_protocol.dissector(buffer, pinfo, tree)
    local length = buffer:len()

    if length < 9 then
        return
    end
    local vsip_start = buffer(0, 4):uint()
    local vsip_end = buffer(length - 4, 4):uint()
    -- Is this a vsomeip packet ? vsip packets start with 0x67376D07 and end with 0x076D3767
    if vsip_start ~= 0x67376D07 or vsip_end ~= 0x076D3767 then
        return
    end

    pinfo.cols.protocol = "vSomeip"

    -- Command
    local command_number = buffer(4, 1)
    local command_name = get_command_name(command_number:uint())

    local subtree = tree:add(vsomeip_protocol, buffer(), "vSomeip (" .. length .. " bytes) " .. command_name)
    subtree:add_le(vsomeip_command, command_number):append_text(" (" .. command_name .. ")")
    pinfo.cols.info = command_name

    if command_name == "VSOMEIP_APPLICATION_LOST"
    or command_name == "VSOMEIP_ID_RESPONSE"
    or command_name == "VSOMEIP_ID_REQUEST"
    or command_name == "VSOMEIP_UNKOWN"
    or length < 11 then
        return
    end

    -- Version
    local command_version = buffer(5, 2)
    subtree:add_le(vsomeip_version, command_version)

    local buffer_cursor = 7
    if command_name ~= "VSOMEIP_SUSPEND" then
        -- Client
        local command_client = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        -- Size
        local command_size = buffer(buffer_cursor, 4)
        buffer_cursor = buffer_cursor + 4
        subtree:add_le(vsomeip_client, command_client)
        subtree:add_le(vsomeip_size, command_size)
        pinfo.cols.info:append(" (" ..command_client(1,1)..command_client(0,1).. ")")
    else
        -- Size
        local command_size = buffer(buffer_cursor, 4)
        buffer_cursor = buffer_cursor + 4
        subtree:add_le(vsomeip_size, command_size)
    end

    -- More Complex commands here (buffer_cursor starts after size)
    if command_name == "VSOMEIP_SEND" or command_name == "VSOMEIP_NOTIFY" or command_name == "VSOMEIP_NOTIFY_ONE" then
        local command_instance = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_reliable = buffer(buffer_cursor, 1)
        local command_reliable_name = get_reliability(command_reliable:uint())
        buffer_cursor = buffer_cursor + 1
        local command_crc = buffer(buffer_cursor, 1)
        buffer_cursor = buffer_cursor + 1
        local command_dstClient = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_payload = buffer(buffer_cursor, length - buffer_cursor - 4)

        subtree:add_le(vsomeip_instance, command_instance)
        subtree:add(vsomeip_reliable, command_reliable):append_text(" (" .. command_reliable_name .. ")")
        subtree:add(vsomeip_crc, command_crc)
        subtree:add_le(vsomeip_dstClient, command_dstClient)
        subtree:add(vsomeip_payload, command_payload)

        pinfo.cols.info:append(" --"..command_reliable_name.."--> (" ..command_dstClient(1,1)..command_dstClient(0,1).. ")")
    elseif command_name == "VSOMEIP_ASSIGN_CLIENT" then
        local command_name = buffer(buffer_cursor, length - buffer_cursor - 4)
        subtree:add(vsomeip_name, command_name)

        pinfo.cols.info:append(" "..command_name)

    elseif command_name == "VSOMEIP_ROUTING_INFO" then
        local command_entries = buffer(buffer_cursor, length - buffer_cursor - 4)

        subtree:add(vsomeip_entries, command_entries)

    elseif command_name == "VSOMEIP_OFFER_SERVICE" or command_name == "VSOMEIP_STOP_OFFER_SERVICE" then
        local command_service = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_instance = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_major = buffer(buffer_cursor, 1)
        buffer_cursor = buffer_cursor + 1
        local command_minor = buffer(buffer_cursor, 4)
        buffer_cursor = buffer_cursor + 4

        subtree:add_le(vsomeip_service, command_service)
        subtree:add_le(vsomeip_instance, command_instance)
        subtree:add_le(vsomeip_major, command_major)
        subtree:add_le(vsomeip_minor, command_minor)

        pinfo.cols.info:append(" [" .. command_service(1,1)..command_service(0,1) ..".".. command_instance(1,1)..command_instance(0,1) .. "]")

    elseif command_name == "VSOMEIP_SUBSCRIBE" then
        local command_service = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_instance = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_eventgroup = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_major = buffer(buffer_cursor, 1)
        buffer_cursor = buffer_cursor + 1
        local command_event = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_id = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2

        subtree:add_le(vsomeip_service, command_service)
        subtree:add_le(vsomeip_instance, command_instance)
        subtree:add_le(vsomeip_eventgroup, command_eventgroup)
        subtree:add(vsomeip_major, command_major)
        subtree:add_le(vsomeip_event, command_event)
        subtree:add_le(vsomeip_id, command_id)
        if (length - buffer_cursor - 4) > 0 then
            local command_filter = buffer(buffer_cursor, length - buffer_cursor - 4)
            subtree:add(vsomeip_filter, command_filter)
        end

        pinfo.cols.info:append(" [" .. command_service(1,1)..command_service(0,1) ..".".. command_instance(1,1)..command_instance(0,1)
                             .. "." .. command_eventgroup(1,1)..command_eventgroup(0,1) .. "." .. command_event(1,1)..command_event(0,1) .. "]")

    elseif command_name == "VSOMEIP_UNSUBSCRIBE" or command_name == "VSOMEIP_EXPIRE" then
        local command_service = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_instance = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_eventgroup = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_event = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_id = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2

        subtree:add_le(vsomeip_service, command_service)
        subtree:add_le(vsomeip_instance, command_instance)
        subtree:add_le(vsomeip_eventgroup, command_eventgroup)
        subtree:add_le(vsomeip_event, command_event)
        subtree:add_le(vsomeip_id, command_id)

        pinfo.cols.info:append(" [" .. command_service(1,1)..command_service(0,1) ..".".. command_instance(1,1)..command_instance(0,1)
                             .. "." .. command_eventgroup(1,1)..command_eventgroup(0,1) .. "." .. command_event(1,1)..command_event(0,1) .. "]")

    elseif command_name == "VSOMEIP_RELEASE_SERVICE" then
        local command_service = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_instance = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2

        subtree:add_le(vsomeip_service, command_service)
        subtree:add_le(vsomeip_instance, command_instance)

        pinfo.cols.info:append(" [" .. command_service(1,1)..command_service(0,1) ..".".. command_instance(1,1)..command_instance(0,1) .. "]")

    elseif command_name == "VSOMEIP_SUBSCRIBE_NACK" or command_name == "VSOMEIP_SUBSCRIBE_ACK" then
        local command_service = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_instance = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_eventgroup = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_subscriber = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_event = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_id = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2

        subtree:add_le(vsomeip_service, command_service)
        subtree:add_le(vsomeip_instance, command_instance)
        subtree:add_le(vsomeip_eventgroup, command_eventgroup)
        subtree:add_le(vsomeip_subscriber, command_subscriber)
        subtree:add_le(vsomeip_event, command_event)
        subtree:add_le(vsomeip_id, command_id)

        pinfo.cols.info:append(" [" .. command_service(1,1)..command_service(0,1) ..".".. command_instance(1,1)..command_instance(0,1)
                             .. "." .. command_eventgroup(1,1)..command_eventgroup(0,1) .. "." .. command_event(1,1)..command_event(0,1)
                             .. "] (" .. command_subscriber(1,1)..command_subscriber(0,1) .. ")")
    elseif command_name == "VSOMEIP_REGISTER_EVENT" then
        local command_entries = buffer(buffer_cursor, length - buffer_cursor - 4)

        subtree:add(vsomeip_entries, command_entries)

    elseif command_name == "VSOMEIP_UNREGISTER_EVENT" then
        local command_service = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_instance = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_notifier = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_provided = buffer(buffer_cursor, 1)
        buffer_cursor = buffer_cursor + 1

        subtree:add_le(vsomeip_service, command_service)
        subtree:add_le(vsomeip_instance, command_instance)
        subtree:add_le(vsomeip_notifier, command_notifier)
        subtree:add(vsomeip_provided, command_provided)

        pinfo.cols.info:append(" [" .. command_service(1,1)..command_service(0,1) ..".".. command_instance(1,1)..command_instance(0,1) .. "]")

    elseif command_name == "VSOMEIP_OFFERED_SERVICES_REQUEST" then
        local command_offer_type = buffer(buffer_cursor, 1)
        local command_offer_type_name = get_offer_type(command_offer_type:uint())

        subtree:add(vsomeip_offer_type, command_offer_type):append_text(" (" .. command_offer_type_name .. ")")

        pinfo.cols.info:append(" (" .. command_offer_type_name .. ")")
    elseif command_name == "VSOMEIP_OFFERED_SERVICES_RESPONSE" then
        local command_offered_services = buffer(buffer_cursor, length - buffer_cursor - 4)

        subtree:add(vsomeip_offered_services, command_offered_services)

    elseif command_name == "VSOMEIP_UNSUBSCRIBE_ACK" then
        local command_service = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_instance = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_eventgroup = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2
        local command_id = buffer(buffer_cursor, 2)
        buffer_cursor = buffer_cursor + 2

        subtree:add_le(vsomeip_service, command_service)
        subtree:add_le(vsomeip_instance, command_instance)
        subtree:add_le(vsomeip_eventgroup, command_eventgroup)
        subtree:add_le(vsomeip_id, command_id)

        pinfo.cols.info:append(" [" .. command_service(1,1)..command_service(0,1) ..".".. command_instance(1,1)..command_instance(0,1)
                             .. "." .. command_eventgroup(1,1)..command_eventgroup(0,1) .. "]")
    elseif command_name == "VSOMEIP_RESEND_PROVIDED_EVENTS" then
        local command_pending_offer_id = buffer(buffer_cursor, 4)
        buffer_cursor = buffer_cursor + 4

        subtree:add_le(vsomeip_pending_offer_id, command_pending_offer_id)

    elseif command_name == "VSOMEIP_UPDATE_SECURITY_POLICY" or command_name == "VSOMEIP_UPDATE_SECURITY_POLICY_INT" then
        local command_update_id = buffer(buffer_cursor, 4)
        buffer_cursor = buffer_cursor + 4
        local command_offered_services = buffer(buffer_cursor, length - buffer_cursor - 4)

        subtree:add_le(vsomeip_update_id, command_update_id)
        subtree:add(vsomeip_offered_services, command_offered_services)

    elseif command_name == "VSOMEIP_UPDATE_SECURITY_POLICY_RESPONSE" or command_name == "VSOMEIP_REMOVE_SECURITY_POLICY_RESPONSE" then
        local command_update_id = buffer(buffer_cursor, 4)

        subtree:add_le(vsomeip_update_id, command_update_id)
    elseif command_name == "VSOMEIP_REMOVE_SECURITY_POLICY" then
        local command_update_id = buffer(buffer_cursor, 4)
        buffer_cursor = buffer_cursor + 4
        local command_uid = buffer(buffer_cursor, 4)
        buffer_cursor = buffer_cursor + 4
        local command_gid = buffer(buffer_cursor, 4)
        buffer_cursor = buffer_cursor + 4

        subtree:add_le(vsomeip_update_id, command_update_id)
        subtree:add_le(vsomeip_uid, command_uid)
        subtree:add_le(vsomeip_gid, command_gid)

    elseif command_name == "VSOMEIP_UPDATE_SECURITY_CREDENTIALS" then
        local command_credentials = buffer(buffer_cursor, length - buffer_cursor - 4)

        subtree:add(vsomeip_credentials, command_credentials)

    elseif command_name == "VSOMEIP_DISTRIBUTE_SECURITY_POLICIES" then
        local command_policy_count = buffer(buffer_cursor, 4)
        buffer_cursor = buffer_cursor + 4
        local command_policies = buffer(buffer_cursor, length - buffer_cursor - 4)

        subtree:add_le(vsomeip_policy_count, command_policy_count)
        subtree:add(vsomeip_policies, command_policies)
    elseif command_name == "VSOMEIP_CONFIG" then
        local command_configurations = buffer(buffer_cursor, length - buffer_cursor - 4)

        subtree:add(vsomeip_configurations, command_configurations)
    end
end

DissectorTable.get('tcp.port'):add('1-65535', vsomeip_protocol)

function get_command_name(cmd)
    local cmd_name = "VSOMEIP_UNKOWN"

    -- ¯\_(ツ)_/¯
        if cmd == 0x00 then cmd_name = "VSOMEIP_ASSIGN_CLIENT"
    elseif cmd == 0x01 then cmd_name = "VSOMEIP_ASSIGN_CLIENT_ACK"
    elseif cmd == 0x02 then cmd_name = "VSOMEIP_REGISTER_APPLICATION"
    elseif cmd == 0x03 then cmd_name = "VSOMEIP_DEREGISTER_APPLICATION"
    elseif cmd == 0x04 then cmd_name = "VSOMEIP_APPLICATION_LOST"
    elseif cmd == 0x05 then cmd_name = "VSOMEIP_ROUTING_INFO"
    elseif cmd == 0x06 then cmd_name = "VSOMEIP_REGISTERED_ACK"
    elseif cmd == 0x07 then cmd_name = "VSOMEIP_PING"
    elseif cmd == 0x08 then cmd_name = "VSOMEIP_PONG"
    elseif cmd == 0x10 then cmd_name = "VSOMEIP_OFFER_SERVICE"
    elseif cmd == 0x11 then cmd_name = "VSOMEIP_STOP_OFFER_SERVICE"
    elseif cmd == 0x12 then cmd_name = "VSOMEIP_SUBSCRIBE"
    elseif cmd == 0x13 then cmd_name = "VSOMEIP_UNSUBSCRIBE"
    elseif cmd == 0x14 then cmd_name = "VSOMEIP_REQUEST_SERVICE"
    elseif cmd == 0x15 then cmd_name = "VSOMEIP_RELEASE_SERVICE"
    elseif cmd == 0x16 then cmd_name = "VSOMEIP_SUBSCRIBE_NACK"
    elseif cmd == 0x17 then cmd_name = "VSOMEIP_SUBSCRIBE_ACK"
    elseif cmd == 0x18 then cmd_name = "VSOMEIP_SEND"
    elseif cmd == 0x19 then cmd_name = "VSOMEIP_NOTIFY"
    elseif cmd == 0x1A then cmd_name = "VSOMEIP_NOTIFY_ONE"
    elseif cmd == 0x1B then cmd_name = "VSOMEIP_REGISTER_EVENT"
    elseif cmd == 0x1C then cmd_name = "VSOMEIP_UNREGISTER_EVENT"
    elseif cmd == 0x1D then cmd_name = "VSOMEIP_ID_RESPONSE"
    elseif cmd == 0x1E then cmd_name = "VSOMEIP_ID_REQUEST"
    elseif cmd == 0x1F then cmd_name = "VSOMEIP_OFFERED_SERVICES_REQUEST"
    elseif cmd == 0x20 then cmd_name = "VSOMEIP_OFFERED_SERVICES_RESPONSE"
    elseif cmd == 0x21 then cmd_name = "VSOMEIP_UNSUBSCRIBE_ACK"
    elseif cmd == 0x22 then cmd_name = "VSOMEIP_RESEND_PROVIDED_EVENTS"
    elseif cmd == 0x23 then cmd_name = "VSOMEIP_UPDATE_SECURITY_POLICY"
    elseif cmd == 0x24 then cmd_name = "VSOMEIP_UPDATE_SECURITY_POLICY_RESPONSE"
    elseif cmd == 0x25 then cmd_name = "VSOMEIP_REMOVE_SECURITY_POLICY"
    elseif cmd == 0x26 then cmd_name = "VSOMEIP_REMOVE_SECURITY_POLICY_RESPONSE"
    elseif cmd == 0x27 then cmd_name = "VSOMEIP_UPDATE_SECURITY_CREDENTIALS"
    elseif cmd == 0x28 then cmd_name = "VSOMEIP_DISTRIBUTE_SECURITY_POLICIES"
    elseif cmd == 0x29 then cmd_name = "VSOMEIP_UPDATE_SECURITY_POLICY_INT"
    elseif cmd == 0x2A then cmd_name = "VSOMEIP_EXPIRE"
    elseif cmd == 0x30 then cmd_name = "VSOMEIP_SUSPEND"
    elseif cmd == 0x31 then cmd_name = "VSOMEIP_CONFIG"
    end

  return cmd_name
end

function get_reliability(reliable)
    if reliable == 0 then
        return "UDP"
    else
        return "TCP"
    end
end

function get_offer_type(offer)
    if offer == 0 then
        return "LOCAL"
    elseif offer == 1 then
        return "REMOTE"
    elseif offer == 2 then
        return "ALL"
    else
        return "UNKOWN"
    end
end
