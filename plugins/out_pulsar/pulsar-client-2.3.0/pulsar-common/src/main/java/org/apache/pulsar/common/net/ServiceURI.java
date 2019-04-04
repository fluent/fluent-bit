/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pulsar.common.net;


import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

import com.google.common.base.CharMatcher;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;
import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang.StringUtils;

/**
 * ServiceURI represents service uri within pulsar cluster.
 *
 * <p>This file is based on
 * {@link https://github.com/apache/bookkeeper/blob/master/bookkeeper-common/src/main/java/org/apache/bookkeeper/common/net/ServiceURI.java}
 */
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
@EqualsAndHashCode
public class ServiceURI {

    private static final String BINARY_SERVICE = "pulsar";
    private static final String HTTP_SERVICE = "http";
    private static final String HTTPS_SERVICE = "https";
    private static final String SSL_SERVICE = "ssl";

    private static final int BINARY_PORT = 6650;
    private static final int BINARY_TLS_PORT = 6651;
    private static final int HTTP_PORT = 8080;
    private static final int HTTPS_PORT = 8443;

    /**
     * Create a service uri instance from a uri string.
     *
     * @param uriStr service uri string
     * @return a service uri instance
     * @throws NullPointerException if {@code uriStr} is null
     * @throws IllegalArgumentException if the given string violates RFC&nbsp;2396
     */
    public static ServiceURI create(String uriStr) {
        checkNotNull(uriStr, "service uri string is null");

        // a service uri first should be a valid java.net.URI
        URI uri = URI.create(uriStr);

        return create(uri);
    }

    /**
     * Create a service uri instance from a {@link URI} instance.
     *
     * @param uri {@link URI} instance
     * @return a service uri instance
     * @throws NullPointerException if {@code uriStr} is null
     * @throws IllegalArgumentException if the given string violates RFC&nbsp;2396
     */
    public static ServiceURI create(URI uri) {
        checkNotNull(uri, "service uri instance is null");

        String serviceName;
        final String[] serviceInfos;
        String scheme = uri.getScheme();
        if (null != scheme) {
            scheme = scheme.toLowerCase();
            final String serviceSep = "+";
            String[] schemeParts = StringUtils.split(scheme, serviceSep);
            serviceName = schemeParts[0];
            serviceInfos = new String[schemeParts.length - 1];
            System.arraycopy(schemeParts, 1, serviceInfos, 0, serviceInfos.length);
        } else {
            serviceName = null;
            serviceInfos = new String[0];
        }

        String userAndHostInformation = uri.getAuthority();
        checkArgument(!Strings.isNullOrEmpty(userAndHostInformation),
            "authority component is missing in service uri : " + uri);

        String serviceUser;
        List<String> serviceHosts;
        int atIndex = userAndHostInformation.indexOf('@');
        Splitter splitter = Splitter.on(CharMatcher.anyOf(",;"));
        if (atIndex > 0) {
            serviceUser = userAndHostInformation.substring(0, atIndex);
            serviceHosts = splitter.splitToList(userAndHostInformation.substring(atIndex + 1));
        } else {
            serviceUser = null;
            serviceHosts = splitter.splitToList(userAndHostInformation);
        }
        serviceHosts = serviceHosts
            .stream()
            .map(host -> validateHostName(serviceName, serviceInfos, host))
            .collect(Collectors.toList());

        String servicePath = uri.getPath();
        checkArgument(null != servicePath,
            "service path component is missing in service uri : " + uri);

        return new ServiceURI(
            serviceName,
            serviceInfos,
            serviceUser,
            serviceHosts.toArray(new String[serviceHosts.size()]),
            servicePath,
            uri);
    }

    private static String validateHostName(String serviceName,
                                           String[] serviceInfos,
                                           String hostname) {
        String[] parts = hostname.split(":");
        if (parts.length >= 3) {
            throw new IllegalArgumentException("Invalid hostname : " + hostname);
        } else if (parts.length == 2) {
            try {
                Integer.parseUnsignedInt(parts[1]);
            } catch (NumberFormatException nfe) {
                throw new IllegalArgumentException("Invalid hostname : " + hostname);
            }
            return hostname;
        } else if (parts.length == 1) {
            return hostname + ":" + getServicePort(serviceName, serviceInfos);
        } else {
            return hostname;
        }
    }

    private final String serviceName;
    private final String[] serviceInfos;
    private final String serviceUser;
    private final String[] serviceHosts;
    private final String servicePath;
    private final URI uri;

    public String[] getServiceInfos() {
        return serviceInfos;
    }

    public String[] getServiceHosts() {
        return serviceHosts;
    }

    public String getServiceScheme() {
        if (null == serviceName) {
            return null;
        } else {
            if (serviceInfos.length == 0) {
                return serviceName;
            } else {
                return serviceName + "+" + StringUtils.join(serviceInfos, '+');
            }
        }
    }

    private static int getServicePort(String serviceName, String[] serviceInfos) {
        int port;
        switch (serviceName.toLowerCase()) {
            case BINARY_SERVICE:
                if (serviceInfos.length == 0) {
                    port = BINARY_PORT;
                } else if (serviceInfos.length == 1 && serviceInfos[0].toLowerCase().equals(SSL_SERVICE)) {
                    port = BINARY_TLS_PORT;
                } else {
                    throw new IllegalArgumentException("Invalid pulsar service : " + serviceName + "+" + serviceInfos);
                }
                break;
            case HTTP_SERVICE:
                port = HTTP_PORT;
                break;
            case HTTPS_SERVICE:
                port = HTTPS_PORT;
                break;
            default:
                throw new IllegalArgumentException("Invalid pulsar service : " + serviceName);
        }
        return port;
    }

}
