/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hive.metastore;


import com.google.common.base.Strings;
import com.google.common.net.InetAddresses;
import com.logicalclocks.servicediscoverclient.Builder;
import com.logicalclocks.servicediscoverclient.ServiceDiscoveryClient;
import com.logicalclocks.servicediscoverclient.exceptions.ServiceDiscoveryException;
import com.logicalclocks.servicediscoverclient.service.Service;
import com.logicalclocks.servicediscoverclient.service.ServiceQuery;
import io.hops.net.ServiceDiscoveryClientFactory;
import org.apache.commons.math3.util.Pair;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.metastore.api.MetaException;

import java.net.URI;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CachedServiceDiscoveryResolver {
  private static final Logger LOG = LoggerFactory.getLogger(CachedServiceDiscoveryResolver.class);
  private final Configuration conf;
  private final ServiceDiscoveryClient client;

  public CachedServiceDiscoveryResolver(Configuration conf) {
    this.conf = conf;
    client = initializeServiceDiscoveryClient();
  }

  public void close() {
    if (client != null) {
      client.close();
    }
  }

  public String resolveLocationURI(String locationURI) throws MetaException {
    // We are not configured to run with service discovery
    if (client == null) {
      return locationURI;
    }

    URI uri = URI.create(locationURI);
    if (Strings.isNullOrEmpty(uri.getHost())) {
      return locationURI;
    }
    if (InetAddresses.isInetAddress(uri.getHost())) {
      return locationURI;
    }
    try {
      Service nn = client.getService(ServiceQuery.of(uri.getHost(), Collections.emptySet()))
          .findAny()
          .orElseThrow(() -> new MetaException("Service Discovery is enabled but could not resolve domain " + uri.getHost()));

      return locationURI.replaceFirst(uri.getHost(), nn.getAddress());
    } catch (ServiceDiscoveryException ex) {
      String msg = "Could not resolve NameNode service with Service Discovery";
      LOG.warn(msg, ex);
      throw new MetaException(ex.getMessage() != null ? ex.getMessage() : msg);
    }
  }

  private ServiceDiscoveryClient initializeServiceDiscoveryClient() {
    if (conf.getBoolean("hops.service-discovery.enabled", false)) {
      ServiceDiscoveryClient dnsResolver = null;
      ServiceDiscoveryClientFactory factory = ServiceDiscoveryClientFactory.getInstance();
      Pair<String, Integer> nameserver = factory.getNameserver(conf);
      try {
        dnsResolver = new Builder(com.logicalclocks.servicediscoverclient.resolvers.Type.DNS)
                .withDnsHost(nameserver.getFirst())
                .withDnsPort(nameserver.getSecond())
                .build();
        Builder cachedDNSResolver = new Builder(com.logicalclocks.servicediscoverclient.resolvers.Type.CACHING)
                .withCacheExpiration(Duration.of(30, ChronoUnit.SECONDS))
                .withServiceDiscoveryClient(dnsResolver);
        return factory.getClient(cachedDNSResolver);
      } catch (ServiceDiscoveryException ex) {
        if (dnsResolver != null) {
          dnsResolver.close();
          throw new RuntimeException("Could not initialize Service Discovery client", ex);
        }
      }
    }
    return null;
  }
}
