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

import java.io.Closeable;
import java.net.URI;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.metastore.conf.MetastoreConf;
import org.apache.hadoop.hive.metastore.conf.MetastoreConf.ConfVars;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Rewrites the locations the metastore hands out so that they are reachable by clients.
 *
 * <p>Two independent rewrites are applied, in this order:
 * <ol>
 *   <li>the authority is forced to the authority of {@link ConfVars#WAREHOUSE}, when
 *       {@link ConfVars#ENFORCE_WAREHOUSE_AUTHORITY} is on. This is off by default because it
 *       also rewrites locations that legitimately live on another filesystem;</li>
 *   <li>a consul service name in the authority is resolved to an address through service
 *       discovery, so clients that cannot resolve consul names still get a usable location.</li>
 * </ol>
 *
 * <p>Both the JDO and the direct SQL read paths go through {@link #resolveLocation(String)}; the
 * write paths go through {@link #enforceWarehouseAuthority(String)} only, so that an address a
 * client received from service discovery is never persisted back into the metastore in place of
 * the consul name.
 *
 * <p>Rewriting is best-effort: a location that cannot be parsed or resolved is passed through
 * unchanged rather than failing the metadata operation.
 */
public class HopsLocationResolver implements Closeable {
  private static final Logger LOG = LoggerFactory.getLogger(HopsLocationResolver.class);

  private final CachedServiceDiscoveryResolver serviceDiscoveryClient;
  private final String whAuthority;

  public HopsLocationResolver(Configuration conf) {
    String authority = null;
    CachedServiceDiscoveryResolver client = null;
    try {
      if (MetastoreConf.getBoolVar(conf, ConfVars.ENFORCE_WAREHOUSE_AUTHORITY)) {
        String warehouseUri = MetastoreConf.getVar(conf, ConfVars.WAREHOUSE);
        if (warehouseUri != null && !warehouseUri.isEmpty()) {
          authority = URI.create(warehouseUri).getAuthority();
        }
      }
      client = new CachedServiceDiscoveryResolver(conf);
    } catch (Exception e) {
      LOG.warn("HopsFS location resolution is disabled, initialization failed", e);
    }
    this.whAuthority = authority;
    this.serviceDiscoveryClient = client;
  }

  /**
   * Forces the authority of a location to the warehouse authority. Returns {@code location}
   * unchanged when the enforcement is off, when the location carries no authority, or when it
   * already matches.
   */
  public String enforceWarehouseAuthority(String location) {
    if (whAuthority == null || location == null || location.isEmpty()) {
      return location;
    }
    URI uri;
    try {
      uri = URI.create(location);
    } catch (IllegalArgumentException e) {
      return location;
    }
    if (uri.getAuthority() == null || uri.getAuthority().equals(whAuthority)) {
      return location;
    }
    return location.replaceFirst(uri.getAuthority(), whAuthority);
  }

  /**
   * Returns the location as it should be handed to a client: warehouse authority enforced and
   * the consul service name in the authority resolved through service discovery.
   */
  public String resolveLocation(String location) {
    String enforced = enforceWarehouseAuthority(location);
    if (serviceDiscoveryClient == null || enforced == null || enforced.isEmpty()) {
      return enforced;
    }
    try {
      return serviceDiscoveryClient.resolveLocationURI(enforced);
    } catch (Exception e) {
      LOG.warn("Failed to resolve location {}: {}", enforced, e.getMessage());
      return enforced;
    }
  }

  @Override
  public void close() {
    if (serviceDiscoveryClient != null) {
      serviceDiscoveryClient.close();
    }
  }
}
