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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.metastore.annotation.MetastoreUnitTest;
import org.apache.hadoop.hive.metastore.conf.MetastoreConf;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * The warehouse-authority rewrite is shared by the JDO and the direct SQL read paths, and is also
 * applied on the write paths so a resolved address never replaces the configured name in the
 * database. Service discovery itself is not exercised here: it is off unless
 * hops.service-discovery.enabled is set, and then the resolver is a pass-through.
 */
@Category(MetastoreUnitTest.class)
public class TestHopsLocationResolver {

  private HopsLocationResolver resolver(boolean enforce, String warehouse) {
    Configuration conf = MetastoreConf.newMetastoreConf();
    MetastoreConf.setVar(conf, MetastoreConf.ConfVars.WAREHOUSE, warehouse);
    MetastoreConf.setBoolVar(conf, MetastoreConf.ConfVars.ENFORCE_WAREHOUSE_AUTHORITY, enforce);
    return new HopsLocationResolver(conf);
  }

  @Test
  public void testAuthorityIsNotRewrittenByDefault() {
    // Off by default: a table on another filesystem must keep pointing at it.
    HopsLocationResolver resolver = resolver(false, "hdfs://namenode.service.consul:8020/apps/hive/warehouse");
    assertEquals("s3a://bucket/data", resolver.resolveLocation("s3a://bucket/data"));
    assertEquals("hdfs://other:8020/data", resolver.enforceWarehouseAuthority("hdfs://other:8020/data"));
  }

  @Test
  public void testForeignAuthorityIsRewrittenWhenEnforced() {
    HopsLocationResolver resolver = resolver(true, "hdfs://namenode.service.consul:8020/apps/hive/warehouse");
    assertEquals("hdfs://namenode.service.consul:8020/data",
        resolver.enforceWarehouseAuthority("hdfs://10.0.0.5:8020/data"));
  }

  @Test
  public void testMatchingAuthorityIsLeftAlone() {
    HopsLocationResolver resolver = resolver(true, "hdfs://namenode.service.consul:8020/apps/hive/warehouse");
    assertEquals("hdfs://namenode.service.consul:8020/data",
        resolver.enforceWarehouseAuthority("hdfs://namenode.service.consul:8020/data"));
  }

  @Test
  public void testLocationWithoutAuthorityIsLeftAlone() {
    HopsLocationResolver resolver = resolver(true, "hdfs://namenode.service.consul:8020/apps/hive/warehouse");
    assertEquals("/apps/hive/warehouse/t", resolver.enforceWarehouseAuthority("/apps/hive/warehouse/t"));
  }

  @Test
  public void testNullAndEmptyAndUnparseableLocationsArePassedThrough() {
    HopsLocationResolver resolver = resolver(true, "hdfs://namenode.service.consul:8020/apps/hive/warehouse");
    assertNull(resolver.resolveLocation(null));
    assertNull(resolver.enforceWarehouseAuthority(null));
    assertEquals("", resolver.resolveLocation(""));
    // A location the URI parser rejects must not fail the metadata operation.
    assertEquals("hdfs://name node:8020/t", resolver.enforceWarehouseAuthority("hdfs://name node:8020/t"));
  }

  @Test
  public void testResolveLocationEnforcesTheAuthority() {
    // resolveLocation is what the read paths call; it has to include the authority rewrite.
    HopsLocationResolver resolver = resolver(true, "hdfs://namenode.service.consul:8020/apps/hive/warehouse");
    assertEquals("hdfs://namenode.service.consul:8020/data",
        resolver.resolveLocation("hdfs://10.0.0.5:8020/data"));
  }
}
