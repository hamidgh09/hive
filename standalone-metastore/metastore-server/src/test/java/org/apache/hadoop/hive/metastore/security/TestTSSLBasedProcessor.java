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
package org.apache.hadoop.hive.metastore.security;

import io.hops.security.HopsX509AuthenticationException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hive.metastore.annotation.MetastoreUnitTest;
import org.apache.hadoop.hive.metastore.api.ThriftHiveMetastore;
import org.apache.hadoop.hive.metastore.conf.MetastoreConf;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.thrift.TException;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.mockito.Mockito;

import java.net.InetAddress;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Covers how the metastore turns the user declared through set_ugi into the UGI its rpcs run as
 * when Hops two-way TLS is enabled. Before this check existed the declared user was taken on the
 * client's word, so the cases where the certificate does not authenticate the user have to keep
 * failing.
 */
@Category(MetastoreUnitTest.class)
public class TestTSSLBasedProcessor {

  private Configuration conf;

  /** Decides the outcome of the certificate check without needing a real certificate. */
  private static class TestProcessor extends TSSLBasedProcessor<ThriftHiveMetastore.Iface> {
    private final HopsX509AuthenticationException failure;

    TestProcessor(Configuration conf, HopsX509AuthenticationException failure) throws Exception {
      super(Mockito.mock(ThriftHiveMetastore.Iface.class), conf);
      this.failure = failure;
    }

    @Override
    void authenticateConnection(UserGroupInformation ugi, X509Certificate clientCert,
        InetAddress clientAddress) throws HopsX509AuthenticationException {
      if (failure != null) {
        throw failure;
      }
    }
  }

  @Before
  public void setUp() {
    conf = MetastoreConf.newMetastoreConf();
    MetastoreConf.setVar(conf, MetastoreConf.ConfVars.HIVE_SUPER_USER, "hive");
    MetastoreConf.setVar(conf, MetastoreConf.ConfVars.HIVE_SUPERUSER_ALLOWED_IMPERSONATION,
        "glassfish,hdfs");
  }

  @Test
  public void testAuthenticatedUserActsAsItself() throws Exception {
    UserGroupInformation ugi = new TestProcessor(conf, null)
        .resolveClientUgi("myproject__alice", null, InetAddress.getLoopbackAddress());
    assertEquals("myproject__alice", ugi.getUserName());
  }

  @Test
  public void testUserOnImpersonationListIsElevatedToSuperuser() throws Exception {
    UserGroupInformation ugi = new TestProcessor(conf, null)
        .resolveClientUgi("glassfish", null, InetAddress.getLoopbackAddress());
    assertEquals("hive", ugi.getUserName());
  }

  @Test
  public void testCertificateThatDoesNotAuthenticateTheUserIsRejected() throws Exception {
    TSSLBasedProcessor<ThriftHiveMetastore.Iface> processor =
        new TestProcessor(conf, new HopsX509AuthenticationException("CN does not match user"));
    TException e = assertThrows(TException.class, () ->
        processor.resolveClientUgi("myproject__alice", null, InetAddress.getLoopbackAddress()));
    assertTrue(e.getMessage(), e.getMessage().contains("Client not authorized"));
  }

  @Test
  public void testImpersonationIsRefusedWhenTheCertificateCheckFails() throws Exception {
    // A failed certificate check must not be short-circuited by the impersonation list.
    TSSLBasedProcessor<ThriftHiveMetastore.Iface> processor =
        new TestProcessor(conf, new HopsX509AuthenticationException("CN does not match user"));
    assertThrows(TException.class, () ->
        processor.resolveClientUgi("glassfish", null, InetAddress.getLoopbackAddress()));
  }

  @Test
  public void testUserNotOnImpersonationListIsNotElevated() throws Exception {
    MetastoreConf.setVar(conf, MetastoreConf.ConfVars.HIVE_SUPERUSER_ALLOWED_IMPERSONATION, "");
    UserGroupInformation ugi = new TestProcessor(conf, null)
        .resolveClientUgi("glassfish", null, InetAddress.getLoopbackAddress());
    assertEquals("glassfish", ugi.getUserName());
  }
}
