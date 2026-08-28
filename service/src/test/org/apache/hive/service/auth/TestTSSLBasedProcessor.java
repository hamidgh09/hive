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
package org.apache.hive.service.auth;

import io.hops.security.HopsX509AuthenticationException;
import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hive.service.rpc.thrift.TCLIService;
import org.apache.thrift.TException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import java.net.InetAddress;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Covers the mapping from a client X.509 certificate to the user HiveServer2 acts as when Hops
 * two-way TLS is enabled. This is the check that keeps a client from acting as a user it holds
 * no certificate for, so it needs to keep failing closed for every subject it does not
 * recognise.
 */
public class TestTSSLBasedProcessor {

  private static final String CLIENT_IP = "127.0.0.1";

  private HiveConf conf;

  /** Lets the tests decide the outcome of the host/CN check without doing any name resolution. */
  private static class TestProcessor extends TSSLBasedProcessor<TCLIService.Iface> {
    private final boolean trusted;
    private final HopsX509AuthenticationException failure;

    TestProcessor(HiveConf conf, boolean trusted, HopsX509AuthenticationException failure) {
      super(Mockito.mock(TCLIService.Iface.class), conf);
      this.trusted = trusted;
      this.failure = failure;
    }

    @Override
    boolean isTrustedConnection(InetAddress clientAddress, String cn)
        throws HopsX509AuthenticationException {
      if (failure != null) {
        throw failure;
      }
      return trusted;
    }
  }

  @Before
  public void setUp() {
    conf = new HiveConf();
    conf.setVar(HiveConf.ConfVars.HIVE_SUPER_USER, "hive");
    conf.setVar(HiveConf.ConfVars.HIVE_SUPERUSER_ALLOWED_IMPERSONATION, "glassfish,hdfs");
  }

  private TSSLBasedProcessor<TCLIService.Iface> processor(boolean trusted) {
    return new TestProcessor(conf, trusted, null);
  }

  @Test
  public void testProjectUserCertificateIsAcceptedAsItsOwnUser() throws Exception {
    // A project__user CN needs no host check: the certificate names the user directly.
    assertEquals("myproject__alice",
        processor(false).resolveUserName("CN=myproject__alice, O=myproject, L=alice", CLIENT_IP));
  }

  @Test
  public void testServiceCertificateFromAllowedLocalityBecomesSuperuser() throws Exception {
    assertEquals("hive",
        processor(true).resolveUserName("CN=hiveserver.service.consul, O=hive, L=glassfish", CLIENT_IP));
  }

  @Test
  public void testServiceCertificateFromDisallowedLocalityIsRejected() {
    // Trusted host, but the certificate's L is not on the impersonation list.
    TException e = assertThrows(TException.class, () ->
        processor(true).resolveUserName("CN=hiveserver.service.consul, O=hive, L=mallory", CLIENT_IP));
    assertTrue(e.getMessage(), e.getMessage().contains("Failed to authenticate superuser"));
  }

  @Test
  public void testServiceCertificateFromUntrustedHostIsRejected() {
    // Certificate says glassfish, but the connection does not come from the host it was issued to.
    TException e = assertThrows(TException.class, () ->
        processor(false).resolveUserName("CN=hiveserver.service.consul, O=hive, L=glassfish", CLIENT_IP));
    assertTrue(e.getMessage(), e.getMessage().contains("Failed to authenticate superuser"));
  }

  @Test
  public void testCertificateWithoutLocalityIsRejected() {
    TException e = assertThrows(TException.class, () ->
        processor(true).resolveUserName("CN=hiveserver.service.consul, O=hive", CLIENT_IP));
    assertTrue(e.getMessage(), e.getMessage().contains("Failed to authenticate superuser"));
  }

  @Test
  public void testSubjectWithoutCommonNameIsRejected() {
    TException e = assertThrows(TException.class, () ->
        processor(true).resolveUserName("O=hive, L=glassfish", CLIENT_IP));
    assertTrue(e.getMessage(), e.getMessage().contains("Unrecognized CN format"));
  }

  @Test
  public void testAuthenticatorFailureIsNotTreatedAsSuccess() {
    TSSLBasedProcessor<TCLIService.Iface> proc =
        new TestProcessor(conf, true, new HopsX509AuthenticationException("boom"));
    TException e = assertThrows(TException.class, () ->
        proc.resolveUserName("CN=hiveserver.service.consul, O=hive, L=glassfish", CLIENT_IP));
    assertTrue(e.getMessage(), e.getMessage().contains("Authentication failure"));
  }

  @Test
  public void testImpersonationListIsReadFromConfiguration() throws Exception {
    conf.setVar(HiveConf.ConfVars.HIVE_SUPERUSER_ALLOWED_IMPERSONATION, "");
    // With nobody allowed to impersonate, even a trusted service certificate gets nothing.
    assertThrows(TException.class, () ->
        processor(true).resolveUserName("CN=hiveserver.service.consul, O=hive, L=glassfish", CLIENT_IP));
  }
}
