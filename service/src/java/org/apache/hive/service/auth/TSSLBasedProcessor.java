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

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import io.hops.security.HopsUtil;
import io.hops.security.HopsX509AuthenticationException;
import io.hops.security.HopsX509Authenticator;
import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.net.HopsSSLSocketFactory;
import org.apache.hive.service.rpc.thrift.TCLIService;
import org.apache.thrift.TException;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.security.cert.X509Certificate;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;


public class TSSLBasedProcessor<I extends TCLIService.Iface> extends TSetIpAddressProcessor<TCLIService.Iface> {
  private static final Logger LOGGER = LoggerFactory.getLogger(TSetIpAddressProcessor.class.getName());
  private static final Pattern PROJECT_USER = Pattern.compile(HopsSSLSocketFactory.USERNAME_PATTERN);
  private final HopsX509Authenticator hopsX509Authenticator;
  private final Set<String> usersAllowedToImpersonateSuperuser;
  private HiveConf hiveConf = null;

  public TSSLBasedProcessor(TCLIService.Iface iface, HiveConf hiveConf) {
    super(iface);
    this.hiveConf = hiveConf;
    hopsX509Authenticator = new HopsX509Authenticator(hiveConf);
    usersAllowedToImpersonateSuperuser = new HashSet<>(5);
    String defaultAllowedUsersStr = (String) HiveConf.ConfVars.HIVE_SUPERUSER_ALLOWED_IMPERSONATION.defaultStrVal;
    String[] defaultAllowedUsers;
    if (!Strings.isNullOrEmpty(defaultAllowedUsersStr)) {
      defaultAllowedUsers = defaultAllowedUsersStr.split(",");
    } else {
      defaultAllowedUsers = new String[0];
    }

    Collections.addAll(usersAllowedToImpersonateSuperuser,
            hiveConf.getTrimmedStrings(HiveConf.ConfVars.HIVE_SUPERUSER_ALLOWED_IMPERSONATION.varname,
                    defaultAllowedUsers));
  }

  @Override
  protected void setUserName(final TProtocol in) throws TException {

    // Do not check the certificates if the username has already been set for this connection
    if (TSetIpAddressProcessor.getUserName() != null) {
      return;
    }

    try {
      TTransport transport = in.getTransport();
      if (!(transport instanceof TSocket)) {
        throw new TException("Cannot authenticate the user: transport is not a socket");
      }
      Socket socket = ((TSocket) transport).getSocket();
      if (!(socket instanceof SSLSocket)) {
        throw new TException("Cannot authenticate the user: connection is not TLS");
      }
      X509Certificate[] certs = ((SSLSocket) socket).getSession().getPeerCertificateChain();

      // Make sure it's 2 way ssl, i.e. client certificate is available
      if (certs == null || certs.length == 0) {
        throw new TException("Missing certificates");
      }

      // Client certificate is always the first
      TSetIpAddressProcessor.setUserNameForCurrentThread(
          resolveUserName(certs[0].getSubjectDN().getName(),
              TSetIpAddressProcessor.getUserIpAddress()));
    } catch (SSLException e) {
      throw new TException(e);
    }
  }

  /**
   * Derives the user this connection acts as from the subject of its client certificate.
   *
   * <p>A {@code project__user} CN identifies that user directly. Any other CN is only accepted
   * as the Hive superuser, and only when the connection comes from the host the certificate was
   * issued to and the certificate's L field names a user allowed to impersonate the superuser.
   *
   * @return the authenticated user name, never null
   * @throws TException if the certificate does not authenticate anybody
   */
  @VisibleForTesting
  String resolveUserName(String subjectDN, String clientIpAddress) throws TException {
    String cn = HopsUtil.extractCNFromSubject(subjectDN);
    if (cn == null) {
      throw new TException("Cannot authenticate the user: Unrecognized CN format");
    }

    if (PROJECT_USER.matcher(cn).matches()) {
      // The certificate is in the format projectName__userName
      return cn;
    }

    try {
      if (isTrustedConnection(InetAddress.getByName(clientIpAddress), cn)) {
        String locality = HopsUtil.extractLFromSubject(subjectDN);
        if (locality != null && usersAllowedToImpersonateSuperuser.contains(locality.trim())) {
          // Operate as superuser
          return hiveConf.getVar(HiveConf.ConfVars.HIVE_SUPER_USER);
        }
      }
    } catch (UnknownHostException ex) {
      LOGGER.error("Cannot resolve machine address: ", ex);
      throw new TException("Cannot authenticate the user");
    } catch (HopsX509AuthenticationException ex) {
      LOGGER.debug("Cannot authenticate super user", ex);
      throw new TException("Authentication failure", ex);
    }

    throw new TException("Failed to authenticate superuser");
  }

  @VisibleForTesting
  boolean isTrustedConnection(InetAddress clientAddress, String cn)
      throws HopsX509AuthenticationException {
    return hopsX509Authenticator.isTrustedConnection(clientAddress, cn);
  }
}
