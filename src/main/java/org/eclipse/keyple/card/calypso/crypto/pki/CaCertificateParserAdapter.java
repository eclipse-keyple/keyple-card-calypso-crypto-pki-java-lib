/* **************************************************************************************
 * Copyright (c) 2024 Calypso Networks Association https://calypsonet.org/
 *
 * See the NOTICE file(s) distributed with this work for additional information
 * regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License 2.0 which is available at http://www.eclipse.org/legal/epl-2.0
 *
 * SPDX-License-Identifier: EPL-2.0
 ************************************************************************************** */
package org.eclipse.keyple.card.calypso.crypto.pki;
;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificateParser;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateParserSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateSpi;

public class CaCertificateParserAdapter implements CaCertificateParser, CaCertificateParserSpi {
  @Override
  public byte getCertificateType() {
    return 0;
  }

  @Override
  public CaCertificateSpi parseCertificate(byte[] cardOutputData) {
    return null;
  }
}
