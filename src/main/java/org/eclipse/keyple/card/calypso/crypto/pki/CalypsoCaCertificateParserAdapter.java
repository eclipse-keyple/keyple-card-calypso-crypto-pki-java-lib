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

import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificateParser;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateParserSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateSpi;

/**
 * Adapter for {@link CaCertificateParserSpi} dedicated to the parsing of Calypso version 1
 * compliant CA certificates.
 *
 * @since 0.1.0
 */
final class CalypsoCaCertificateParserAdapter
    implements CaCertificateParser, CaCertificateParserSpi {

  private static final byte CA_KEY_CERTIFICATE = (byte) 0x90;

  /**
   * Constructor.
   *
   * @since 0.1.0 ;
   */
  CalypsoCaCertificateParserAdapter() {}

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte getCertificateType() {
    return CA_KEY_CERTIFICATE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CaCertificateSpi parseCertificate(byte[] cardOutputData)
      throws CertificateValidationException {
    return new CalypsoCaCertificateV1Adapter(cardOutputData);
  }
}
