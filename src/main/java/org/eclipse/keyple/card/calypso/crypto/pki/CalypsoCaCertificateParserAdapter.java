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

import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificateParser;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateParserSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateSpi;

/**
 * Adapter for {@link CaCertificateParser} dedicated to the parsing of Calypso version 1 compliant
 * CA certificates.
 *
 * @since 0.1.0
 */
final class CalypsoCaCertificateParserAdapter
    implements CaCertificateParser, CaCertificateParserSpi {

  /**
   * Constructor.
   *
   * @since 0.1.0
   */
  CalypsoCaCertificateParserAdapter() {}

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte getCertificateType() {
    return CalypsoCaCertificateV1Constants.TYPE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CaCertificateSpi parseCertificate(byte[] cardOutputData)
      throws CertificateValidationException {

    if (cardOutputData.length != CalypsoCaCertificateV1Constants.RAW_DATA_SIZE) {
      throw new CertificateValidationException(
          "Invalid CA certificate size: expected "
              + CalypsoCaCertificateV1Constants.RAW_DATA_SIZE
              + ", but got "
              + cardOutputData.length);
    }

    if (cardOutputData[0] != CalypsoCaCertificateV1Constants.TYPE) {
      throw new CertificateValidationException(
          "Invalid CA certificate type: Expected "
              + HexUtil.toHex(CalypsoCaCertificateV1Constants.TYPE)
              + ", but got "
              + HexUtil.toHex(cardOutputData[0]));
    }

    if (cardOutputData[1] != CalypsoCaCertificateV1Constants.VERSION) {
      throw new CertificateValidationException(
          "Invalid CA certificate version: Expected "
              + HexUtil.toHex(CalypsoCaCertificateV1Constants.VERSION)
              + ", but got "
              + HexUtil.toHex(cardOutputData[1]));
    }

    return new CalypsoCaCertificateV1Adapter(cardOutputData);
  }
}
