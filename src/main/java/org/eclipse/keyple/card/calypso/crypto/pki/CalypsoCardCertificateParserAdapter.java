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
import org.eclipse.keypop.calypso.card.transaction.spi.CardCertificateParser;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateParserSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateSpi;

/**
 * Adapter for {@link CardCertificateParserSpi} dedicated to the parsing of Calypso version 1
 * compliant card certificates.
 *
 * @since 0.1.0
 */
final class CalypsoCardCertificateParserAdapter
    implements CardCertificateParser, CardCertificateParserSpi {

  /**
   * Constructor.
   *
   * @since 0.1.0 ;
   */
  CalypsoCardCertificateParserAdapter() {}

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte getCertificateType() {
    return CalypsoCardCertificateV1Constants.TYPE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateSpi parseCertificate(byte[] cardOutputData)
      throws CertificateValidationException {

    if (cardOutputData[CalypsoCardCertificateV1Constants.TYPE_OFFSET]
        != CalypsoCardCertificateV1Constants.TYPE) {
      throw new CertificateValidationException(
          "Invalid card certificate type: Expected "
              + HexUtil.toHex(CalypsoCardCertificateV1Constants.TYPE)
              + ", but got "
              + HexUtil.toHex(cardOutputData[CalypsoCardCertificateV1Constants.TYPE_OFFSET]));
    }

    if (cardOutputData[CalypsoCardCertificateV1Constants.VERSION]
        != CalypsoCardCertificateV1Constants.VERSION) {
      throw new CertificateValidationException(
          "Invalid card certificate version: Expected "
              + HexUtil.toHex(CalypsoCardCertificateV1Constants.VERSION)
              + ", but got "
              + HexUtil.toHex(cardOutputData[CalypsoCardCertificateV1Constants.VERSION_OFFSET]));
    }

    return new CalypsoCardCertificateV1Adapter(cardOutputData);
  }
}
