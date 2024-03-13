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
    return Constants.CalypsoCardCertificateV1Constants.CARD_CERTIFICATE_TYPE_BYTE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateSpi parseCertificate(byte[] cardOutputData)
      throws CertificateValidationException {
    return new CalypsoCardCertificateV1Adapter(cardOutputData);
  }
}
