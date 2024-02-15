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

import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.card.transaction.spi.CardCertificateParser;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CardIdentifierApi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateParserSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateSpi;

/**
 * Adapter for {@link CardCertificateParserSpi} dedicated to the parsing of Calypso version 1
 * compliant card certificates.
 */
class CardCertificateParserCalypsoV1Adapter
    implements CardCertificateParser, CardCertificateParserSpi {

  private static final byte CARD_KEY_CERTIFICATE = (byte) 0x91;

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte getCertificateType() {
    return CARD_KEY_CERTIFICATE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateSpi parseCertificate(
      byte[] cardOutputData, CardIdentifierApi cardIdentifierApi) {
    Assert.getInstance()
        .notNull(cardOutputData, "cardOutputData")
        .notNull(cardIdentifierApi, "cardIdentifierApi");
    return new CardCertificateCalypsoV1Adapter(cardOutputData, cardIdentifierApi);
  }
}
