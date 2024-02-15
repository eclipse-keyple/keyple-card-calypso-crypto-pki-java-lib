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

import java.security.PrivateKey;
import org.eclipse.keypop.calypso.certificate.card.CardCertificateSettingsV1;
import org.eclipse.keypop.calypso.certificate.card.spi.CardCertificateSignerSpi;

/**
 * Adapter of {@link CardCertificateSettingsV1} dedicated to the definition of a card certificate.
 *
 * @since 0.1.0
 */
class CardCertificateSettingsV1Adapter implements CardCertificateSettingsV1 {

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateSettingsV1 useExternalSigner(
      CardCertificateSignerSpi cardCertificateSigner) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateSettingsV1 useInternalSigner(
      PrivateKey issuerPrivateKey, byte[] issuerPublicKeyReference) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateSettingsV1 setCardPublicKey(byte[] cardPublicKey) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateSettingsV1 setValidityPeriod(
      int startDateYear,
      int startDateMonth,
      int startDateDay,
      int endDateYear,
      int endDateMonth,
      int endDateDay) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateSettingsV1 setAid(byte[] aid) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateSettingsV1 setCardSerialNumber(byte[] serialNumber) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateSettingsV1 setCardStartupInfo(byte[] startupInfo) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardCertificateSettingsV1 setIndex(int index) {
    return null;
  }
}
