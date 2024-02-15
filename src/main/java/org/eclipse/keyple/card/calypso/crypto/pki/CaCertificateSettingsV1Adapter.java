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
import java.security.PublicKey;
import org.eclipse.keypop.calypso.certificate.ca.CaCertificateSettingsV1;
import org.eclipse.keypop.calypso.certificate.ca.spi.CaCertificateSignerSpi;

/**
 * Adapter of {@link CaCertificateSettingsV1} dedicated to the definition of a CA certificate.
 *
 * @since 0.1.0
 */
class CaCertificateSettingsV1Adapter implements CaCertificateSettingsV1 {
  @Override
  public CaCertificateSettingsV1 useExternalSigner(CaCertificateSignerSpi caCertificateSigner) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CaCertificateSettingsV1 useInternalSigner(
      PrivateKey issuerPrivateKey, byte[] issuerPublicKeyReference) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CaCertificateSettingsV1 setCaPublicKey(
      PublicKey caPublicKey, byte[] caPublicKeyReference) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CaCertificateSettingsV1 setValidityPeriod(
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
  public CaCertificateSettingsV1 setAid(byte[] aid) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CaCertificateSettingsV1 setCaRights(byte caRights) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CaCertificateSettingsV1 setCaScope(byte caScope) {
    return null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CaCertificateSettingsV1 setCaOperatingMode(byte caOperatingMode) {
    return null;
  }
}
