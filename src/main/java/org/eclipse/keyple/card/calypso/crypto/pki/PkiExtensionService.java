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
import org.eclipse.keypop.calypso.card.transaction.spi.*;
import org.eclipse.keypop.calypso.certificate.CalypsoCertificateApiFactory;

/**
 * Extension service dedicated to the management of Calypso PKI card transaction and certificate
 * creation.
 *
 * @since 0.1.0
 */
public class PkiExtensionService {

  /** Singleton */
  private static final PkiExtensionService INSTANCE = new PkiExtensionService();

  /**
   * Returns the service instance.
   *
   * @return A not null reference.
   * @since 0.1.0
   */
  public static PkiExtensionService getInstance() {
    return INSTANCE;
  }

  /**
   * Creates a factory for asymmetric crypto card transaction managers.
   *
   * @return A not null reference.
   * @since 0.1.0
   */
  public AsymmetricCryptoCardTransactionManagerFactory
      createAsymmetricCryptoCardTransactionManagerFactory() {
    return new AsymmetricCryptoCardTransactionManagerFactoryAdapter();
  }

  /**
   * Creates a PCA (Primary Certificate Authority) certificate.
   *
   * @return A not null reference.
   * @since 0.1.0
   */
  public PcaCertificate createPcaCertificate() {
    // TODO
    return null;
  }

  /**
   * Creates a CA (Certificate Authority) certificate.
   *
   * @return A not null reference.
   * @since 0.1.0
   */
  public CaCertificate createCaCertificate() {
    // TODO
    return null;
  }

  /**
   * Creates a {@link CaCertificateParser} object based on the provided CA certificate type.
   *
   * @param certificateType The type of CA certificate.
   * @return A not null reference.
   * @throws IllegalArgumentException If the provided argument is null.
   * @since 0.1.0
   */
  public CaCertificateParser createCaCertificateParser(CaCertificateType certificateType) {
    Assert.getInstance().notNull(certificateType, "certificateType");
    return new CaCertificateParserCalypsoV1();
  }

  /**
   * Creates a {@link CardCertificateParser} object based on the provided card certificate type.
   *
   * @param certificateType The type of card certificate.
   * @return A not null reference.
   * @throws IllegalArgumentException If the provided argument is null.
   * @since 0.1.0
   */
  public CardCertificateParser createCardCertificateFactory(CardCertificateType certificateType) {
    Assert.getInstance().notNull(certificateType, "certificateType");
    return new CardCertificateParserCalypsoV1();
  }

  /**
   * Get the factory for creating Calypso certificate.
   *
   * @return A not null reference.
   * @since 0.1.0
   */
  public CalypsoCertificateApiFactory getCalypsoCertificateApiFactory() {
    return null;
  }
}
