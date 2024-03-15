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
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.certificate.CalypsoCaCertificateV1Generator;
import org.eclipse.keypop.calypso.certificate.CalypsoCardCertificateV1Generator;
import org.eclipse.keypop.calypso.certificate.CalypsoCertificateApiFactory;
import org.eclipse.keypop.calypso.certificate.CalypsoCertificateStore;
import org.eclipse.keypop.calypso.certificate.spi.CalypsoCertificateSignerSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;

/**
 * Adapter of {@link CalypsoCertificateApiFactory}.
 *
 * @since 0.1.0
 */
final class CalypsoCertificateApiFactoryAdapter implements CalypsoCertificateApiFactory {

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCertificateStore getCalypsoCertificateStore() {
    return CalypsoCertificateStoreAdapter.getInstance();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateV1Generator createCalypsoCaCertificateV1Generator(
      byte[] issuerPublicKeyReference, CalypsoCertificateSignerSpi caCertificateSigner) {

    Assert.getInstance()
        .notNull(issuerPublicKeyReference, "issuerPublicKeyReference")
        .isEqual(
            issuerPublicKeyReference.length,
            CalypsoCaCertificateV1Constants.KEY_REFERENCE_SIZE,
            "issuerPublicKeyReference length")
        .notNull(caCertificateSigner, "caCertificateSigner");

    CaCertificateContentSpi issuerCertificateContent =
        ((CalypsoCertificateStoreAdapter)
                PkiExtensionService.getInstance()
                    .getCalypsoCertificateApiFactory()
                    .getCalypsoCertificateStore())
            .getCertificateContent(issuerPublicKeyReference);

    if (issuerCertificateContent == null) {
      throw new IllegalStateException(
          "Issuer public key not found. Reference: " + HexUtil.toHex(issuerPublicKeyReference));
    }

    return new CalypsoCaCertificateV1GeneratorAdapter(
        issuerCertificateContent, caCertificateSigner);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateV1Generator createCalypsoCardCertificateV1Generator(
      byte[] issuerPublicKeyReference, CalypsoCertificateSignerSpi cardCertificateSigner) {

    Assert.getInstance()
        .notNull(issuerPublicKeyReference, "issuerPublicKeyReference")
        .isEqual(
            issuerPublicKeyReference.length,
            CalypsoCardCertificateV1Constants.KEY_REFERENCE_SIZE,
            "issuerPublicKeyReference length")
        .notNull(cardCertificateSigner, "cardCertificateSigner");

    CaCertificateContentSpi issuerCertificateContent =
        ((CalypsoCertificateStoreAdapter)
                PkiExtensionService.getInstance()
                    .getCalypsoCertificateApiFactory()
                    .getCalypsoCertificateStore())
            .getCertificateContent(issuerPublicKeyReference);

    if (issuerCertificateContent == null) {
      throw new IllegalStateException(
          "Issuer public key not found. Reference: " + HexUtil.toHex(issuerPublicKeyReference));
    }

    return new CalypsoCardCertificateV1GeneratorAdapter(
        issuerCertificateContent, cardCertificateSigner);
  }
}
