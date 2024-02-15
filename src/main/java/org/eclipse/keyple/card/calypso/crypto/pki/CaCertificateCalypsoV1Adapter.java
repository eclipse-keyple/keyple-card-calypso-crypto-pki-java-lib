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

import java.security.PublicKey;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificate;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.PublicKeySpi;

/**
 * Adapter of {@link CardCertificateSpi} for Calypso V1-compliant CA certificates.
 *
 * @since 0.1.0
 */
class CaCertificateCalypsoV1Adapter implements CaCertificate, CaCertificateSpi {

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getIssuerPublicKeyReference() {
    return new byte[0];
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public PublicKeySpi checkCertificateAndGetPublicKey(PublicKey issuerPublicKey)
      throws CertificateException {
    return null;
  }
}
