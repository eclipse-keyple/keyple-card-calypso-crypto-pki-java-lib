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
import java.security.interfaces.RSAPublicKey;
import org.eclipse.keypop.calypso.card.transaction.spi.PcaCertificate;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.PcaCertificateSpi;

/**
 * Adapter of {@link PcaCertificate}.
 *
 * @since 0.1.0
 */
final class PcaCertificateAdapter
    implements PcaCertificate, PcaCertificateSpi, CaCertificateContentSpi {

  private final byte[] publicKeyReference;
  private final RSAPublicKey publicKey;

  /**
   * Creates an instance from a public key and its reference.
   *
   * @param publicKeyReference The public key reference.
   * @param publicKey The public key.
   * @since 0.1.0
   */
  PcaCertificateAdapter(byte[] publicKeyReference, RSAPublicKey publicKey) {
    this.publicKeyReference = publicKeyReference;
    this.publicKey = publicKey;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CaCertificateContentSpi checkCertificateAndGetContent() {
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public PublicKey getPublicKey() {
    return publicKey;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getPublicKeyReference() {
    return publicKeyReference;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public long getStartDate() {
    // no start date defined for a PCA certificate
    return 0;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public long getEndDate() {
    // no end date defined for a PCA certificate
    return 0;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isAidCheckRequested() {
    // no AID for a PCA certificate
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isAidTruncated() {
    // no AID for a PCA certificate
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getAid() {
    // no AID for a PCA certificate
    return null; // NOSONAR
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isCaCertificatesAuthenticationAllowed() {
    // A PCA certificate is allowed to authenticate CA certificates.
    return true;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isCardCertificatesAuthenticationAllowed() {
    // A PCA certificate is allowed to authenticate card certificates.
    return true;
  }
}
