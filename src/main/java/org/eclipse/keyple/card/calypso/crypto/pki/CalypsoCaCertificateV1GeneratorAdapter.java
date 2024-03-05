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

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.certificate.CalypsoCaCertificateV1Generator;
import org.eclipse.keypop.calypso.certificate.spi.CalypsoCertificateSignerSpi;

/**
 * Adapter of {@link CalypsoCaCertificateV1Generator} dedicated to the creation of CA certificates.
 *
 * @since 0.1.0
 */
class CalypsoCaCertificateV1GeneratorAdapter implements CalypsoCaCertificateV1Generator {

  private RSAPublicKey caPublicKey;
  private byte[] caPublicKeyReference;
  private long startDateBcd;
  private long endDateBcd;
  private byte[] aid;
  private boolean isAidTruncationAllowed;
  private byte caRights;
  private byte caScope;

  CalypsoCaCertificateV1GeneratorAdapter(
      byte[] issuerPublicKeyReference, CalypsoCertificateSignerSpi caCertificateSigner) {}

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateV1Generator withCaPublicKey(
      byte[] caPublicKeyReference, RSAPublicKey caPublicKey) {
    Assert.getInstance()
        .notNull(caPublicKeyReference, "caPublicKeyReference")
        .isEqual(caPublicKeyReference.length, 29, "caPublicKeyReference length")
        .notNull(caPublicKey, "caPublicKey");

    // Check if the RSA public key is 2048 bits
    if (caPublicKey.getModulus().bitLength() != 2048) {
      throw new IllegalArgumentException("Public key must be 2048 bits");
    }

    // Check if the RSA public key's modulus is equal to 65537
    if (!caPublicKey.getPublicExponent().equals(BigInteger.valueOf(65537))) {
      throw new IllegalArgumentException("Public key's modulus must be 65537");
    }

    this.caPublicKey = caPublicKey;
    this.caPublicKeyReference = caPublicKeyReference;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateV1Generator withStartDate(int year, int month, int day) {
    Assert.getInstance()
        .isInRange(year, 0, 9999, "year")
        .isInRange(month, 1, 99, "month")
        .isInRange(day, 1, 99, "day");
    startDateBcd = CryptoUtils.convertDateToBcdLong(year, month, day);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateV1Generator withEndDate(int year, int month, int day) {
    Assert.getInstance()
        .isInRange(year, 0, 9999, "year")
        .isInRange(month, 1, 99, "month")
        .isInRange(day, 1, 99, "day");
    endDateBcd = CryptoUtils.convertDateToBcdLong(year, month, day);
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateV1Generator withAid(byte[] aid, boolean isTruncated) {
    Assert.getInstance().notNull(aid, "aid").isInRange(aid.length, 5, 16, "aid length");
    this.aid = aid;
    this.isAidTruncationAllowed = isTruncated;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateV1Generator withCaRights(byte caRights) {
    this.caRights = caRights;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCaCertificateV1Generator withCaScope(byte caScope) {
    this.caScope = caScope;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] generate() {
    return null;
  }

  /**
   * @return The CA public key.
   * @since 0.1.0
   */
  RSAPublicKey getCaPublicKey() {
    return caPublicKey;
  }

  /**
   * @return The CA public key reference.
   * @since 0.1.0
   */
  byte[] getCaPublicKeyReference() {
    return caPublicKeyReference;
  }

  /**
   * @return The certificate start date.
   * @since 0.1.0
   */
  long getStartDateBcd() {
    return startDateBcd;
  }

  /**
   * @return The certificate end date.
   * @since 0.1.0
   */
  long getEndDateBcd() {
    return endDateBcd;
  }

  /**
   * @return The AID.
   * @since 0.1.0
   */
  byte[] getAid() {
    return aid;
  }

  /**
   * @return true if the AID truncation is allowed.
   * @since 0.1.0
   */
  boolean isAidTruncationAllowed() {
    return isAidTruncationAllowed;
  }

  /**
   * @return The CA rights.
   * @since 0.1.0
   */
  byte getCaRights() {
    return caRights;
  }

  /**
   * @return The CA scope.
   * @since 0.1.0
   */
  byte getCaScope() {
    return caScope;
  }
}
