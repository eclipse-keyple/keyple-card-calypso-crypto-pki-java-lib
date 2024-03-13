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
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keypop.calypso.certificate.CalypsoCaCertificateV1Generator;
import org.eclipse.keypop.calypso.certificate.spi.CalypsoCertificateSignerSpi;

/**
 * Adapter of {@link CalypsoCaCertificateV1Generator} dedicated to the creation of CA certificates.
 *
 * @since 0.1.0
 */
final class CalypsoCaCertificateV1GeneratorAdapter implements CalypsoCaCertificateV1Generator {

  private final byte[] issuerPublicKeyReference;
  private final CalypsoCertificateSignerSpi caCertificateSigner;
  private RSAPublicKey caPublicKey;
  private byte[] caPublicKeyReference;
  private long startDateBcd;
  private long endDateBcd;
  private byte[] aid;
  private boolean isAidTruncationAllowed;
  private byte caRights;
  private byte caScope;

  /**
   * Constructor.
   *
   * @param issuerPublicKeyReference The certificate public key reference.
   * @param caCertificateSigner The signer to use to generate the signature.
   * @since 0.1.0
   */
  CalypsoCaCertificateV1GeneratorAdapter(
      byte[] issuerPublicKeyReference, CalypsoCertificateSignerSpi caCertificateSigner) {
    this.issuerPublicKeyReference = issuerPublicKeyReference;
    this.caCertificateSigner = caCertificateSigner;
  }

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
    startDateBcd = CertificateUtils.convertDateToBcdLong(year, month, day);
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
    endDateBcd = CertificateUtils.convertDateToBcdLong(year, month, day);
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
    ByteBuffer certificateRawData =
        ByteBuffer.allocate(CalypsoCaCertificateV1Constants.RAW_DATA_SIZE);

    // Type
    certificateRawData.put(CalypsoCaCertificateV1Constants.TYPE);
    // Version
    certificateRawData.put(CalypsoCaCertificateV1Constants.VERSION);
    // Issuer public key reference
    certificateRawData.put(issuerPublicKeyReference);
    // Certificate public key reference
    certificateRawData.put(caPublicKeyReference);
    // Start date
    certificateRawData.put(
        ByteArrayUtil.extractBytes(
            startDateBcd, CalypsoCaCertificateV1Constants.VALIDITY_DATE_SIZE));
    // RFU1
    certificateRawData.putInt(0);
    // CA rights
    certificateRawData.put(caRights);
    // CA scope
    certificateRawData.put(caScope);
    // End date
    certificateRawData.put(
        ByteArrayUtil.extractBytes(endDateBcd, CalypsoCaCertificateV1Constants.VALIDITY_DATE_SIZE));
    // Target AID size
    certificateRawData.put((byte) (aid.length & 0xFF));
    // Target AID
    certificateRawData.put(aid);
    byte[] padding = new byte[CalypsoCaCertificateV1Constants.AID_SIZE_MAX - aid.length];
    certificateRawData.put(padding);
    // Operating mode
    certificateRawData.put((byte) (isAidTruncationAllowed ? 1 : 0));

    // Create an array containing the 222 first bytes of the public key
    byte[] recoverableData =
        Arrays.copyOf(
            caPublicKey.getEncoded(), CalypsoCaCertificateV1Constants.RECOVERED_DATA_SIZE);

    // Generate the final certificate from the data and recoverable data
    return caCertificateSigner.generateSignedCertificate(
        certificateRawData.array(), recoverableData);
  }
}
