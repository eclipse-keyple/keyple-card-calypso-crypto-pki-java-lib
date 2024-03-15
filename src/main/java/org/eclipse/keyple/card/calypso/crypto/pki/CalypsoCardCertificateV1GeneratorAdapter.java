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

import java.nio.ByteBuffer;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.certificate.CalypsoCardCertificateV1Generator;
import org.eclipse.keypop.calypso.certificate.spi.CalypsoCertificateSignerSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;

/**
 * Adapter of {@link CalypsoCardCertificateV1Generator} dedicated to the generation of card
 * certificates.
 *
 * @since 0.1.0
 */
final class CalypsoCardCertificateV1GeneratorAdapter implements CalypsoCardCertificateV1Generator {

  private final CaCertificateContentSpi issuerCertificateContent;
  private final CalypsoCertificateSignerSpi cardCertificateSigner;
  private byte[] cardPublicKey;
  long startDateBcd;
  long endDateBcd;
  private byte[] aid;
  private byte[] serialNumber;
  private byte[] startupInfo;
  private int index;

  /**
   * Constructor.
   *
   * @param issuerCertificateContent The issuer certificate content.
   * @param cardCertificateSigner The signer to use to generate the signature.
   * @since 0.1.0
   */
  CalypsoCardCertificateV1GeneratorAdapter(
      CaCertificateContentSpi issuerCertificateContent,
      CalypsoCertificateSignerSpi cardCertificateSigner) {
    this.issuerCertificateContent = issuerCertificateContent;
    this.cardCertificateSigner = cardCertificateSigner;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateV1Generator withCardPublicKey(byte[] cardPublicKey) {
    Assert.getInstance()
        .notNull(cardPublicKey, "cardPublicKey")
        .isEqual(cardPublicKey.length, 64, "cardPublicKey");
    this.cardPublicKey = cardPublicKey;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateV1Generator withStartDate(int year, int month, int day) {
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
  public CalypsoCardCertificateV1Generator withEndDate(int year, int month, int day) {
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
  public CalypsoCardCertificateV1Generator withCardAid(byte[] aid) {
    Assert.getInstance().notNull(aid, "aid").isInRange(aid.length, 5, 16, "aid length");
    this.aid = aid;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateV1Generator withCardSerialNumber(byte[] serialNumber) {
    Assert.getInstance()
        .notNull(serialNumber, "serialNumber")
        .isEqual(serialNumber.length, 8, "serialNumber length");
    this.serialNumber = serialNumber;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateV1Generator withCardStartupInfo(byte[] startupInfo) {
    Assert.getInstance()
        .notNull(startupInfo, "startupInfo")
        .isEqual(startupInfo.length, 7, "startupInfo length");
    this.startupInfo = startupInfo;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCardCertificateV1Generator withIndex(int index) {
    this.index = index;
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] generate() {

    // TODO Check consistency with current value and issuer content

    ByteBuffer certificateRawData =
        ByteBuffer.allocate(CalypsoCardCertificateV1Constants.RAW_DATA_SIZE);

    // Type
    certificateRawData.put(CalypsoCardCertificateV1Constants.TYPE);
    // Version
    certificateRawData.put(CalypsoCardCertificateV1Constants.VERSION);
    // Issuer reference
    certificateRawData.put(issuerCertificateContent.getPublicKeyReference());
    // AID length
    certificateRawData.put(aid != null ? (byte) aid.length : (byte) 0xFF);
    // AID
    certificateRawData.put(aid);
    byte[] padding = new byte[CalypsoCaCertificateV1Constants.AID_SIZE_MAX - aid.length];
    certificateRawData.put(padding);
    // Serial number
    certificateRawData.put(serialNumber);
    // Index
    certificateRawData.putInt(index);

    // Prepare recoverable data section
    ByteBuffer recoverableBuffer =
        ByteBuffer.allocate(CalypsoCardCertificateV1Constants.RECOVERED_DATA_SIZE);
    // Start date
    recoverableBuffer.putInt((int) startDateBcd);
    // End date
    recoverableBuffer.putInt((int) endDateBcd);
    // Startup info
    recoverableBuffer.put(startupInfo);
    // Card public key
    recoverableBuffer.put(cardPublicKey);

    // Generate the final certificate from the data and recoverable data
    return cardCertificateSigner.generateSignedCertificate(
        certificateRawData.array(), recoverableBuffer.array());
  }
}
