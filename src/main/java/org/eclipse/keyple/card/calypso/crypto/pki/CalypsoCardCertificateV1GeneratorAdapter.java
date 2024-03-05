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
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.certificate.CalypsoCardCertificateV1Generator;
import org.eclipse.keypop.calypso.certificate.spi.CalypsoCertificateSignerSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;

/**
 * Adapter of {@link CalypsoCardCertificateV1Generator} dedicated to the generation of card
 * certificates.
 *
 * @since 0.1.0
 */
class CalypsoCardCertificateV1GeneratorAdapter implements CalypsoCardCertificateV1Generator {

  private final CaCertificateContentSpi issuerCertificate;
  private final CalypsoCertificateSignerSpi cardCertificateSigner;
  private byte[] cardPublicKey;
  long startDateBcd;
  long endDateBcd;
  private byte[] aid;
  private byte[] serialNumber;
  private byte[] startupInfo;
  private int index;

  CalypsoCardCertificateV1GeneratorAdapter(
      byte[] issuerPublicKeyReference, CalypsoCertificateSignerSpi cardCertificateSigner) {

    issuerCertificate =
        ((CalypsoCertificateStoreAdapter)
                PkiExtensionService.getInstance()
                    .getCalypsoCertificateApiFactory()
                    .getCalypsoCertificateStore())
            .getCertificate(issuerPublicKeyReference);
    if (issuerCertificate == null) {
      throw new IllegalStateException(
          "Issuer public key not found. Reference: " + HexUtil.toHex(issuerPublicKeyReference));
    }
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
    startDateBcd = CryptoUtils.convertDateToBcdLong(year, month, day);
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
    endDateBcd = CryptoUtils.convertDateToBcdLong(year, month, day);
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
    ByteBuffer buffer =
        ByteBuffer.allocate(CalypsoCardCertificateV1Adapter.CERTIFICATE_RAW_DATA_SIZE);

    // Type
    buffer.put(CalypsoCardCertificateV1Adapter.CERTIFICATE_TYPE_BYTE);
    // Version
    buffer.put(CalypsoCardCertificateV1Adapter.CERTIFICATE_VERSION_BYTE);
    // Issuer reference
    buffer.put(issuerCertificate.getPublicKeyReference());
    // AID length
    buffer.put(aid != null ? (byte) aid.length : (byte) 0xFF);
    // AID
    if (aid != null) {
      buffer.put(aid);
      // Calculate the remaining space to fill with zeros
      int remainingLength = 16 - aid.length;
      if (remainingLength > 0) {
        byte[] padding = new byte[remainingLength];
        buffer.put(padding);
      }
    } else {
      // If AID is not present, fill the entire 16-byte space with zeros
      byte[] padding = new byte[16];
      buffer.put(padding);
    }
    // Serial number
    buffer.put(serialNumber);
    // Index
    buffer.put(ByteArrayUtil.extractBytes(index, 4));

    // Prepare recoverable data section
    ByteBuffer recoverableBuffer =
        ByteBuffer.allocate(CalypsoCardCertificateV1Adapter.RECOVERED_DATA_SIZE);
    // Start date
    recoverableBuffer.put(ByteArrayUtil.extractBytes(startDateBcd, 4));
    // End date
    recoverableBuffer.put(ByteArrayUtil.extractBytes(endDateBcd, 4));
    // Startup info
    recoverableBuffer.put(startupInfo);
    // Card public key
    recoverableBuffer.put(cardPublicKey);

    // Generate the final certificate from the data and recoverable data
    return cardCertificateSigner.generateSignedCertificate(
        buffer.array(), recoverableBuffer.array());
  }
}
