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
import java.security.interfaces.RSAPublicKey;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.transaction.spi.CardCertificate;
import org.eclipse.keypop.calypso.certificate.CertificateConsistencyException;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardPublicKeySpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link CardCertificate} for Calypso V1-compliant card certificates.
 *
 * @since 0.1.0
 */
final class CalypsoCardCertificateV1Adapter implements CardCertificate, CardCertificateSpi {

  private static final Logger logger =
      LoggerFactory.getLogger(CalypsoCardCertificateV1Adapter.class);

  private final ByteBuffer certificateRawData;
  private final byte[] issuerKeyReference =
      new byte[CalypsoCardCertificateV1Constants.KEY_REFERENCE_SIZE];
  private final byte[] cardAid;
  private final byte[] cardSerialNumber =
      new byte[CalypsoCardCertificateV1Constants.CARD_SERIAL_NUMBER_SIZE];
  private long startDate;
  private long endDate;
  byte[] eccPublicKey = new byte[CalypsoCardCertificateV1Constants.ECC_PUBLIC_KEY_SIZE];

  /**
   * Creates a new instance from the data returned by the card.
   *
   * @param cardOutputData The raw data obtained from the card.
   * @since 0.1.0
   */
  CalypsoCardCertificateV1Adapter(byte[] cardOutputData) {

    // Wrap the card output data and keep it for later use
    certificateRawData = ByteBuffer.wrap(cardOutputData);

    // Extract Issuer key reference
    certificateRawData.position(CalypsoCardCertificateV1Constants.ISSUER_KEY_REFERENCE_OFFSET);
    certificateRawData.get(issuerKeyReference);

    // Extract AID
    byte cardAidSize = certificateRawData.get();
    if (cardAidSize >= CalypsoCardCertificateV1Constants.AID_SIZE_MIN
        && cardAidSize <= CalypsoCardCertificateV1Constants.AID_SIZE_MAX) {
      cardAid = new byte[cardAidSize];
      certificateRawData.get(cardAid);
      // Move buffer position after reading AID
      certificateRawData.position(
          certificateRawData.position()
              + CalypsoCardCertificateV1Constants.AID_SIZE_MAX
              - cardAidSize);
    } else {
      throw new IllegalArgumentException(
          "Bad card AID size: " + cardAidSize + ", expected between 5 and 16");
    }

    // Extract serial number
    certificateRawData.get(cardSerialNumber);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getIssuerPublicKeyReference() {
    return issuerKeyReference;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getCardAid() {
    return cardAid;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getCardSerialNumber() {
    return cardSerialNumber;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CardPublicKeySpi checkCertificateAndGetPublicKey(
      CaCertificateContentSpi issuerCertificateContent)
      throws CertificateValidationException, AsymmetricCryptoException {

    // Check if issuer is allowed to authenticate this certificate
    if (!issuerCertificateContent.isCardCertificatesAuthenticationAllowed()) {
      throw new CertificateValidationException(
          "Parent certificate ("
              + HexUtil.toHex(issuerCertificateContent.getPublicKeyReference())
              + ") not allowed to authenticate a card certificate");
    }

    ByteBuffer recoveredData =
        ByteBuffer.wrap(
            CertificateUtils.checkCertificateSignatureAndRecoverData(
                certificateRawData.array(),
                (RSAPublicKey) issuerCertificateContent.getPublicKey()));

    parseContent(recoveredData);

    checkDates();

    // Check AID consistency
    if (!CertificateUtils.isAidValidForIssuer(cardAid, issuerCertificateContent)) {
      throw new CertificateConsistencyException("Certificate AID mismatch parent certificate AID");
    }

    return new CardPublicKeyAdapter(eccPublicKey);
  }

  private void parseContent(ByteBuffer recoveredData) {

    // Start date
    startDate = recoveredData.getInt();

    // End date
    endDate = recoveredData.getInt();

    // Skip card rights + card info + card RFU
    recoveredData.position(
        recoveredData.position()
            + CalypsoCardCertificateV1Constants.RIGHTS_SIZE
            + CalypsoCardCertificateV1Constants.CARD_INFO_SIZE
            + CalypsoCardCertificateV1Constants.RFU_SIZE);

    // Card ECC public key
    recoveredData.get(eccPublicKey);
  }

  private void checkDates() throws CertificateValidationException {

    long currentDate = CertificateUtils.getCurrentDateAsBcdLong();

    if (startDate != 0 && currentDate < startDate) {
      throw new CertificateValidationException(
          "Certificate not yet valid. Start date: " + HexUtil.toHex(startDate));
    }

    if (endDate != 0 && currentDate > endDate) {
      logger.warn("Certificate expired. End date: {}", HexUtil.toHex(endDate));
    }
  }

  @Override
  public String toString() {
    return "CalypsoCardCertificateV1Adapter{"
        + "issuerKeyReference="
        + HexUtil.toHex(issuerKeyReference)
        + ", cardAid="
        + HexUtil.toHex(cardAid)
        + ", cardSerialNumber="
        + HexUtil.toHex(cardSerialNumber)
        + ", startDate="
        + HexUtil.toHex(startDate)
        + ", endDate="
        + HexUtil.toHex(endDate)
        + '}';
  }
}
