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

import static org.eclipse.keyple.card.calypso.crypto.pki.CertificatesConstants.KEY_REFERENCE_SIZE;

import java.nio.ByteBuffer;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.transaction.spi.CardCertificate;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardPublicKeySpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link CardCertificateSpi} for Calypso V1-compliant card certificates.
 *
 * @since 0.1.0
 */
final class CalypsoCardCertificateV1Adapter implements CardCertificate, CardCertificateSpi {

  private static final Logger logger =
      LoggerFactory.getLogger(CalypsoCardCertificateV1Adapter.class);

  private static final String MSG_CERTIFICATE_AID_MISMATCH_PARENT_CERTIFICATE_AID =
      "Certificate AID mismatch parent certificate AID";

  private final ByteBuffer certificateRawData;
  private final byte[] issuerKeyReference;
  private final byte[] cardAidValue;
  private final byte[] cardSerialNumber;
  private long recoveredStartDate;
  private long recoveredEndDate;

  /**
   * Creates a new instance from the data returned by the card.
   *
   * @param cardOutputData The raw data obtained from the card.
   * @throws IllegalArgumentException If the provided data length is not 384 bytes.
   * @throws CertificateValidationException If there is an error during certificate validation.
   * @since 0.1.0
   */
  CalypsoCardCertificateV1Adapter(byte[] cardOutputData) throws CertificateValidationException {
    Assert.getInstance()
        .isEqual(
            cardOutputData.length,
            CertificatesConstants.CARD_CERTIFICATE_RAW_DATA_SIZE,
            "cardOutputData size");

    // Wrap the card output data and keep it for later use
    certificateRawData = ByteBuffer.wrap(cardOutputData);

    // Type
    certificateRawData.position(
        certificateRawData.position()
            + CertificatesConstants.CA_TYPE_SIZE); // skip type, already checked

    // Version
    CertificateUtils.checkVersion(
        CertificatesConstants.CARD_CERTIFICATE_VERSION_BYTE, certificateRawData.get());

    // Issuer key reference
    issuerKeyReference = new byte[KEY_REFERENCE_SIZE];
    certificateRawData.get(issuerKeyReference);

    // Get AID
    cardAidValue = checkAndGetAidValue(certificateRawData);

    // Get serial number
    cardSerialNumber = new byte[CertificatesConstants.CARD_SERIAL_NUMBER_SIZE];
    certificateRawData.get(cardSerialNumber);

    if (logger.isDebugEnabled()) {
      logger.debug("Calypso card certificate V1");
      logger.debug("Target public key reference {}", HexUtil.toHex(issuerKeyReference));
      logger.debug("Card AID: {}", HexUtil.toHex(cardAidValue));
      logger.debug("Card serial number: {}", HexUtil.toHex(cardSerialNumber));
    }
  }

  /**
   * Checks and gets the target AID value based on the given buffer.
   *
   * @param buffer The ByteBuffer containing the certificate data.
   * @return The target AID value as a byte array.
   * @throws CertificateValidationException If the target AID size is invalid.
   */
  private byte[] checkAndGetAidValue(ByteBuffer buffer) throws CertificateValidationException {
    byte cardAidSize = buffer.get();
    if (cardAidSize >= CertificatesConstants.AID_SIZE_MIN
        && cardAidSize <= CertificatesConstants.AID_SIZE_MAX) {
      byte[] aid = new byte[cardAidSize];
      buffer.get(aid);
      buffer.position(buffer.position() + cardAidSize); // Move buffer position after reading AID
      return aid;
    } else {
      throw new CertificateValidationException(
          "Bad target AID size: " + cardAidSize + ", expected between 5 and 16");
    }
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
    return cardAidValue;
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

    ByteBuffer recoveredData =
        ByteBuffer.wrap(
            CertificateUtils.checkCertificateSignatureAndRecoverData(
                certificateRawData.array(), issuerCertificateContent));

    // Start date
    byte[] dateBytes = new byte[CertificatesConstants.VALIDITY_DATE_SIZE];
    recoveredData.get(dateBytes);
    recoveredStartDate =
        ByteArrayUtil.extractLong(dateBytes, 0, CertificatesConstants.VALIDITY_DATE_SIZE, false);

    // End date
    recoveredData.get(dateBytes);
    recoveredEndDate =
        ByteArrayUtil.extractLong(dateBytes, 0, CertificatesConstants.VALIDITY_DATE_SIZE, false);

    // Card certificate rights and card startup info
    recoveredData.position(
        recoveredData.position()
            + CertificatesConstants.CARD_CERTIFICATE_RIGHT_SIZE
            + CertificatesConstants
                .CARD_CERTIFICATE_RECOVERED_CARD_INFO_SIZE); // skip card certificates rights and
    // startup info

    // Card certificate RFU
    recoveredData.position(
        recoveredData.position()
            + CertificatesConstants.CARD_CERTIFICATE_RFU_SIZE); // skip card certificates RFU

    // Card ECC public key
    byte[] recoveredEccPublicKey =
        new byte[CertificatesConstants.CARD_CERTIFICATE_RECOVERED_ECC_PUBLIC_KEY_SIZE];
    recoveredData.get(recoveredEccPublicKey);

    checkCertificateConsistency(issuerCertificateContent);

    if (logger.isDebugEnabled()) {
      logger.debug("Start date: {}", HexUtil.toHex(recoveredStartDate));
      logger.debug("End date: {}", HexUtil.toHex(recoveredEndDate));
    }

    return new CardPublicKeyAdapter(recoveredEccPublicKey);
  }

  /**
   * Analyzes the certificate's fields to detect inconsistencies.
   *
   * <p>This method performs a check of the certificate's integrity and validity.
   *
   * @param issuerCertificateContent The CA certificate of the issuer.
   */
  private void checkCertificateConsistency(CaCertificateContentSpi issuerCertificateContent)
      throws CertificateValidationException {

    // Check validity
    CertificateUtils.checkValidity(recoveredStartDate, recoveredEndDate);

    // Constraints from the parent certificate
    // Verify if the parent is allowed to authenticate this certificate
    CertificateUtils.checkAuthenticationAllowed(true, issuerCertificateContent);

    // Verify if the AID is consistent with the parent profile
    checkAidAgainstParentAid(issuerCertificateContent);
  }

  /**
   * Checks the AID value of the given issuerCertificateContent against the parent certificate AID.
   *
   * @param issuerCertificateContent The issuer certificate content.
   * @throws CertificateValidationException If the AID values mismatch.
   */
  private void checkAidAgainstParentAid(CaCertificateContentSpi issuerCertificateContent)
      throws CertificateValidationException {

    if (issuerCertificateContent.isAidCheckRequested()) {
      byte[] issuerAid = issuerCertificateContent.getAid();

      int compareLength =
          issuerCertificateContent.isAidTruncated() ? issuerAid.length : cardAidValue.length;

      if (cardAidValue.length < compareLength || issuerAid.length < compareLength) {
        throw new CertificateValidationException(
            MSG_CERTIFICATE_AID_MISMATCH_PARENT_CERTIFICATE_AID);
      }

      for (int i = 0; i < compareLength; i++) {
        if (cardAidValue[i] != issuerAid[i]) {
          throw new CertificateValidationException(
              MSG_CERTIFICATE_AID_MISMATCH_PARENT_CERTIFICATE_AID);
        }
      }
    }
  }
}
