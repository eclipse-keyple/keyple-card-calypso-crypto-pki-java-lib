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

import static org.eclipse.keyple.card.calypso.crypto.pki.CryptoUtils.KEY_REFERENCE_SIZE;

import java.util.Arrays;
import org.eclipse.keyple.card.calypso.crypto.pki.spi.CardCertificateValidatorSpi;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.transaction.spi.CardCertificate;
import org.eclipse.keypop.calypso.certificate.CertificateConsistencyException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CardIdentifierApi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardPublicKeySpi;

/**
 * Adapter of {@link CardCertificateSpi} for Calypso V1-compliant card certificates.
 *
 * @since 0.1.0
 */
class CalypsoCardCertificateV1Adapter implements CardCertificate, CardCertificateSpi {
  static final int CERTIFICATE_RAW_DATA_SIZE = 316;
  static final byte CERTIFICATE_TYPE_BYTE = (byte) 0x91;
  static final byte CERTIFICATE_VERSION_BYTE = 1;
  static final int CERTIFICATE_TYPE_OFFSET = 0;
  static final int CERTIFICATE_VERSION_OFFSET = 1;
  static final int ISSUER_KEY_REFERENCE_OFFSET = 2;
  static final int CARD_AID_SIZE_OFFSET = ISSUER_KEY_REFERENCE_OFFSET + KEY_REFERENCE_SIZE;
  static final int CARD_AID_SIZE_SIZE = 1;
  static final int CARD_AID_VALUE_OFFSET = CARD_AID_SIZE_OFFSET + CARD_AID_SIZE_SIZE;
  static final int CARD_AID_VALUE_SIZE = 16;
  static final int CARD_SERIAL_NUMBER_OFFSET = CARD_AID_VALUE_OFFSET + CARD_AID_VALUE_SIZE;
  static final int CARD_SERIAL_NUMBER_SIZE = 8;
  static final int CARD_INDEX_OFFSET = CARD_SERIAL_NUMBER_OFFSET + CARD_SERIAL_NUMBER_SIZE;
  static final int CARD_INDEX_SIZE = 4;
  static final int RECOVERED_START_DATE_OFFSET = 0;
  static final int RECOVERED_START_DATE_SIZE = 4;
  static final int RECOVERED_END_DATE_OFFSET =
      RECOVERED_START_DATE_OFFSET + RECOVERED_START_DATE_SIZE;
  static final int RECOVERED_END_DATE_SIZE = 4;
  static final int RECOVERED_CARD_RIGHTS_OFFSET =
      RECOVERED_END_DATE_OFFSET + RECOVERED_END_DATE_SIZE;
  static final int RECOVERED_CARD_RIGHTS_SIZE = 1;
  static final int RECOVERED_CARD_INFO_OFFSET =
      RECOVERED_CARD_RIGHTS_OFFSET + RECOVERED_CARD_RIGHTS_SIZE;
  static final int RECOVERED_CARD_INFO_SIZE = 7;
  static final int RECOVERED_CARD_RFU_OFFSET =
      RECOVERED_CARD_INFO_OFFSET + RECOVERED_CARD_INFO_SIZE;
  static final int RECOVERED_CARD_RFU_SIZE = 18;
  static final int RECOVERED_ECC_PUBLIC_KEY_OFFSET =
      RECOVERED_CARD_RFU_OFFSET + RECOVERED_CARD_RFU_SIZE;
  static final int RECOVERED_ECC_PUBLIC_KEY_SIZE = 64;
  static final int RECOVERED_DATA_SIZE = 222;
  private final byte[] certificateRawData;
  private final CardCertificateValidatorSpi cardCertificateValidator;
  // TODO Clean up this:
  // private final byte type;
  // private final byte structureVersion;
  private final byte[] issuerKeyReference;
  private final byte cardAidSize;
  private final byte[] cardAidValue;
  private final byte[] cardSerialNumber;
  // private final int cardIndex;
  private long recoveredStartDate;
  private long recoveredEndDate;
  // private byte recoveredCardRights;
  // private byte[] recoveredCardInfo;
  private byte[] recoveredEccPublicKey;

  /**
   * Creates a new instance from the data returned by the card.
   *
   * @param cardOutputData The raw data obtained from the card.
   * @param cardCertificateValidator The card certificate validator, may be null.
   * @throws IllegalArgumentException If the provided data length is not 384 bytes.
   * @since 0.1.0
   */
  CalypsoCardCertificateV1Adapter(
      byte[] cardOutputData, CardCertificateValidatorSpi cardCertificateValidator) {
    Assert.getInstance()
        .isEqual(cardOutputData.length, CERTIFICATE_RAW_DATA_SIZE, "cardOutputData size");
    certificateRawData = cardOutputData;
    this.cardCertificateValidator = cardCertificateValidator;

    issuerKeyReference =
        Arrays.copyOfRange(
            cardOutputData,
            ISSUER_KEY_REFERENCE_OFFSET,
            ISSUER_KEY_REFERENCE_OFFSET + KEY_REFERENCE_SIZE);
    cardAidSize = cardOutputData[CARD_AID_SIZE_OFFSET];
    cardAidValue =
        Arrays.copyOfRange(
            cardOutputData, CARD_AID_VALUE_OFFSET, CARD_AID_VALUE_OFFSET + CARD_AID_VALUE_SIZE);
    cardSerialNumber =
        Arrays.copyOfRange(
            cardOutputData,
            CARD_SERIAL_NUMBER_OFFSET,
            CARD_SERIAL_NUMBER_OFFSET + CARD_SERIAL_NUMBER_SIZE);
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
  public CardPublicKeySpi checkCertificateAndGetPublicKey(
      CaCertificateContentSpi issuerCertificateContent, CardIdentifierApi cardIdentifierApi) {
    byte[] recoveredData =
        CryptoUtils.checkCertificateSignatureAndRecoverData(
            certificateRawData, issuerCertificateContent);
    parseRecoveredData(recoveredData);
    checkCertificateConsistency(cardIdentifierApi, issuerCertificateContent);
    return new CardPublicKeyAdapter(recoveredEccPublicKey);
  }

  /**
   * Parses the recovered data obtained from the card.
   *
   * @param recoveredData The recovered data obtained from the card.
   */
  private void parseRecoveredData(byte[] recoveredData) {
    recoveredStartDate =
        ByteArrayUtil.extractLong(
            recoveredData, RECOVERED_START_DATE_OFFSET, RECOVERED_START_DATE_SIZE, false);
    recoveredEndDate =
        ByteArrayUtil.extractLong(
            recoveredData, RECOVERED_END_DATE_OFFSET, RECOVERED_END_DATE_SIZE, false);
    recoveredEccPublicKey =
        Arrays.copyOfRange(
            recoveredData,
            RECOVERED_ECC_PUBLIC_KEY_OFFSET,
            RECOVERED_ECC_PUBLIC_KEY_OFFSET + RECOVERED_ECC_PUBLIC_KEY_SIZE);
  }

  /**
   * Analyzes the certificate's fields to detect inconsistencies.
   *
   * <p>This method performs a check of the certificate's integrity and validity. If a {@link
   * CardCertificateValidatorSpi} implementation is set, this method delegates the entire validation
   * process to it. Otherwise, it performs a basic consistency check by verifying the card
   * identification data and the certificate's validity period.
   *
   * @param cardIdentifierApi The API for accessing the card's identification data.
   * @param issuerCertificateContent The CA certificate of the issuer.
   */
  private void checkCertificateConsistency(
      CardIdentifierApi cardIdentifierApi, CaCertificateContentSpi issuerCertificateContent) {
    if (cardCertificateValidator != null) {
      cardCertificateValidator.isCertificateValid(
          certificateRawData, new CardIdentifierAdapter(cardIdentifierApi));
    } else {
      CryptoUtils.checkCertificateValidityPeriod(recoveredStartDate, recoveredEndDate);
      checkAidValues(cardIdentifierApi, issuerCertificateContent);
    }

    checkSerialNumbers(cardIdentifierApi);
  }

  /**
   * Compares the certificates AID with the card's AID according to the policy defined by the issuer
   * certificate.
   */
  private void checkAidValues(
      CardIdentifierApi cardIdentifierApi, CaCertificateContentSpi issuerCertificateContent) {
    // Determine the length of the AID from the API
    int aidLength = cardIdentifierApi.getAid().length;

    // Ensure the cardAidValue array is at least as long as the API's AID
    if (cardAidValue.length < aidLength) {
      throw new CertificateConsistencyException(
          generateMismatchErrorMessage(
              "Certificate AID length mismatch", cardIdentifierApi.getAid(), cardAidValue));
    }

    // Create a prefix array from cardAidValue with the length of the AID
    byte[] cardAidValuePrefix = Arrays.copyOfRange(cardAidValue, 0, aidLength);

    // Compare the prefix with the entire AID from the API
    if (!Arrays.equals(cardAidValuePrefix, cardIdentifierApi.getAid())) {
      throw new CertificateConsistencyException(
          generateMismatchErrorMessage(
              "Certificate AID mismatch", cardIdentifierApi.getAid(), cardAidValue));
    }
    if (issuerCertificateContent.isAidCheckRequested()) {
      byte[] caTargetAidValue = issuerCertificateContent.getAid();
      if (issuerCertificateContent.isAidTruncated()) {
        checkTruncatedAids(caTargetAidValue);
      } else {
        checkUntruncatedAids(caTargetAidValue);
      }
    }
  }

  /**
   * Compares the certificate's AID with the issuer certificate's AID when truncation is allowed.
   */
  private void checkTruncatedAids(byte[] caTargetAidValue) {
    // Truncation allowed
    if (cardAidValue.length >= caTargetAidValue.length) {
      if (!Arrays.equals(Arrays.copyOf(cardAidValue, caTargetAidValue.length), caTargetAidValue)) {
        throw new CertificateConsistencyException(
            generateMismatchErrorMessage(
                "AID mismatch with truncation allowed",
                caTargetAidValue,
                Arrays.copyOf(cardAidValue, caTargetAidValue.length)));
      }
    } else {
      throw new CertificateConsistencyException("Card AID is shorter than CA target AID.");
    }
  }

  /**
   * Compares the certificate's AID with the issuer certificate's AID when truncation is not
   * allowed.
   */
  private void checkUntruncatedAids(byte[] caTargetAidValue) {
    // Truncation forbidden
    if (cardAidValue.length == caTargetAidValue.length) {
      if (!Arrays.equals(cardAidValue, caTargetAidValue)) {
        throw new CertificateConsistencyException(
            generateMismatchErrorMessage(
                "AID mismatch with no truncation allowed", caTargetAidValue, cardAidValue));
      }
    } else {
      throw new CertificateConsistencyException("AID size mismatch with no truncation allowed.");
    }
  }

  /** Compares the card's serial number to the serial number found into the certificate. */
  private void checkSerialNumbers(CardIdentifierApi cardIdentifierApi) {
    if (!Arrays.equals(cardSerialNumber, cardIdentifierApi.getSerialNumber())) {
      throw new CertificateConsistencyException(
          generateMismatchErrorMessage(
              "Certificate serial number mismatch",
              cardIdentifierApi.getSerialNumber(),
              cardSerialNumber));
    }
  }

  /** Generates a String dedicated to mismatch error message. */
  private String generateMismatchErrorMessage(String reason, byte[] expected, byte[] found) {
    return reason + ": expected " + HexUtil.toHex(expected) + ", but found " + HexUtil.toHex(found);
  }
}
