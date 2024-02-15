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
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.ISO9796d2PSSSigner;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.certificate.card.CardCertificateBuilder;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CardIdentifierApi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardPublicKeySpi;

/**
 * Adapter of {@link CardCertificateSpi} for Calypso V1-compliant card certificates.
 *
 * @since 0.1.0
 */
class CardCertificateCalypsoV1Adapter implements CardCertificateSpi, CardCertificateBuilder {
  private static final int CERTIFICATE_RAW_DATA_SIZE = 384;
  private static final int ISSUER_KEY_REFERENCE_OFFSET = 2;
  private static final int ISSUER_KEY_REFERENCE_SIZE = 29;
  private static final int CARD_AID_SIZE_OFFSET =
      ISSUER_KEY_REFERENCE_OFFSET + ISSUER_KEY_REFERENCE_SIZE;
  private static final int CARD_AID_SIZE_SIZE = 1;
  private static final int CARD_AID_VALUE_OFFSET = CARD_AID_SIZE_OFFSET + CARD_AID_SIZE_SIZE;
  private static final int CARD_AID_VALUE_SIZE = 16;
  private static final int CARD_SERIAL_NUMBER_OFFSET = CARD_AID_VALUE_OFFSET + CARD_AID_VALUE_SIZE;
  private static final int CARD_SERIAL_NUMBER_SIZE = 8;
  private static final int CARD_INDEX_OFFSET = CARD_SERIAL_NUMBER_OFFSET + CARD_SERIAL_NUMBER_SIZE;
  private static final int CARD_INDEX_SIZE = 4;
  private static final int SIGNATURE_OFFSET = CARD_INDEX_OFFSET + CARD_INDEX_SIZE;
  private static final int SIGNATURE_SIZE = 256;
  private static final int RECOVERED_START_DATE_OFFSET = 0;
  private static final int RECOVERED_START_DATE_SIZE = 4;
  private static final int RECOVERED_END_DATE_OFFSET =
      RECOVERED_START_DATE_OFFSET + RECOVERED_START_DATE_SIZE;
  private static final int RECOVERED_END_DATE_SIZE = 4;
  private static final int RECOVERED_CARD_RIGHTS_OFFSET =
      RECOVERED_END_DATE_OFFSET + RECOVERED_END_DATE_SIZE;
  private static final int RECOVERED_CARD_RIGHTS_SIZE = 1;
  private static final int RECOVERED_CARD_INFO_OFFSET =
      RECOVERED_CARD_RIGHTS_OFFSET + RECOVERED_CARD_RIGHTS_SIZE;
  private static final int RECOVERED_CARD_INFO_SIZE = 7;
  private static final int RECOVERED_CARD_RFU_OFFSET =
      RECOVERED_CARD_INFO_OFFSET + RECOVERED_CARD_INFO_SIZE;
  private static final int RECOVERED_CARD_RFU_SIZE = 18;
  private static final int RECOVERED_ECC_PUBLIC_KEY_OFFSET =
      RECOVERED_CARD_RFU_OFFSET + RECOVERED_CARD_RFU_SIZE;
  private static final int RECOVERED_ECC_PUBLIC_KEY_SIZE = 64;
  private static final int RSA_SIGNATURE_SIZE = 256;
  private final byte[] certificateRawData;
  private final CardIdentifierApi cardIdentifierApi;
  // private final byte type;
  // private final byte structureVersion;
  private final byte[] issuerKeyReference;
  private final byte cardAidSize;
  private final byte[] cardAidValue;
  private final byte[] cardSerialNumber;
  // private final int cardIndex;
  private final byte[] signature;
  private final String currentDate;
  private String recoveredStartDate;
  private String recoveredEndDate;
  // private byte recoveredCardRights;
  // private byte[] recoveredCardInfo;
  private byte[] recoveredEccPublicKey;

  /**
   * Creates a new instance from the data returned by the card.
   *
   * @param cardOutputData The raw data obtained from the card.
   * @throws IllegalArgumentException If the provided data length is not 384 bytes.
   * @since 0.1.0
   */
  CardCertificateCalypsoV1Adapter(byte[] cardOutputData, CardIdentifierApi cardIdentifierApi) {
    Assert.getInstance()
        .isEqual(cardOutputData.length, CERTIFICATE_RAW_DATA_SIZE, "cardOutputData size");
    certificateRawData = cardOutputData;
    this.cardIdentifierApi = cardIdentifierApi;
    issuerKeyReference =
        Arrays.copyOfRange(
            cardOutputData,
            ISSUER_KEY_REFERENCE_OFFSET,
            ISSUER_KEY_REFERENCE_OFFSET + ISSUER_KEY_REFERENCE_SIZE);
    cardAidSize = cardOutputData[CARD_AID_SIZE_OFFSET];
    cardAidValue =
        Arrays.copyOfRange(
            cardOutputData, CARD_AID_VALUE_OFFSET, CARD_AID_VALUE_OFFSET + CARD_AID_VALUE_SIZE);
    cardSerialNumber =
        Arrays.copyOfRange(
            cardOutputData,
            CARD_SERIAL_NUMBER_OFFSET,
            CARD_SERIAL_NUMBER_OFFSET + CARD_SERIAL_NUMBER_SIZE);
    signature =
        Arrays.copyOfRange(cardOutputData, SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_SIZE);
    SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMdd");
    currentDate = formatter.format(new Date());
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
  public CardPublicKeySpi checkCertificateAndGetPublicKey(PublicKey issuerPublicKey)
      throws CertificateException {

    byte[] recoveredData = verifySignatureAndGetRecoveredData((RSAPublicKey) issuerPublicKey);
    parseRecoveredData(recoveredData);
    checkCertificateConsistency();
    return new CardPublicKeyAdapter(recoveredEccPublicKey);
  }

  /**
   * Verifies the signature of the certificate and retrieves the recovered data.
   *
   * @param rsaIssuerPublicKey The RSA public key of the certificate issuer.
   * @return The recovered data obtained from the certificate.
   * @throws CertificateException If the signature is invalid or if there is an error while
   *     retrieving the recovered data.
   */
  private byte[] verifySignatureAndGetRecoveredData(RSAPublicKey rsaIssuerPublicKey)
      throws CertificateException {

    RSAKeyParameters rsaKeyParameters =
        new RSAKeyParameters(
            false, rsaIssuerPublicKey.getModulus(), rsaIssuerPublicKey.getPublicExponent());

    ISO9796d2PSSSigner pssSigner =
        new ISO9796d2PSSSigner(new RSAEngine(), new SHA256Digest(), 0, true);

    pssSigner.init(false, rsaKeyParameters);

    try {
      pssSigner.updateWithRecoveredMessage(
          Arrays.copyOfRange(
              certificateRawData,
              certificateRawData.length - RSA_SIGNATURE_SIZE,
              certificateRawData.length));
    } catch (InvalidCipherTextException e) {
      throw new CertificateException(e.getMessage(), e);
    }

    pssSigner.update(certificateRawData, 0, certificateRawData.length - RSA_SIGNATURE_SIZE);

    if (!pssSigner.verifySignature(certificateRawData)) {
      throw new CertificateException("Invalid card certificate signature");
    }
    return pssSigner.getRecoveredMessage();
  }

  /**
   * Parses the recovered data obtained from the card.
   *
   * @param recoveredData The recovered data obtained from the card.
   * @throws CertificateException If there is an error parsing the recovered data.
   */
  private void parseRecoveredData(byte[] recoveredData) throws CertificateException {
    recoveredStartDate =
        bcdDateToString(
            Arrays.copyOfRange(
                recoveredData,
                RECOVERED_START_DATE_OFFSET,
                RECOVERED_START_DATE_OFFSET + RECOVERED_START_DATE_SIZE));
    recoveredEndDate =
        bcdDateToString(
            Arrays.copyOfRange(
                recoveredData,
                RECOVERED_END_DATE_OFFSET,
                RECOVERED_END_DATE_OFFSET + RECOVERED_END_DATE_SIZE));
    recoveredEccPublicKey =
        Arrays.copyOfRange(
            recoveredData,
            RECOVERED_ECC_PUBLIC_KEY_OFFSET,
            RECOVERED_ECC_PUBLIC_KEY_OFFSET + RECOVERED_ECC_PUBLIC_KEY_SIZE);
  }

  /**
   * Convert BCD encoded date to string representation.
   *
   * @param bcdData The BCD encoded date to convert.
   * @return The string representation of the BCD encoded date.
   * @throws CertificateException If an invalid BCD digit is found in the date.
   */
  private static String bcdDateToString(byte[] bcdData) throws CertificateException {
    StringBuilder date = new StringBuilder();
    for (byte bcdByte : bcdData) {
      int high = (bcdByte & 0xF0) >> 4;
      int low = bcdByte & 0x0F;
      if (high > 9 || low > 9) {
        throw new CertificateException(
            "Invalid BCD digit found in date: " + HexUtil.toHex(bcdData));
      }
      date.append(high).append(low);
    }
    return date.toString();
  }

  private void checkCertificateConsistency() throws CertificateException {
    if (recoveredStartDate.compareTo(currentDate) > 0) {
      throw new CertificateException("Certificate start date not yet valid: " + recoveredStartDate);
    }
    if (recoveredEndDate.compareTo(currentDate) < 0) {
      throw new CertificateException("Certificate expiry date has passed: " + recoveredEndDate);
    }
    if (!Arrays.equals(cardSerialNumber, cardIdentifierApi.getSerialNumber())) {
      throw new CertificateException(
          "Certificate serial number mismatch: expected "
              + HexUtil.toHex(cardIdentifierApi.getSerialNumber())
              + ", but found "
              + HexUtil.toHex(cardSerialNumber));
    }
  }

  @Override
  public byte[] createCertificate() {
    throw new UnsupportedOperationException("Not yet implemented.");
  }

  @Override
  public byte[] getCardPublicKeyData() {
    throw new UnsupportedOperationException("Not yet implemented.");
  }
}
