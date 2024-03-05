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

import java.security.PublicKey;
import java.util.Arrays;
import org.eclipse.keyple.card.calypso.crypto.pki.spi.CaCertificateValidatorSpi;
import org.eclipse.keyple.core.util.ByteArrayUtil;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificate;
import org.eclipse.keypop.calypso.certificate.CertificateConsistencyException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateSpi;

/**
 * Adapter of {@link CardCertificateSpi} for Calypso V1-compliant CA certificates.
 *
 * @since 0.1.0
 */
class CalypsoCaCertificateV1Adapter
    implements CaCertificate, CaCertificateSpi, CaCertificateContentSpi {

  static final int CERTIFICATE_RAW_DATA_SIZE = 384;
  static final byte CERTIFICATE_TYPE_BYTE = (byte) 0x90;
  static final byte CERTIFICATE_VERSION_BYTE = 1;
  static final int CERTIFICATE_TYPE_OFFSET = 0;
  static final int CERTIFICATE_VERSION_OFFSET = 1;
  static final int ISSUER_KEY_REFERENCE_OFFSET = 2;
  static final int CA_TARGET_KEY_REFERENCE_OFFSET =
      ISSUER_KEY_REFERENCE_OFFSET + KEY_REFERENCE_SIZE;
  private static final int START_DATE_OFFSET = CA_TARGET_KEY_REFERENCE_OFFSET + KEY_REFERENCE_SIZE;
  private static final int VALIDITY_DATE_SIZE = 4;
  private static final int CA_RFU1_OFFSET = START_DATE_OFFSET + VALIDITY_DATE_SIZE;
  private static final int CA_RFU1_SIZE = 4;
  private static final int CA_RIGHTS_OFFSET = CA_RFU1_OFFSET + CA_RFU1_SIZE;
  private static final int CA_RIGHTS_SIZE = 1;
  private static final int CA_SCOPE_OFFSET = CA_RIGHTS_OFFSET + CA_RIGHTS_SIZE;
  private static final int CA_SCOPE_SIZE = 1;
  private static final int END_DATE_OFFSET = CA_SCOPE_OFFSET + CA_SCOPE_SIZE;
  private static final int CA_TARGET_AID_SIZE_OFFSET = END_DATE_OFFSET + VALIDITY_DATE_SIZE;
  private static final int CA_TARGET_AID_SIZE = 1;
  private static final int CA_TARGET_AID_VALUE_OFFSET =
      CA_TARGET_AID_SIZE_OFFSET + CA_TARGET_AID_SIZE;
  private static final int CA_TARGET_AID_VALUE_SIZE = 16;
  private static final int CA_OPERATING_MODE_OFFSET =
      CA_TARGET_AID_VALUE_OFFSET + CA_TARGET_AID_VALUE_SIZE;
  private static final int CA_OPERATING_MODE_SIZE = 1;
  private static final int CA_RFU2_OFFSET = CA_OPERATING_MODE_OFFSET + CA_OPERATING_MODE_SIZE;
  private static final int CA_RFU2_SIZE = 2;
  private static final int CA_PUBLIC_KEY_HEADER_OFFSET = CA_RFU2_OFFSET + CA_RFU2_SIZE;
  private static final int CA_PUBLIC_KEY_HEADER_SIZE = 34;
  private static final int RSA_KEY_SIZE = 256;
  private final byte[] certificateRawData;
  private final CaCertificateValidatorSpi caCertificateValidator;
  private final byte[] issuerKeyReference;
  private final byte[] caTargetKeyReference;
  // TODO Check if new getters are needed
  private final long startDate;
  private final byte caRights;
  private final byte caScope;
  private final long endDate;
  private final byte caTargetAidSize;
  private final byte[] caTargetAidValue;
  private final byte caOperatingMode;
  private final byte[] caPublicKeyHeader;
  private PublicKey caPublicKey;

  /**
   * Creates an instance from the certificate raw value as stored into the card.
   *
   * <p>When defined, the optional validator is used to performed verifications defined by the upper
   * layer.
   *
   * @param cardOutputData A 384-byte byte array representing the certificate.
   * @param caCertificateValidator null if no external validator is defined.
   * @since 0.1.0
   */
  CalypsoCaCertificateV1Adapter(
      byte[] cardOutputData, CaCertificateValidatorSpi caCertificateValidator) {

    this.certificateRawData = cardOutputData;
    this.caCertificateValidator = caCertificateValidator;

    // parse the provided byte array
    issuerKeyReference =
        Arrays.copyOfRange(
            cardOutputData,
            ISSUER_KEY_REFERENCE_OFFSET,
            ISSUER_KEY_REFERENCE_OFFSET + KEY_REFERENCE_SIZE);
    caTargetKeyReference =
        Arrays.copyOfRange(
            cardOutputData,
            CA_TARGET_KEY_REFERENCE_OFFSET,
            CA_TARGET_KEY_REFERENCE_OFFSET + KEY_REFERENCE_SIZE);
    byte[] startDateBytes =
        Arrays.copyOfRange(
            cardOutputData, START_DATE_OFFSET, START_DATE_OFFSET + VALIDITY_DATE_SIZE);
    startDate = ByteArrayUtil.extractLong(startDateBytes, 0, 4, false);
    caRights = cardOutputData[CA_RIGHTS_OFFSET];
    caScope = cardOutputData[CA_SCOPE_OFFSET];
    byte[] endDateBytes =
        Arrays.copyOfRange(cardOutputData, END_DATE_OFFSET, END_DATE_OFFSET + VALIDITY_DATE_SIZE);
    endDate = ByteArrayUtil.extractLong(endDateBytes, 0, 4, false);
    caTargetAidSize = cardOutputData[CA_TARGET_AID_SIZE_OFFSET];
    caTargetAidValue =
        Arrays.copyOfRange(
            cardOutputData,
            CA_TARGET_AID_VALUE_OFFSET,
            CA_TARGET_AID_VALUE_OFFSET + CA_TARGET_AID_VALUE_SIZE);
    caOperatingMode = cardOutputData[CA_OPERATING_MODE_OFFSET];
    caPublicKeyHeader =
        Arrays.copyOfRange(
            cardOutputData,
            CA_PUBLIC_KEY_HEADER_OFFSET,
            CA_PUBLIC_KEY_HEADER_OFFSET + CA_PUBLIC_KEY_HEADER_SIZE);
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
  public CaCertificateContentSpi checkCertificateAndGetContent(
      CaCertificateContentSpi issuerCertificateContent) {
    byte[] recoveredData =
        CryptoUtils.checkCertificateSignatureAndRecoverData(
            certificateRawData, issuerCertificateContent);
    byte[] caPublicKeyModulus = new byte[RSA_KEY_SIZE];
    System.arraycopy(caPublicKeyHeader, 0, caPublicKeyModulus, 0, caPublicKeyHeader.length);
    System.arraycopy(
        recoveredData, 0, caPublicKeyModulus, caPublicKeyHeader.length, recoveredData.length);
    caPublicKey = CryptoUtils.generateRSAPublicKeyFromModulus(caPublicKeyModulus);
    if (caCertificateValidator != null) {
      if (!caCertificateValidator.isCertificateValid(certificateRawData)) {
        throw new CertificateConsistencyException("Certificate is invalid.");
      }
    } else {
      CryptoUtils.checkCertificateValidityPeriod(startDate, endDate);
    }
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public PublicKey getPublicKey() {
    return caPublicKey;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getPublicKeyReference() {
    return caTargetKeyReference;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public long getStartDate() {
    return startDate;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public long getEndDate() {
    return endDate;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isAidCheckRequested() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isAidTruncated() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getAid() {
    return new byte[0];
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isCaCertificatesAuthenticationAllowed() {
    return false;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isCardCertificatesAuthenticationAllowed() {
    return false;
  }
}
