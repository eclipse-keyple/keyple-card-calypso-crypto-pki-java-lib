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
import java.security.PublicKey;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificate;
import org.eclipse.keypop.calypso.certificate.CertificateConsistencyException;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardCertificateSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link CardCertificateSpi} for Calypso V1-compliant CA certificates.
 *
 * @since 0.1.0
 */
final class CalypsoCaCertificateV1Adapter
    implements CaCertificate, CaCertificateSpi, CaCertificateContentSpi {

  private static final Logger logger = LoggerFactory.getLogger(CalypsoCaCertificateV1Adapter.class);

  private static final String MSG_CERTIFICATE_AID_MISMATCH_PARENT_CERTIFICATE_AID =
      "Certificate AID mismatch parent certificate AID";
  private static final String MSG_ALLOWED = "allowed";
  private static final String MSG_FORBIDDEN = "forbidden";

  private final ByteBuffer certificateRawData;
  private final byte[] issuerKeyReference;
  private byte[] caTargetKeyReference;
  private long startDate;
  private long endDate;
  private byte[] caTargetAidValue;
  private boolean isAidTruncated;
  private boolean isCardCertificatesAuthenticationAllowed;
  private boolean isCaCertificatesAuthenticationAllowed;
  private PublicKey caPublicKey;

  /**
   * Initializes a CalypsoCaCertificateV1Adapter object with the provided card output data.
   *
   * @param cardOutputData The card output data containing the certificate.
   * @since 0.1.0
   */
  CalypsoCaCertificateV1Adapter(byte[] cardOutputData) {

    // Wrap the card output data and keep it for later use
    certificateRawData = ByteBuffer.wrap(cardOutputData);

    // Extract issuer key reference
    certificateRawData.position(CalypsoCaCertificateV1Constants.ISSUER_KEY_REFERENCE_OFFSET);
    issuerKeyReference = new byte[CalypsoCaCertificateV1Constants.KEY_REFERENCE_SIZE];
    certificateRawData.get(issuerKeyReference);
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
      CaCertificateContentSpi issuerCertificateContent)
      throws CertificateValidationException, AsymmetricCryptoException {

    // Check if issuer is allowed to authenticate this certificate
    if (!issuerCertificateContent.isCaCertificatesAuthenticationAllowed()) {
      throw new CertificateValidationException(
          "Parent certificate ("
              + HexUtil.toHex(issuerCertificateContent.getPublicKeyReference())
              + ") not allowed to authenticate a CA certificate");
    }

    // Target key reference
    certificateRawData.position(CalypsoCaCertificateV1Constants.TARGET_KEY_REFERENCE_OFFSET);
    caTargetKeyReference = new byte[CalypsoCaCertificateV1Constants.KEY_REFERENCE_SIZE];
    certificateRawData.get(caTargetKeyReference);

    // Start date
    startDate = certificateRawData.getInt();

    long currentDate = CertificateUtils.getCurrentDateAsBcdLong();

    // Check start date
    if (startDate != 0 && currentDate < startDate) {
      throw new CertificateConsistencyException(
          "Certificate not yet valid. Start date: " + HexUtil.toHex(startDate));
    }

    // RFU1
    certificateRawData.position(
        certificateRawData.position() + CalypsoCaCertificateV1Constants.RFU1_SIZE); // skip RFU1

    // CaRights
    byte caRights = certificateRawData.get();
    checkCaRights(caRights);
    isCardCertificatesAuthenticationAllowed =
        checkAndGetCardCertificateAuthenticationAuthorization(caRights);
    isCaCertificatesAuthenticationAllowed =
        checkAndGetCaCertificateAuthenticationAuthorization(caRights);

    // CaScope
    checkCaScope(certificateRawData.get());

    // End date
    endDate = certificateRawData.getInt();

    if (endDate != 0 && currentDate > endDate) {
      throw new CertificateConsistencyException(
          "Certificate expired. End date: " + HexUtil.toHex(endDate));
    }

    // Check AID target size and create the expected caTargetAidValue
    caTargetAidValue = checkAndGetAidValue(certificateRawData);

    // Determine if the AID is truncated analyzing the CA operating mode
    isAidTruncated = checkAndGetOperatingMode(certificateRawData.get());

    // Verify if the AID is consistent with the parent profile
    checkAidAgainstParentAid(issuerCertificateContent);

    // RFU 2
    certificateRawData.position(
        certificateRawData.position() + CalypsoCaCertificateV1Constants.RFU2_SIZE); // skip RFU2

    // Public key header
    byte[] caPublicKeyHeader = new byte[CalypsoCaCertificateV1Constants.PUBLIC_KEY_HEADER_SIZE];
    certificateRawData.get(caPublicKeyHeader);

    // Verify the signature and recover the data (the 222 first bytes of public key)
    byte[] recoveredData =
        CertificateUtils.checkCertificateSignatureAndRecoverData(
            certificateRawData.array(), issuerCertificateContent);

    // Combines the recovered data and the header transmitted in clear to create the CA public key
    byte[] caPublicKeyModulus = new byte[CalypsoCaCertificateV1Constants.RSA_KEY_SIZE];
    System.arraycopy(caPublicKeyHeader, 0, caPublicKeyModulus, 0, caPublicKeyHeader.length);
    System.arraycopy(
        recoveredData, 0, caPublicKeyModulus, caPublicKeyHeader.length, recoveredData.length);
    caPublicKey = CertificateUtils.generateRSAPublicKeyFromModulus(caPublicKeyModulus);

    if (logger.isDebugEnabled()) {
      logger.debug("Calypso CA certificate V1");
      logger.debug("Target public key reference {}", HexUtil.toHex(issuerKeyReference));
      logger.debug("Issuer public key reference {}", HexUtil.toHex(caTargetKeyReference));
      logger.debug("Start date: {}", HexUtil.toHex(startDate));
      logger.debug("End date: {}", HexUtil.toHex(endDate));
      logger.debug(
          "Card certificate authentication: {}",
          isCardCertificatesAuthenticationAllowed ? MSG_ALLOWED : MSG_FORBIDDEN);
      logger.debug(
          "CA certificate authentication: {}",
          isCaCertificatesAuthenticationAllowed ? MSG_ALLOWED : MSG_FORBIDDEN);
      logger.debug(
          "Scope: {}", PkiExtensionService.getInstance().isTestMode() ? "test" : "production");
      logger.debug(
          "Target AID: {}",
          caTargetAidValue == null ? "unspecified" : HexUtil.toHex(caTargetAidValue));
      if (caTargetAidValue != null) {
        logger.debug("AID truncation: {}", isAidTruncated ? MSG_ALLOWED : MSG_FORBIDDEN);
      }
    }

    return this;
  }

  /**
   * Checks the format of CA rights.
   *
   * @param caRights The byte representing the rights of the certificate.
   * @throws CertificateValidationException If the upper four bits of caRights are non-zero.
   */
  private void checkCaRights(byte caRights) throws CertificateValidationException {
    // Check if any of the four most significant bits are set to 1.
    if ((caRights & 0xF0) != 0) {
      throw new CertificateValidationException(
          "Upper four bits of caRights must be zero: " + HexUtil.toHex(caRights));
    }
  }

  /**
   * Checks and gets the card certificate authentication authorization based on the given CA rights.
   *
   * @param caRights The byte representing the rights of the certificate.
   * @return true if card certificate authentication is allowed, false otherwise.
   * @throws CertificateValidationException If the certificate authentication authorization value is
   *     unexpected.
   */
  private boolean checkAndGetCardCertificateAuthenticationAuthorization(byte caRights)
      throws CertificateValidationException {
    int rights = (caRights & 0x0C) >> 2;
    if (rights == 1) {
      return false;
    } else if (rights == 0 || rights == 2) {
      return true;
    } else {
      throw new CertificateValidationException(
          "Unexpected card certificate authentication authorization value: "
              + HexUtil.toHex(caRights));
    }
  }

  /**
   * Checks and gets the CA Certificate authentication authorization based on the given CA rights.
   *
   * @param caRights The byte representing the rights of the certificate.
   * @return true if CA Certificate authentication is allowed, false otherwise.
   * @throws CertificateValidationException If the certificate authentication authorization value is
   *     unexpected.
   */
  private boolean checkAndGetCaCertificateAuthenticationAuthorization(byte caRights)
      throws CertificateValidationException {
    int rights = caRights & 0x03;
    if (rights == 1) {
      return false;
    } else if (rights == 0 || rights == 2) {
      return true;
    } else {
      throw new CertificateValidationException(
          "Unexpected CA certificate authentication authorization value: "
              + HexUtil.toHex(caRights));
    }
  }

  /**
   * Checks the scope of the certificate with regard to the context.
   *
   * @param caScope The byte value representing the scope of the certificate.
   * @throws CertificateValidationException If the certificate scope is invalid.
   */
  private void checkCaScope(byte caScope) throws CertificateValidationException {
    // check the scope of the certificate with regard to the context
    switch (caScope) {
      case 0x00:
        if (PkiExtensionService.getInstance().isTestMode()) {
          throw new CertificateValidationException(
              "Test certificate not allowed in production context");
        }
        break;
      case 0x01:
        if (!PkiExtensionService.getInstance().isTestMode()) {
          throw new CertificateValidationException(
              "Production certificate not allowed in test context");
        }
        break;
      case (byte) 0xFF:
        // allowed in all contexts
        break;
      default:
        throw new CertificateValidationException(
            "Invalid certificate scope: " + HexUtil.toHex(caScope));
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
    byte caTargetAidSize = buffer.get();
    if (caTargetAidSize == (byte) 0xFF) {
      buffer.position(buffer.position() + CalypsoCaCertificateV1Constants.AID_SIZE_MAX);
      return null; // no AID NOSONAR
    } else if (caTargetAidSize >= CalypsoCaCertificateV1Constants.AID_SIZE_MIN
        && caTargetAidSize <= CalypsoCaCertificateV1Constants.AID_SIZE_MAX) {
      byte[] aid = new byte[caTargetAidSize];
      buffer.position(
          buffer.position() + caTargetAidSize); // Move buffer position after reading AID
      return aid;
    } else {
      throw new CertificateValidationException(
          "Bad target AID size: " + caTargetAidSize + ", expected between 5 and 16");
    }
  }

  /**
   * Checks and gets the operating mode based on the given byte value.
   *
   * @param caOperatingMode The byte value representing the operating mode.
   * @return true if the operating mode is 1 (test), false if the operating mode is 0 (production).
   * @throws CertificateValidationException If the operating mode value is unexpected.
   */
  private boolean checkAndGetOperatingMode(byte caOperatingMode)
      throws CertificateValidationException {
    if (caOperatingMode == 0) {
      return false;
    } else if (caOperatingMode == 1) {
      return true;
    } else {
      throw new CertificateValidationException(
          "Unexpected operating mode value: " + HexUtil.toHex(caOperatingMode));
    }
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
          issuerCertificateContent.isAidTruncated() ? issuerAid.length : caTargetAidValue.length;

      if (caTargetAidValue.length < compareLength || issuerAid.length < compareLength) {
        throw new CertificateValidationException(
            MSG_CERTIFICATE_AID_MISMATCH_PARENT_CERTIFICATE_AID);
      }

      for (int i = 0; i < compareLength; i++) {
        if (caTargetAidValue[i] != issuerAid[i]) {
          throw new CertificateValidationException(
              MSG_CERTIFICATE_AID_MISMATCH_PARENT_CERTIFICATE_AID);
        }
      }
    }
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
    return caTargetAidValue != null;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isAidTruncated() {
    return isAidTruncated;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getAid() {
    return caTargetAidValue;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isCaCertificatesAuthenticationAllowed() {
    return isCaCertificatesAuthenticationAllowed;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isCardCertificatesAuthenticationAllowed() {
    return isCardCertificatesAuthenticationAllowed;
  }
}
