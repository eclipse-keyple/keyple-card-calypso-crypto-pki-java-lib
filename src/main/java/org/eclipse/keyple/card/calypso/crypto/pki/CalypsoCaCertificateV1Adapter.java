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
import java.security.interfaces.RSAPublicKey;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.card.transaction.spi.CaCertificate;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateSpi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapter of {@link CaCertificate} for Calypso V1-compliant CA certificates.
 *
 * @since 0.1.0
 */
final class CalypsoCaCertificateV1Adapter
    implements CaCertificate, CaCertificateSpi, CaCertificateContentSpi {

  private static final Logger logger = LoggerFactory.getLogger(CalypsoCaCertificateV1Adapter.class);

  private final ByteBuffer certificateRawData;
  private final byte[] issuerKeyReference =
      new byte[CalypsoCaCertificateV1Constants.KEY_REFERENCE_SIZE];
  private final byte[] caTargetKeyReference =
      new byte[CalypsoCaCertificateV1Constants.KEY_REFERENCE_SIZE];
  private long startDate;
  private byte caScope;
  private long endDate;
  private byte[] aid;
  private boolean isAidTruncated;
  private boolean isCardCertificatesAuthenticationAllowed;
  private boolean isCaCertificatesAuthenticationAllowed;
  private PublicKey caPublicKey;

  /**
   * Constructor
   *
   * @param cardOutputData The card output data containing the certificate as a 384-byte byte array.
   * @since 0.1.0
   */
  CalypsoCaCertificateV1Adapter(byte[] cardOutputData) {

    // Wrap the card output data and keep it for later use
    certificateRawData = ByteBuffer.wrap(cardOutputData);

    // Extract issuer key reference
    certificateRawData.position(CalypsoCaCertificateV1Constants.ISSUER_KEY_REFERENCE_OFFSET);
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

    byte[] recoveredData =
        CertificateUtils.checkCertificateSignatureAndRecoverData(
            certificateRawData.array(), (RSAPublicKey) issuerCertificateContent.getPublicKey());

    parseContent(recoveredData);

    checkCaScope();
    checkDates();

    if (!CertificateUtils.isAidValidForIssuer(aid, issuerCertificateContent)) {
      throw new CertificateValidationException("Certificate AID mismatch parent certificate AID");
    }

    return this;
  }

  private void parseContent(byte[] recoveredData)
      throws CertificateValidationException, AsymmetricCryptoException {

    // Target key reference
    certificateRawData.position(CalypsoCaCertificateV1Constants.TARGET_KEY_REFERENCE_OFFSET);
    certificateRawData.get(caTargetKeyReference);

    // Start date
    startDate = certificateRawData.getInt();

    // skip RFU1
    certificateRawData.position(
        certificateRawData.position() + CalypsoCaCertificateV1Constants.RFU1_SIZE);

    // CaRights
    byte caRights = certificateRawData.get();
    isCardCertificatesAuthenticationAllowed = (caRights & 4) == 0; // true if b3 == 0
    isCaCertificatesAuthenticationAllowed = (caRights & 1) == 0; // true if b0 == 0

    // CaScope
    caScope = certificateRawData.get();

    // End date
    endDate = certificateRawData.getInt();

    // Check AID target size and create the expected caTargetAidValue
    byte caTargetAidSize = certificateRawData.get();
    if (caTargetAidSize == (byte) 0xFF) {
      // no AID
      certificateRawData.position(
          certificateRawData.position() + CalypsoCaCertificateV1Constants.AID_SIZE_MAX);
    } else if (caTargetAidSize >= CalypsoCaCertificateV1Constants.AID_SIZE_MIN
        && caTargetAidSize <= CalypsoCaCertificateV1Constants.AID_SIZE_MAX) {
      aid = new byte[caTargetAidSize];
      certificateRawData.get(aid);
      // Move buffer position after reading AID
      certificateRawData.position(
          certificateRawData.position()
              + CalypsoCaCertificateV1Constants.AID_SIZE_MAX
              - caTargetAidSize);
    } else {
      throw new CertificateValidationException(
          "Bad target AID size: " + caTargetAidSize + ", expected between 5 and 16");
    }

    // Determine if the AID is truncated analyzing the CA operating mode
    byte caOperatingMode = certificateRawData.get();
    isAidTruncated = (caOperatingMode & 1) == 1; // true if b0 == 1

    // skip RFU2
    certificateRawData.position(
        certificateRawData.position() + CalypsoCaCertificateV1Constants.RFU2_SIZE);

    // Public key header
    byte[] caPublicKeyHeader = new byte[CalypsoCaCertificateV1Constants.PUBLIC_KEY_HEADER_SIZE];
    certificateRawData.get(caPublicKeyHeader);

    // Combines the recovered data and the header transmitted in clear to create the CA public key
    byte[] caPublicKeyModulus = new byte[CalypsoCaCertificateV1Constants.RSA_KEY_SIZE];
    System.arraycopy(caPublicKeyHeader, 0, caPublicKeyModulus, 0, caPublicKeyHeader.length);
    System.arraycopy(
        recoveredData, 0, caPublicKeyModulus, caPublicKeyHeader.length, recoveredData.length);
    caPublicKey = CertificateUtils.generateRSAPublicKeyFromModulus(caPublicKeyModulus);
  }

  private void checkCaScope() throws CertificateValidationException {
    switch (caScope) {
      case 0x00:
        if (PkiExtensionService.getInstance().isTestMode()) {
          throw new CertificateValidationException(
              "Production certificate not allowed in test context");
        }
        break;
      case 0x01:
        if (!PkiExtensionService.getInstance().isTestMode()) {
          throw new CertificateValidationException(
              "Test certificate not allowed in production context");
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

  private void checkDates() throws CertificateValidationException {

    long currentDate = CertificateUtils.getCurrentDateAsBcdLong();

    if (startDate != 0 && currentDate < startDate) {
      throw new CertificateValidationException(
          "Certificate not yet valid. Start date: " + HexUtil.toHex(startDate));
    }

    if (endDate != 0 && currentDate > endDate) {
      String endDateHex = HexUtil.toHex(endDate);
      logger.warn("Certificate expired. End date: {}", endDateHex);
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
    return aid != null;
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
    return aid;
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

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public String toString() {
    return "CalypsoCaCertificateV1Adapter{"
        + "caScope="
        + HexUtil.toHex(caScope)
        + ", issuerKeyReference="
        + HexUtil.toHex(issuerKeyReference)
        + ", caTargetKeyReference="
        + HexUtil.toHex(caTargetKeyReference)
        + ", startDate="
        + HexUtil.toHex(startDate)
        + ", endDate="
        + HexUtil.toHex(endDate)
        + ", aid="
        + HexUtil.toHex(aid)
        + ", isAidTruncated="
        + isAidTruncated
        + ", isCardCertificatesAuthenticationAllowed="
        + isCardCertificatesAuthenticationAllowed
        + ", isCaCertificatesAuthenticationAllowed="
        + isCaCertificatesAuthenticationAllowed
        + '}';
  }
}
