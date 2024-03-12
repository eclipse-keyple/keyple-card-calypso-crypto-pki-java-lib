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
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.card.transaction.spi.*;
import org.eclipse.keypop.calypso.certificate.CalypsoCertificateApiFactory;
import org.eclipse.keypop.calypso.certificate.CertificateConsistencyException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;

/**
 * Extension service dedicated to the management of Calypso PKI card transaction and certificate
 * creation.
 *
 * @since 0.1.0
 */
public class PkiExtensionService {

  /** Singleton */
  private static final PkiExtensionService INSTANCE = new PkiExtensionService();

  private boolean isTestMode = false;
  private boolean isTestModeFinalized = false;

  // Add BouncyCastle provider to support RSA PSS signing not available in standard Java.
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  /**
   * Returns the service instance.
   *
   * @return A not null reference.
   * @since 0.1.0
   */
  public static PkiExtensionService getInstance() {
    return INSTANCE;
  }

  /**
   * Sets the system in test mode.
   *
   * <p>In test mode, the system allows the use of test certificates.
   *
   * <p>Note that enabling test mode should only be done in testing and development environments. It
   * should not be used in production as it may compromise system security or integrity.
   *
   * <p>The test mode can be set only just after the creation of the instance, this means that as
   * soon as one of the class's other methods is called, the call to this method will generate an
   * exception {@link IllegalStateException}.
   *
   * @since 0.1.0
   */
  public void setTestMode() {
    if (isTestModeFinalized) {
      throw new IllegalStateException("Test mode must be set first.");
    }
    isTestMode = true;
    isTestModeFinalized = true;
  }

  /**
   * Creates a factory for asymmetric crypto card transaction managers.
   *
   * @return A not null reference.
   * @since 0.1.0
   */
  public AsymmetricCryptoCardTransactionManagerFactory
      createAsymmetricCryptoCardTransactionManagerFactory() {
    isTestModeFinalized = true; // force test mode to be set first
    return new AsymmetricCryptoCardTransactionManagerFactoryAdapter();
  }

  /**
   * Creates a Primary Certificate Authority (PCA) certificate from a provided public key as a
   * {@link PublicKey}.
   *
   * @param pcaPublicKeyReference The reference to the PCA public key.
   * @param pcaPublicKey The PCA's public key.
   * @return A not null reference.
   * @throws IllegalArgumentException If the public key reference or the key is null or invalid.
   * @since 0.1.0
   */
  public PcaCertificate createPcaCertificate(byte[] pcaPublicKeyReference, PublicKey pcaPublicKey) {
    Assert.getInstance()
        .notNull(pcaPublicKeyReference, "pcaPublicKeyReference")
        .isEqual(pcaPublicKeyReference.length, 29, "pcaPublicKeyReference length");
    isTestModeFinalized = true; // force test mode to be set first
    CryptoUtils.checkRSA2048PublicKey(pcaPublicKey);
    return new PcaCertificateAdapter(pcaPublicKeyReference, pcaPublicKey);
  }

  /**
   * Creates a Primary Certificate Authority (PCA) certificate from a provided public key modulus.
   *
   * @param pcaPublicKeyReference The reference to the PCA public key.
   * @param pcaPublicKeyModulus The modulus of the PCA public key.
   * @return A not null reference.
   * @since 0.1.0
   */
  public PcaCertificate createPcaCertificate(
      byte[] pcaPublicKeyReference, byte[] pcaPublicKeyModulus) {
    Assert.getInstance()
        .notNull(pcaPublicKeyReference, "pcaPublicKeyReference")
        .isEqual(pcaPublicKeyReference.length, 29, "pcaPublicKeyReference length")
        .notNull(pcaPublicKeyModulus, "pcaPublicKeyModulus")
        .isEqual(pcaPublicKeyModulus.length, 256, "pcaPublicKeyModulus length");
    isTestModeFinalized = true; // force test mode to be set first
    return new PcaCertificateAdapter(pcaPublicKeyReference, pcaPublicKeyModulus);
  }

  /**
   * Creates a Certificate Authority (CA) certificate from raw data provided as a byte array.
   *
   * <p>This method takes a raw byte array representation of a CA certificate and parses it into a
   * usable {@link CaCertificate} object.
   *
   * <p>In addition to the signature check, a validation of the certificate validity period is done.
   *
   * @param caCertificate The 384-byte byte array containing the CA certificate data.
   * @return A not null reference.
   * @throws IllegalArgumentException If the provided value is null or invalid.
   * @throws CertificateConsistencyException If the certificate fails the internal validation.
   * @since 0.1.0
   */
  public CaCertificate createCaCertificate(byte[] caCertificate) {
    Assert.getInstance()
        .notNull(caCertificate, "caCertificate")
        .isEqual(
            caCertificate.length,
            CertificatesConstants.CA_CERTIFICATE_RAW_DATA_SIZE,
            "caCertificate length")
        .isEqual(
            (int) caCertificate[0],
            CertificatesConstants.CA_CERTIFICATE_TYPE_BYTE,
            "caCertificate type");
    isTestModeFinalized = true; // force test mode to be set first
    try {
      return new CalypsoCaCertificateV1Adapter(caCertificate);
    } catch (CertificateValidationException e) {
      throw new CertificateConsistencyException("Invalid CA certificate" + e.getMessage(), e);
    }
  }

  /**
   * Creates a {@link CaCertificateParser} object specifically tailored to parse the given CA
   * certificate type.
   *
   * <p>This method selects and instantiates the appropriate {@link CaCertificateParser}
   * implementation based on the provided {@link CaCertificateType}. This ensures that the parser is
   * capable of handling the specific format and structure of the certificate type, enabling
   * accurate parsing and data extraction.
   *
   * @param caCertificateType The type of CA certificate to be parsed, indicating the expected
   *     format and structure.
   * @return A not null reference.
   * @throws UnsupportedOperationException If the specified type is not supported by this factory.
   * @since 0.1.0
   */
  public CaCertificateParser createCaCertificateParser(CaCertificateType caCertificateType) {
    isTestModeFinalized = true; // force test mode to be set first
    if (caCertificateType == CaCertificateType.CALYPSO) {
      return new CalypsoCaCertificateParserAdapter();
    }
    throw new UnsupportedOperationException(
        "Unsupported CA certificate type: " + caCertificateType);
  }

  /**
   * Creates a {@link CardCertificateParser} object specifically tailored to parse the given card
   * certificate type.
   *
   * <p>This method selects and instantiates the appropriate {@link CardCertificateParser}
   * implementation based on the provided {@link CardCertificateType}. This ensures that the parser
   * is capable of handling the specific format and structure of the certificate type, enabling
   * accurate parsing and data extraction.
   *
   * @param cardCertificateType The type of card certificate to be parsed, indicating the expected
   *     format and structure.
   * @return A not null reference.
   * @throws UnsupportedOperationException If the specified type is not supported by this factory.
   * @since 0.1.0
   */
  public CardCertificateParser createCardCertificateParser(
      CardCertificateType cardCertificateType) {
    isTestModeFinalized = true; // force test mode to be set first
    if (cardCertificateType == CardCertificateType.CALYPSO) {
      return new CalypsoCardCertificateParserAdapter();
    }
    throw new UnsupportedOperationException(
        "Unsupported card certificate type: " + cardCertificateType);
  }

  /**
   * Get the factory for creating Calypso certificate.
   *
   * @return A not null reference.
   * @since 0.1.0
   */
  public CalypsoCertificateApiFactory getCalypsoCertificateApiFactory() {
    isTestModeFinalized = true; // force test mode to be set first
    return new CalypsoCertificateApiFactoryAdapter();
  }

  /**
   * Checks if the system is in test mode.
   *
   * @return true if the system is in test mode, false otherwise.
   * @since 0.1.0
   */
  boolean isTestMode() {
    return isTestMode;
  }
}
