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

import java.security.interfaces.RSAPublicKey;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keypop.calypso.card.transaction.spi.*;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;

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
  private boolean isTestModeConfigurable = true;

  /**
   * Returns the service instance.
   *
   * @return A non-null reference.
   * @since 0.1.0
   */
  public static PkiExtensionService getInstance() {
    return INSTANCE;
  }

  /**
   * Sets the system in test mode.
   *
   * <p>In test mode, the system requires the use of test certificates.
   *
   * <p>Note that enabling test mode should only be done in testing and development environments. It
   * should not be used in production as it may compromise system security or integrity.
   *
   * <p>The test mode can be set only just after the creation of the instance, this means that as
   * soon as one of the class's other methods is called, the call to this method will generate an
   * {@link IllegalStateException} exception.
   *
   * @since 0.1.0
   */
  public void setTestMode() {
    if (!isTestModeConfigurable) {
      throw new IllegalStateException("Test mode must be set first");
    }
    isTestMode = true;
    isTestModeConfigurable = false;
  }

  /**
   * Creates a factory for asymmetric crypto card transaction managers.
   *
   * @return A non-null reference.
   * @since 0.1.0
   */
  public AsymmetricCryptoCardTransactionManagerFactory
      createAsymmetricCryptoCardTransactionManagerFactory() {
    isTestModeConfigurable = false; // force test mode to be set first
    return new AsymmetricCryptoCardTransactionManagerFactoryAdapter();
  }

  /**
   * Creates a {@link PcaCertificate} from a provided 2048-bit RSA public key with a public exponent
   * equal to 65537, to be injected as root certificate of the chain of trust in the security
   * settings of a card PKI transaction.
   *
   * @param pcaPublicKeyReference The PCA public key reference (29 bytes).
   * @param pcaPublicKey The PCA public key (2048-bit RSA key with public exponent equal to 65537).
   * @return A non-null reference.
   * @throws IllegalArgumentException If the public key reference or the key is null or invalid.
   * @since 0.1.0
   */
  public PcaCertificate createPcaCertificate(
      byte[] pcaPublicKeyReference, RSAPublicKey pcaPublicKey) {

    Assert.getInstance()
        .notNull(pcaPublicKeyReference, "pcaPublicKeyReference")
        .isEqual(
            pcaPublicKeyReference.length,
            CalypsoCaCertificateV1Constants.KEY_REFERENCE_SIZE,
            "pcaPublicKeyReference length")
        .notNull(pcaPublicKey, "pcaPublicKey");

    CertificateUtils.checkRSA2048PublicKey(pcaPublicKey);

    isTestModeConfigurable = false; // force test mode to be set first
    return new PcaCertificateAdapter(pcaPublicKeyReference, pcaPublicKey);
  }

  /**
   * Creates a {@link PcaCertificate} from a provided 2048-bit RSA key modulus with a public
   * exponent equal to 65537, to be injected as root certificate of the chain of trust in the
   * security settings of a card PKI transaction.
   *
   * @param pcaPublicKeyReference The PCA public key reference (29 bytes).
   * @param pcaPublicKeyModulus The RSA public key modulus (256 bytes).
   * @return A non-null reference.
   * @throws IllegalArgumentException If the public key reference or the key modulus is null or
   *     invalid.
   * @since 0.1.0
   */
  public PcaCertificate createPcaCertificate(
      byte[] pcaPublicKeyReference, byte[] pcaPublicKeyModulus) {

    Assert.getInstance()
        .notNull(pcaPublicKeyReference, "pcaPublicKeyReference")
        .isEqual(
            pcaPublicKeyReference.length,
            CalypsoCaCertificateV1Constants.KEY_REFERENCE_SIZE,
            "pcaPublicKeyReference length")
        .notNull(pcaPublicKeyModulus, "pcaPublicKeyModulus")
        .isEqual(
            pcaPublicKeyModulus.length,
            CalypsoCaCertificateV1Constants.RSA_KEY_SIZE,
            "pcaPublicKeyModulus length");

    RSAPublicKey pcaPublicKey;
    try {
      pcaPublicKey = CertificateUtils.generateRSAPublicKeyFromModulus(pcaPublicKeyModulus);
    } catch (AsymmetricCryptoException e) {
      throw new IllegalArgumentException(e.getMessage(), e);
    }

    isTestModeConfigurable = false; // force test mode to be set first
    return new PcaCertificateAdapter(pcaPublicKeyReference, pcaPublicKey);
  }

  /**
   * Creates a {@link CaCertificate} from raw data of a CA certificate provided as a 384-byte byte
   * array, to be injected as intermediate certificate of the chain of trust in the security
   * settings of a card PKI transaction.
   *
   * <p>Currently, only CA certificates conforming to Calypso format V1 are supported.
   *
   * @param caCertificate The 384-byte byte array containing the CA certificate data.
   * @return A non-null reference.
   * @throws IllegalArgumentException If the provided value is null or invalid.
   * @since 0.1.0
   */
  public CaCertificate createCaCertificate(byte[] caCertificate) {

    Assert.getInstance()
        .notNull(caCertificate, "caCertificate")
        .isEqual(
            caCertificate.length,
            CalypsoCaCertificateV1Constants.RAW_DATA_SIZE,
            "caCertificate length")
        .isEqual((int) caCertificate[0], CalypsoCaCertificateV1Constants.TYPE, "caCertificate type")
        .isEqual(
            (int) caCertificate[1],
            CalypsoCaCertificateV1Constants.VERSION,
            "caCertificate version");

    isTestModeConfigurable = false; // force test mode to be set first
    return new CalypsoCaCertificateV1Adapter(caCertificate);
  }

  /**
   * Creates a {@link CaCertificateParser} object specifically tailored to parse card CA
   * certificates having the given CA certificate type, to be injected in the security settings of a
   * card PKI transaction.
   *
   * <p>This method selects and instantiates the appropriate {@link CaCertificateParser}
   * implementation based on the provided {@link CertificateType}. This ensures that the parser is
   * capable of handling the specific format and structure of the certificate type, enabling
   * accurate parsing and data extraction.
   *
   * <p>Currently, only CA certificates conforming to Calypso format V1 are supported.
   *
   * @param certificateType The type of CA certificate to be parsed, indicating the expected format
   *     and structure.
   * @return A non-null reference.
   * @throws IllegalArgumentException If the specified type null.
   * @since 0.1.0
   */
  public CaCertificateParser createCaCertificateParser(CertificateType certificateType) {

    Assert.getInstance().notNull(certificateType, "certificateType");

    isTestModeConfigurable = false; // force test mode to be set first
    return new CalypsoCaCertificateParserAdapter();
  }

  /**
   * Creates a {@link CardCertificateParser} object specifically tailored to parse card certificates
   * having the given card certificate type, to be injected in the security settings of a card PKI
   * transaction.
   *
   * <p>This method selects and instantiates the appropriate {@link CardCertificateParser}
   * implementation based on the provided {@link CertificateType}. This ensures that the parser is
   * capable of handling the specific format and structure of the certificate type, enabling
   * accurate parsing and data extraction.
   *
   * <p>Currently, only card certificates conforming to Calypso format V1 are supported.
   *
   * @param certificateType The type of card certificate to be parsed, indicating the expected
   *     format and structure.
   * @return A non-null reference.
   * @throws IllegalArgumentException If the specified type null.
   * @since 0.1.0
   */
  public CardCertificateParser createCardCertificateParser(CertificateType certificateType) {

    Assert.getInstance().notNull(certificateType, "certificateType");

    isTestModeConfigurable = false; // force test mode to be set first
    return new CalypsoCardCertificateParserAdapter();
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
