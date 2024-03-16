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
import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.certificate.CalypsoCertificateStore;
import org.eclipse.keypop.calypso.certificate.CertificateConsistencyException;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateSpi;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.PcaCertificateSpi;

/**
 * Adapter of {@link CalypsoCertificateStore}.
 *
 * @since 0.1.0
 */
final class CalypsoCertificateStoreAdapter implements CalypsoCertificateStore {

  private static final String MSG_THE_PROVIDED_PUBLIC_KEY_REFERENCE_ALREADY_REGISTERED =
      "The provided public key reference already registered.";
  private static final String MSG_INVALID_PUBLIC_KEY = "Invalid public key: ";
  private static final String MSG_AN_ERROR_OCCURS_DURING_THE_CHECK_OF_THE_PUBLIC_KEY =
      "An error occurs during the check of the public key: ";
  private static final String MSG_THE_ISSUER_CERTIFICATE_IS_NOT_REGISTERED =
      "The issuer certificate is not registered: ";
  private static final String MSG_INVALID_CERTIFICATE = "Invalid certificate: ";
  private static final String MSG_AN_ERROR_OCCURS_DURING_THE_CHECK_OF_THE_CERTIFICATE =
      "An error occurs during the check of the certificate: ";
  private static final String
      MSG_A_CERTIFICATE_IS_ALREADY_REGISTERED_FOR_THE_PROVIDED_PUBLIC_KEY_REFERENCE =
          "A certificate is already registered for the provided public key reference: ";

  /** singleton instance of CalypsoCertificateStore */
  private static final CalypsoCertificateStoreAdapter INSTANCE =
      new CalypsoCertificateStoreAdapter();

  private final Map<String, CaCertificateContentSpi> caCertificates =
      new HashMap<String, CaCertificateContentSpi>();

  /** Private constructor */
  private CalypsoCertificateStoreAdapter() {}

  /**
   * Returns the store instance.
   *
   * @return A non-null reference.
   * @since 0.1.0
   */
  static CalypsoCertificateStoreAdapter getInstance() {
    return INSTANCE;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public void addPcaPublicKey(byte[] pcaPublicKeyReference, RSAPublicKey pcaPublicKey) {

    Assert.getInstance()
        .notNull(pcaPublicKeyReference, "pcaPublicKeyReference")
        .isEqual(
            pcaPublicKeyReference.length,
            CalypsoCaCertificateV1Constants.KEY_REFERENCE_SIZE,
            "pcaPublicKeyReference length")
        .notNull(pcaPublicKey, "pcaPublicKey");

    String pcaPublicKeyReferenceKey = HexUtil.toHex(pcaPublicKeyReference);

    // Check if the reference exists
    if (caCertificates.containsKey(pcaPublicKeyReferenceKey)) {
      throw new IllegalStateException(MSG_THE_PROVIDED_PUBLIC_KEY_REFERENCE_ALREADY_REGISTERED);
    }

    // Check if the RSA public key has the expected characteristics (size and exponent)
    CertificateUtils.checkRSA2048PublicKey(pcaPublicKey);

    PcaCertificateSpi pcaCertificateSpi =
        new PcaCertificateAdapter(pcaPublicKeyReference, pcaPublicKey);

    // Check certificate and get content
    CaCertificateContentSpi certificateContent;
    try {
      certificateContent = pcaCertificateSpi.checkCertificateAndGetContent();
    } catch (CertificateValidationException e) {
      throw new IllegalArgumentException(MSG_INVALID_PUBLIC_KEY + e.getMessage(), e);
    } catch (AsymmetricCryptoException e) {
      throw new IllegalArgumentException(
          MSG_AN_ERROR_OCCURS_DURING_THE_CHECK_OF_THE_PUBLIC_KEY + e.getMessage(), e);
    }

    // Add a new PCA certificate to the map
    caCertificates.put(pcaPublicKeyReferenceKey, certificateContent);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public void addPcaPublicKey(byte[] pcaPublicKeyReference, byte[] pcaPublicKeyModulus) {

    Assert.getInstance()
        .notNull(pcaPublicKeyModulus, "pcaPublicKeyModulus")
        .isEqual(
            pcaPublicKeyModulus.length,
            CalypsoCaCertificateV1Constants.RSA_KEY_SIZE,
            "pcaPublicKeyModulus length");

    // Create a compliant RSA public key with the provided modulus
    RSAPublicKey pcaPublicKey;
    try {
      pcaPublicKey = CertificateUtils.generateRSAPublicKeyFromModulus(pcaPublicKeyModulus);
    } catch (AsymmetricCryptoException e) {
      throw new IllegalArgumentException(
          MSG_AN_ERROR_OCCURS_DURING_THE_CHECK_OF_THE_PUBLIC_KEY + e.getMessage(), e);
    }

    addPcaPublicKey(pcaPublicKeyReference, pcaPublicKey);
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] addCalypsoCaCertificate(byte[] caCertificate) {

    // For now, the only supported format is Calypso V1
    Assert.getInstance()
        .notNull(caCertificate, "caCertificate")
        .isEqual(
            caCertificate.length,
            CalypsoCaCertificateV1Constants.RAW_DATA_SIZE,
            "caCertificate length")
        .isEqual(
            (int) caCertificate[0], CalypsoCaCertificateV1Constants.TYPE, "CA certificate type")
        .isEqual(
            (int) caCertificate[1],
            CalypsoCaCertificateV1Constants.VERSION,
            "CA certificate version");

    CaCertificateSpi caCertificateSpi = new CalypsoCaCertificateV1Adapter(caCertificate);

    // Get the issuer public key reference
    String issuerKeyRef = HexUtil.toHex(caCertificateSpi.getIssuerPublicKeyReference());

    // Search the issuer certificate
    CaCertificateContentSpi issuerCertificateContent = caCertificates.get(issuerKeyRef);
    if (issuerCertificateContent == null) {
      throw new IllegalStateException(MSG_THE_ISSUER_CERTIFICATE_IS_NOT_REGISTERED + issuerKeyRef);
    }

    // Check the CA certificate using the issuer's certificate content
    CaCertificateContentSpi caCertificateContent;
    try {
      caCertificateContent =
          caCertificateSpi.checkCertificateAndGetContent(issuerCertificateContent);
    } catch (CertificateValidationException e) {
      throw new CertificateConsistencyException(MSG_INVALID_CERTIFICATE + e.getMessage(), e);
    } catch (AsymmetricCryptoException e) {
      throw new CertificateConsistencyException(
          MSG_AN_ERROR_OCCURS_DURING_THE_CHECK_OF_THE_CERTIFICATE + e.getMessage(), e);
    }

    // Save the certificate content into the store
    byte[] caKeyRef = caCertificateContent.getPublicKeyReference();
    String caKeyRefHex = HexUtil.toHex(caKeyRef);
    if (caCertificates.containsKey(caKeyRefHex)) {
      throw new IllegalStateException(
          MSG_A_CERTIFICATE_IS_ALREADY_REGISTERED_FOR_THE_PROVIDED_PUBLIC_KEY_REFERENCE
              + caKeyRefHex);
    }
    caCertificates.put(caKeyRefHex, caCertificateContent);

    return caKeyRef;
  }

  /**
   * Retrieves the certificate associated with the given CA public key reference.
   *
   * @param caPublicKeyReference The byte array representation of the CA public key reference.
   * @return null if the certificate is not found.
   * @since 0.1.0
   */
  CaCertificateContentSpi getCertificateContent(byte[] caPublicKeyReference) {
    return caCertificates.get(HexUtil.toHex(caPublicKeyReference));
  }
}
