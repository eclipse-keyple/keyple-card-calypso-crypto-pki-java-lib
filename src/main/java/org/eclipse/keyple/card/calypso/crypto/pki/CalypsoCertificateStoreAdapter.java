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

import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.eclipse.keyple.core.util.Assert;
import org.eclipse.keyple.core.util.HexUtil;
import org.eclipse.keypop.calypso.certificate.CalypsoCertificateStore;
import org.eclipse.keypop.calypso.certificate.CertificateConsistencyException;
import org.eclipse.keypop.calypso.crypto.asymmetric.AsymmetricCryptoException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CertificateValidationException;
import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CaCertificateContentSpi;

/**
 * Adapter of {@link CalypsoCertificateStore}.
 *
 * @since 0.1.0
 */
final class CalypsoCertificateStoreAdapter implements CalypsoCertificateStore {

  private static final String MSG_THE_PROVIDED_PUBLIC_KEY_REFERENCE_ALREADY_IN_THE_STORE =
      "The provided public key reference already in the store.";
  private final Map<String, CaCertificateContentSpi> publicKeyReferenceToCaCertificateContentSpi =
      new HashMap<String, CaCertificateContentSpi>();

  /** singleton instance of CalypsoCertificateStore */
  private static final CalypsoCertificateStoreAdapter INSTANCE =
      new CalypsoCertificateStoreAdapter();

  /** Private constructor */
  private CalypsoCertificateStoreAdapter() {}

  /**
   * Returns the store instance.
   *
   * @return A not null reference.
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
  public CalypsoCertificateStore addPcaPublicKey(
      byte[] pcaPublicKeyReference, RSAPublicKey pcaPublicKey) {
    Assert.getInstance()
        .notNull(pcaPublicKeyReference, "pcaPublicKeyReference")
        .isEqual(pcaPublicKeyReference.length, 29, "pcaPublicKeyReference length")
        .notNull(pcaPublicKey, "pcaPublicKey");

    String pcaPublicKeyReferenceKey = HexUtil.toHex(pcaPublicKeyReference);

    // Check if the reference exists
    if (publicKeyReferenceToCaCertificateContentSpi.containsKey(pcaPublicKeyReferenceKey)) {
      throw new IllegalStateException(MSG_THE_PROVIDED_PUBLIC_KEY_REFERENCE_ALREADY_IN_THE_STORE);
    }

    // Check if the RSA public key has the expected characteristics (size and exponent)
    CryptoUtils.checkRSA2048PublicKey(pcaPublicKey);

    // Add a new PCA certificate to the map
    publicKeyReferenceToCaCertificateContentSpi.put(
        pcaPublicKeyReferenceKey, new PcaCertificateAdapter(pcaPublicKeyReference, pcaPublicKey));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCertificateStore addPcaPublicKey(
      byte[] pcaPublicKeyReference, byte[] pcaPublicKeyModulus) {
    Assert.getInstance()
        .notNull(pcaPublicKeyReference, "pcaPublicKeyReference")
        .isEqual(pcaPublicKeyReference.length, 29, "pcaPublicKeyReference length")
        .notNull(pcaPublicKeyModulus, "pcaPublicKeyModulus")
        .isEqual(pcaPublicKeyModulus.length, 256, "pcaPublicKeyModulus length");

    String pcaPublicKeyReferenceKey = HexUtil.toHex(pcaPublicKeyReference);

    // Check if the reference exists
    if (publicKeyReferenceToCaCertificateContentSpi.containsKey(pcaPublicKeyReferenceKey)) {
      throw new IllegalStateException(MSG_THE_PROVIDED_PUBLIC_KEY_REFERENCE_ALREADY_IN_THE_STORE);
    }

    // Create a compliant RSA public key with the provided modulus
    RSAPublicKey pcaPublicKey = null;
    try {
      pcaPublicKey = CryptoUtils.generateRSAPublicKeyFromModulus(pcaPublicKeyModulus);
    } catch (AsymmetricCryptoException e) {
      throw new IllegalArgumentException(e.getMessage(), e);
    }

    // Add a new PCA certificate to the map
    publicKeyReferenceToCaCertificateContentSpi.put(
        pcaPublicKeyReferenceKey, new PcaCertificateAdapter(pcaPublicKeyReference, pcaPublicKey));
    return this;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public CalypsoCertificateStore addCalypsoCaCertificate(byte[] caCertificate) {

    // For now, the only supported format is Calypso V1
    Assert.getInstance()
        .notNull(caCertificate, "caCertificate")
        .isEqual(
            caCertificate.length,
            CertificatesConstants.CA_CERTIFICATE_RAW_DATA_SIZE,
            "caCertificate length");

    if (caCertificate[CertificatesConstants.CA_CERTIFICATE_TYPE_OFFSET]
        != CertificatesConstants.CA_CERTIFICATE_TYPE_BYTE) {
      throw new IllegalArgumentException(
          "Invalid certificate type: "
              + HexUtil.toHex(caCertificate[CertificatesConstants.CA_CERTIFICATE_TYPE_OFFSET]));
    }

    // Extract the certificate reference and check if already present
    byte[] certificateReference =
        Arrays.copyOfRange(
            caCertificate,
            CertificatesConstants.CA_CERTIFICATE_TARGET_KEY_REFERENCE_OFFSET,
            CertificatesConstants.CA_CERTIFICATE_TARGET_KEY_REFERENCE_OFFSET + KEY_REFERENCE_SIZE);

    String certificateReferenceKey = HexUtil.toHex(certificateReference);

    if (publicKeyReferenceToCaCertificateContentSpi.containsKey(certificateReferenceKey)) {
      throw new IllegalStateException(MSG_THE_PROVIDED_PUBLIC_KEY_REFERENCE_ALREADY_IN_THE_STORE);
    }

    // Extract the parent certificate reference and check if already present
    byte[] parentCertificateReference =
        Arrays.copyOfRange(
            caCertificate,
            CertificatesConstants.CA_CERTIFICATE_ISSUER_KEY_REFERENCE_OFFSET,
            CertificatesConstants.CA_CERTIFICATE_ISSUER_KEY_REFERENCE_OFFSET + KEY_REFERENCE_SIZE);

    String parentCertificateReferenceKey = HexUtil.toHex(parentCertificateReference);

    CaCertificateContentSpi parentCertificate =
        publicKeyReferenceToCaCertificateContentSpi.get(parentCertificateReferenceKey);

    if (parentCertificate == null) {
      throw new IllegalStateException(
          "Parent certificate not found. Reference: " + parentCertificateReferenceKey);
    }

    // Create a new CA certificate from the raw data, check it and add its content to the map
    try {
      CalypsoCaCertificateV1Adapter certificateAdapter =
          new CalypsoCaCertificateV1Adapter(caCertificate);
      publicKeyReferenceToCaCertificateContentSpi.put(
          parentCertificateReferenceKey,
          certificateAdapter.checkCertificateAndGetContent(parentCertificate));
    } catch (CertificateValidationException e) {
      throw new CertificateConsistencyException(
          "Check of the certificate fails: " + e.getMessage(), e);
    } catch (AsymmetricCryptoException e) {
      throw new CertificateConsistencyException(
          "An error occurred while checking the CA certificate: " + e.getMessage(), e);
    }
    return this;
  }

  /**
   * Retrieves the certificate associated with the given CA public key reference.
   *
   * @param caPublicKeyReference The byte array representation of the CA public key reference.
   * @return null if the certificate is not found.
   * @since 0.1.0
   */
  CaCertificateContentSpi getCertificate(byte[] caPublicKeyReference) {
    return publicKeyReferenceToCaCertificateContentSpi.get(HexUtil.toHex(caPublicKeyReference));
  }
}
