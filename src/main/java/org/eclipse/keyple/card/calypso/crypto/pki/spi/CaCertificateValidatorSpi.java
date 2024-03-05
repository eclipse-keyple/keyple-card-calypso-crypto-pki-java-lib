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
package org.eclipse.keyple.card.calypso.crypto.pki.spi;

/**
 * Service provider interface for validating CA certificates.
 *
 * <p>Implementations of this interface should provide mechanisms to verify the validity of the
 * certificate considering the information fields it contains, the signature being already verified.
 *
 * @since 0.1.0
 */
public interface CaCertificateValidatorSpi {

  /**
   * Validates the provided CA certificate. Implementations should define specific validation logic,
   * such as verifying checking certificate expiry dates or validating the certificate's issuer,
   * etc.
   *
   * @param caCertificate The CA certificate to be validated.
   * @return true if the certificate is valid; false otherwise.
   * @throws IllegalArgumentException If caCertificate is null or does not meet the expected format
   *     or content requirements.
   * @since 0.1.0
   */
  boolean isCertificateValid(byte[] caCertificate);
}
