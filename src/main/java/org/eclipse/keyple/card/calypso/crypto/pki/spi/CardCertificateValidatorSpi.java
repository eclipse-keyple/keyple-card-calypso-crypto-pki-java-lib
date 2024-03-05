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

import org.eclipse.keyple.card.calypso.crypto.pki.CardIdentifier;

/**
 * Service provider interface for validating card certificates.
 *
 * <p>Implementations of this interface should provide mechanisms to verify the validity of the
 * certificate considering the information fields it contains, the signature being already verified.
 *
 * @since 0.1.0
 */
public interface CardCertificateValidatorSpi {

  /**
   * Validates the provided card certificate. Implementations should define specific validation
   * logic, such as verifying checking certificate expiry dates or validating the certificate's
   * issuer, etc.
   *
   * <p>The card image is required to check the certificate content against the card identification.
   *
   * @param cardCertificate The card certificate to be validated.
   * @param cardIdentifier The card identifier.
   * @return true if the certificate is valid; false otherwise.
   * @throws IllegalArgumentException If the cardCertificate is null or does not meet the expected
   *     format or content requirements.
   * @since 0.1.0
   */
  boolean isCertificateValid(byte[] cardCertificate, CardIdentifier cardIdentifier);
}
