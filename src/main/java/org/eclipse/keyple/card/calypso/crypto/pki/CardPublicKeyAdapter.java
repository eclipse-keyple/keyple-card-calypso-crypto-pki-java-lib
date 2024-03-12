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

import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.spi.CardPublicKeySpi;

/**
 * Adapter of {@link CardPublicKeySpi}.
 *
 * @since 0.1.0
 */
final class CardPublicKeyAdapter implements CardPublicKeySpi {

  private final byte[] publicKeyRawValue;

  /**
   * Constructor.
   *
   * @param publicKeyRawValue A 64-byte byte array containing the ECC public key.
   * @since 0.1.0
   */
  CardPublicKeyAdapter(byte[] publicKeyRawValue) {
    this.publicKeyRawValue = publicKeyRawValue;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getRawValue() {
    return publicKeyRawValue;
  }
}
