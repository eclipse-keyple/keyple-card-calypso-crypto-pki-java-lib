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

import org.eclipse.keypop.calypso.crypto.asymmetric.certificate.CardIdentifierApi;

/**
 * Adapter of {@link CardIdentifier}.
 *
 * @since 0.1.0
 */
class CardIdentifierAdapter implements CardIdentifier {
  private final CardIdentifierApi cardIdentifier;

  /** Constructor. */
  CardIdentifierAdapter(CardIdentifierApi cardIdentifier) {
    this.cardIdentifier = cardIdentifier;
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getAid() {
    return cardIdentifier.getAid();
  }

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public byte[] getSerialNumber() {
    return cardIdentifier.getSerialNumber();
  }
}