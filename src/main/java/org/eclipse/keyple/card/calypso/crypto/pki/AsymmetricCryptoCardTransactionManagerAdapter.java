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
import org.eclipse.keypop.calypso.crypto.asymmetric.transaction.spi.AsymmetricCryptoCardTransactionManagerSpi;

/**
 * Adapter of {@link AsymmetricCryptoCardTransactionManagerSpi}.
 *
 * @since 0.1.0
 */
final class AsymmetricCryptoCardTransactionManagerAdapter
    implements AsymmetricCryptoCardTransactionManagerSpi {

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public void initTerminalPkiSession(CardPublicKeySpi cardPublicKey) {}

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public void updateTerminalPkiSession(byte[] cardApdu) {}

  /**
   * {@inheritDoc}
   *
   * @since 0.1.0
   */
  @Override
  public boolean isCardPkiSessionValid(byte[] cardSessionSignature) {
    return false;
  }
}
