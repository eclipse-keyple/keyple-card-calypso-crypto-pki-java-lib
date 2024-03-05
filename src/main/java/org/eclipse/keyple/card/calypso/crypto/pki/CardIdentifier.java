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

/**
 * Provides methods for retrieving card identifiers.
 *
 * @since 0.1.0
 */
public interface CardIdentifier {

  /**
   * Retrieves the AID of the card, as a byte array.
   *
   * @return A not empty byte array.
   * @since 0.1.0
   */
  byte[] getAid();

  /**
   * Retrieves the serial number of the card, as a byte array.
   *
   * @return An 8-byte byte array.
   * @since 0.1.0
   */
  byte[] getSerialNumber();
}
