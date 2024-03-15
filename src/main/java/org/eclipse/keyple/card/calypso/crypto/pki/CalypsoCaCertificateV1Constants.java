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
 * Constants for Calypso CA certificate version 1.
 *
 * @since 0.1.0
 */
class CalypsoCaCertificateV1Constants {
  static final byte TYPE = (byte) 0x90;
  static final byte VERSION = 1;

  static final int RAW_DATA_SIZE = 384;

  static final int TYPE_SIZE = 1;
  static final int VERSION_SIZE = 1;
  static final int KEY_REFERENCE_SIZE = 29;
  static final int VALIDITY_DATE_SIZE = 4;
  static final int RFU1_SIZE = 4;
  static final int RIGHTS_SIZE = 1;
  static final int SCOPE_SIZE = 1;
  static final int AID_SIZE_MIN = 5;
  static final int AID_SIZE_MAX = 16;
  static final int OPERATING_MODE_SIZE = 1;
  static final int RFU2_SIZE = 2;
  static final int PUBLIC_KEY_HEADER_SIZE = 34;

  static final int RECOVERED_DATA_SIZE = 222;

  static final int ISSUER_KEY_REFERENCE_OFFSET = 2;
  static final int TARGET_KEY_REFERENCE_OFFSET = ISSUER_KEY_REFERENCE_OFFSET + KEY_REFERENCE_SIZE;

  static final int RSA_KEY_SIZE = 256;

  private CalypsoCaCertificateV1Constants() {}
}
