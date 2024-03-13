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
 * Provides constant values for Calypso V1 certificates.
 *
 * @since 0.1.0
 */
class CertificatesConstants {

  // Common definitions
  static final int KEY_REFERENCE_SIZE = 29;
  static final int AID_SIZE_MIN = 5;
  static final int AID_SIZE_MAX = 16;
  static final int VALIDITY_DATE_SIZE = 4;
  static final int RSA_KEY_SIZE = 256;
  static final int RSA_SIGNATURE_SIZE = 256;

  // CA certificate specific definitions
  static final int CA_CERTIFICATE_RAW_DATA_SIZE = 384;
  static final byte CA_CERTIFICATE_TYPE_BYTE = (byte) 0x90;
  static final int CA_CERTIFICATE_RECOVERED_DATA_SIZE = 222;
  static final byte CA_CERTIFICATE_VERSION_BYTE = 1;
  static final int CA_CERTIFICATE_TYPE_OFFSET = 0;
  static final int CA_CERTIFICATE_ISSUER_KEY_REFERENCE_OFFSET = 2;
  static final int CA_CERTIFICATE_TARGET_KEY_REFERENCE_OFFSET =
      CA_CERTIFICATE_ISSUER_KEY_REFERENCE_OFFSET + KEY_REFERENCE_SIZE;
  static final int CA_TYPE_SIZE = 1;
  static final int CA_RFU1_SIZE = 4;
  static final int CA_RFU2_SIZE = 2;
  static final int CA_PUBLIC_KEY_HEADER_SIZE = 34;

  // Card certificate specific definitions
  static final int CARD_CERTIFICATE_RAW_DATA_SIZE = 316;
  static final byte CARD_CERTIFICATE_TYPE_BYTE = (byte) 0x91;
  static final int CARD_CERTIFICATE_RECOVERED_DATA_SIZE = 222;
  static final byte CARD_CERTIFICATE_VERSION_BYTE = 1;
  static final int CARD_SERIAL_NUMBER_SIZE = 8;
  static final int CARD_CERTIFICATE_RIGHT_SIZE = 1;
  static final int CARD_CERTIFICATE_RFU_SIZE = 18;
  static final int CARD_CERTIFICATE_RECOVERED_CARD_INFO_SIZE = 7;
  static final int CARD_CERTIFICATE_RECOVERED_ECC_PUBLIC_KEY_SIZE = 64;

  /** Private constructor. */
  private CertificatesConstants() {}
}
