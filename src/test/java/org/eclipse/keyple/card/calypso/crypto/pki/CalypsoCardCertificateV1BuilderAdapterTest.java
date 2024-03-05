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

import static org.junit.Assert.*;

public class CalypsoCardCertificateV1BuilderAdapterTest {

  //  @Test(expected = IllegalArgumentException.class)
  //  public void withCardPublicKey_whenNullKey_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withCardPublicKey(null);
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withCardPublicKey_whenInvalidKeyLength_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withCardPublicKey(new byte[1]);
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withStartDate_whenInvalidYear_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withStartDate(10000, 2, 17);
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withStartDate_whenInvalidMonth_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withStartDate(2024, 0, 17);
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withStartDate_whenInvalidDay_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withStartDate(2024, 2, 0);
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withEndDate_whenInvalidYear_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withEndDate(10000, 2, 17);
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withEndDate_whenInvalidMonth_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withEndDate(2024, 0, 17);
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withEndDate_whenInvalidDay_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withEndDate(2024, 2, 0);
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withAid_whenAidIsNull_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withAid(null);
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withAid_whenAidIsTooShort_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withAid(HexUtil.toByteArray("01020304"));
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withAid_whenAidIsTooLong_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withAid(HexUtil.toByteArray("0102030405060708010203040506070801"));
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withCardSerialNumber_whenCardSerialNumberIsNull_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withCardSerialNumber(null);
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withCardSerialNumber_whenCardSerialNumberLengthIsWrong_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withCardSerialNumber(HexUtil.toByteArray("01"));
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withCardStartupInfo_whenCardStartupInfoIsNull_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withCardStartupInfo(null);
  //  }
  //
  //  @Test(expected = IllegalArgumentException.class)
  //  public void withCardStartupInfo_whenCardStartupInfoLengthIsWrong_throwsIAE() {
  //    CalypsoCardCertificateV1Builder builder = new CalypsoCardCertificateV1BuilderAdapter();
  //    builder.withCardStartupInfo(HexUtil.toByteArray("01"));
  //  }
  //
  //  @Test
  //  public void build() {}
}
