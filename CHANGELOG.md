# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.3] - 2025-09-10
### Changed
- Removed explicit use of the BouncyCastle (`"BC"`) provider when selecting key factories and signature algorithms.  
  The provider is now chosen automatically by the JVM/Android runtime.  
  This change improves compatibility with Android (API 28+) where `KeyFactory.RSA` and similar algorithms are no longer
  available through the `BC` provider.

## [0.2.2] - 2025-07-21
### Fixed
- Fixed a `NoSuchMethodError` at runtime to ensure full compatibility with Java 8 JREs.
### Changed
- Migrated the CI pipeline from Jenkins to GitHub Actions.

## [0.2.1] - 2025-01-22
### Fixed
- Enhanced integrity validation in signature verification process.
### Changed
- Logging improvement.

## [0.2.0] - 2024-04-17
### Changed
- Merged `CaCertificateType` and `CardCertificateType` to `CertificateType`.

## [0.1.0] - 2024-04-12
This is the initial release.

[unreleased]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-pki-java-lib/compare/0.2.3...HEAD
[0.2.3]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-pki-java-lib/compare/0.2.2...0.2.3
[0.2.2]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-pki-java-lib/compare/0.2.1...0.2.2
[0.2.1]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-pki-java-lib/compare/0.2.0...0.2.1
[0.2.0]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-pki-java-lib/compare/0.1.0...0.2.0
[0.1.0]: https://github.com/eclipse-keyple/keyple-card-calypso-crypto-pki-java-lib/releases/tag/0.1.0