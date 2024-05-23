v0.1.0
* Initial release

v0.1.1
* Made it Dart 2 compatible

v0.1.2
* Changed SDK constraint in `pubspec.yaml` to allow Dart 2.0.0 release

v0.1.3
* Updated formatting

v0.1.4
* Added unittests, fixed minor issues, cleaned code

v0.1.5-dev.1
* Changed versioning format.

v0.1.5
* Added JSON representaion of the shares.
* Added more unittests.
* Added dart analyzer option file.

v0.1.6-dev.1
* Removed redundant code.

v0.1.6-dev.2
* Added validateMnemonic

v0.1.6-dev.3
* Added changes based on Auronmatrix`s PRs of the https://github.com/ilap/slip39-js/issues/4

v0.1.6-dev.4
* Added changes based on iancoleman's PR (https://github.com/ilap/slip39-js/issues/12)
* Removed redundant unit test.

v0.2.0
* Migrated to null-safety.
* Use an own decodeBigInt and encodeBigInt as the pointycastle's started handling negative BigInts which is not implemented in SLIP-0039.

v0.2.1
* Removed pointycastle and HEX package dependencies.

v0.2.2
* Added support for the `extendable backup flag`. See details in the recent [revision](https://github.com/satoshilabs/slips/commit/8d060706b549af6443e04f55605b71f65c981663?short_path=ee22765#diff-ee22765e198171085aada68244108cf54a020b79e69e67440854e27a4a927f04) of the [SLIP-39 specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md).

v0.3.0
* Update version to 0.3.0 for Dart SDK v3.4.0 compatibility.
