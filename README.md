# slip39-dart

[![pub package](https://img.shields.io/pub/v/slip39.svg)](https://pub.dartlang.org/packages/slip39)

The dart implementation of the [SLIP39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) for Shamir's Secret-Sharing for Mnemonic Codes.

The code based on the [Reference implementation of SLIP-0039](https://github.com/trezor/python-shamir-mnemonic/).

# DISCLAIMER

This project is still in early development phase. Use it at your own risk.

## Description

 This SLIP39 implementation uses a 3 level height (l=3) of a 16 degree (d=16) tree (T), which is represented as an array of the level two nodes (groups, G).

 The degree (d) and the level (l) of the tree are 16 and 3 respectively,
 which means that max d^(l-1), i.e. 16^2, leaf nodes (M) can be in a complete tree (or forest).

 The first level (l=1) node of the tree is the the root (R), the level 2 ones are the `SSS` groups (Gs or group nodes) e.g. `[G0, ..., Gd]`.
 
 The last, the third, level nodes are the only leafs (M, group members) which contains the generated mnemonics.
 
 Every node has two values:
  - the N and 
  - M i.e. n(N,M).
 
 Whihc means, that N (`threshold`) number of M children are required to reconstruct the node's secret.

## Format

There are two formats for representing the shares:
  - The JSON format, see details [here](#json-representation)
  - and a simplye array/List format.
  
The The tree's human friendly array representation only uses the group (l=2) nodes as arrays.
For example. : ``` [[1,1], [1,1], [3,5], [2,6]]```
The group's first parameter is the `N` (group threshold) while the second is the `M`, the number of members in the group. See, details in [Example](#Example).

## Installing

Add the following into the `pubspec.yaml`:

```
dependencies:
  slip39: ^0.1.6-dev.3
```

## Example

  ``` dart
  import 'package:slip39/slip39dart';

  int main() {
  // threshold (N) number of group shares required to reconstruct the master secret.
  final threshold = 2;
  final masterSecret = "ABCDEFGHIJKLMNOP";
  final passphrase = "TREZOR";

  // 4 groups shares and 2 are required to reconstruct the master secret.
  final groups = [
    // Alice group shares. 1 is enough to reconstruct a group share,
    // therefore she needs at least two group shares to be reconstructed,
    [1, 1],
    [1, 1],
    // 3 of 5 Friends' shares are required to reconstruct this group share
    [3, 5],
    // 2 of 6 Family's shares are required to reconstruct this group share
    [2, 6]
  ];

  final slip = Slip39.fromArray(
      masterSecret: masterSecret,
      passphrase: passphrase,
      threshold: threshold,
      groups: groups);

  // One of Alice's share
  final aliceShare = slip.fromPath('r/0').mnemonics;

  // and any two of family's shares.
  var familyShares = slip.fromPath('r/3/1').mnemonics;
  familyShares = familyShares..addAll(slip.fromPath('r/3/3').mnemonics);

  final allShares = aliceShare..addAll(familyShares);

  print("Shares used for restoring the master secret:");
  allShares..forEach((s) => print(s));
  
  final recoveredSecret = Slip39.recoverSecret(allShares, passphrase);
  assert(masterSecret == recoveredSecret);
  print("Recovered secret: $recoveredSecret");
}
```
## TODOS

- [x] Add unit tests.
- [x] Test with the reference code's test vectors.
- [ ] Refactor the helpers to different helper classes e.g. `CryptoHelper()`, `ShamirHelper()` etc.
- [x] Add `JSON` representation, see [JSON representation](#json-representation) below.
- [ ] Refactor to much simpler code.

### JSON Representation 

See in an example code from `eample/example.dart` below:
``` dart
import 'dart:convert';

import 'package:slip39/slip39.dart';

void main() {
  String masterSecret = "ABCDEFGHIJKLMNOP";
  String passphrase = "TREZOR";

  //
  // RFC 4627 compliant JSON
  //
  final jsonString = '''
{
  "name": "Alice's shares",
  "threshold": 2,
  "shares" : [
    {
      "name": "Primary",
      "threshold": 1,
      "shares": ["Primary share"]
    },
    {
      "name": "Secondary",
      "threshold": 1,
      "shares": ["Secondary share"]
    },
    {
      "name": "Friends",
      "threshold": 3,
      "shares": ["Albert", "Ben", "Carol", "David", "Edward", "Fred"]
    },
    {
      "name": "Family",
      "threshold": 2,
      "shares": ["Adam", "Brenda", "Cecil", "Donald", "Elissa"]
    }
  ]
}
''';

  final json = jsonDecode(jsonString);

  final slip = Slip39.from(
    json,
    masterSecret: masterSecret.codeUnits,
    passphrase: passphrase,
  );

  final masterNode = slip.fromPath('r');

  final jsonText = jsonEncode(masterNode);
  assert(jsonEncode(json) == jsonText);

  final familyNode = masterNode.derive(3);
  final familyNode2 = masterNode.deriveByName('Family');
  assert(familyNode == familyNode2);

  var familyShares = familyNode.mnemonics..shuffle();
  familyShares = familyShares.sublist(0, 2);

  // Recover from: 3 of 5 firend's shares and 2 of 6 of family shares
  // three Friend's shares
  var friendsShares = masterNode.deriveByName('Friends').mnemonics..shuffle();
  friendsShares = friendsShares.sublist(0, 3);

  final allShares = familyShares..addAll(friendsShares);

  print("Shares used for restoring the master secret:");
  allShares..forEach((s) => print(s));

  final recoveredSecret = String.fromCharCodes(
      Slip39.recoverSecret(allShares, passphrase: passphrase));
  print('\nMaster secret: $masterSecret');
  print("Recovered one: $recoveredSecret");
  assert(masterSecret == recoveredSecret);
}
```

## Package Direcotry Structure

The `dart` package directory structure follows the official [dart's recommendations](https://dart.dev/tools/pub/package-layout).

# LICENSE

CopyRight (c) 2019 Pal Dorogi `"iLap"` <pal.dorogi@gmail.com>

[MIT License](LICENSE)
