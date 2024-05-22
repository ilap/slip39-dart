import 'dart:convert';
import 'dart:typed_data';

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
    masterSecret: Uint8List.fromList(masterSecret.codeUnits),
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
  for (var s in allShares) {
    print(s);
  }

  final recoveredSecret = String.fromCharCodes(
      Slip39.recoverSecret(allShares, passphrase: passphrase));
  print('\nMaster secret: $masterSecret');
  print("Recovered one: $recoveredSecret");
  assert(masterSecret == recoveredSecret);
}
