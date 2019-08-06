import '../lib/slip39.dart';

void main() {
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
  print("Recovered secret: $recoveredSecret");
  assert(masterSecret == recoveredSecret);
}
