import 'package:test/test.dart';
import 'package:hex/hex.dart';

import 'package:slip39/slip39.dart';

void main() {
  const passphrase = "TREZOR";

  group("Groups test (T=1, N=1 e.g. [1,1]) - ", () {
    final masterSecret = 'ABCDEFGHIJKLMNOP';
    final totalGroups = 16;

    final groups = List<List<int>>.generate(totalGroups, (_) => [1, 1]);

    for (int group = 1; group <= totalGroups; group++) {
      for (int threshold = 1; threshold <= group; threshold++) {
       
        test("recover master secret for $threshold shares (threshold=$threshold) of $group '[1, 1,]' groups", () {
           final slip = Slip39.from(groups.sublist(0, group),
            masterSecret: masterSecret.codeUnits, passphrase: passphrase, threshold: threshold);

          final mnemonics = slip.fromPath('r').mnemonics.sublist(0, threshold);
          final recoveredSecret = Slip39.recoverSecret(mnemonics, passphrase: passphrase);
          assert(masterSecret == String.fromCharCodes(recoveredSecret));
        });
      }
    }
  });
}
