import 'dart:io';
import 'dart:convert';

import 'package:pinenacl/ed25519.dart';
import 'package:test/test.dart';

import 'package:slip39/slip39.dart';

void main() {
  final masterSecret = 'ABCDEFGHIJKLMNOP';
  final passphrase = 'TREZOR';
  final oneOfOne = [
    [1, 1]
  ];
  final fiveOfSeven = [
    [5, 7]
  ];

  final slip15 = Slip39.from(fiveOfSeven,
      masterSecret: Uint8List.fromList(masterSecret.codeUnits),
      passphrase: passphrase,
      threshold: 1);

  final slip15NoPW = Slip39.from(fiveOfSeven,
      masterSecret: Uint8List.fromList(masterSecret.codeUnits), threshold: 1);

//
// Combinations C(n, k) of the grooups
//
  List getCombinations(array, k) {
    List<List<int>> result = List<List<int>>.empty(growable: true);
    var combinations = List<int>.filled(k, 0);

    void helper(int level, int start) {
      for (var i = start; i < array.length - k + level + 1; i++) {
        combinations[level] = array[i];

        if (level < k - 1) {
          helper(level + 1, i + 1);
        } else {
          result.add(combinations.sublist(0));
        }
      }
    }

    helper(0, 0);
    return result;
  }

  group('Basic Tests', () {
    group('Test threshold 1 with 5 of 7 shares of a group combinations', () {
      var mnemonics = slip15.fromPath('r/0').mnemonics;

      var combinations = getCombinations([0, 1, 2, 3, 4, 5, 6], 5);
      for (var item in combinations) {
        item.shuffle();
        var description = 'Test shuffled combination ${item.join(' ')}.';
        test(description, () {
          var shares = item.map<String>((idx) => mnemonics[idx]).toList();
          assert(masterSecret ==
              String.fromCharCodes(
                  Slip39.recoverSecret(shares, passphrase: passphrase)));
        });
      }
    });

    group('Test passhrase', () {
      var mnemonics = slip15.fromPath('r/0').mnemonics;
      var nopwMnemonics = slip15NoPW.fromPath('r/0').mnemonics;

      test('should return valid mastersecret when user submits valid passphrse',
          () {
        assert(masterSecret ==
            String.fromCharCodes(Slip39.recoverSecret(mnemonics.sublist(0, 5),
                passphrase: passphrase)));
      });
      test(
          'should NOT return valid mastersecret when user submits invalid passphrse',
          () {
        assert(masterSecret !=
            String.fromCharCodes(
                Slip39.recoverSecret(mnemonics.sublist(0, 5))));
      });
      test(
          'should return valid mastersecret when user does not submit passphrse',
          () {
        assert(masterSecret ==
            String.fromCharCodes(
                Slip39.recoverSecret(nopwMnemonics.sublist(0, 5))));
      });
    });

    group('Test iteration exponent', () {
      test(
          'should return valid mastersecret when user apply valid iteration exponent',
          () {
        final slip1 = Slip39.from(oneOfOne,
            threshold: 1,
            masterSecret: Uint8List.fromList(masterSecret.codeUnits),
            iterationExponent: 1);

        final slip2 = Slip39.from(oneOfOne,
            threshold: 1,
            masterSecret: Uint8List.fromList(masterSecret.codeUnits),
            iterationExponent: 2);
        var m1 = slip1.fromPath('r/0').mnemonics;
        var m2 = slip2.fromPath('r/0').mnemonics;
        assert(masterSecret == String.fromCharCodes(Slip39.recoverSecret(m1)));

        assert(masterSecret == String.fromCharCodes(Slip39.recoverSecret(m2)));
      });

      test('should throw an Error when user submits invalid iteration exponent',
          () {
        expect(
            () => Slip39.from(oneOfOne,
                masterSecret: Uint8List.fromList(masterSecret.codeUnits),
                iterationExponent: -1),
            throwsException);
        expect(
            () => Slip39.from(oneOfOne,
                masterSecret: Uint8List.fromList(masterSecret.codeUnits),
                iterationExponent: 33),
            throwsException);
      });
    });
  });

// FIXME: finish it.
  group('Group Sharing Tests', () {
    group('Test all valid combinations of mnemonics', () {
      /*final groups = [
        [3, 5],
        [3, 3],
        [2, 5],
        [1, 1]
      ];
      final slip = Slip39.from(groups,  masterSecret: Uint8List.fromList(masterSecret.codeUnits), threshold: 2);
      */
      test(
          'Should return the valid master secret when it tested with minimal sets of mnemonics.',
          () {
        /*  final mnemonics = slip.fromPath('r').mnemonics;
        print(mnemonics);
        group2Mnemonics.filter((_, index) {
        return index == 0 || index == 2;
      }).concat(group3Mnemonic);

      assert(Uint8List.fromList(masterSecret.codeUnits) == String.fromCharCodes(Slip39.recoverSecret(mnemonics)));
      */
      });
      test(
          'TODO: Should NOT return the valid master secret when one compare group and one incompvare group out of two groups required',
          () {
        assert(true);
      });
      test(
          'TODO: Should return the valid master secret when one group of two required but only one applied.',
          () {
        assert(true);
      });
    });
  });

  group('Original test vectors Tests', () {
    final dir = Directory.current;
    final file = File('${dir.path}/test/vectors.json');
    final contents = file.readAsStringSync();
    final tests = JsonDecoder().convert(contents);

    tests.forEach((item) {
      String? description = item[0];
      final mnemonics = List<String>.from(item[1]);
      String? ms = item[2];
      if (item[0].toString().startsWith("17.")) {
        print("TEST:");
      }

      test(description, () {
        if (ms!.isNotEmpty) {
          List<int> result =
              Slip39.recoverSecret(mnemonics, passphrase: passphrase);
          assert(ms == Base16Encoder.instance.encode(result));
        } else {
          expect(() => Slip39.recoverSecret(mnemonics, passphrase: passphrase),
              throwsException);
        }
      });
    });
  });

  const vectors = [
    [
      "2. Mnemonic with invalid checksum (128 bits)",
      [
        "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision kidney"
      ]
    ],
    [
      "21. Mnemonic with invalid checksum (256 bits)",
      [
        "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect lunar"
      ]
    ],
    [
      "3. Mnemonic with invalid padding (128 bits)",
      [
        "duckling enlarge academic academic email result length solution fridge kidney coal piece deal husband erode duke ajar music cargo fitness"
      ]
    ],
    [
      "22. Mnemonic with invalid padding (256 bits)",
      [
        "theory painting academic academic campus sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips facility obtain sister"
      ]
    ],
    [
      "10. Mnemonics with greater group threshold than group counts (128 bits)",
      [
        "music husband acrobat acid artist finance center either graduate swimming object bike medical clothes station aspect spider maiden bulb welcome",
        "music husband acrobat agency advance hunting bike corner density careful material civil evil tactics remind hawk discuss hobo voice rainbow",
        "music husband beard academic black tricycle clock mayor estimate level photo episode exclude ecology papa source amazing salt verify divorce"
      ]
    ],
    [
      "29. Mnemonics with greater group threshold than group counts (256 bits)",
      [
        "smirk pink acrobat acid auction wireless impulse spine sprinkle fortune clogs elbow guest hush loyalty crush dictate tracks airport talent",
        "smirk pink acrobat agency dwarf emperor ajar organize legs slice harvest plastic dynamic style mobile float bulb health coding credit",
        "smirk pink beard academic alto strategy carve shame language rapids ruin smart location spray training acquire eraser endorse submit peaceful"
      ]
    ],
    [
      "39. Mnemonic with insufficient length",
      [
        "junk necklace academic academic acne isolate join hesitate lunar roster dough calcium chemical ladybug amount mobile glasses verify cylinder"
      ]
    ],
    [
      "40. Mnemonic with invalid master secret length",
      [
        "fraction necklace academic academic award teammate mouse regular testify coding building member verdict purchase blind camera duration email prepare spirit quarter"
      ]
    ]
  ];

  group('Mnemonic validation', () {
    for (var item in vectors) {
      final mnemonics = List<String>.from(item[1] as Iterable<dynamic>);
      var index = 0;
      test('Mnemonic at index ${index++} should be invalid', () {
        for (var mnemonic in mnemonics) {
          final isValid = Slip39.validateMnemonic(mnemonic);
          assert(!isValid);
        }
      });
    }

    var mnemonics = slip15.fromPath('r/0').mnemonics;

    var index = 0;
    for (var mnemonic in mnemonics) {
      test('Mnemonic at index ${index++} should be valid', () {
        final isValid = Slip39.validateMnemonic(mnemonic);
        assert(isValid);
      });
    }
  });

  group('Invalid Shares', () {
    final tests = [
      [
        'Short master secret',
        1,
        [
          [2, 3]
        ],
        Uint8List.fromList(masterSecret.codeUnits).sublist(0, 14)
      ],
      [
        'Odd length master secret',
        1,
        [
          [2, 3]
        ],
        Uint8List.fromList(masterSecret.codeUnits) + [55]
      ],
      [
        'Group threshold exceeds number of groups',
        3,
        [
          [3, 5],
          [2, 5]
        ],
        Uint8List.fromList(masterSecret.codeUnits)
      ],
      [
        'Invalid group threshold.',
        0,
        [
          [3, 5],
          [2, 5]
        ],
        Uint8List.fromList(masterSecret.codeUnits)
      ],
      [
        'Member threshold exceeds number of members',
        2,
        [
          [3, 2],
          [2, 5]
        ],
        Uint8List.fromList(masterSecret.codeUnits)
      ],
      [
        'Invalid member threshold',
        2,
        [
          [0, 2],
          [2, 5]
        ],
        Uint8List.fromList(masterSecret.codeUnits)
      ],
      [
        'Group with multiple members and threshold 1',
        2,
        [
          [3, 5],
          [1, 3],
          [2, 5]
        ],
        Uint8List.fromList(masterSecret.codeUnits)
      ]
    ];

    for (var item in tests) {
      var description = item[0];
      var threshold = item[1];

      var groups = item[2];
      var secret = item[3];

      test(description, () {
        expect(
            () => Slip39.from(groups,
                masterSecret: Uint8List.fromList(secret as List<int>),
                threshold: threshold as int),
            throwsException);
      });
    }
  });
  group("Groups test (T=1, N=1 e.g. [1,1]) - ", () {
    final totalGroups = 16;
    final groups = List<List<int>>.generate(totalGroups, (_) => [1, 1]);

    for (int extFlag = 0; extFlag < 2; extFlag++) {
      for (int group = 1; group <= totalGroups; group++) {
        for (int threshold = 1; threshold <= group; threshold++) {
          test(
              "recover master secret for $threshold shares (threshold=$threshold) of $group '[1, 1,]'groups  with extendable backup flag set to $extFlag",
              () {
            final slip = Slip39.from(groups.sublist(0, group),
                masterSecret: Uint8List.fromList(masterSecret.codeUnits),
                passphrase: passphrase,
                threshold: threshold,
                extendableBackupFlag: extFlag);

            final mnemonics =
                slip.fromPath('r').mnemonics.sublist(0, threshold);
            final recoveredSecret =
                Slip39.recoverSecret(mnemonics, passphrase: passphrase);
            assert(masterSecret == String.fromCharCodes(recoveredSecret));
          });
        }
      }
    }
  });
}
