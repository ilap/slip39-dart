import 'dart:io';
import 'dart:convert';

import 'package:test/test.dart';
import 'package:hex/hex.dart';

import '../lib/slip39.dart';

main() {
  final masterSecret = 'ABCDEFGHIJKLMNOP';
  final passphrase = 'TREZOR';
  final oneGroup = [
    [5, 7]
  ];

  final slip15 = Slip39.fromArray(
      masterSecret: masterSecret.codeUnits,
      passphrase: passphrase,
      threshold: 1,
      groups: oneGroup);

  final slip15NoPW = Slip39.fromArray(
      masterSecret: masterSecret.codeUnits, threshold: 1, groups: oneGroup);

//
// Combinations C(n, k) of the grooups
//
  getCombinations(array, k) {
    var result = List<List<int>>();
    var combinations = List<int>(k);

    helper(int level, int start) {
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
      combinations.forEach((item) {
        var description = 'Test combination ${item.join(' ')}.';
        test(description, () {
          var shares = item.map((idx) => mnemonics[idx]).toList();
          assert(masterSecret ==
              String.fromCharCodes(
                  Slip39.recoverSecret(shares, passphrase: passphrase)));
        });
      });
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
      final slip1 = Slip39.fromArray(
          masterSecret: masterSecret.codeUnits, iterationExponent: 1);

      final slip2 = Slip39.fromArray(
          masterSecret: masterSecret.codeUnits, iterationExponent: 2);

      test(
          'should return valid mastersecret when user apply valid iteration exponent',
          () {
        assert(masterSecret ==
            String.fromCharCodes(
                Slip39.recoverSecret(slip1.fromPath('r/0').mnemonics)));

        assert(masterSecret ==
            String.fromCharCodes(
                Slip39.recoverSecret(slip2.fromPath('r/0').mnemonics)));
      });
      /**
     * assert.throws(() => x.y.z);
     * assert.throws(() => x.y.z, ReferenceError);
     * assert.throws(() => x.y.z, ReferenceError, /is not defined/);
     * assert.throws(() => x.y.z, /is not defined/);
     * assert.doesNotThrow(() => 42);
     * assert.throws(() => x.y.z, Error);
     * assert.throws(() => model.get.z, /Property does not exist in model schema./)
     * Ref: https://stackoverflow.com/questions/21587122/mocha-chai-expect-to-throw-not-catching-thrown-errors
     */
      test('should throw an Error when user submits invalid iteration exponent',
          () {
        expect(
            () => Slip39.fromArray(
                masterSecret: masterSecret.codeUnits, iterationExponent: -1),
            throwsException);
        expect(
            () => Slip39.fromArray(
                masterSecret: masterSecret.codeUnits, iterationExponent: 33),
            throwsException);
      });
    });
  });

// FIXME: finish it.
  group('Group Sharing Tests', () {
    group('Test all valid combinations of mnemonics', () {
      final groups = [
        [3, 5],
        [3, 3],
        [2, 5],
        [1, 1]
      ];
      final slip = Slip39.fromArray(
          masterSecret: masterSecret.codeUnits, threshold: 2, groups: groups);

      final group2Mnemonics = slip.fromPath('r/2').mnemonics;
      final group3Mnemonic = slip.fromPath('r/3').mnemonics[0];

      test(
          'Should return the valid master secret when it tested with minimal sets of mnemonics.',
          () {
        /*FIXME:  final mnemonics = group2Mnemonics.filter((_, index) {
        return index == 0 || index == 2;
      }).concat(group3Mnemonic);

      assert(masterSecret.codeUnits == String.fromCharCodes(Slip39.recoverSecret(mnemonics)));
      */
      });
      test(
          'TODO: Should NOT return the valid master secret when one compvare group and one incompvare group out of two groups required',
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
      String description = item[0];
      var mnemonics = List<String>.from(item[1]);
      String ms = item[2];

      test(description, () {
        if (ms.length != 0) {
          List<int> result =
              Slip39.recoverSecret(mnemonics, passphrase: passphrase);
          assert(ms == HEX.encode(result));
        } else {
          expect(() => Slip39.recoverSecret(mnemonics, passphrase: passphrase),
              throwsException);
        }
      });
    });
  });

  /*group('Invalid Shares', () {
    final tests = [
      [
        'Short master secret',
        1,
        [
          [2, 3]
        ],
        masterSecret.codeUnits.sublist(0, 14)
      ],
      [
        'Odd length master secret',
        1,
        [
          [2, 3]
        ],
        masterSecret.codeUnits..add(55)
      ],
      [
        'Group threshold exceeds number of groups',
        3,
        [
          [3, 5],
          [2, 5]
        ],
        masterSecret.codeUnits
      ],
      [
        'Invalid group threshold.',
        0,
        [
          [3, 5],
          [2, 5]
        ],
        masterSecret.codeUnits
      ],
      [
        'Member threshold exceeds number of members',
        2,
        [
          [3, 2],
          [2, 5]
        ],
        masterSecret.codeUnits
      ],
      [
        'Invalid member threshold',
        2,
        [
          [0, 2],
          [2, 5]
        ],
        masterSecret.codeUnits
      ],
      [
        'Group with multiple members and threshold 1',
        2,
        [
          [3, 5],
          [1, 3],
          [2, 5]
        ],
        masterSecret.codeUnits
      ]
    ];

    tests.forEach((item) {
      var description = item[0];
      var threshold = item[1];

      var groups = item[2];
      var secret = item[3];

      test(description, () {
        expect(
            Slip39.fromArray(
                masterSecret: secret, threshold: threshold, groups: groups),
            throwsException);
      });
    });
  });*/
}