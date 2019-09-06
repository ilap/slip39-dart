import 'dart:core';
import 'dart:math';
import 'dart:typed_data';

import 'package:hex/hex.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/key_derivators/api.dart' show Pbkdf2Parameters;
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';
//import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/src/utils.dart';

part 'slip39_helpers.dart';
part 'slip39_node.dart';

///
/// The dart implementation of the [SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
///
class Slip39 {
  // Private constructor
  Slip39._({root, groupCount, groupThreshold, iterationExponent, identifier})
      : this._root = root,
        this.groupCount = groupCount ?? 0,
        this.groupThreshold = groupThreshold ?? 0,
        this.iterationExponent = iterationExponent ?? 0,
        this.identifier = identifier ?? _generateIdentifier();

  factory Slip39.from(
    dynamic data, {
    List<int> masterSecret = const [],
    String passphrase = '',
    int threshold = 0,
    int iterationExponent = 0,
  }) {
    final name = data is Map ? data['name'] : 'All Shares';
    try {
      threshold = data is Map ? data['threshold'] : threshold;
    } on Error {
      throw 'Threshold must be a number';
    }
    final groups = data is Map ? data['shares'] : data;

    Slip39._validateParams(
        masterSecret: masterSecret,
        passphrase: passphrase,
        threshold: threshold,
        iterationExponent: iterationExponent,
        groups: groups);

    final identifier = _generateIdentifier();
    final encryptedMasterSecret =
        _crypt(masterSecret, passphrase, iterationExponent, identifier);

    final slip = Slip39._(
        iterationExponent: iterationExponent,
        identifier: identifier,
        groupCount: groups.length,
        groupThreshold: threshold);

    final currentNode = Slip39Node(name: name, threshold: threshold);

    var root = slip._from(
        current: currentNode, nodes: groups, secret: encryptedMasterSecret);
    return slip.copyWith(root: root);
  }

  static const _keyPrefix = 'r';
  static const _maxDepth = 2;

  final Slip39Node _root;
  final int groupCount;
  final int groupThreshold;

  // Random identifier
  final Uint8List identifier;
  final int iterationExponent;

  ///
  /// Methods
  ///
  Slip39 copyWith({Slip39Node root, String iterationExponent}) {
    return Slip39._(
      root: root ?? this._root,
      iterationExponent: iterationExponent ?? this.iterationExponent,
      identifier: identifier ?? this.identifier,
      groupCount: groupCount ?? this.groupCount,
      groupThreshold: groupThreshold ?? this.groupThreshold,
    );
  }

  static List<int> recoverSecret(List<String> mnemonics,
      {String passphrase = ''}) {
    return _combineMnemonics(mnemonics: mnemonics, passphrase: passphrase);
  }

  static bool validateMnemonic(mnemonic) {
    return _validateMnemonic(mnemonic);
  }

  Slip39Node fromPath(String path) {
    _validatePath(path);

    Iterable<int> children = _parseChildren(path);

    if (children.isEmpty) {
      return _root;
    }

    return children.fold(_root, (Slip39Node prev, int childNumber) {
      if (childNumber >= prev._children.length) {
        throw ArgumentError(
            'The path index ($childNumber) exceeds the children index (${prev._children.length - 1}).');
      }

      return prev._children[childNumber];
    });
  }

  Slip39Node _from(
      {Slip39Node current,
      List nodes,
      Uint8List secret,
      int index = 0,
      int depth = 0}) {
    if (depth++ > _maxDepth) {
      throw 'The dart implementation of the `Slip39` only supports ${_maxDepth + 1} level tree.';
    }
    if (nodes.isEmpty) {
      final mnemonic = _encodeMnemonic(
          identifier,
          iterationExponent,
          index,
          groupThreshold,
          groupCount,
          current._index,
          current._threshold,
          secret);

      return current._copyWith(mnemonic: mnemonic);
    }

    var children = [];
    final secretShares = _splitSecret(current._threshold, nodes.length, secret);
    var idx = 0;
    nodes.forEach((item) {
      var name;
      var threshold;
      var shares;
      var node;

      if (item is Map) {
        name = item['name'];
        threshold = item['threshold'];
        if (threshold is String) {
          throw 'Threshold must be a number';
        }
        shares = item['shares'];
      } else if (item is List) {
        name = item[1] != 0 ? 'Group Shares ${idx + 1}' : 'Share ${idx + 1}';
        final n = item[0];
        // m=members
        final m = item[1];

        threshold = n;
        // Genereate leaf members, means their `m` is `0`
        shares = List.unmodifiable(List.generate(m, (_) => [n, 0]));
      } else {
        name = item;
        threshold = current._threshold;
        shares = [];
      }

      node = Slip39Node(name: name, index: idx, threshold: threshold);

      var branch = _from(
          current: node,
          nodes: shares,
          secret: Uint8List.fromList(secretShares[idx]),
          index: current._index,
          depth: depth);
      children..add(branch);
      idx++;
    });
    return current._copyWith(children: List.unmodifiable(children));
  }

  void _validatePath(String path) {
    final source =
        r'(^' + _keyPrefix + r')(\/\d{1,2}){0,' + _maxDepth.toString() + r'}$';
    final regex = RegExp(source);

    if (!regex.hasMatch(path)) {
      throw ArgumentError('Expected valid path e.g. \'$_keyPrefix/0/0\'.');
    }

    final depth = path.split('/');
    final pathLength = depth.length - 1;
    if (pathLength > _maxDepth) {
      throw ArgumentError(
          'Path\'s (\'$path\') max depth ($_maxDepth) is exceeded ($pathLength).');
    }
  }

  static void _validateParams(
      {List<int> masterSecret = const [],
      String passphrase,
      int iterationExponent,
      int threshold,
      List groups}) {
    if (masterSecret.length * 8 < _minEntropyBits) {
      throw Exception(
          'The length of the master secret (${masterSecret.length} bytes) must be at least ${_bitsToBytes(_minEntropyBits)} bytes.');
    }

    if (masterSecret.length % 2 != 0) {
      throw Exception(
          'The length of the master secret in bytes must be an even number.');
    }

    final hasMatch = RegExp(r'^[\x20-\x7E]*$').hasMatch(passphrase);
    if (!hasMatch) {
      throw Exception(
          'The passphrase must contain only printable ASCII characters (code points 32-126).');
    }

    if (threshold > groups.length) {
      throw Exception(
          'The requested group threshold ($threshold) must not exceed the number of groups (${groups.length}).');
    }

    groups.forEach((item) {
      // Assume it's malformed.
      var throwNeeded = true;
      if (item is List) {
        throwNeeded = item[0] == 1 && item[1] > 1;
      } else if (item is Map) {
        throwNeeded = item['threshold'] == 1 && item['shares'].length > 1;
      }
      if (throwNeeded) {
        throw Exception(
            'Creating multiple member shares with member threshold 1 is not allowed. Use 1-of-1 member sharing instead. $groups');
      }
    });
  }

  Iterable<int> _parseChildren(String path) {
    List<String> splitted = path.split('/')
      ..removeAt(0)
      ..removeWhere((child) => child == '');

    final result = splitted.map((String pathFragment) {
      return int.parse(pathFragment);
    });
    return result;
  }
}
