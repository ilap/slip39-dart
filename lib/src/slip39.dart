import 'dart:core';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:pointycastle/digests/sha256.dart';
//import 'package:pointycastle/random/fortuna_random.dart';
import 'package:pointycastle/key_derivators/api.dart' show Pbkdf2Parameters;
import 'package:pointycastle/key_derivators/pbkdf2.dart';
import 'package:pointycastle/macs/hmac.dart';
//import 'package:quiver/iterables.dart';
import 'package:hex/hex.dart';

part 'slip39_helpers.dart';

///
/// The dart implementation of the [SLIP-0039: Shamir's Secret-Sharing for Mnemonic Codes](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
///
class Slip39 {
  // Private constructor
  Slip39._(
      {this.root, iterationExponent, identifier, groupCount, groupThreshold})
      : this.iterationExponent = iterationExponent ?? 0,
        this.identifier = identifier ?? _generateIdentifier(),
        this.groupCount = groupCount ?? 0,
        this.groupThreshold = groupThreshold ?? 0;

  final Slip39Node root;

  final int iterationExponent;
  // Random identifier
  final Uint8List identifier;
  final int groupCount;
  final int groupThreshold;

  static const _maxDepth = 2;
  static const _keyPrefix = 'r';

  Slip39 copyWith({Slip39Node root, String iterationExponent}) {
    return Slip39._(
      root: root ?? this.root,
      iterationExponent: iterationExponent ?? this.iterationExponent,
      identifier: identifier ?? this.identifier,
      groupCount: groupCount ?? this.groupCount,
      groupThreshold: groupThreshold ?? this.groupThreshold,
    );
  }

  factory Slip39.fromArray(
      {String masterSecret,
      String passphrase,
      int iterationExponent = 0,
      int threshold,
      List<List<int>> groups}) {
    
    final identifier = _generateIdentifier();

    final slip = Slip39._(
        iterationExponent: iterationExponent,
        identifier: identifier,
        groupCount: groups.length,
        groupThreshold: threshold);
    final ems = _crypt(masterSecret.codeUnits, passphrase, iterationExponent, slip.identifier);

    final root = slip._buildRecursive(
      Slip39Node(),
      groups,
      ems,
      threshold: threshold,
    );
    return slip.copyWith(root: root);
  }

  Slip39Node _buildRecursive(Slip39Node current, List nodes, Uint8List secret,
      {int threshold, int index = 0}) {
    // It means it's a leaf.
    if (nodes.isEmpty) {
      final mnemonic = _encodeMnemonic(identifier, iterationExponent, index,
          groupThreshold, groupCount, current.index, threshold, secret);

      return current.copyWith(mnemonic: mnemonic);
    }

    final secretShares = _splitSecret(threshold, nodes.length, secret);
    var idx = 0;
    var children = <Slip39Node>[];
    nodes.forEach((item) {
      // n=threshold
      final n = item[0];
      // m=members
      final m = item[1];

      // Genereate leaf members, means their `m` is `0`
      final members = List.generate(m, (_) => [n, 0]);

      final node = Slip39Node(index: idx);
      final branch = _buildRecursive(
          node, members, Uint8List.fromList(secretShares[idx]),
          threshold: n, index: current.index);
      children..add(branch);

      idx++;
    });
    return current.copyWith(children: List.unmodifiable(children));
  }

  static String recoverSecret(List<String> mnemonics, String passphrase) {
      return _combineMnemonics(mnemonics: mnemonics, passphrase: passphrase);
  }

  Slip39Node fromPath(String path) {
    _validatePath(path);

    Iterable<int> children = _parseChildren(path);

    if (children.isEmpty) {
      return root;
    }

    return children.fold(root, (Slip39Node prev, int childNumber) {
      if (childNumber >= prev._children.length) {
        throw ArgumentError("The path index ($childNumber) exceeds the children index (${prev._children.length - 1}).");
      }

      return prev._children[childNumber];
    });
  }

  void _validatePath(String path) {
    final source =
        r"(^" + _keyPrefix + r")(\/\d{1,2}){0," + _maxDepth.toString() + r"}$";
    final regex = new RegExp(source);
    
    if (!regex.hasMatch(path)) {
      throw ArgumentError("Expected valid path e.g. \"${_keyPrefix}/0/0\".");
    }

    final depth = path.split("/");
    final pathLength = depth.length - 1;
    if (pathLength > _maxDepth) {
      throw ArgumentError(
          "Path's (\"${path}\") max depth ($_maxDepth) is exceeded ($pathLength).");
    }
  }

  Iterable<int> _parseChildren(String path) {
    List<String> splitted = path.split("/")
      ..removeAt(0)
      ..removeWhere((child) => child == "");

    final result = splitted.map((String pathFragment) {
      return int.parse(pathFragment);
    });
    return result;
  }
}

///
/// Slip39Node
///
class Slip39Node {
  Slip39Node({mnemonic, index, children})
      : this._mnemonic = mnemonic ?? "",
        this.index = index ?? 0,
        this._children = children ?? <Slip39Node>[];

  final String _mnemonic;
  final int index;
  final List<Slip39Node> _children;

  List<String> get mnemonics {
    if (_children.isEmpty) {
      return [_mnemonic];
    } else {
      final result = _children.fold(<String>[], (prev, item) {
        return prev..addAll(item.mnemonics);
      });
      return result;
    }
  }

  Slip39Node copyWith({String mnemonic, int index, List<Slip39Node> children}) {
    return Slip39Node(
        mnemonic: mnemonic ?? this._mnemonic,
        index: index ?? this.index,
        children: children ?? this._children);
  }
}