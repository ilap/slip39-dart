part of 'slip39.dart';

///
/// Constants
///

// The length of the radix in bits.
const _radixBits = 10;

// The length of the random identifier in bits.
const _identifierBitsLength = 15;

// The length of the iteration exponent in bits.
const _iterationExponentBitsLength = 5;

// The length of the random identifier and iteration exponent in words.
const _identifierExpWordsLength =
    (_identifierBitsLength + _iterationExponentBitsLength + _radixBits - 1) ~/
        _radixBits;

// The maximum number of shares that can be created.
const _maxShareCount = 16;

// The length of the RS1024 checksum in words.
const _checksumWordsLength = 3;

// The length of the digest of the shared secret in bytes.
const _digestLength = 4;

// The customization string used in the RS1024 checksum and in the PBKDF2 salt.
const _saltString = 'shamir';

// The minimum allowed entropy of the master secret.
const _minEntropyBits = 128;

// The minimum allowed length of the mnemonic in words.
const _metadataWordsLength =
    _identifierExpWordsLength + 2 + _checksumWordsLength;

// The length of the mnemonic in words without the share value.
const _minMnemonicWordsLength =
    _metadataWordsLength + (_minEntropyBits + _radixBits - 1) ~/ _radixBits;

// The minimum number of iterations to use in PBKDF2.
const _iterationCount = 10000;

// The number of rounds to use in the Feistel cipher.
const _roundCount = 4;

// The index of the share containing the digest of the shared secret.
const _digestIndex = 254;

// The index of the share containing the shared secret.
const _secretIndex = 255;

///
/// Helper functions for SLIP39 implementation.
///

int _bitsToBytes(n) => (n + 7) ~/ 8;
int _bitsToWords(n) => (n + _radixBits - 1) ~/ _radixBits;

final _derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64));
final Random _random = Random.secure();

///
/// Returns a randomly generated integer in the range 0, ... , 2**ID_LENGTH_BITS - 1.
/// - [Check this](https://www.scottbrady91.com/Dart/Generating-a-Crypto-Random-String-in-Dart)
///
List<int> _randomBytes([int length = 32]) {
  //FIXME: use the following only for testing.
  return List<int>.generate(length, (_) => 0x12);
  //return List<int>.generate(length, (i) => _random.nextInt(256));
}

///
/// The round function used internally by the Feistel cipher.
///
Uint8List _roundFunction(
    i, Uint8List passphrase, e, Uint8List salt, Uint8List r) {
  final saltAndR = Uint8List.fromList(salt + r);
  final List<int> round = [i];
  final roundedPhrase = Uint8List.fromList(round + passphrase);
  final count = (_iterationCount << e) ~/ _roundCount;

  _derivator..init(Pbkdf2Parameters(saltAndR, count, r.length));
  final result = _derivator.process(roundedPhrase);

  return result;
}

Uint8List _crypt(List master_secret, String passphrase, int iteration_exponent,
    Uint8List identifier,
    {bool encrypt = true}) {
  var IL =
      Uint8List.fromList(master_secret.sublist(0, master_secret.length ~/ 2));
  var IR = Uint8List.fromList(master_secret.sublist(master_secret.length ~/ 2));

  var pwd = Uint8List.fromList(passphrase.codeUnits);

  var salt = _getSalt(identifier);

  var range = List.generate(_roundCount, (i) => i);
  range = encrypt ? range : range.reversed.toList();

  for (var i in range) {
    var f = _roundFunction(i, pwd, iteration_exponent, salt, IR);
    var t = _xor(IL, f);
    IL = IR;
    IR = t;
  }
  return Uint8List.fromList(IR + IL);
}

Uint8List _createDigest(Uint8List randomData, Uint8List sharedSecret) {
  final mac = new Mac("SHA-256/HMAC");
  final keyParam = new KeyParameter(randomData);
  mac.init(keyParam);
  var result = mac.process(sharedSecret);

  return Uint8List.fromList(result.sublist(0, 4));
}

List _splitSecret(int threshold, int shareCount, Uint8List sharedSecret) {
  // "The requested threshold ({}) must be a positive integer.".format(threshold)
  assert(threshold >= 1);

  //  "The requested threshold ({}) must not exceed the number of shares ({}).".format(
  //              threshold, share_count
  assert(threshold <= shareCount);

  //  "The requested number of shares ({}) must not exceed {}.".format(
  //              share_count, MAX_SHARE_COUNT
  assert(shareCount <= _maxShareCount);

  //  If the threshold is 1, then the digest of the shared secret is not used.
  if (threshold == 1) {
    return List.generate(shareCount, (_) => sharedSecret);
  }

  final random_share_count = threshold - 2;

  var random_part = _randomBytes(sharedSecret.length - _digestLength);
  final digest = _createDigest(Uint8List.fromList(random_part), sharedSecret);

  var sharesIdx = List.generate(random_share_count, (i) => i);
  var shares = List.generate(
      random_share_count, (_) => _randomBytes(sharedSecret.length));

  final base_shares = Map.fromIterables(sharesIdx, shares);
  base_shares[_digestIndex] = digest + random_part;
  base_shares[_secretIndex] = sharedSecret;

  print("SHARE: $random_share_count ${shares.toString()}");
  for (var i = random_share_count; i < shareCount; i++) {
    var rr = _interpolate(base_shares, i);
    print("Share: $i  $rr");
    shares.add(rr);
  }

  return shares;
}

///
/// Returns a randomly generated integer in the range 0, ... , 2**_identifierBitsLength - 1.
///
Uint8List _generateIdentifier() {
  final byte = _bitsToBytes(_identifierBitsLength);
  final bits = _identifierBitsLength % 8;
  final identifier = _randomBytes(byte);

  identifier[0] = identifier[0] & ((1 << bits) - 1);

  return Uint8List.fromList(identifier);
}

Uint8List _xor(Uint8List a, Uint8List b) {
  assert(a.length == b.length);
  return Uint8List.fromList(List.generate(a.length, (i) => a[i] ^ b[i]));
}

Uint8List _getSalt(Uint8List identifier) {
  final salt = Uint8List.fromList(_saltString.codeUnits);
  return Uint8List.fromList(salt + identifier);
}

List<int> _interpolate(Map shares, int x) {
  final xCoord = Set.from(shares.keys);
  final sharesValueLengths = Set.from(shares.values.map((m) => m.length));

  if (sharesValueLengths.length != 1) {
    throw Exception(
        "Invalid set of shares. All share values must have the same length.");
  }

  if (xCoord.contains(x)) {
    shares.forEach((k, v) {
      if (k == x) {
        return v;
      }
    });
  }

  // Logarithm of the product of (x_i - x) for i = 1, ... , k.
  var logProd = 0;

  shares.forEach((k, v) {
    logProd += _logTable[k ^ x];
  });

  List<int> results = List<int>.filled(sharesValueLengths.first, 0);

  shares.forEach((k, v) {
    // The logarithm of the Lagrange basis polynomial evaluated at x.
    var sum = 0;
    shares.forEach((kk, vv) {
      sum = sum + _logTable[k ^ kk];
    });

    var logBasisEval = (logProd - _logTable[k ^ x] - sum) % 255;

    var idx = 0;

    for (var item in v as List) {
      var shareVal = item;
      var intermediateSum = results[idx];
      var r = shareVal != 0
          ? _expTable[(_logTable[shareVal] + logBasisEval) % 255]
          : 0;

      var res = intermediateSum ^ r;

      results[idx] = res;
      idx += 1;
    }
  });

  return results;
}

int _rs1024Polymod(values) {
  const _gen = [
    0xE0E040,
    0x1C1C080,
    0x3838100,
    0x7070200,
    0xE0E0009,
    0x1C0C2412,
    0x38086C24,
    0x3090FC48,
    0x21B1F890,
    0x3F3F120,
  ];

  var chk = 1;

  for (var v in values) {
    var b = chk >> 20;
    chk = (chk & 0xFFFFF) << 10 ^ v;
    for (var i = 0; i < 10; i++) {
      var bb = ((b >> i) & 1);
      var cc = bb != 0 ? _gen[i] : 0;

      chk ^= cc;
    }
  }
  return chk;
}

List<int> _rs1024CreateChecksum(data) {
  var values =
      _saltString.codeUnits + data + List<int>.filled(_checksumWordsLength, 0);

  int polymod = _rs1024Polymod(values) ^ 1;
  var result =
      List.generate(_checksumWordsLength, (i) => (polymod >> 10 * i) & 1023);
        print("VALUES: ${polymod} ... $result ... ");
  return result.reversed.toList();
}

bool _rs1024VerifyChecksum(data) {
  print("CCCCC: ${_saltString.codeUnits} ${data}");
  return _rs1024Polymod(_saltString.codeUnits + data) == 1;
}

///
/// Converts a list of base 1024 indices in big endian order to an integer value.
///
_intFromIndices(List indices) {
  var value = BigInt.from(0);
  var radix = BigInt.from(pow(2, _radixBits));
  for (var index in indices) {
    value = value * radix + BigInt.from(index);
  }

  return value;
}

///
/// Converts a Big integer value to indices in big endian order.
///
List<int> _intToIndices(BigInt value, length, bits) {
  var mask = BigInt.from((1 << bits) - 1);
  var result =
      List.generate(length, (i) => (((value >> (i * bits)) & mask)).toInt());
  return result.reversed.toList();
}

String _mnemomicFromIndices(List indices) {
  var result = indices.fold("", (prev, index) {
    var separator = prev == "" ? "" : " ";
    return prev + separator + _wordList[index];
  });
  return result;
}

List<int> _mnemonicToIndices(String mnemonic) {
  var words = mnemonic.toLowerCase().split(" ");
  try {
    var result = words.fold(<int>[], (prev, item) {
      var index = _wordListMap[item];
      return prev..add(index);
    });
    return result;
  } on Error catch (e) {
    throw Exception("Invalid mnemonic word ${e}.");
  }
}

Uint8List _recoverSecret(threshold, shares) {
  // If the threshold is 1, then the digest of the shared secret is not used.
  if (threshold == 1) {
    return shares.values.first; //next(iter(shares))[1]
  }

  var sharedSecret = _interpolate(shares, _secretIndex);
  var digestShare = _interpolate(shares, _digestIndex);
  var digest = digestShare.sublist(0, _digestLength);
  var randomPart = digestShare.sublist(_digestLength);

  var recoveredDigest = _createDigest(
      Uint8List.fromList(randomPart), Uint8List.fromList(sharedSecret));
  if (!_listsAreEqual(digest, recoveredDigest)) {
    throw Exception("Invalid digest of the shared secret.");
  }
  return Uint8List.fromList(sharedSecret);
}

///
/// Combines mnemonic shares to obtain the master secret which was previously
/// split using Shamir's secret sharing scheme.
///     :param mnemonics: List of mnemonics.
///     :type mnemonics: List of byte arrays.
///     :param passphrase: The passphrase used to encrypt the master secret.
///     :type passphrase: Array of bytes.
///     :return: The master secret.
///     :rtype: Array of bytes.

String _combineMnemonics({List<String> mnemonics, String passphrase = ""}) {
  if (mnemonics == null || mnemonics.isEmpty) {
    throw Exception("The list of mnemonics is empty.");
  }

  var data = _decodeMnemonics(mnemonics);
  var identifier = data[0];
  var iterationExponent = data[1];
  var groupThreshold = data[2];
  var groupCount = data[3];
  var groups = data[4];

  if (groups.length < groupThreshold) {
    throw Exception(
        "Insufficient number of mnemonic groups (${groups.length}). The required number of groups is $groupThreshold.");
  }

  if (groups.length != groupThreshold) {
    throw Exception(
        "Wrong number of mnemonic groups. Expected $groupThreshold groups, but ${groups.length} were provided.");
  }

  var allShares = {};
  groups.forEach((groupIndex, members) {
    var threshold = members.keys.first;
    var shares = members.values.first;
    if (shares.length != threshold) {
      var prefix = _groupPrefix(
        identifier,
        iterationExponent,
        groupIndex,
        groupThreshold,
        groupCount,
      );
      throw Exception(
          'Wrong number of mnemonics. Expected ${groupIndex} mnemonics starting with ${_mnemomicFromIndices(prefix)}, \n but ${members.length} were provided.');
    }

    var recovered = _recoverSecret(threshold, shares);
    allShares[groupIndex] = recovered;
  });

  //var groupShares = groups.foreach();
  var ems = _recoverSecret(groupThreshold, allShares);
  var id = _intToIndices(BigInt.from(identifier), _identifierExpWordsLength, 8);
  id = Uint8List.fromList(id);
  var ms = _crypt(ems, passphrase, iterationExponent, id, encrypt: false);
  return String.fromCharCodes(ms);
}

_decodeMnemonics(mnemonics) {
  var identifiers = Set();
  var iterationExponents = Set();
  var groupThresholds = Set();
  var groupCounts = Set();
  var groups = {};

  mnemonics.forEach((mnemonic) {
    var data = _decodeMnemonic(mnemonic);

    identifiers.add(data[0]);
    iterationExponents.add(data[1]);
    var groupIndex = data[2];
    groupThresholds.add(data[3]);
    groupCounts.add(data[4]);
    var memberIndex = data[5];
    var memberThreshold = data[6];
    var share = data[7];

    var group = groups[groupIndex] ?? Map();
    var member = group[memberThreshold] ?? Map();
    member[memberIndex] = share;
    group[memberThreshold] = member;
    if (group.keys.length != 1) {
      throw Exception(
          "Invalid set of mnemonics. All mnemonics in a group must have the same member threshold.");
    }
    groups[groupIndex] = group;
  });

  if (identifiers.length != 1 || iterationExponents.length != 1) {
    throw Exception(
        "Invalid set of mnemonics. All mnemonics must begin with the same ($_identifierExpWordsLength) words.");
  }

  if (groupThresholds.length != 1) {
    throw Exception(
        "Invalid set of mnemonics. All mnemonics must have the same group threshold.");
  }

  if (groupCounts.length != 1) {
    throw Exception(
        "Invalid set of mnemonics. All mnemonics must have the same group count.");
  }

  return [
    identifiers.first,
    iterationExponents.first,
    groupThresholds.first,
    groupCounts.first,
    groups,
  ];
}

///
/// Converts a share mnemonic to share data.
///
_decodeMnemonic(mnemonic) {
  var data = _mnemonicToIndices(mnemonic);

  if (mnemonic.length < _minMnemonicWordsLength) {
    throw Exception(
        "Invalid mnemonic length. The length of each mnemonic must be at least $_minMnemonicWordsLength words.");
  }

  var paddingLen = (_radixBits * (data.length - _metadataWordsLength)) % 16;
  if (paddingLen > 8) {
    throw Exception("Invalid mnemonic length.");
  }

  if (!_rs1024VerifyChecksum(data)) {
    throw Exception("Invalid mnemonic checksum");
  }

  var idExpInt =
      _intFromIndices(data.sublist(0, _identifierExpWordsLength)).toInt();
  var identifier = idExpInt >> _iterationExponentBitsLength;
  var iterationExponent = idExpInt & ((1 << _iterationExponentBitsLength) - 1);
  var tmp = _intFromIndices(
      data.sublist(_identifierExpWordsLength, _identifierExpWordsLength + 2));

  var indices = _intToIndices(tmp, 5, 4);

  var groupIndex = indices[0];
  var groupThreshold = indices[1];
  var groupCount = indices[2];
  var memberIndex = indices[3];
  var memberThreshold = indices[4];

  var valueData = data.sublist(
      _identifierExpWordsLength + 2, data.length - _checksumWordsLength);

  if (groupCount < groupThreshold) {
    throw Exception(
        'Invalid mnemonic: ${mnemonic}.\n Group threshold  ($groupThreshold) cannot be greater than group count ($groupCount).');
  }

  var valueInt = _intFromIndices(valueData);

  try {
    var value = encodeBigInt(valueInt);

    return [
      identifier,
      iterationExponent,
      groupIndex,
      groupThreshold + 1,
      groupCount + 1,
      memberIndex,
      memberThreshold + 1,
      value,
    ];
  } on Exception catch (e) {
    throw Exception('Invalid mnemonic padding ($e}');
  }
}

List<int> _groupPrefix(
    identifier, iteration_exponent, groupIndex, groupThreshold, groupCount) {
  var id_exp_int = BigInt.from(
      (identifier << _iterationExponentBitsLength) + iteration_exponent);

  var indc = _intToIndices(id_exp_int, _identifierExpWordsLength, _radixBits);

  var indc2 =
      (groupIndex << 6) + ((groupThreshold - 1) << 2) + ((groupCount - 1) >> 2);

  return <int>[]
    ..addAll(indc)
    ..add(indc2);
}

bool _listsAreEqual(List a, List b) {
  if (a == null || b == null || a.length != b.length) {
    return false;
  }

  var i = 0;
  return a.every((item) {
    return b[i++] == item;
  });
}

///
///   Converts share data to a share mnemonic.
///
String _encodeMnemonic(
  identifier,
  iteration_exponent,
  groupIndex,
  groupThreshold,
  groupCount,
  memberIndex,
  memberThreshold,
  value,
) {
// Convert the share value from bytes to wordlist indices.
  final value_word_count = _bitsToWords(value.length * 8);

  BigInt valueInt = decodeBigInt(value);
  identifier = int.parse(HEX.encode(identifier), radix: 16);

  var gp = _groupPrefix(
      identifier, iteration_exponent, groupIndex, groupThreshold, groupCount);
  var tp = //tuple(
      _intToIndices(valueInt, value_word_count, _radixBits);

  var calc = (((groupCount - 1) & 3) << 8) +
      (memberIndex << 4) +
      (memberThreshold - 1);

  var shareData = <int>[]
    ..addAll(gp)
    ..add(calc)
    ..addAll(tp);
  var checksum = _rs1024CreateChecksum(shareData);

  return _mnemomicFromIndices(shareData + checksum);
}

/// The precomputed exponent and log tables.
/// ```
///     var exp = List<int>.filled(255, 0);
///     var log = List<int>.filled(256, 0);
///     var poly = 1;
///
///     for (var i = 0; i < exp.length; i++) {
///       exp[i] = poly;
///       log[poly] = i;
///       // Multiply poly by the polynomial x + 1.
///       poly = (poly << 1) ^ poly;
///       // Reduce poly by x^8 + x^4 + x^3 + x + 1.
///       if (poly & 0x100 == 0x100) poly ^= 0x11B;
///    }
/// ```
const _expTable = [
  1,
  3,
  5,
  15,
  17,
  51,
  85,
  255,
  26,
  46,
  114,
  150,
  161,
  248,
  19,
  53,
  95,
  225,
  56,
  72,
  216,
  115,
  149,
  164,
  247,
  2,
  6,
  10,
  30,
  34,
  102,
  170,
  229,
  52,
  92,
  228,
  55,
  89,
  235,
  38,
  106,
  190,
  217,
  112,
  144,
  171,
  230,
  49,
  83,
  245,
  4,
  12,
  20,
  60,
  68,
  204,
  79,
  209,
  104,
  184,
  211,
  110,
  178,
  205,
  76,
  212,
  103,
  169,
  224,
  59,
  77,
  215,
  98,
  166,
  241,
  8,
  24,
  40,
  120,
  136,
  131,
  158,
  185,
  208,
  107,
  189,
  220,
  127,
  129,
  152,
  179,
  206,
  73,
  219,
  118,
  154,
  181,
  196,
  87,
  249,
  16,
  48,
  80,
  240,
  11,
  29,
  39,
  105,
  187,
  214,
  97,
  163,
  254,
  25,
  43,
  125,
  135,
  146,
  173,
  236,
  47,
  113,
  147,
  174,
  233,
  32,
  96,
  160,
  251,
  22,
  58,
  78,
  210,
  109,
  183,
  194,
  93,
  231,
  50,
  86,
  250,
  21,
  63,
  65,
  195,
  94,
  226,
  61,
  71,
  201,
  64,
  192,
  91,
  237,
  44,
  116,
  156,
  191,
  218,
  117,
  159,
  186,
  213,
  100,
  172,
  239,
  42,
  126,
  130,
  157,
  188,
  223,
  122,
  142,
  137,
  128,
  155,
  182,
  193,
  88,
  232,
  35,
  101,
  175,
  234,
  37,
  111,
  177,
  200,
  67,
  197,
  84,
  252,
  31,
  33,
  99,
  165,
  244,
  7,
  9,
  27,
  45,
  119,
  153,
  176,
  203,
  70,
  202,
  69,
  207,
  74,
  222,
  121,
  139,
  134,
  145,
  168,
  227,
  62,
  66,
  198,
  81,
  243,
  14,
  18,
  54,
  90,
  238,
  41,
  123,
  141,
  140,
  143,
  138,
  133,
  148,
  167,
  242,
  13,
  23,
  57,
  75,
  221,
  124,
  132,
  151,
  162,
  253,
  28,
  36,
  108,
  180,
  199,
  82,
  246
];
const _logTable = [
  0,
  0,
  25,
  1,
  50,
  2,
  26,
  198,
  75,
  199,
  27,
  104,
  51,
  238,
  223,
  3,
  100,
  4,
  224,
  14,
  52,
  141,
  129,
  239,
  76,
  113,
  8,
  200,
  248,
  105,
  28,
  193,
  125,
  194,
  29,
  181,
  249,
  185,
  39,
  106,
  77,
  228,
  166,
  114,
  154,
  201,
  9,
  120,
  101,
  47,
  138,
  5,
  33,
  15,
  225,
  36,
  18,
  240,
  130,
  69,
  53,
  147,
  218,
  142,
  150,
  143,
  219,
  189,
  54,
  208,
  206,
  148,
  19,
  92,
  210,
  241,
  64,
  70,
  131,
  56,
  102,
  221,
  253,
  48,
  191,
  6,
  139,
  98,
  179,
  37,
  226,
  152,
  34,
  136,
  145,
  16,
  126,
  110,
  72,
  195,
  163,
  182,
  30,
  66,
  58,
  107,
  40,
  84,
  250,
  133,
  61,
  186,
  43,
  121,
  10,
  21,
  155,
  159,
  94,
  202,
  78,
  212,
  172,
  229,
  243,
  115,
  167,
  87,
  175,
  88,
  168,
  80,
  244,
  234,
  214,
  116,
  79,
  174,
  233,
  213,
  231,
  230,
  173,
  232,
  44,
  215,
  117,
  122,
  235,
  22,
  11,
  245,
  89,
  203,
  95,
  176,
  156,
  169,
  81,
  160,
  127,
  12,
  246,
  111,
  23,
  196,
  73,
  236,
  216,
  67,
  31,
  45,
  164,
  118,
  123,
  183,
  204,
  187,
  62,
  90,
  251,
  96,
  177,
  134,
  59,
  82,
  161,
  108,
  170,
  85,
  41,
  157,
  151,
  178,
  135,
  144,
  97,
  190,
  220,
  252,
  188,
  149,
  207,
  205,
  55,
  63,
  91,
  209,
  83,
  57,
  132,
  60,
  65,
  162,
  109,
  71,
  20,
  42,
  158,
  93,
  86,
  242,
  211,
  171,
  68,
  17,
  146,
  217,
  35,
  32,
  46,
  137,
  180,
  124,
  184,
  38,
  119,
  153,
  227,
  165,
  103,
  74,
  237,
  222,
  197,
  49,
  254,
  24,
  13,
  99,
  140,
  128,
  192,
  247,
  112,
  7
];

///
/// SLIP39 wordlist
///
const _wordList = [
  "academic",
  "acid",
  "acne",
  "acquire",
  "acrobat",
  "activity",
  "actress",
  "adapt",
  "adequate",
  "adjust",
  "admit",
  "adorn",
  "adult",
  "advance",
  "advocate",
  "afraid",
  "again",
  "agency",
  "agree",
  "aide",
  "aircraft",
  "airline",
  "airport",
  "ajar",
  "alarm",
  "album",
  "alcohol",
  "alien",
  "alive",
  "alpha",
  "already",
  "alto",
  "aluminum",
  "always",
  "amazing",
  "ambition",
  "amount",
  "amuse",
  "analysis",
  "anatomy",
  "ancestor",
  "ancient",
  "angel",
  "angry",
  "animal",
  "answer",
  "antenna",
  "anxiety",
  "apart",
  "aquatic",
  "arcade",
  "arena",
  "argue",
  "armed",
  "artist",
  "artwork",
  "aspect",
  "auction",
  "august",
  "aunt",
  "average",
  "aviation",
  "avoid",
  "award",
  "away",
  "axis",
  "axle",
  "beam",
  "beard",
  "beaver",
  "become",
  "bedroom",
  "behavior",
  "being",
  "believe",
  "belong",
  "benefit",
  "best",
  "beyond",
  "bike",
  "biology",
  "birthday",
  "bishop",
  "black",
  "blanket",
  "blessing",
  "blimp",
  "blind",
  "blue",
  "body",
  "bolt",
  "boring",
  "born",
  "both",
  "boundary",
  "bracelet",
  "branch",
  "brave",
  "breathe",
  "briefing",
  "broken",
  "brother",
  "browser",
  "bucket",
  "budget",
  "building",
  "bulb",
  "bulge",
  "bumpy",
  "bundle",
  "burden",
  "burning",
  "busy",
  "buyer",
  "cage",
  "calcium",
  "camera",
  "campus",
  "canyon",
  "capacity",
  "capital",
  "capture",
  "carbon",
  "cards",
  "careful",
  "cargo",
  "carpet",
  "carve",
  "category",
  "cause",
  "ceiling",
  "center",
  "ceramic",
  "champion",
  "change",
  "charity",
  "check",
  "chemical",
  "chest",
  "chew",
  "chubby",
  "cinema",
  "civil",
  "class",
  "clay",
  "cleanup",
  "client",
  "climate",
  "clinic",
  "clock",
  "clogs",
  "closet",
  "clothes",
  "club",
  "cluster",
  "coal",
  "coastal",
  "coding",
  "column",
  "company",
  "corner",
  "costume",
  "counter",
  "course",
  "cover",
  "cowboy",
  "cradle",
  "craft",
  "crazy",
  "credit",
  "cricket",
  "criminal",
  "crisis",
  "critical",
  "crowd",
  "crucial",
  "crunch",
  "crush",
  "crystal",
  "cubic",
  "cultural",
  "curious",
  "curly",
  "custody",
  "cylinder",
  "daisy",
  "damage",
  "dance",
  "darkness",
  "database",
  "daughter",
  "deadline",
  "deal",
  "debris",
  "debut",
  "decent",
  "decision",
  "declare",
  "decorate",
  "decrease",
  "deliver",
  "demand",
  "density",
  "deny",
  "depart",
  "depend",
  "depict",
  "deploy",
  "describe",
  "desert",
  "desire",
  "desktop",
  "destroy",
  "detailed",
  "detect",
  "device",
  "devote",
  "diagnose",
  "dictate",
  "diet",
  "dilemma",
  "diminish",
  "dining",
  "diploma",
  "disaster",
  "discuss",
  "disease",
  "dish",
  "dismiss",
  "display",
  "distance",
  "dive",
  "divorce",
  "document",
  "domain",
  "domestic",
  "dominant",
  "dough",
  "downtown",
  "dragon",
  "dramatic",
  "dream",
  "dress",
  "drift",
  "drink",
  "drove",
  "drug",
  "dryer",
  "duckling",
  "duke",
  "duration",
  "dwarf",
  "dynamic",
  "early",
  "earth",
  "easel",
  "easy",
  "echo",
  "eclipse",
  "ecology",
  "edge",
  "editor",
  "educate",
  "either",
  "elbow",
  "elder",
  "election",
  "elegant",
  "element",
  "elephant",
  "elevator",
  "elite",
  "else",
  "email",
  "emerald",
  "emission",
  "emperor",
  "emphasis",
  "employer",
  "empty",
  "ending",
  "endless",
  "endorse",
  "enemy",
  "energy",
  "enforce",
  "engage",
  "enjoy",
  "enlarge",
  "entrance",
  "envelope",
  "envy",
  "epidemic",
  "episode",
  "equation",
  "equip",
  "eraser",
  "erode",
  "escape",
  "estate",
  "estimate",
  "evaluate",
  "evening",
  "evidence",
  "evil",
  "evoke",
  "exact",
  "example",
  "exceed",
  "exchange",
  "exclude",
  "excuse",
  "execute",
  "exercise",
  "exhaust",
  "exotic",
  "expand",
  "expect",
  "explain",
  "express",
  "extend",
  "extra",
  "eyebrow",
  "facility",
  "fact",
  "failure",
  "faint",
  "fake",
  "false",
  "family",
  "famous",
  "fancy",
  "fangs",
  "fantasy",
  "fatal",
  "fatigue",
  "favorite",
  "fawn",
  "fiber",
  "fiction",
  "filter",
  "finance",
  "findings",
  "finger",
  "firefly",
  "firm",
  "fiscal",
  "fishing",
  "fitness",
  "flame",
  "flash",
  "flavor",
  "flea",
  "flexible",
  "flip",
  "float",
  "floral",
  "fluff",
  "focus",
  "forbid",
  "force",
  "forecast",
  "forget",
  "formal",
  "fortune",
  "forward",
  "founder",
  "fraction",
  "fragment",
  "frequent",
  "freshman",
  "friar",
  "fridge",
  "friendly",
  "frost",
  "froth",
  "frozen",
  "fumes",
  "funding",
  "furl",
  "fused",
  "galaxy",
  "game",
  "garbage",
  "garden",
  "garlic",
  "gasoline",
  "gather",
  "general",
  "genius",
  "genre",
  "genuine",
  "geology",
  "gesture",
  "glad",
  "glance",
  "glasses",
  "glen",
  "glimpse",
  "goat",
  "golden",
  "graduate",
  "grant",
  "grasp",
  "gravity",
  "gray",
  "greatest",
  "grief",
  "grill",
  "grin",
  "grocery",
  "gross",
  "group",
  "grownup",
  "grumpy",
  "guard",
  "guest",
  "guilt",
  "guitar",
  "gums",
  "hairy",
  "hamster",
  "hand",
  "hanger",
  "harvest",
  "have",
  "havoc",
  "hawk",
  "hazard",
  "headset",
  "health",
  "hearing",
  "heat",
  "helpful",
  "herald",
  "herd",
  "hesitate",
  "hobo",
  "holiday",
  "holy",
  "home",
  "hormone",
  "hospital",
  "hour",
  "huge",
  "human",
  "humidity",
  "hunting",
  "husband",
  "hush",
  "husky",
  "hybrid",
  "idea",
  "identify",
  "idle",
  "image",
  "impact",
  "imply",
  "improve",
  "impulse",
  "include",
  "income",
  "increase",
  "index",
  "indicate",
  "industry",
  "infant",
  "inform",
  "inherit",
  "injury",
  "inmate",
  "insect",
  "inside",
  "install",
  "intend",
  "intimate",
  "invasion",
  "involve",
  "iris",
  "island",
  "isolate",
  "item",
  "ivory",
  "jacket",
  "jerky",
  "jewelry",
  "join",
  "judicial",
  "juice",
  "jump",
  "junction",
  "junior",
  "junk",
  "jury",
  "justice",
  "kernel",
  "keyboard",
  "kidney",
  "kind",
  "kitchen",
  "knife",
  "knit",
  "laden",
  "ladle",
  "ladybug",
  "lair",
  "lamp",
  "language",
  "large",
  "laser",
  "laundry",
  "lawsuit",
  "leader",
  "leaf",
  "learn",
  "leaves",
  "lecture",
  "legal",
  "legend",
  "legs",
  "lend",
  "length",
  "level",
  "liberty",
  "library",
  "license",
  "lift",
  "likely",
  "lilac",
  "lily",
  "lips",
  "liquid",
  "listen",
  "literary",
  "living",
  "lizard",
  "loan",
  "lobe",
  "location",
  "losing",
  "loud",
  "loyalty",
  "luck",
  "lunar",
  "lunch",
  "lungs",
  "luxury",
  "lying",
  "lyrics",
  "machine",
  "magazine",
  "maiden",
  "mailman",
  "main",
  "makeup",
  "making",
  "mama",
  "manager",
  "mandate",
  "mansion",
  "manual",
  "marathon",
  "march",
  "market",
  "marvel",
  "mason",
  "material",
  "math",
  "maximum",
  "mayor",
  "meaning",
  "medal",
  "medical",
  "member",
  "memory",
  "mental",
  "merchant",
  "merit",
  "method",
  "metric",
  "midst",
  "mild",
  "military",
  "mineral",
  "minister",
  "miracle",
  "mixed",
  "mixture",
  "mobile",
  "modern",
  "modify",
  "moisture",
  "moment",
  "morning",
  "mortgage",
  "mother",
  "mountain",
  "mouse",
  "move",
  "much",
  "mule",
  "multiple",
  "muscle",
  "museum",
  "music",
  "mustang",
  "nail",
  "national",
  "necklace",
  "negative",
  "nervous",
  "network",
  "news",
  "nuclear",
  "numb",
  "numerous",
  "nylon",
  "oasis",
  "obesity",
  "object",
  "observe",
  "obtain",
  "ocean",
  "often",
  "olympic",
  "omit",
  "oral",
  "orange",
  "orbit",
  "order",
  "ordinary",
  "organize",
  "ounce",
  "oven",
  "overall",
  "owner",
  "paces",
  "pacific",
  "package",
  "paid",
  "painting",
  "pajamas",
  "pancake",
  "pants",
  "papa",
  "paper",
  "parcel",
  "parking",
  "party",
  "patent",
  "patrol",
  "payment",
  "payroll",
  "peaceful",
  "peanut",
  "peasant",
  "pecan",
  "penalty",
  "pencil",
  "percent",
  "perfect",
  "permit",
  "petition",
  "phantom",
  "pharmacy",
  "photo",
  "phrase",
  "physics",
  "pickup",
  "picture",
  "piece",
  "pile",
  "pink",
  "pipeline",
  "pistol",
  "pitch",
  "plains",
  "plan",
  "plastic",
  "platform",
  "playoff",
  "pleasure",
  "plot",
  "plunge",
  "practice",
  "prayer",
  "preach",
  "predator",
  "pregnant",
  "premium",
  "prepare",
  "presence",
  "prevent",
  "priest",
  "primary",
  "priority",
  "prisoner",
  "privacy",
  "prize",
  "problem",
  "process",
  "profile",
  "program",
  "promise",
  "prospect",
  "provide",
  "prune",
  "public",
  "pulse",
  "pumps",
  "punish",
  "puny",
  "pupal",
  "purchase",
  "purple",
  "python",
  "quantity",
  "quarter",
  "quick",
  "quiet",
  "race",
  "racism",
  "radar",
  "railroad",
  "rainbow",
  "raisin",
  "random",
  "ranked",
  "rapids",
  "raspy",
  "reaction",
  "realize",
  "rebound",
  "rebuild",
  "recall",
  "receiver",
  "recover",
  "regret",
  "regular",
  "reject",
  "relate",
  "remember",
  "remind",
  "remove",
  "render",
  "repair",
  "repeat",
  "replace",
  "require",
  "rescue",
  "research",
  "resident",
  "response",
  "result",
  "retailer",
  "retreat",
  "reunion",
  "revenue",
  "review",
  "reward",
  "rhyme",
  "rhythm",
  "rich",
  "rival",
  "river",
  "robin",
  "rocky",
  "romantic",
  "romp",
  "roster",
  "round",
  "royal",
  "ruin",
  "ruler",
  "rumor",
  "sack",
  "safari",
  "salary",
  "salon",
  "salt",
  "satisfy",
  "satoshi",
  "saver",
  "says",
  "scandal",
  "scared",
  "scatter",
  "scene",
  "scholar",
  "science",
  "scout",
  "scramble",
  "screw",
  "script",
  "scroll",
  "seafood",
  "season",
  "secret",
  "security",
  "segment",
  "senior",
  "shadow",
  "shaft",
  "shame",
  "shaped",
  "sharp",
  "shelter",
  "sheriff",
  "short",
  "should",
  "shrimp",
  "sidewalk",
  "silent",
  "silver",
  "similar",
  "simple",
  "single",
  "sister",
  "skin",
  "skunk",
  "slap",
  "slavery",
  "sled",
  "slice",
  "slim",
  "slow",
  "slush",
  "smart",
  "smear",
  "smell",
  "smirk",
  "smith",
  "smoking",
  "smug",
  "snake",
  "snapshot",
  "sniff",
  "society",
  "software",
  "soldier",
  "solution",
  "soul",
  "source",
  "space",
  "spark",
  "speak",
  "species",
  "spelling",
  "spend",
  "spew",
  "spider",
  "spill",
  "spine",
  "spirit",
  "spit",
  "spray",
  "sprinkle",
  "square",
  "squeeze",
  "stadium",
  "staff",
  "standard",
  "starting",
  "station",
  "stay",
  "steady",
  "step",
  "stick",
  "stilt",
  "story",
  "strategy",
  "strike",
  "style",
  "subject",
  "submit",
  "sugar",
  "suitable",
  "sunlight",
  "superior",
  "surface",
  "surprise",
  "survive",
  "sweater",
  "swimming",
  "swing",
  "switch",
  "symbolic",
  "sympathy",
  "syndrome",
  "system",
  "tackle",
  "tactics",
  "tadpole",
  "talent",
  "task",
  "taste",
  "taught",
  "taxi",
  "teacher",
  "teammate",
  "teaspoon",
  "temple",
  "tenant",
  "tendency",
  "tension",
  "terminal",
  "testify",
  "texture",
  "thank",
  "that",
  "theater",
  "theory",
  "therapy",
  "thorn",
  "threaten",
  "thumb",
  "thunder",
  "ticket",
  "tidy",
  "timber",
  "timely",
  "ting",
  "tofu",
  "together",
  "tolerate",
  "total",
  "toxic",
  "tracks",
  "traffic",
  "training",
  "transfer",
  "trash",
  "traveler",
  "treat",
  "trend",
  "trial",
  "tricycle",
  "trip",
  "triumph",
  "trouble",
  "true",
  "trust",
  "twice",
  "twin",
  "type",
  "typical",
  "ugly",
  "ultimate",
  "umbrella",
  "uncover",
  "undergo",
  "unfair",
  "unfold",
  "unhappy",
  "union",
  "universe",
  "unkind",
  "unknown",
  "unusual",
  "unwrap",
  "upgrade",
  "upstairs",
  "username",
  "usher",
  "usual",
  "valid",
  "valuable",
  "vampire",
  "vanish",
  "various",
  "vegan",
  "velvet",
  "venture",
  "verdict",
  "verify",
  "very",
  "veteran",
  "vexed",
  "victim",
  "video",
  "view",
  "vintage",
  "violence",
  "viral",
  "visitor",
  "visual",
  "vitamins",
  "vocal",
  "voice",
  "volume",
  "voter",
  "voting",
  "walnut",
  "warmth",
  "warn",
  "watch",
  "wavy",
  "wealthy",
  "weapon",
  "webcam",
  "welcome",
  "welfare",
  "western",
  "width",
  "wildlife",
  "window",
  "wine",
  "wireless",
  "wisdom",
  "withdraw",
  "wits",
  "wolf",
  "woman",
  "work",
  "worthy",
  "wrap",
  "wrist",
  "writing",
  "wrote",
  "year",
  "yelp",
  "yield",
  "yoga",
  "zero"
];

final _wordListMap =
    _wordList.asMap().map((idx, value) => MapEntry(value, idx));
