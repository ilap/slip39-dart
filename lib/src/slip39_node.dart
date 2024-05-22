part of 'slip39.dart';

///
/// Slip39Node
///
class Slip39Node {
  Slip39Node({required this.name, String mnemonic = "", int index = 0, int threshold = 1, List<Slip39Node> children = const <Slip39Node>[]})
      : _mnemonic = mnemonic,
        _index = index,
        _threshold = threshold,
        _children = children;

  final List<Slip39Node> _children;
  final int _index;
  final String _mnemonic;
  final int _threshold;
  final String name;

  List<String> get mnemonics {
    if (_children.isEmpty) {
      return [_mnemonic];
    } else {
      final result = _children.fold(<String>[], (dynamic prev, item) {
        return prev..addAll(item.mnemonics);
      });
      return result;
    }
  }

  Slip39Node _copyWith(
      {String? name,
      String? mnemonic,
      int? threshold,
      int? index,
      List<Slip39Node>? children}) {
    return Slip39Node(
        name: name ?? this.name,
        mnemonic: mnemonic ?? _mnemonic,
        threshold: threshold ?? _threshold,
        index: index ?? _index,
        children: children ?? _children);
  }

  Map<String, Object?> toJson() {
    var encoded = _children.map((child) {
      if (child._children.isEmpty) {
        return child.name;
      } else {
        return child.toJson();
      }
    }).toList();

    return {
      "name": name,
      "threshold": _threshold,
      "shares": encoded,
    };
  }

  Slip39Node derive(int groupIndex) => _children[groupIndex];
  Slip39Node deriveByName(String name) =>
      _children.where((child) => name == child.name).first;
}
