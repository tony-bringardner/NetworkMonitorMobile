
class Label {
  static const String wildcard = "*";
  String label = "";
  bool isWildCard = false;

  Label(this.label) {
    isWildCard = wildcard == (label);
  }

  Label.fromLabel(Label label) {
    this.label = (label.label);
    isWildCard = label.isWildCard;
  }

  @override
  operator ==(other) => other is Label && other.label == label;

  @override
  String toString() {
    return label;
  }

  @override
  int get hashCode => label.hashCode;


}
