
import 'package:network_monitor/dns/utility.dart';

import 'byte_buffer.dart';
import 'dns.dart';
import 'name.dart';


///     This class represents a 'Section' of a DNS Message (as defined in RFC 1035)

class Section extends Utility {
  /// A Domain name
  Name name = Name();

  /// DNS TYPE (A,MX,NS,...)
  /// 16 bit == type of query
  int type = DNS.A;

  /// DNS CLASS (IN,...)
  /// 16 bit = Query dnsClass (IN,...)
  int dnsClass = DNS.IN;

  Section();

  Section.fromNameString(String nameStr) {
    name = Name.fromString(nameStr);
  }

  Section.fromArgs(this.name, this.dnsClass, this.type);

  ///Construct a Section from the data in a byte buffer

  Section.fromByteBuffer(ByteBuffer inme) {
    name = Name.fromByteBuffer(inme);
    type = inme.nextShort();
    dnsClass = inme.nextShort();
  }

  void copy(Section newObj) {
    newObj.dnsClass = dnsClass;
    newObj.name = Name.fromName(name);
    newObj.type = type;
  }

  int getDnsClass() {
    return dnsClass;
  }

  String getName() {
    return name.toString();
  }

  Name getNameAsName() {
    return name;
  }

  String getParentName() {
    String ret = "";
    ret = name.getParent();
    return ret;
  }

  Name? getParentNameAsName() {
    if (name == null) {
      return null;
    } else {
      return name.getParentName();
    }
  }

  int getType() {
    return type;
  }

  int matchCount1(Name other) {
    int ret = 0;
    ret = name.matchCount(other);
    return ret;
  }

  int matchCount(Section other) {
    int ret = 0;
    if (!(other.name == null)) {
      ret = name.matchCount(other.name);
    }

    return ret;
  }

  /*
	 * Replace any wild cards in this name with lables from the other name
	 */
  void replaceWildCards(String otherName) {
    replaceWildCards1(Name.fromString(otherName));
  }

  /*
	 * Replace any wild cards in this name with lables from the other name
	 */
  void replaceWildCards1(Name otherName) {
    name.replaceWildCards(otherName);
  }

  void setDnsClass(int c) {
    dnsClass = c;
  }

  void setDnsClassFromString(String t) {
    dnsClass = classOf(t);
  }

  void setName(String n) {
    name = Name.fromString(n);
  }

  void setType(int t) {
    type = t;
  }

  void setTypeFromString(String t) {
    type = typeOf(t);
  }

  int size() {
    int ret = 0;
    ret = name.size() + 4;
    return ret;
  }

  void toByteArray(ByteBuffer buf) {
    buf.setNameFromName(name);
    buf.setShort(type);
    buf.setShort(dnsClass);
  }

  @override
  String toString() {
    String p1 = (type == 255 ? "ANY" : DNS.recordTypeName[type]);
    String p2 = (dnsClass == 255
        ? "ANY"
        : dnsClass > 255
            ? "CLASS=" + dnsClass.toString()
            : DNS.dnsClassNames[dnsClass]);
    return "${name.toString()}  $p1 $p2";
  }
}
