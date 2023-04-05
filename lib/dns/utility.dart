import 'dns.dart';

const int MAXUDPLEN=1024;
/// Required to get rid of the high end bits that Jave likes to add when converting bytes to larger values 
const int MASK = 0x00FF;


const int MINUTE=60;
const int HOUR=MINUTE*60;
const int DAY=HOUR*24;
const int WEEK=DAY*7;

const int MONTH=WEEK*4;
const List<int> bitMask = [
  1 ,  // bit 0
  2 , // bit 1
  4 , // bit 2
  8 , // bit 3
  16 , // bit 4
  32 , // bit 5
  64 , // bit 6
  128 ,// bit 7
  256, // bit 8
  512, // bit 9
  1024, // bit 10
  2048, // bit 11
  4096, // bit 12
  8192, // bit 13
  16384, // bit 14
  32768  // bit 15
];

class Utility {

  /// Shorthand for Integer.toBinaryString (yes, I'm that lazy) **/
  String bi(int i) {
    int newInt = i & 0x0ffff;
    String bin = newInt.toRadixString(2);

    return pad( bin,8);
  }

  /// Determine the DNS 'CLASS' based on a string (example "IN") *
  int classOf(String t) {
    int dnsClass = 0;
    t = t.toUpperCase();
    for(int i=0 ; i< DNS.dnsClassNames.length; i++) {
      if(DNS.dnsClassNames[i]== t) {
        dnsClass = i;
        break;
      }
    }
    return dnsClass;
  }
  
  /// Clear the specified bit in a int value (set it to 0) *
  int clearBit(int s, int b ) {
    return (s & bitMask[b]);
  }
  
  /// Check to see if the specified bit is set (==1)
  ///       @param s A Java int
  ///       @param b an int index to the specified bit
  ///       @return true if the specified bit ==1

  bool isSet(int s, int b) {
    bool ret =  (s&bitMask[b]) == bitMask[b];
    return ret;
  }

  static int makeInt(int b1, int b2, int b3, int b4) {
    int s1 = makeShort(b1,b2);
    int s2 = makeShort(b3,b4);
    int ret = (((s1<<16)|s2));
    return ret;
  }

  /// Build a Java int from two bytes *
  static int makeShort(int b1, int b2) {
    int i1 = (b1 & 0xff);
    int i2 = (b2 & 0xff);
    int ret = ((i1<<8)|i2)&0xffff;
    return ret;
  }

  /// Shorthand for Integer.toBinaryString (yes, I'm that lazy) *
  static String pad(String val, int len) {
    String ret = "00000000$val";
    return ret.substring(ret.length-len);
  }

  /// Set the specified bit in a int value (set it to 1) *
  static int setBit(int s, int b ) {
    int ret = (s | bitMask[b]);
    return ret;
  }

 static  RegExp digitRegExp = RegExp(r'\d');
  static bool isDigit(String s, {int idx = 0} ) => s[idx].contains(digitRegExp);

  /// Convert a Java int into two bytes and place them into a byte array
  ///       @param buf A byte array to recieve the bytes
  ///       @param idx array index to place the bytes
  ///       @param val a Java int


  ///     Convert a Java int into four bytes and place them into a byte array
  ///       @param buf A byte array to recieve the bytes
  ///       @param idx array index to place the bytes
  ///       @param val a Java int

  void setInt(List<int> buf, int idx, int val) {
    int s = (val >> 16);
    setShort1(buf,idx,s);
    s = val;
    setShort1(buf,idx+2,s);
  }

  void setShort2(List<int> buf, int idx, int s) {
    buf[idx] = (s >> 8);
    buf[idx+1] = s;
  }

  /// Determine the DNS 'TYPE' based on a string (example "MX") **/

  ///     Convert a Java int into two bytes and place them into a byte array
  ///       @param buf A byte array to recieve the bytes
  ///       @param idx array index to place the bytes
  ///       @param val a Java int

  void setShort1(List<int> buf, int idx, int s) {
    buf[idx] = (s >> 8);
    buf[idx+1] = s;
  }

  /// Calculate a number of seconds (1, 1d, 1h, 1m, 1w)

  int toSeconds(String val)  {

    val = val.trim();
    if( val.isEmpty) {
      return 0;
    }

    int i=0;
    int sz = val.length;

    for(; i< sz; i++ ) {

      if( isDigit(val[i]) == false) {
        break;
      }
    }

    if( i < 1 ) {
      return 0;
    }

    String num = val;
    String mul = "s";

    if( i != sz) {
      num = val.substring(0,i);
      mul = val.substring(i);
    }

    int unit = 1;
    if( mul.isNotEmpty ) {
      switch(mul[0]) {
        case 's':
        case 'S':unit = 1;	break;
        case 'm':
        case 'M':unit = MINUTE;	break;
        case 'h':
        case 'H':unit = HOUR;	break;
        case 'd':
        case 'D':unit = DAY;	break;
        case 'w':
        case 'W':unit = WEEK;	break;

      }
    }

    int ret = int.parse(num);
    ret = ret * unit;

    return ret;

  }


  int typeOf(String t) {
    t = t.toUpperCase();

    int type = 0;
    for(int i=0 ; i< DNS.recordTypeName.length; i++) {
      if(DNS.recordTypeName[i]==t) {
        type = i;
        break;
      }
    }

    if( type == 0 ) {
      if( t == "ANY" ) {
        type = DNS.QTYPE_ALL;
      }
    }

    return type;
  }

}