
import 'dart:typed_data';

import 'package:network_monitor/dns/byte_buffer.dart';
import 'package:network_monitor/dns/label.dart';
import 'package:network_monitor/dns/section.dart';
import 'package:network_monitor/dns/srv.dart';

import 'dns.dart';
import 'name.dart';

class RR extends Section {
  //  Fields inPut this order
  int ttl = 0; // 32 bit == Time to live (0 == only this trans)
  int rdlength = 0; // 16 bit == bytes inPut RDATA
  List<int> rdata = []; //  Diff for each type
  //  Time this record was inited (this can be used to
  //  determine if the record should be expired
  int initTime = 0;
  bool isBase = true;
  bool dirty = true;
  ByteBuffer? source;
  int sourcePos = -1;

  RR() : super();

  RR.fromByteBuffer(ByteBuffer buf) : super.fromByteBuffer(buf) {
    init(buf);
  }

  RR.fromData(String name, int type, int dnsClass) {
    setName(name);
    setType(type);
    setDnsClass(dnsClass);
  }

  RR.fromRR(RR sec) {
    setName(sec.getName());
    setType(sec.getType());
    setDnsClass(sec.dnsClass);
    initFromRR(sec);
  }

  int getInitTime() {
    return initTime;
  }

  List<int> getRdata() {
    return rdata;
  }

  String getRdataAsString() {
    throw Exception("call to getRDataAsString not valid for this object");
  }

  int getRdLength() {
    return rdlength;
  }

  int getTTL() {
    return ttl;
  }

  bool hasExpired() {
    bool ret = false;
    int now = DateTime.now().millisecondsSinceEpoch;
    int expTime = initTime + (ttl * 1000);
    ret = (now > expTime);
    return ret;
  }

  void init(ByteBuffer inPut) {
    source = inPut;
    ttl = inPut.nextInt();
    readRdata(inPut);
  }

  void setRdata(List<int> list) {
    rdata = list;
    rdlength = rdata.length;
  }

  void initFromRR(RR sec) {
    setTTL(sec.getTTL());
    setRdata(sec.getRdata());
    source = sec.source;
    sourcePos = sec.sourcePos;
    setFromRdata();
    dirty = false;
  }

  static RR parseRR(ByteBuffer inPut) {
    RR sec = RR.fromByteBuffer(inPut);

    RR ret = sec;

    switch (sec.getType()) {
      case DNS.A:
        ret = A.fromRR(sec);
        break;
      case DNS.NS:
        ret = Ns(sec);
        break;
      case DNS.CNAME:
        ret = Cname(sec);
        break;
      case DNS.SOA:
        ret = Soa(sec);
        break;
      case DNS.PTR:
        ret = Ptr.fromRR(sec);
        break;
      case DNS.TXT:
        ret = Txt.fromtRR(sec);
        break;
      case DNS.HINFO:
        ret = Hinfo(sec);
        break;
      case DNS.MX:
        ret = Mx(sec);
        break;
      case DNS.RP:
        ret = Rp(sec);
        break;
      case DNS.AFSDB:
        ret = Afsdb(sec);
        break;
      case DNS.SRV:
        ret = Srv.fromRR(sec);
        break;

      //  This is to prevent the log file from filling with unsupported errors
      //case OPT	: ret =  RR(sec);break;

      default:
      //print(inPut.buf);
      //print("Parse RR n rr.dart Un Supported type=$type (${type < DNS.TYPENAMES.length ?  (DNS.TYPENAMES[type]) :'type out of range'}) ");
    }
    //print("type = ${ret.runtimeType}");
    return ret;
  }

  //  Read all the bytes
  void readRdata(ByteBuffer inPut) {
    rdlength = inPut.nextShort();
    rdata = [];
    source = inPut;
    sourcePos = inPut.getReadPos();
    int remainder = inPut.available();

    if (remainder <= rdlength) {
      rdlength = remainder - 1;
    }

    for (int i = 0; i < rdlength; i++) {
      rdata.insert(i, inPut.next());
    }

    setFromRdata();
  }

  /// Set the TYPE Specific data elements from the RDATA array, this method is intended to be implemented by a subclass,  It has no value a this level, however, we can't make it abstract becouse parseRR needs to be able to create an RR without knowing what type it is (I'm sure there is a better way to do this, but, it works).

  void setFromRdata() {
    if (!isBase) {
      throw Exception("setFromRdata MUST be overridden! type = ${getType()}");
    }
  }

  /// Sets the initTime
  /// @param initTime The initTime to set
  void setInitTime(int initTime) {
    this.initTime = initTime;
  }

  void setTTL(int t) {
    ttl = t;
  }

  @override
  int size() {
    // super + ttl(4)+ rdlen(2)
    return super.size() + 6;
  }

  @override
  void toByteArray(ByteBuffer buf) {
    if (!dirty) {
      setFromRdata();
    }

    super.toByteArray(buf);
    buf.setInt(ttl);
    buf.markPos(rdlength);
  }

  @override
  String toString() {
    return "${super.toString()}  ttl=$ttl rdlen=$rdlength ";
  }
}

class A extends RR {
  A.fromRR(RR sec) : super.fromRR(sec);

  /// Get the String representation of the host four byte array containing the address of this host
  /// (in dot notation as in 999.999.999.999)
  String getAddressString() {
    return "${(rdata[0]&0xff)}.${(rdata[1]&0xff)}.${(rdata[2]&0xff)}.${(rdata[3]&0xff)}";
  }
}

class Ns extends RR {
  Ns(RR sec);
}

class Cname extends RR {
  Cname(RR sec);
}

class Soa extends RR {
  Soa(RR sec);
}

class Ptr extends RR {
  //  This is the rdata
  Name? ptr;


  ///     Default Constructor

  Ptr() : super() {
    setType(DNS.PTR);
    setDnsClass(DNS.IN);
    isBase = false;
    dirty = true;
  }


  ///     Construct a PTR and assign the RR.name from a parameter

  Ptr.fromAgs(String name) : super.fromData(name, DNS.PTR, DNS.IN) {
    isBase = false;
    dirty = true;
  }

  /// Construct a PTR from an RR
  Ptr.fromRR(RR rr) : super.fromRR(rr) {
    isBase = false;
    dirty = true;
    setFromRdata();
  }

  ///	Make a copy of the RR

  RR makeCopy() {
    Ptr ret = Ptr.fromRR(this);
    ret.ptr = ptr;
    return ret;
  }

  ///    Get the String representaion of the PTR value

  String getPtr() {
    return ptr.toString();
  }

  /// Convert to a Java String

  @override
  String getRdataAsString() {
    return ptr.toString();
  }

  @override
  void setFromRdata() {
    ByteBuffer inp = ByteBuffer.fromNew();

    if (source != null) {
      inp = ByteBuffer.fromSouce(source!, sourcePos);
    }
    ptr = Name.fromByteBuffer(inp);
  }

  /// Set the PTR value from a Java String

  void setPtr(String c) {
    ptr = Name.fromString(c);
    rdata = ptr!.toByteArray();
    rdlength = rdata.length;
    dirty = false;
    source = null;
  }

  @override
  void toByteArray(ByteBuffer buf) {
    super.toByteArray(buf);
    buf.setName(ptr.toString());
    buf.setRdLength();
  }

  ///Convert to a Java String
  @override
  String toString() {
    return super.toString() + " " + ptr.toString();
  }
}

class Txt extends RR {
  String text = "";
  Txt.fromtRR(RR sec) : super.fromRR(sec) {
    isBase = false;
    dirty = true;
    setFromRdata();
  }

  @override
  void setFromRdata() {
    if (text.isEmpty) {
      var inp = ByteBuffer(Uint8List.fromList(getRdata()), 0);

      if (source != null) {
        inp = ByteBuffer.fromSouce(source!, sourcePos);
      }

      if(inp.available()>0) {
          Name name = Name.fromByteBuffer(inp);

          text = "";
          for (Label l in name.myLabels) {
            text += "${l.toString()} ";
          }
      }
      dirty = false;
    }
  }

  @override
  String toString() {
    return "${super.toString()} $text";
  }
}

class Hinfo extends RR {
  Hinfo(RR sec);
}

class Mx extends RR {
  Mx(RR sec);
}

class Rp extends RR {
  Rp(RR sec);
}

class Afsdb extends RR {
  Afsdb(RR sec);
}

class Opt extends RR {
  Opt(RR sec);
}
