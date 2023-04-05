
import 'dart:core';
import 'dart:typed_data';
import 'package:network_monitor/dns/utility.dart';
import 'package:network_monitor/dns/dns.dart';

import 'name.dart';



//  Inner class used to manage message compression

class Pointer {
  int idx=-1;
  String name="";
}


/// This class manages the creation and parsing of the DNS message format (it's main pureadPose is to implement message compression as described in RFC 1035)
class ByteBuffer {


  Uint8List _buf = Uint8List(0);
  int _readPos=0; // Read position
  int _writePos = 0; // Write Position
  Map<String, Pointer> _labels = {};
  int _rdlengthPos = 0;

  ByteBuffer.fromSouce(ByteBuffer oldBuf, int sourcePos):super(){
      _buf = oldBuf._buf;
      _readPos = sourcePos;
      _labels.addAll(oldBuf._labels);
  }

  get length => _buf.length;


  static void log(String msg) {
    print (msg);
  }

  /// Create a ByteBuffer from a byte array setting the current position (used mainly to manage message compression in recieving messages)
  ByteBuffer.fromNew();

  ByteBuffer(Uint8List buffer, int idx) {
    _buf = buffer;
    _readPos = idx;
    _writePos = 0;
    _labels = {};
  }

  /// retu the amount of data left to read
  /// (buf.length - readPos)
  int available() {
    return _buf.length - _readPos;
  }

  /// Check to see if there is a pointer at the current position (a pointer is described in RFC 1035)
  /// @return A ByteBuffer representing the current position with pointers dereferenced
  ByteBuffer chkPointer() {

    /*
			If we are currently pointed at a pointer
			create a new buffer pointing to the real
			string, and return it, otherwise return this.
		 */
    if (_readPos >= _buf.length || (_buf[_readPos] & DNS.POINTER) == 0) {
      return this;
    }

    int newPos = nextShort();
    ByteBuffer ret =  ByteBuffer(_buf, (newPos & 0x3FFF));
    ret._writePos = _writePos;
    return ret;
  }


  /// Dump the ByteBuffer showing the position, hex value, binary value and character of each int (use to debug)

  void dump() {
    int cnt = _buf.length - 1;

    for (cnt = _buf.length - 1; cnt > 0; cnt--) {
      if (_buf[cnt] != 0) {
        break;
      }
    }

    log("ByteBuffer Dump readPos=$_readPos writePos = $_writePos length=$_buf.length");
    log("cnt=$cnt");

    //  Just to mak esure I save it all.
    if (cnt < _buf.length) {
      cnt++;
    }

    if (cnt < _buf.length) {
      cnt++;
    }

    int space = ' '.codeUnitAt(0);
    int val = 0;
    int c = space;

    for (int i = 0; i < cnt; i++) {
      val = (_buf[i] & 0xff);
      if (val > 30 && val < 128) {
        c = val;
      } else {
        c = space;
      }
      log("buf[${Utility.pad(i.toString(),3)}] =  ${Utility.pad(val.toString(),3)} , ${Utility.pad(val.toRadixString(16),2)} , ${_toBinaryString(val)} , raw(${_buf[i]}) , $c");
    }


    // show format rfc1035 4.1.1
    /*
                                1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		 */
    /*
		 * ID  A 16 bit identifier assigned by the program that
                generates any kind of query.  This identifier is copied
                the corresponding reply and can be used by the requester
                to match up replies to outstanding queries.
		 */
    log("\tID\t${Utility.makeShort(_buf[0], _buf[1])}");
    /*
		 
			QR  A one bit field that specifies whether this message is a
                query (0), or a response (1).
		 */
    String tmp = _toBinaryString(_buf[2]);
    log("\tQR\t${tmp[0]}");

    /*
		 OPCODE          A four bit field that specifies kind of query in this
                message.  This value is set by the originator of a query
                and copied into the response.  The values are:

                0               a standard query (QUERY)

                1               an inverse query (IQUERY)

                2               a server status request (STATUS)

                3-15            reserved for future use
		 */
    String t2 = tmp.substring(1, 5);
    int v = int.parse(t2, radix: 2);

    log("\tOPCODE\t $t2  =  $v");
    switch (v) {
      case 0:
        log(" a standard query (QUERY)");
        break;
      case 1:
        log(" an inverse query (IQUERY)");
        break;
      case 2:
        log(" a server status request (STATUS)");
        break;

      default:
        log(" reserved for future use");
        break;
    }
    /*
AA              Authoritative Answer - this bit is valid in responses,
                and specifies that the responding name server is an
                authority for the domain name in question section.

                Note that the contents of the answer section may have
                multiple owner names because of aliases.  The AA bit
                corresponds to the name which matches the query name, or
                the first owner name in the answer section.
		 */
    log("\tAA\t${tmp[5]}");

    /*
TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
		 */
    log("\tTC\t${tmp[6]}");

    /*
RD              Recursion Desired - this bit may be set in a query and
                is copied into the response.  If RD is set, it directs
                the name server to pursue the query recursively.
                Recursive query support is optional.
		 */
    log("\tRD\t${tmp[7]}");

/*
 RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
 
 */
    tmp = _toBinaryString(_buf[3]);


    log("\tRA\t${tmp[0]}");
/*
Z               Reserved for future use.  Must be zero in all queries
                and responses.
 */
    log("\tZ\t${tmp.substring(1, 4)} \tReserved for future use.  Must be zero in all queries and responses.");

/*
 RCODE           Response code - this 4 bit field is set as part of
                responses.  The values have the following
                interpretation:

                0               No error condition

                1               Format error - The name server was
                                unable to interpret the query.

                2               Server failure - The name server was
                                unable to process this query due to a
                                problem with the name server.

                3               Name Error - Meaningful only for
                                responses from an authoritative name
                                server, this code signifies that the
                                domain name referenced in the query does
                                not exist.

                4               Not Implemented - The name server does
                                not support the requested kind of query.

                5               Refused - The name server refuses to
                                perform the specified operation for
                                policy reasons.  For example, a name
                                server may not wish to provide the
                                information to the particular requester,
                                or a name server may not wish to perform
                                a particular operation (e.g., zone
                                transfer) for particular data.

                6-15            Reserved for future use.
 */
    t2 = tmp.substring(4);
    v = int.parse(t2, radix: 2);
    log("\tRCODE\t$t2  =   $v");
    switch (v) {
      case 0:
        log(" No error condition");
        break;
      case 1:
        log(
            " Format error - The name server was unable to interpret the query.");
        break;
      case 2:
        log(" Server failure - The name server was\n                                unable to process this query due to a\n                                problem with the name server.");
        break;
      case 3:
        log(" Name Error - Meaningful only for\n                                responses from an authoritative name\n                                server, this code signifies that the\n                                domain name referenced in the query does\n                                not exist.");
        break;
      case 4:
        log(" Not Implemented - The name server does\n"
            "                                not support the requested kind of query.");
        break;
      case 5:
        log(" Refused - The name server refuses to\n                                perform the specified operation for\n                                policy reasons.  For example, a name\n                                server may not wish to provide the\n                                information to the particular requester,\n                                or a name server may not wish to perform\n                                a particular operation (e.g., zone\n                                transfer) for particular data.");
        break;


      default:
        log(" reserved for future use");
        break;
    }

/*
QDCOUNT         an unsigned 16 bit integer specifying the number of
                entries in the question section.
*/
    log("\tQDCOUNT\t${Utility.makeShort(_buf[4], _buf[5]).toString()}");
/*		
ANCOUNT         an unsigned 16 bit integer specifying the number of
                resource records in the answer section.
*/
    log("\tANCOUNT\t${Utility.makeShort(_buf[6], _buf[7])}");
/*		
NSCOUNT         an unsigned 16 bit integer specifying the number of name
                server resource records in the authority records
                section.
*/
    log("\tNSCOUNT\t${Utility.makeShort(_buf[8], _buf[9])}");
/*
ARCOUNT         an unsigned 16 bit integer specifying the number of
                resource records in the additional records section.		
 */
    log("\tARCOUNT\t${Utility.makeShort(_buf[10], _buf[11])}");
  }

  String _toBinaryString(int b) {
    String ret = b.toRadixString(2);
    while (ret.length < 8) {
      ret = "0$ret";
    }

    if (ret.length > 8) {
      ret = ret.substring(ret.length - 8);
    }
    return ret;
  }

  /// Get the internal int array
  List<int> getInternalBufffer() {
    List<int> ret = [];
    for(int idx=0; idx < _buf.length; idx++) {
      ret[idx] = _buf[idx];
    }
    return ret;
  }

  /// Get a copy of the internal int array
  /// (the array 'may' be trimmed to the size of the data actually in the array)
  List<int> getByteArray() {
    if (_writePos < _buf.length) {
      List<int> ret = [];
      for(int idx=0; idx < _writePos; idx++) {
          ret[idx] = _buf[idx];
      }
      return ret;
    } else {
      return _buf;
    }
  }


  /// Get the position of the read pointer

  int getReadPos() {
    return _readPos;
  }

  /// Get the position of the write pointer

  int getWritePos() {
    return _writePos;
  }

  /// Get the next 8 bit byte from the ByteBuffer, incrementing the read position

   int next() {
    int ret = _buf[_readPos++]&0xff;

    return ret;
  }
  /// Get a 32 bit int from the buffer
  /// @return int representation of the next four bytes in the ByteBuffer, incrementing the readPosition accordingly

   int nextInt() {
    return Utility.makeInt( next(), next(),	next(), next());
  }
  /// Get a 16 bit int from the buffer
  /// @return short representation of the next two bytes in the ByteBuffer, incrementing the readPosition accordingly


   int nextShort() {
    return Utility.makeShort( next(), next());
  }

  //  Setters
  ///   Add a 8 bit byte to the byte array , incrementing the write position

   void setByte(int b) {
    _buf.add(b);
  }

  /// Copy a byte array into the internal buffer at the current position

   void setBytes(List<int> b) {
      for(int i=0; i < b.length; i++ ) {
        setByte(b[i]);
    }
  }


  /// Add a 32 bit integer to the byte array in Big Endian order (incrementing the write pointer accordingly)
   void setInt(int val) {
    int s = (val >> 16);
    setShort(s);
    s = val&0xffff;
    setShort(s);
  }

  ///Add a name to this buffer and implement compression as described in RFC 1035.

   void setName(String name) {

    Pointer? p = _labels[name];
    if( p != null ) {
      setShort((p.idx|(DNS.POINTER<<8))); //  ptr.idx is already made into a pointer
      return;
    }

    //	If we made it to here, at lease part of the name will be new in the label list

    if( name.length > 3 ) {
      //  But only do it if there is a savings of 2 or more bytes
      p = Pointer();
      p.idx = _writePos;
      p.name = name;
      _labels[name]=p;
    }

    //  Now, break the name apart and check each segment
    int idx = name.indexOf(".");
    String tmp = "";
    if( idx > 0 ) {
      tmp  = name.substring(idx+1);
      name = name.substring(0,idx);
    }
    setByte(name.length);
    setBytes(name.codeUnits);
    setName(tmp);
  }

  /// Add a name to this buffer and implement compression as described in RFC 1035.

   void setNameFromName(Name name) {
    setName(name.toString());
  }

  /// Write the rdlength into the marked location rdlength is calculated from the mark to the current pos

   void setRdLength() {
    int hld = _writePos;
    int rdlength = _writePos-_rdlengthPos-2;
    _writePos = _rdlengthPos;
    setShort(rdlength);
    _writePos = hld;
  }

   void setShort(int s) {
    setByte((s >> 8));
    setByte(s);
  }

  void markPos(int s){
    _rdlengthPos = _writePos;
    setShort(s);
  }

}