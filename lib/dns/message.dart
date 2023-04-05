

import 'dart:io';
import 'dart:typed_data';

import 'package:network_monitor/dns/byte_buffer.dart';
import 'package:network_monitor/dns/rr.dart';
import 'package:network_monitor/dns/section.dart';
import 'package:network_monitor/dns/utility.dart';

import 'header.dart';
import 'dns.dart';
import 'name.dart';

void main() {
  List<int> bytes = [0, 0, 0, 0, 0, 3, 0, 2, 0, 0, 0, 1, 2, 108, 98, 7, 95, 100, 110, 115, 45, 115, 100, 4, 95, 117, 100, 112, 5, 108, 111, 99, 97, 108, 0, 0, 12, 0, 1, 15, 95, 99, 111, 109, 112, 97, 110, 105, 111, 110, 45, 108, 105, 110, 107, 4, 95, 116, 99, 112, 192, 28, 0, 12, 0, 1, 8, 95, 104, 111, 109, 101, 107, 105, 116, 192, 55, 0, 12, 0, 1, 192, 39, 0, 12, 0, 1, 0, 0, 17, 145, 0, 18, 15, 73, 99, 108, 111, 117, 100, 226, 128, 153, 115, 32, 105, 77, 97, 99, 192, 39, 192, 39, 0, 12, 0, 1, 0, 0, 17, 148, 0, 11, 8, 105, 80, 97, 100, 32, 40, 53, 41, 192, 39, 0, 0, 41, 5, 160, 0, 0, 17, 148, 0, 18, 0, 4, 0, 14, 0, 217, 106, 201, 55, 34, 204, 27, 202, 50, 182, 69, 225, 101];
  Uint8List data = Uint8List.fromList(bytes);


  var buf = ByteBuffer(data,0);

  Message m = Message.fromByteBuffer(buf);
  print(m.toString());

}
/// This class manages a DNS Message.

class Message extends Utility {
  int initTime = DateTime.now().millisecondsSinceEpoch;
  bool debug = false;
  bool udp = true;
  bool defname = false;
  int Qtype = DNS.A;
  int DnsClass = DNS.IN;
  int port = DNS.DNSPORT;
  int retry = 4;
  int timeOut = 3000;
  String domain = "";

  Header hdr =  Header();
  List<Section> que = []; // Question section (QD)
  List<RR> ans = []; //  Answer Section (AN)
  List<RR> ath = []; //  Authoritative (NS)
  List<RR> add = []; //  Additional info (AR)
  Map<String, List<RR>>? all; //  All RRs

  String server = "dns.minemall.com";
  //  For use in query (getaddress of server name)
  //  Store the result of toByteArray so that size can function
  //byte [] data = null;
  int dataSize = 0;

  Message() ;

  factory Message.fromByteBuffer(ByteBuffer inPut) {
    Message ret = Message();
    ret.buildMessage(inPut);
    return ret;
  }

  List<RR> findType(int target) {
    List<RR> ret = [];
    for(RR rr in getAdditional()) {
      if( rr.type == target) {
        ret.add(rr);
      }
    }
    for(RR rr in getAuthority()) {
      if( rr.type == target) {
        ret.add(rr);
      }
    }
    for(RR rr in getAnswer()) {
      if( rr.type == target) {
        ret.add(rr);
      }
    }

    return ret;
  }

  void addAdditional(RR rr) {
    add.add(rr);
  }

  void addAnswer(RR rr) {
    ans.add(rr);
  }

  void addAuthority(RR rr) {
    ath.add(rr);
  }

  List<RR> additional() {
    return add;
  }

  void addQuestionFromArgs(String name, int type, int dnsClass) {
    addQuestionFromSection(
        Section.fromArgs(Name.fromString(name), type, dnsClass));
  }

  void addQuestionFromSection(Section rr) {
    que.add(rr);
  }

  void addToAll(List<RR> it) {
    List<RR>? lst = [];
    String key = "";


    for (RR rr in it) {
      key = rr.getName().toLowerCase();
      lst = all?[key];
      if ((lst) == null) {
        lst = [];
        all?[key] = lst;
      }
      lst.add(rr);
    }
  }

  List<RR> answer() {
    return ans;
  }

  List<RR> authority() {
    return ath;
  }

  ///  AA             Authoritative Answer - this bit is valid in responses,
  ///                 and specifies that the responding name server is an
  ///                 authority for the domain name in question section.
  ///
  ///                 Note that the contents of the answer section may have
  ///                 multiple owner names because of aliases.  The AA bit
  ///
  ///                 corresponds to the name which matches the query name, or
  ///                 the first owner name in the answer section.


  void authorityOff() {
    hdr.setAA(false);
  }


  /// AA              Authoritative Answer - this bit is valid in responses,
  ///                 and specifies that the responding name server is an
  ///                 authority for the domain name in question section.
  ///
  ///                 Note that the contents of the answer section may have
  ///                 multiple owner names because of aliases.  The AA bit
  ///
  ///                 corresponds to the name which matches the query name, or
  ///                 the first owner name in the answer section.


  void authorityOn() {
    hdr.setAA(true);
  }

  void buildMessage(ByteBuffer inp) {
    Header h = Header();
    h.init(inp);
    //hdr = h;

    int cnt = h.getQDCOUNT();


    for (int i = 0; i < cnt; i++) {
      que.add(Section.fromByteBuffer(inp));
    }

    cnt = h.getANCOUNT();
    for (int i = 0; i < cnt; i++) {
      ans.add(RR.parseRR(inp));
    }

    cnt = h.getNSCOUNT();
    for (int i = 0; i < cnt; i++) {
      ath.add(RR.parseRR(inp));
    }

    cnt = h.getARCOUNT();
    for (int i = 0; i < cnt; i++) {
      add.add(RR.parseRR(inp));
    }
    hdr = h;

  }

  /// Combine the answer, auth and add section from msg into this
  void combine(Message msg) {
    List<RR> i = msg.answer();
    for (RR r in i) {
      ans.add(r);
    }

    i = msg.authority();
    ath = [];

    for (RR r in i) {
      ath.add(r);
    }

    i = msg.additional();
    add = [];
    for (RR r in i) {
      add.add(r);
    }
  }

  void debugOff() {
    debug = false;
  }

  void debugOn() {
    debug = true;
  }

  void defnameOff() {
    defname = false;
  }

  void defnameOn() {
    defname = true;
  }

  List<RR> getAdditional() {
    return add;
  }

  /// How many additional records

  int getAdditionalCount() {
    return add.length;
  }


  ///    getAddress  serach through this Message for an 'A' record giving the address specified by 'name'
  ///    @param name Server name to search for
  ///    @return 'A' record of the given host or null if no appropriate 'A' record
  ///    exists in this Message.

  A? getAddress(String name) {
    if (all == null) {
      getAll();
    }

    A? ret;
    RR? rr;

    name = name.toLowerCase();
    List<RR>? al = all?[name];

    for (int idx = 0, sz = al!.length; idx < sz; idx++) {
      rr = al[idx];
      if (rr.runtimeType == A) {
        ret = rr as A;
      }
    }

    return ret;
  }

  Map<String, List<RR>> getAll() {
    if (all == null) {
      //int ancnt = hdr.getANCOUNT();
      //int nscnt = hdr.getNSCOUNT();
      //int adcnt = hdr.getARCOUNT();

      all = {};
      addToAll(ans);
      addToAll(add);
      addToAll(ath);
    }

    return all!;
  }

  List<RR> getAnswer() {
    return ans;
  }

  ///How many answers are in the message

  int getAnswerCount() {
    return ans.length;
  }

  List<RR> getAuthority() {
    return ath;
  }

  String getDomain() {
    return domain;
  }

  ///  Return the first section in the question section
  ///  (that's all ther usualy is)
  Section? getFirstQuestion() {
    Section? ret;

    if (que.isNotEmpty) {
      ret = que[0] ;
    }

    return ret;
  }

  Header getHeader() {
    return hdr;
  }


	///ID          A 16 bit identifier assigned by the program that
  ///              generates any kind of query.  This identifier is copied
  ///           the corresponding reply and can be used by the requester
  ///              to match up replies to outstanding queries.

  int getID() {
    return hdr.getID();
  }

  ///    getAddress  serach through this Message for an 'A' record giving the address specified by 'name'
  ///    @param name Server name to search for
  ///    @return InternetAddress of the given host or null if no appropriate 'A' record
  ///    exists in this Message.


  InternetAddress? getInetAddress(String name) {
    InternetAddress? ret;
    name = name.toLowerCase();

    Map<String, List<RR>> hs = getAll();
    List<RR>? al = hs[name];

    if (al != null) {
      for (RR r in al) {
        if (r.runtimeType == A) {
          A a = r as A;
          ret = InternetAddress(a.getAddressString());
        }
      }
    }

    return ret;
  }


  /// Gets the initTime
  /// @return Returns an int

  int getInitTime() {
    return initTime;
  }


  ///    QR              A one bit field that specifies whether this message is a
  ///    query (0), or a response (1).


  int getMessageType() {
    if (hdr.getMessageType()) {
      return DNS.RESPONSE;
    } else {
      return DNS.QUERY;
    }
  }


  ///  How many NS records.  These can be used to send  requests
  ///  for authoratative answers

  int getNSCount() {
    return ath.length;
  }

  /*

      OPCODE          A four bit field that specifies kind of query in this
      message.  This value is set by the originator of a query
      and copied into the response.  The values are:

      0               a standard query (QUERY)

      1               an inverse query (IQUERY)

      2               a server status request (STATUS)

      3-15            reserved for future use

   */
  int getOpCode() {
    return hdr.getOPCODE() & 0xff;
  }

  int getPort() {
    return port;
  }

  int getQueryType() {
    return hdr.getOPCODE();
  }

  List<Section> getQuestion() {
    return que;
  }

  ///	Question Count (How many questions in this message)

  int getQuestionCount() {
    return que.length;
  }

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
  int getResponseCode() {
    return hdr.getRCODE() & 0xff;
  }

  int getRetry() {
    return retry;
  }

  int getTimeOut() {
    return timeOut;
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

  bool isAuthority() {
    return hdr.getAA();
  }

  bool isDebug() {
    return debug;
  }

  bool isDefname() {
    return defname;
  }


  ///    QR              A one bit field that specifies whether this message is a
  ///    query (0), or a response (1).
  bool isQuery() {
    return hdr.getMessageType() == false;
  }

  /// a message is recursive if both RA and RD are true

  bool isRecursive() {
    return hdr.getRD() && hdr.getRA();
  }

  bool isRecursiveAvailable() {
    return hdr.getRA();
  }

/// RD              Recursion Desired - this bit may be set in a query and
///                is copied into the response.  If RD is set, it directs
///                the name server to pursue the query recursively.
///                Recursive query support is optional.


  bool isRecursiveDesired() {
    return hdr.getRD();
  }

  /// QR A one bit field that specifies whether this message is a
  ///    query (0), or a response (1).


  bool isResponse() {
    return hdr.getMessageType();
  }


/// RCODE           Response code - this 4 bit field is set as part of
  ///                 responses.  The values have the following
  ///                 interpretation:
  ///
  ///                 0               No error condition
  ///
  ///                 1               Format error - The name server was
  ///                           unable to interpret the query.
  ///
  ///                 2               Server failure - The name server was
  ///                                 unable to process this query due to a
  ///                                 problem with the name server.
  ///
  ///                 3               Name Error - Meaningful only for
  ///                                 responses from an authoritative name
  ///                                 server, this code signifies that the
  ///                                 domain name referenced in the query does
  ///                                 not exist.
  ///
  ///                 4               Not Implemented - The name server does
  ///                                 not support the requested kind of query.
  ///
  ///                 5               Refused - The name server refuses to
  ///                                 perform the specified operation for
  ///                                 policy reasons.  For example, a name
  ///                                 server may not wish to provide the
  ///                                 information to the particular requester,
  ///                                 or a name server may not wish to perform
  ///                                 a particular operation (e.g., zone
  ///                                 transfer) for particular data.
  ///
  ///                 6-15            Reserved for future use.

  bool isResponseCodeFormatError() {
    return getResponseCode() == DNS.FORMAT_ERROR;
  }


  /// RCODE           Response code - this 4 bit field is set as part of
  ///                 responses.  The values have the following
  ///                 interpretation:
  ///
  ///                 0               No error condition
  ///
  ///                 1               Format error - The name server was
  ///                                 unable to interpret the query.
  ///
  ///                 2               Server failure - The name server was
  ///                                 unable to process this query due to a
  ///                                 problem with the name server.
  ///
  ///                 3               Name Error - Meaningful only for
  ///                                 responses from an authoritative name
  ///                                 server, this code signifies that the
  ///                                 domain name referenced in the query does
  ///                                 not exist.
  ///
  ///                 4               Not Implemented - The name server does
  ///                                 not support the requested kind of query.
  ///
  ///                 5               Refused - The name server refuses to
  ///                                 perform the specified operation for
  ///                                 policy reasons.  For example, a name
  ///                                 server may not wish to provide the
  ///                                 information to the particular requester,
  ///                                 or a name server may not wish to perform
  ///                                 a particular operation (e.g., zone
  ///                                 transfer) for particular data.
  ///
  ///                 6-15            Reserved for future use.

  bool isResponseCodeNameError() {
    return getResponseCode() == DNS.NAME_ERROR;
  }

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
  bool isResponseCodeNoError() {
    return getResponseCode() == DNS.NOERROR;
  }

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
  bool isResponseCodeNotImplemented() {
    return getResponseCode() == DNS.NOT_IMPLEMENTED;
  }

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
  bool isResponseCodeRefused() {
    return getResponseCode() == DNS.REFUSED;
  }

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
  bool isResponseCodeServerFalure() {
    return getResponseCode() == DNS.SERVER_ERROR;
  }

  bool isTCP() {
    return !udp;
  }

  /*
TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
	 */
  bool isTruncated() {
    return hdr.getTC();
  }

  bool isUDP() {
    return udp;
  }



  /// RA              Recursion Available - this be is set or cleared in a
  ///                 response, and denotes whether recursive query support is
  ///                 available in the name server.

  void recursiveAvailable(bool b) {
    hdr.setRA(b);
  }


  /// RA              Recursion Available - this be is set or cleared in a
  ///                 response, and denotes whether recursive query support is
  ///                 available in the name server.

  void recursiveAvailableOff() {
    hdr.setRA(false);
  }


  /// RA              Recursion Available - this be is set or cleared in a
  ///                 response, and denotes whether recursive query support is
  ///                 available in the name server.

  void recursiveAvailableOn() {
    hdr.setRA(true);
  }

  /// RD              Recursion Desired - this bit may be set in a query and
  ///                 is copied into the response.  If RD is set, it directs
  ///                 the name server to pursue the query recursively.
  ///                 Recursive query support is optional.


  void recursiveDesired(bool b) {
    hdr.setRD(b);
  }

  /// RD              Recursion Desired - this bit may be set in a query and
  ///                 is copied into the response.  If RD is set, it directs
  ///                 the name server to pursue the query recursively.
  ///                 Recursive query support is optional.

  void recursiveDesiredOff() {
    hdr.setRD(false);
  }


  /// RD              Recursion Desired - this bit may be set in a query and
  ///                 is copied into the response.  If RD is set, it directs
  ///                 the name server to pursue the query recursively.
  ///                 Recursive query support is optional.


  void recursiveDesiredOn() {
    hdr.setRD(true);
  }

  void setAnswer(RR rr) {
    if (ans.isNotEmpty) {
      ans = [];
    }
    addAnswer(rr);
  }

/// Set the values in the header
///
  void setAuthority() {
    hdr.setAA(true);
  }

/// Set the values in the header
///
  void setAuthorityAnswer(bool b) {
    hdr.setAA(b);
  }

/// Set the values in the header
///
  void setAuthorityAnswerOff() {
    hdr.setAA(false);
  }

/// Set the values in the header
///
  void setAuthorityAnswerOn() {
    hdr.setAA(true);
  }

  void setDomain(String dom) {
    domain = dom;
  }

  void setHeader(Header h) {
    hdr = h;
  }

/*
	ID          A 16 bit identifier assigned by the program that
                generates any kind of query.  This identifier is copied
                the corresponding reply and can be used by the requester
                to match up replies to outstanding queries.
	 */
  void setID(int id) {
    hdr.setID(id);
  }

/// Sets the initTime
/// @param initTime The initTime to set
  void setInitTime(int initTime) {
    this.initTime = initTime;
//  Set the same time on all RRs in the message
    setInitTimeForRr(ans);
    setInitTimeForRr(ath);
    setInitTimeForRr(add);
  }

//  Set the init time of the list of RRs to the initTime
//  of this message
  void setInitTimeForRr(List<RR> lst) {
    //RR rr = null;
    for (RR r in lst) {
      r.setInitTime(initTime);
    }
  }


  ///     QR              A one bit field that specifies whether this message is a
  ///     query (0), or a response (1).


  void setMessageType(int t) {
    hdr.setMessageType(t);
  }


  ///     QR              A one bit field that specifies whether this message is a
  /// query (0), or a response (1).


  void setMessageTypeQuery() {
    hdr.setMessageType(DNS.QUERY);
  }


  ///     QR              A one bit field that specifies whether this message is a
  ///     query (0), or a response (1).


  void setMessageTypeResponse() {
    hdr.setMessageType(DNS.RESPONSE);
  }

  ///  OPCODE          A four bit field that specifies kind of query in this
  ///message.  This value is set by the originator of a query
  ///and copied into the response.  The values are:
  ///
  /// 0               a standard query (QUERY)
  /// 1               an inverse query (IQUERY)
  /// 2               a server status request (STATUS)
  /// 3-15            reserved for future use

  void setOpCode(int val) {
    hdr.setOPCODE(val);
  }

  void setPort(int p) {
    port = p;
  }


    ///   Set the type of QUERY (QUERY, IQUERY or STATUS) QUERY is the default

  void setQueryType(int id) {
    hdr.setOPCODE(id);
  }

  void setQuestion(String name, int type, int dnsClass) {
    que = [];
    ans = [];
    ath = [];
    add = [];
    addQuestionFromArgs(name, type, dnsClass);
  }

  void setQuestionFromRr(Section rr) {
    que = [];
    que.add(rr);
  }

/*
RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
	 */
  void setRecursiveAvailable(bool b) {
    recursiveAvailable(b);
  }

/*
RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
	 */
  void setRecursiveAvailableOff() {
    recursiveAvailableOff();
  }

/*
RA              Recursion Available - this be is set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.
	 */
  void setRecursiveAvailableOn() {
    recursiveAvailableOn();
  }

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
  void setResponseCode(int code) {
    hdr.setRCODE(code);
  }

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
  void setResponseCodeFormatError() {
    setResponseCode(DNS.FORMAT_ERROR);
  }

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
  void setResponseCodeNameError() {
    setResponseCode(DNS.NAME_ERROR);
  }

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
  void setResponseCodeNoError() {
    setResponseCode(DNS.NOERROR);
  }

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
  void setResponseCodeNotImplemented() {
    setResponseCode(DNS.NOT_IMPLEMENTED);
  }

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
  void setResponseCodeRefused() {
    setResponseCode(DNS.REFUSED);
  }

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
  void setResponseCodeServerFailure() {
    setResponseCode(DNS.SERVER_ERROR);
  }

  void setRetry(int i) {
    retry = i;
  }

  void setTimeOut(int to) {
    timeOut = to;
  }

/*
TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
	 */
  void setTruncated(bool b) {
    hdr.setTC(b);
  }

/*
TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
	 */
  void setTruncatedOff() {
    hdr.setTC(false);
  }

/*
TC              TrunCation - specifies that this message was truncated
                due to length greater than that permitted on the
                transmission channel.
	 */
  void setTruncatedOn() {
    hdr.setTC(true);
  }

  int size() {
    toByteArray();

    return dataSize;
  }

  void tcpOff() {
    udp = true;
  }

  void tcpOn() {
    udp = false;
  }

  ByteBuffer toByteArray() {
    ByteBuffer rd = ByteBuffer.fromNew();
    hdr.setQDCOUNT(que.length);
    hdr.setANCOUNT(ans.length);
    hdr.setNSCOUNT(ath.length);
    hdr.setARCOUNT(add.length);

    hdr.toByteArray2(rd);

    int cnt = hdr.getQDCOUNT();
    for (int i = 0; i < cnt; i++) {
      Section sec = que[i];
      sec.toByteArray(rd);
    }

    cnt = hdr.getANCOUNT();
    for (int i = 0; i < cnt; i++) {
      RR sec = ans[i];
      sec.toByteArray(rd);
    }

    cnt = hdr.getNSCOUNT();
    for (int i = 0; i < cnt; i++) {
      RR sec = ath[i];
      sec.toByteArray(rd);
    }

    cnt = hdr.getARCOUNT();
    for (int i = 0; i < cnt; i++) {
      RR sec = add[i];
      sec.toByteArray(rd);
    }

    //data =  rd.getByteArray();
    //dataSize = data.length;
    return rd;
  }

  String toSmallString() {
    String ret = "";

    ret += ("Q(");
    for (Section e in getQuestion()) {
      ret += ("{$e}");
    }

    ret += (") A(");
    for (RR r in answer()) {
      ret += ("{$r}");
    }
    ret += (')');

    return ret.toString();
  }

  @override
  String toString() {
    hdr.setQDCOUNT(que.length);
    hdr.setANCOUNT(ans.length);
    hdr.setNSCOUNT(ath.length);
    hdr.setARCOUNT(add.length);

    String ret = "";
    ret += ("Header \n");
    ret += (hdr.toString());
    ret += ('\n');
    ret += ("Qtype = $Qtype");
    if (Qtype < DNS.recordTypeName.length) {
      ret += ("(${DNS.recordTypeName[Qtype]})");
    }
    ret += ('\n');

    ret += ("DnsClass = $DnsClass");
    if (DnsClass < DNS.dnsClassNames.length) {
      ret += ("(${DNS.dnsClassNames[DnsClass]})");
    }
    ret += ('\n');

    ret += ("Question \n");
    for (Section s in getQuestion()) {
      ret += ("\t$s");
      ret += ('\n');
    }
    ret += ("Answer \n");
    for (RR r in getAnswer()) {
      ret += ("\t$r");
      ret += ('\n');
    }

    ret += ("Authority \n");
    for (RR r in authority()) {
      ret += ("\t$r");
      ret += ('\n');
    }
    ret += ("Additional \n");
    for (RR r in getAdditional()) {
      ret += ("\t$r");
      ret += ('\n');
    }

    return ret.toString();
  }

  void truncateOff() {
    hdr.setTC(false);
  }

  ///Is the message truncated due to transport limitation

  void truncateOn() {
    hdr.setTC(true);
  }

  void udpOff() {
    udp = false;
  }

  void udpOn() {
    udp = true;
  }
}
