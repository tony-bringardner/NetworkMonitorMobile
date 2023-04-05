/*
RFC 2782                       DNS SRV RR                  February 2000
Service (TB Label / Name)
        The symbolic name of the desired service, as defined in Assigned
        Numbers [STD 2] or locally.  An underscore (_) is prepended to
        the service identifier to avoid collisions with DNS labels that
        occur in nature.

        Some widely used services, notably POP, don't have a single
        universal name.  If Assigned Numbers names the service
        indicated, that name is the only name which is legal for SRV
        lookups.  The Service is case insensitive.

   Proto
     The symbolic name of the desired protocol, with an underscore
        (_) prepended to prevent collisions with DNS labels that occur
        in nature.  _TCP and _UDP are at present the most useful values
        for this field, though any name defined by Assigned Numbers or
        locally may be used (as for Service).  The Proto is case
        insensitive.

   Name
        The domain this RR refers to.  The SRV RR is unique in that the
        name one searches for is not this name; the example near the end
        shows this clearly.

   TTL
        Standard DNS meaning [RFC 1035].

   Class
        Standard DNS meaning [RFC 1035].   SRV records occur in the IN
        Class.

   Priority
        The priority of this target host.  A client MUST attempt to
        contact the target host with the lowest-numbered priority it can
        reach; target hosts with the same priority SHOULD be tried in an
        order defined by the weight field.  The range is 0-65535.  This
        is a 16 bit unsigned integer in network byte order.

   Weight
        A server selection mechanism.  The weight field specifies a
        relative weight for entries with the same priority. Larger
        weights SHOULD be given a proportionately higher probability of
        being selected. The range of this number is 0-65535.  This is a
        16 bit unsigned integer in network byte order.  Domain
        administrators SHOULD use Weight 0 when there isn't any server
        selection to do, to make the RR easier to read for humans (less
        noisy).  In the presence of records containing weights greater
        than 0, records with weight 0 should have a very small chance of
        being selected.

        In the absence of a protocol whose specification calls for the
        use of other weighting information, a client arranges the SRV
        RRs of the same Priority in the order in which target hosts,
        specified by the SRV RRs, will be contacted. The following
        algorithm SHOULD be used to order the SRV RRs of the same
        priority:

        To select a target to be contacted next, arrange all SRV RRs
        (that have not been ordered yet) in any order, except that all
        those with weight 0 are placed at the beginning of the list.

        Compute the sum of the weights of those RRs, and with each RR
        associate the running sum in the selected order. Then choose a
        uniform random number between 0 and the sum computed
        (inclusive), and select the RR whose running sum value is the
        first in the selected order which is greater than or equal to
        the random number selected. The target host specified in the
        selected SRV RR is the next one to be contacted by the client.
        Remove this SRV RR from the set of the unordered SRV RRs and
        apply the described algorithm to the unordered SRV RRs to select
        the next target host.  Continue the ordering process until there
        are no unordered SRV RRs.  This process is repeated for each
        Priority.

   Port
        The port on this target host of this service.  The range is 0-
        65535.  This is a 16 bit unsigned integer in network byte order.
        This is often as specified in Assigned Numbers but need not be.

   Target
        The domain name of the target host.  There MUST be one or more
        address records for this name, the name MUST NOT be an alias (in
        the sense of RFC 1034 or RFC 2181).  Implementors are urged, but
        not required, to return the address record(s) in the Additional
        Data section.  Unless and until permitted by future standards
        action, name compression is not to be used for this field.

        A Target of "." means that the service is decidedly not
        available at this domain.
 */

import 'package:network_monitor/dns/rr.dart';

import 'dart:typed_data';

import 'package:network_monitor/dns/byte_buffer.dart';
import 'package:validators/validators.dart';
import 'message.dart';
import 'name.dart';

List<int> svrBytes = [
  0,
  0,
  0,
  0,
  0,
  1,
  0,
  0,
  0,
  2,
  0,
  2,
  6,
  71,
  97,
  114,
  100,
  101,
  110,
  8,
  95,
  97,
  114,
  100,
  117,
  105,
  110,
  111,
  4,
  95,
  116,
  99,
  112,
  5,
  108,
  111,
  99,
  97,
  108,
  0,
  0,
  255,
  128,
  1,
  8,
  95,
  97,
  114,
  100,
  117,
  105,
  110,
  111,
  4,
  95,
  116,
  99,
  112,
  5,
  108,
  111,
  99,
  97,
  108,
  0,
  0,
  12,
  0,
  1,
  0,
  0,
  17,
  148,
  0,
  28,
  6,
  71,
  97,
  114,
  100,
  101,
  110,
  8,
  95,
  97,
  114,
  100,
  117,
  105,
  110,
  111,
  4,
  95,
  116,
  99,
  112,
  5,
  108,
  111,
  99,
  97,
  108,
  0,
  192,
  75,
  0,
  33,
  0,
  1,
  0,
  0,
  17,
  148,
  0,
  20,
  0,
  0,
  0,
  0,
  32,
  74,
  6,
  71,
  97,
  114,
  100,
  101,
  110,
  5,
  108,
  111,
  99,
  97,
  108,
  0,
  192,
  75,
  0,
  16,
  0,
  1,
  0,
  0,
  17,
  148,
  0,
  68,
  14,
  97,
  117,
  116,
  104,
  95,
  117,
  112,
  108,
  111,
  97,
  100,
  61,
  110,
  111,
  25,
  98,
  111,
  97,
  114,
  100,
  61,
  34,
  80,
  76,
  65,
  84,
  70,
  79,
  82,
  77,
  73,
  79,
  95,
  69,
  83,
  80,
  49,
  50,
  69,
  34,
  13,
  115,
  115,
  104,
  95,
  117,
  112,
  108,
  111,
  97,
  100,
  61,
  110,
  111,
  12,
  116,
  99,
  112,
  95,
  99,
  104,
  101,
  99,
  107,
  61,
  110,
  111,
  192,
  121,
  0,
  1,
  0,
  1,
  0,
  0,
  0,
  120,
  0,
  4,
  192,
  168,
  1,
  233
];

/*
qr=QUERY /** 01 bit == Type of Message (QUERY or RESPONSE) **/
 opcode=0 (QUERY 04 bit == Type of Query (QUERY, IQUERY or STATUS)
 aa=false tc=false rd=false ra=false
 rcode=0 (NoError)
 qdcount=1 ancount=0 nscount=2 arcount=2
Qtype = 1(A)
DnsClass = 1(IN)
Question  (12->44)
   13-18  20-27   29-32 33-38
	Garden._arduino._tcp.local  ANY CLASS=32769
Answer
Autority
   45-52   54-57  58-63                             76-81  83-90   91-95 97-101
	_arduino._tcp.  local  PTR IN  ttl=4500 rdlen=28  Garden._arduino._tcp.local

	Garden._arduino._tcp.local  SRV IN  ttl=4500 rdlen=20  0 0 8266 Garden.local Garden._arduino._tcp.local
Additional
	Garden._arduino._tcp.local  TXT IN  ttl=4500 rdlen=68
	Garden.local  A IN  ttl=120 rdlen=3

 */
void main() {
  Uint8List data = Uint8List.fromList(svrBytes);

  var inpx = ByteBuffer(data, 0);

  // Just looking for text in the record.
  bool last = false;
  List<int> bufx =  inpx.getInternalBufffer();
  for (int idx1 = 0, sz = bufx.length - 1; idx1 < sz; idx1++) {
    int val = bufx[idx1];
      if(val > 32 ) {
        String s = String.fromCharCode(val);
        if( isAscii(s) && s.trim().isNotEmpty) {
          if( !last ) {
            int cnt = bufx[idx1-1];
            if( cnt <=0 || (cnt+idx1) > sz) {
              continue;
            }
            print("\tidx=${idx1-1}  cnt=$cnt");
          }
          print("idx=$idx1 '$s' ");
          last = true;
        } else {
          last = false;
        }
      } else {
        last = false;
      }
  }

  Message m = Message.fromByteBuffer(inpx);
  print(m.toString());

}


class Srv extends RR {
  int weight = 0;
  int priority = 0;
  int port = 0;
  Name target = Name();
  Name service = Name();
  Name protocol = Name();

  Srv.fromRR(RR rr) : super.fromRR(rr) {
    setFromRdata();
  }

  @override
  String toString() {
    return "${super.toString()} $weight $priority $port ${target.toString()} ${service.toString()} ${protocol.toString()}";
  }

  @override
  void setFromRdata() {
    List<int> bytes = getRdata();
    Uint8List data = Uint8List.fromList(bytes);

    var inp = ByteBuffer(data, 0);
    //print("1.. buf len= ${inp.buf.length}  location=${inp.getReadPos()} ");
    if (source != null) {
      inp = ByteBuffer.fromSouce(source!, sourcePos);
    }
    //102 - 129 is binary
    //print("buf len= ${inp.buf.length} sourceP=${sourcePos} location=${inp.getReadPos()} source pos=${source!.getReadPos()}");

    //The range is 0-65535
    priority = inp.nextShort();
    //print("priority = $priority start=${startPos} pos=${inp.readPos}");
    weight = inp.nextShort();
    //print("weight = $weight start=${startPos} pos=${inp.readPos}");
    //The range is 0-65535
    port = inp.nextShort();
    //print("port = $port start=${startPos} pos=${inp.readPos}");

    target = Name.fromByteBuffer(inp); //121-135
    //print("target = ${target.toString()} start=${startPos} pos=${inp.readPos}");
    service = Name.fromByteBuffer(inp);
    //print("service = ${service.toString()} start=${startPos} pos=${inp.readPos}");
    protocol = Name.fromByteBuffer(inp);
    //print("proto = ${protocol.toString()} start=${startPos} pos=${inp.readPos}");



  }
}
