
import 'package:network_monitor/dns/utility.dart';

import 'byte_buffer.dart';
import 'dns.dart';
import 'label.dart';


///     A Name is made up of a series of labels
///     Each label is a size followed by ascii bytes
///     terminated with a null size
 
class Name implements DNS {
   int chrCount = 0;
   List<Label> myLabels = [];
   bool doWildCard = true;
   bool hasWildCard = false;

   Name () ;
   
  Name.fromString(String name) {
    setNameFromString(name);
  }


  Name.fromName(Name name) {

    for(int i=0,sz=name.myLabels.length; i< sz; i++  ) {
      addLabel(Label(name.myLabels[i].toString()));
    }
  }

   void addLabel(Label label){
    myLabels.add(label);
    if( label.isWildCard ) {
      hasWildCard = true;
    }
  }

  List<Label> getLabels() {
    return myLabels;
  }

  String getParent() {
    String buf = "";
    if( myLabels.length > 1 ) {
      buf+=(myLabels[1].toString());
      for(int i=2,sz=myLabels.length; i< sz; i++ ) {
        buf+=(".${myLabels[i]}");
      }
    }
    return buf.toString();
  }

  Name getParentName() {
    Name parent = Name();

    if( myLabels.isNotEmpty ) {
      for(int i=1,sz=myLabels.length; i< sz; i++ ) {
        parent.myLabels.add(myLabels[i]);
      }
    }
    return parent;
  }

   void init(ByteBuffer inPut) {
     myLabels = [];
      chrCount = 0;

      var in2 = inPut.chkPointer();
      int cnt = in2.next();
      while(cnt > 0 ) {
        chrCount += cnt;
        String sb = "";

        for(int i=0; i< cnt ; i++) {
          try {
            sb += String.fromCharCode(in2.next());
          } catch(e) {
            break;
          }
        }

        addLabel( Label(sb.toString()));
        in2 = in2.chkPointer();
        try {
          cnt = in2.next();
        }catch(e) {
          cnt = 0;
        }
      }
  }

  int matchCountSring(String str) {
    return matchCount( Name.fromString(str) ) ;
  }

  
  ///  Compare two Labels and determine the number of matching myLabels from the root.
  int matchCount(Name other) {
    int ret = 0;
    int me=myLabels.length-1;
    int you = other.myLabels.length-1;
    while( you>=0 && me >=0 ) {
      if( (myLabels[me]) == (other.myLabels[you]) ) {
        ret++;
        me--;
        you--;
      } else {
        break;
      }
    }

    return ret;
  }


   /// Replace any wild card labels in this name with non wild card labels from the other name

  void replaceWildCards(Name other) {
    //int ret = 0;
    int me=myLabels.length-1;
    int you = other.myLabels.length-1;
    while( you>=0 && me >=0 ) {
      Label mine = myLabels[me];
      if( mine.isWildCard ) {
        Label yours = other.myLabels[you];
        myLabels[me] = yours;
      }
      me--;
      you--;
    }
  }

  void setDoWildCard(bool newDoWildCard) {
    doWildCard = newDoWildCard;
  }

  int setName(List<int> buf, int start) {
  myLabels = [];
  chrCount = 0;

  int idx = start;
  int cnt = buf[idx++];

  while(cnt > 0 ) {
  chrCount += cnt;
  String sb = "";
  for(int i=0; i< cnt; i++) {
    sb+=(String.fromCharCode(buf[idx++]));
  }
  addLabel(Label(sb.toString()));
  cnt = buf[idx++];
  }
  return (idx - start);

  }

  void setNameFromString(String n) {
    myLabels = [];
    chrCount = 0;
    String tmp = "";
    if( n.endsWith(".") ) {
      n = n.substring(0,n.length-1);
    }

    int idx = n.indexOf(".");

    while(idx > 0 && idx < n.length) {
      tmp = n.substring(0,idx);
      chrCount += tmp.length;
      n = n.substring(idx+1);
      addLabel( Label(tmp));
      idx = n.indexOf(".");
    }

    addLabel( Label(n));
    chrCount += n.length;

    /*
		  If the name is in %d.%d.%d.%d form, make it an 
		  arpa addres by reversing and appending in-addr.arpa
		  caller should also set the question type to PTR.
		 See RFC-1034 (5.2.1 bullet #2)
		 */

    if( n.isNotEmpty && Utility.isDigit(n[0]) && myLabels.length==4 ) {
      List<Label> tmp1 = [];
      for(int i=3; i>=0; i--) {
        tmp1.add(myLabels[i]);
      }
      tmp1.add( Label("in-addr"));
      tmp1.add( Label("arpa"));
      myLabels = tmp1;
      hasWildCard = false;
      chrCount+= 11;
    }

  }

  int size() {
    return chrCount+myLabels.length+1;
  }

  List<int> toByteArray() {
    List<int> ret = [];
    String tmp="";
    int idx = 0;

    for(int i=0,sz=myLabels.length; i<sz; i++ ) {
      tmp = myLabels[i].toString();
      ret[idx++] = tmp.length;
      for(int ii = 0; ii < tmp.length; ii++) {
        ret[idx++] = tmp.codeUnitAt(ii);
      }
    }

    ret[idx] = 0;
    return ret;

  }


   ///   Convert to String form l1.l2[.ln]
  @override
  String toString() {
    String buf = "";
    if( myLabels.isNotEmpty ) {
      buf+=(myLabels[0].toString());
      for(int i=1,sz=myLabels.length; i< sz; i++ ) {
        buf+=(".${myLabels[i]}");
      }
    }
    return buf.toString();
  }

  Name.fromByteBuffer(ByteBuffer inme) {
     init(inme);
  }

}
