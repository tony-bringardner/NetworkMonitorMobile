import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:network_monitor/clear_cache_page.dart';
import 'package:network_monitor/dns/byte_buffer.dart';
import 'package:network_monitor/dns/message.dart';
import 'package:network_monitor/search_page.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:udp/udp.dart';
import 'package:url_launcher/url_launcher_string.dart';

import 'dns/dns.dart';
import 'dns/rr.dart';
import 'dns/srv.dart';

void main() {
  runApp(const MyApp());
}

class UdpClient {
  String name = "";
  late InternetAddress address;
  String _data = "";
  int _maxLines = 200;
  final List<String> _lines = [];
  String lineTerminator = "\n";
  bool showTimeStamp = false;

  UdpClient(this.name, this.address, maxLines);

  set maxLines(int mx) {
    if (mx < 0) {
      mx = 0;
    }

    _maxLines = mx;

    if (_lines.length > _maxLines) {
      while (_lines.length > _maxLines) {
        _lines.removeAt(0);
      }
      _data = "";
      int idx = 0;
      for (String l in _lines) {
        _data += "${++idx}: $l\n";
      }
    }
  }

  void clear() {
    _data = "";
    _lines.clear();
  }

  void append(String line) {
    for (String l in line.split("\n")) {
      if (showTimeStamp) {
        var now = DateTime.now();
        l = "${now.month}/${now.day}/${now.year} ${now.hour}: ${now.minute} $l";
      }
      _append(l);
    }
  }

  void _append(String line) {
    _lines.add(line);
    _data += "$line\n";
    if (_lines.length > _maxLines) {
      while (_lines.length > _maxLines) {
        _lines.removeAt(0);
      }
      _data = "";

      for (String l in _lines) {
        _data += "$l\n";
      }
    }
  }

  String get data {
    return _data;
  }
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Flutter Demo',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: const MyHomePage(title: 'Flutter Demo Home Page'),
    );
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});

  final String title;

  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  GlobalKey<ScaffoldState> scaffoldKey = GlobalKey();
  var adminIp = InternetAddress("224.0.0.252");
  int adminPort = 60000;
  InternetAddress localIp = InternetAddress.loopbackIPv4;
  int monitorPort = 6000;

  int maxLines = 200;
  Map<InternetAddress, UdpClient> clients = {};
  UdpClient? selectedClient;
  TextEditingController commandController = TextEditingController(text: "status");
  TextEditingController maxLinesController = TextEditingController();
  late UDP receiver;
  late  SharedPreferences prefs;
  void _incrementCounter() {
    setState(() {});
  }

  Future<InternetAddress> _retrieveIPAddress() async {
    InternetAddress ret = InternetAddress.loopbackIPv4;
    for (var interface in await NetworkInterface.list()) {
      for (InternetAddress addr in interface.addresses) {
        if (!addr.isLoopback && addr.type == InternetAddressType.IPv4) {
          ret = addr;
        }
        //print('${addr.address} ${addr.host} ${addr.isLoopback} ${addr.rawAddress} ${addr.type.name}');
      }
    }
    return ret;
  }

  void _processInput(Datagram? datagram) {
    if (datagram != null) {
      var str = String.fromCharCodes(datagram.data).trim();
      UdpClient? client = clients[datagram.address];

      if (client == null) {
        client = UdpClient(datagram.address.host, datagram.address, maxLines);
        clients[client.address] = client;
      }

      client.append(str);
      setState(() {});
    }
  }
//37.83
  Future<void> reStartUdp(int port, int port2, String ip) async {
    if (port != monitorPort) {
      monitorPort = port;
      receiver.close();
      receiver = await UDP.bind(Endpoint.any(port: Port(monitorPort)));

      receiver.asStream().listen((datagram) => _processInput(datagram));
    }

    if (port2 != adminPort || ip != adminIp.address) {
      adminIp = InternetAddress(ip);
      adminPort = port2;
      ping();
    }
  }

  Future<void> startUdp() async {
    localIp = await _retrieveIPAddress();
    print("I am ${localIp.address}");
    prefs = await SharedPreferences.getInstance();
    String? tmp = prefs.getString("clients1");
    if (tmp != null && tmp.isNotEmpty) {
      for (String pair in tmp.split("^")) {
        List<String> parts = pair.split("~");
        if (parts.length == 2) {
          String ip = parts[1]
              .substring(parts[1].indexOf("'") + 1, parts[1].lastIndexOf("'"));

          var address = InternetAddress(ip);

          UdpClient c = UdpClient(parts[0], address, maxLines);
          clients[c.address] = c;
        }
      }
    }

    receiver = await UDP.bind(Endpoint.any(port: Port(monitorPort)));

    receiver.asStream().listen((datagram) => _processInput(datagram));

    final socket = await RawDatagramSocket.bind('224.0.0.251', 5353);
    var group = InternetAddress("224.0.0.251");

    socket.joinMulticast(group);
    socket.multicastHops = 10;
    socket.broadcastEnabled = true;
    socket.writeEventsEnabled = true;

    socket.listen((RawSocketEvent event) {
      if (event == RawSocketEvent.read) {
        final datagramPacket = socket.receive();
        if (datagramPacket == null) {
          return;
        }
        Message msg =
            Message.fromByteBuffer(ByteBuffer(datagramPacket.data, 0));

        for (RR rrr in msg.answer()) {
          if (rrr.runtimeType == Ptr) {
            Ptr p = rrr as Ptr;
            String name = p.getName();
            //print("mdns ${p.name}");
            if (name == "_arduino._tcp.local") {
              //print("mdns process ${msg.toString()}");
              for (RR r in msg.findType(DNS.SRV)) {
                if (r.runtimeType == Srv) {
                  Srv svr = r as Srv;
                  //print("svr=${svr.target} ip=${datagramPacket.address}");

                  String name = svr.target.toString();
                  if (name.endsWith(".local")) {
                    name = name.substring(0, name.lastIndexOf(".local"));
                  }
                  name +=
                      " (${datagramPacket.address.rawAddress[3].toString()})";
                  //print("Set name $name");
                  UdpClient? client;
                  for (UdpClient c in clients.values) {
                    if (c.address == datagramPacket.address) {
                      client = c;
                      break;
                    }
                  }

                  if (client == null) {
                    client = UdpClient(name, datagramPacket.address, maxLines);
                    clients[client.address] = client;
                  } else {
                    client.name = name;
                  }
                  setState(() {});
                 savePref();
                }
              }
            }
          }
        }
        _incrementCounter();
      }
    });
    ping();
  }

  setMaxLines(int max) {
    maxLines = max;
    if (max < 0) {
      maxLines = 0;
    }
    for (UdpClient client in clients.values) {
      client.maxLines = maxLines;
    }
    maxLinesController.text = maxLines.toString();
  }

  @override
  void initState() {
    super.initState();

    startUdp();
    maxLinesController.text = maxLines.toString();
    maxLinesController.addListener(() {
      setState(() {
        setMaxLines(int.parse(maxLinesController.text));
      });
    });
  }

  @override
  Widget build(BuildContext context) {
    if (selectedClient == null && clients.isNotEmpty) {
      selectedClient = clients.entries.first.value;
    }

    var textStyle = const TextStyle();

    List<DropdownMenuItem<String>> getDropdownLineTerminator() {
      List<DropdownMenuItem<String>> menuItems = [];

      var w = const DropdownMenuItem(
        value: "",
        child: Text("No Line ending"),
      );
      menuItems.add(w);
      w = const DropdownMenuItem(
        value: "\n",
        child: Text("New Line"),
      );
      menuItems.add(w);

      w = const DropdownMenuItem(
        value: "\r",
        child: Text("Carriage return"),
      );
      menuItems.add(w);

      w = const DropdownMenuItem(
        value: "\r\n",
        child: Text("Both NL & CR"),
      );
      menuItems.add(w);

      return menuItems;
    }

    final drawer2 = Drawer(
      child: ListView(
        // Important: Remove any padding from the ListView.
        padding: EdgeInsets.zero,
        children: <Widget>[
          const SizedBox(
            height: 40,
          ),
          Row(
            children: [
              const Text("Line Ending: "),
              DropdownButton(
                value: selectedClient?.lineTerminator,
                items: getDropdownLineTerminator(),
                onChanged: (String? value) {
                  setState(() {
                    selectedClient?.lineTerminator = value!;
                  });
                  Navigator.of(context).pop(true);
                },
              ),
            ],
          ),
          Row(
            children: [
              const Text("Show timestamp"),
              Checkbox(
                value: selectedClient == null
                    ? false
                    : selectedClient?.showTimeStamp,
                onChanged: (bool? value) {
                  setState(() {
                    selectedClient?.showTimeStamp = value!;
                  });
                  Navigator.of(context).pop(true);
                },
              ),
            ],
          ),
          ListTile(
            title: Text(
              'Open',
              style: textStyle,
            ),
            onTap: () {
              Navigator.of(context).pop(true);
              open();
            },
          ),
          ListTile(
            title: Text(
              'Ping',
              style: textStyle,
            ),
            onTap: () {
              Navigator.of(context).pop(true);
              ping();
            },
          ),
          ListTile(
            title: Text(
              'Acquire',
              style: textStyle,
            ),
            onTap: () {
              Navigator.of(context).pop(true);
              acquire();
            },
          ),
          ListTile(
            title: Text(
              'Clear All',
              style: textStyle,
            ),
            onTap: () {
              Navigator.of(context).pop(true);
              clearAll();
            },
          ),
          ListTile(
            title: const Text("Search"),
            onTap: (){
              Navigator.of(context).pop();
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (context) => SearchScreen(
                    localIp
                  ),
                ),
              );
            },
          ),
          ListTile(
            title: const Text("Manage Cache"),
            onTap: (){
              Navigator.of(context).pop();
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (context) => ClearCachePage(clients),
                ),
              ).then((value) {
                clients = value;
                if( selectedClient != null ) {
                  if( !clients.containsKey(selectedClient?.address)) {

                    selectedClient = null;
                  }
                }
                savePref();
                setState(() {

                });
              });
            },
          ),
          ListTile(
            title: const Text("Settings"),
            onTap: () {
              showDialog(
                  context: context,
                  builder: (BuildContext context) {
                    TextEditingController controller =
                        TextEditingController(text: "$monitorPort");
                    TextEditingController adminController =
                        TextEditingController(text: "$adminPort");
                    TextEditingController adminIpController =
                        TextEditingController(text: adminIp.address);
                    return AlertDialog(
                      scrollable: true,
                      title: const Text('Settings'),
                      content: Padding(
                        padding: const EdgeInsets.all(8.0),
                        child: Form(
                          child: Column(
                            children: <Widget>[
                              TextFormField(
                                decoration: const InputDecoration(
                                  labelText: 'Monitor Port',
                                  icon: Icon(Icons.account_box),
                                ),
                                controller: controller,
                              ),
                              TextFormField(
                                decoration: const InputDecoration(
                                  labelText: 'Admin Port',
                                  icon: Icon(Icons.account_box),
                                ),
                                controller: adminController,
                              ),
                              TextFormField(
                                decoration: const InputDecoration(
                                  labelText: 'Admin Address',
                                  icon: Icon(Icons.account_box),
                                ),
                                controller: adminIpController,
                              ),
                              Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  IconButton(
                                    icon: const Icon(Icons.save_alt_outlined),
                                    onPressed: () {
                                      int port = int.parse(controller.text);
                                      int port2 =
                                          int.parse(adminController.text);
                                      reStartUdp(
                                          port, port2, adminIpController.text);
                                      Navigator.pop(context);
                                      Navigator.pop(context);
                                    },
                                  ),
                                  IconButton(
                                    icon: const Icon(Icons.cancel_outlined),
                                    onPressed: () {
                                      Navigator.pop(context);
                                      Navigator.pop(context);
                                    },
                                  ),
                                ],
                              ),
                            ],
                          ),
                        ),
                      ),
                    );
                  });
            },
          ),
        ],
      ),
    );

    List<DropdownMenuItem<String>> getDropdownItems() {
      List<DropdownMenuItem<String>> menuItems = [];

      clients.forEach((key, value) {
        UdpClient client = value;
        var w = DropdownMenuItem(
          value: client.name,
          child: Text(client.name),
        );
        menuItems.add(w);
      });

      return menuItems;
    }

    return Scaffold(
      key: scaffoldKey,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.menu),
          onPressed: () => scaffoldKey.currentState?.openDrawer(),
        ),
        title: Text("(${localIp.address})"),
      ),
      drawer: drawer2,
      body: Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: <Widget>[
            DropdownButton(
              value: selectedClient?.name,
              items: getDropdownItems(),
              onChanged: (Object? value) {
                setState(() {
                  for (UdpClient c in clients.values) {
                    if (c.name == value) {
                      setState(() {
                        selectedClient = c;
                      });
                    }
                  }
                });
              },
            ),
            Row(
              children: [
                SizedBox(
                  width: MediaQuery.of(context).size.width-80,
                  child: TextFormField(
                    decoration: InputDecoration(
                      contentPadding: const EdgeInsets.symmetric(
                          vertical: 15.0, horizontal: 10.0),
                      border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10.0)),
                      labelText: "Command",
                    ),
                    controller: commandController,
                  ),
                ),

              ],
            ),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                SizedBox(
                  width: 90,
                  child: TextButton(
                    style: TextButton.styleFrom(
                      textStyle: const TextStyle(fontSize: 20),
                    ),
                    onPressed: () {
                      sendCommand(commandController.text);
                    },
                    child: const Text('Send'),
                  ),
                ),
                TextButton(
                  style: TextButton.styleFrom(
                    textStyle: const TextStyle(fontSize: 20),
                  ),
                  onPressed: () {
                    if (selectedClient != null) {
                      setState(() {
                        selectedClient!.clear();
                      });
                    }
                  },
                  child: const Text('Clear'),
                ),

                Row(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    IconButton(
                      icon: const Icon(Icons.remove),
                      onPressed: () {
                        setState(() {
                          setMaxLines(maxLines - 10);
                        });
                      },
                    ),
                    SizedBox(
                      width: 60,
                      child: TextFormField(
                          enabled: false,
                          controller: maxLinesController,
                          keyboardType: TextInputType.number,
                          inputFormatters: <TextInputFormatter>[
                            // for below version 2 use this
                            FilteringTextInputFormatter.digitsOnly
                          ],
                          decoration: const InputDecoration(
                            labelText: "Max Lines",
                            hintText: "Max Lines",
                          )),
                    ),
                    IconButton(
                      icon: const Icon(Icons.add),
                      onPressed: () {
                        setState(() {
                          setMaxLines(maxLines + 10);
                        });
                      },
                    ),
                  ],
                ),
              ],
            ),
            Expanded(
              flex: 1,
              child: SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: SingleChildScrollView(
                  scrollDirection: Axis.vertical,
                  child: selectedClient == null
                      ? const Text('')
                      : SelectableText(
                          selectedClient!.data,
                          maxLines: 200,
                        ),
                ),
              ),
            ),
          ],
        ),
      ),

      floatingActionButton: FloatingActionButton(
        onPressed: _incrementCounter,
        tooltip: 'Increment',
        child: const Icon(Icons.add),
      ), // This trailing comma makes auto-formatting nicer for build methods.
    );
  }

  Future<void> search() async {
    String base =
        localIp.address.substring(0, localIp.address.lastIndexOf(".") + 1);
    int me = localIp.rawAddress[3];

    for (int ip = 2; ip < 255; ip++) {
      if (ip == me) {
        continue;
      }
      await receiver.send(
          "status\n".codeUnits,
          Endpoint.unicast(InternetAddress("$base$ip"),
              port: Port(monitorPort)));
    }
  }

  void open() {
    if (selectedClient != null) {
      launchUrlString(
        "http://${selectedClient?.address.host}/",
      ).then((value) {
        print("launched value=$value");
      }).onError((error, stackTrace) {
        print("error =$error");
      });
    }
  }

  void ping() {
    var endPoint = Endpoint.multicast(adminIp, port: Port(adminPort));
    String host = localIp.address;
    String cmd = "ping $host $monitorPort";
    UDP.bind(endPoint).then((socket) async {
      await socket.send(cmd.codeUnits, endPoint);
    });
  }

  void acquire() {
    var endPoint = Endpoint.multicast(adminIp, port: Port(adminPort));
    String host = localIp.address;
    String? target = selectedClient?.address.address;

    String cmd = "acquire $host $monitorPort $target";
    print("Sending ping=$cmd");
    UDP.bind(endPoint).then((socket) {
      socket
          .send(cmd.codeUnits, endPoint)
          .then((cnt) => print("after ping cnt=$cnt"));
    });
  }

  void clear() {
    if (selectedClient != null) {
      setState(() {
        selectedClient?.clear();
      });
    }
  }

  void clearAll() {
    for (UdpClient client in clients.values) {
      client.clear();
    }
    setState(() {});
  }

  void sendCommand(String text) {
    if (text.isNotEmpty && selectedClient != null) {
      selectedClient?.append("->$text");
      receiver
          .send(
              "$text${selectedClient?.lineTerminator}".codeUnits,
              Endpoint.unicast(selectedClient?.address,
                  port: Port(monitorPort)))
          .then((cnt) {
        setState(() {
          //print("cnt=$cnt $text  ${selectedClient?.address.toString()} $monitorPort");
        });
      });
      //.onError((error, stackTrace) => print("error=$error"));
    }
  }

  void savePref() {
    //  save to prefs
    String buf = "";
    for (UdpClient c in clients.values) {
      if (buf.isNotEmpty) {
        buf += "^";
      }
      buf += "${c.name}~${c.address.toString()}";
    }
    prefs.setString("clients1", buf);
  }
}
