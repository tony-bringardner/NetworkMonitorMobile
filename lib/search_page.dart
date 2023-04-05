import 'dart:async';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:path/path.dart';
import 'package:path_provider/path_provider.dart';
import 'package:flutter/material.dart';


// A screen that allows users to take a picture using a given camera.
class SearchScreen extends StatefulWidget {
  InternetAddress localIp;
  SearchScreen(this.localIp,{super.key});

  @override
  SearchScreenState createState() => SearchScreenState();
}

class SearchScreenState extends State<SearchScreen> {
  List<String> data = [];
  String data2 = "";
  StreamController<String> controller = StreamController<String>();
  late StreamSubscription<String> streamSubscription ;

  Future<void> search() async {
    String tmp = "${widget.localIp.rawAddress[0]}.${widget.localIp.rawAddress[1]}.${widget.localIp.rawAddress[2]}";
    controller.add("Enter search");
    for(int idx=80; idx <= 255; idx++ ) {
      if( controller.isClosed) {
        break;
      }

      String url = "http://$tmp.$idx/status";
      controller.add("Searching $url");

      Uri uri = Uri.parse(url);

      var response = await http.get(uri)
          .timeout(Duration(seconds: 2))
          .then((response) {
        //print("value = $response");
        if( response == null) {

        } else {
          controller.add(
              "\t${response.statusCode} len=${response.contentLength}");
          if (response!.contentLength! > 0) controller.add(
              "\t${response.body}");
        }
      }).
      onError((error, stackTrace) {
        //print("error = $error");
        controller.add("\tError :$error");
      }
      )
      ;


    }
    controller.add("Exit search");

  }

  @override
  void dispose() {
    controller.close();
    super.dispose();
  }

  @override
  void initState() {
    super.initState();

    streamSubscription = controller.stream.listen((value) {
      setState(() {
        data.add(value);
        data2+="\n$value";
      });
    });
    search().then((value) => print("search then")).whenComplete(() => print("search complete"));
  }


  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text("Search")),
      body: SingleChildScrollView(
        child: SelectableText(data2),
      ),

    );
  }


}