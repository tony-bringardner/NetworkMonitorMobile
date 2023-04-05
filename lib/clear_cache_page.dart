import 'dart:async';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:path/path.dart';
import 'package:path_provider/path_provider.dart';
import 'package:flutter/material.dart';

import 'main.dart';


// A screen that allows users to take a picture using a given camera.
class ClearCachePage extends StatefulWidget {
  Map<InternetAddress, UdpClient> clients;
  ClearCachePage(this.clients,{super.key});

  @override
  _ClearCachePageState createState() => _ClearCachePageState();
}

class _ClearCachePageState extends State<ClearCachePage> {
  List< UdpClient> clients=[];
  List<bool> remove = [];

  @override
  void initState() {
    super.initState();
    for(UdpClient c in widget.clients.values) {
      clients.add(c) ;
      remove.add(false);
    }
  }


  @override
  Widget build(BuildContext context) {
    var list = ListView.builder(
      // the number of items in the list
        itemCount: clients.length,

        // display each item of the product list
        itemBuilder: (context, index) {
          return ListTile(

            title: Text(clients[index].name),
            trailing: Checkbox(
              value: remove[index],
              onChanged: (value){
                if(value != null ) {
                  setState(() {
                    remove[index] = value;
                  });
                }
            },
            ),
          );
        });

    return Scaffold(
      appBar: AppBar(title: const Text("Search")),
      body: SingleChildScrollView(
        child: SizedBox(
            child: list,
          height: MediaQuery.of(context).size.height * .8,
        ),
      ),
      bottomNavigationBar: BottomNavigationBar(
        onTap: (value) {
          switch(value) {
            case 0: Navigator.of(context).pop();break;
            case 1:
              Map<InternetAddress, UdpClient> ret ={};
              for(int idx = 0; idx < remove.length; idx++){
                if( !remove[idx]) {
                  ret[clients[idx].address] = clients[idx];
                }
              }
              Navigator.of(context).pop(ret);
              break;
          }
        },
        items: const [
          BottomNavigationBarItem(
            icon: Icon(Icons.cancel_outlined),
            label: 'Cancel',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.save_outlined),
            label: 'Save',
          ),
        ],
      ),
    );
  }


}