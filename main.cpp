#include "stdafx.h"

#include "arpspoofer.h"

#include <iostream>

using namespace std;

bool scanning;

void on_scan_finished(){
    scanning = false;
}

int main(int argc, char *argv[]) {
    ArpSpoofer spoofer(on_scan_finished);

    if(argc < 4 || argc % 2 == 1){
        cout << "Usage " << argv[0] << "[interface] [sender ip] [target ip] ...\n";
    }

    spoofer.SetInterface(argv[1]);

    spoofer.Start();

    vector<uint32_t> hosts(argc - 2);

    for (int i = 2; i < argc; i++){
        in_addr ip;

        inet_aton(argv[i], &ip);

        hosts[i - 2] = ip.s_addr;
    }

    scanning = true;
    spoofer.Scan(hosts);

    while(scanning);


    for (int i = 0; i < hosts.size(); i+=2){
        spoofer.AddSpoofRule(hosts[i], hosts[i+1], true, true);
    }

    while(spoofer.IsStarted()){}

    return 0;
}
