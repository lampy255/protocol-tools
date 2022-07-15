# Protocol Tools
Simple Utility for analysing packet capture files

## Description
When reverse engineering network protocols this tool might come in handy.

Protocol Tools takes a packet capture in the form of .pcapng and outputs a .csv file.

The csv file is a filtered output of the packet capture, with the payload of each packet displayed as ascii, hex, decimal in each column of the csv.

Packets can also be filtered by source/dest IP address.


## Usage
- Clone Repo
- "npm i"
- Command example: "node ptool.js capture.pcapng"
