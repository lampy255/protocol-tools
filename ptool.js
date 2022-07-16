//Imports
const PCAPNGParser = require('pcap-ng-parser');
const pcapNgParser = new PCAPNGParser();
const createCsvWriter = require('csv-writer').createObjectCsvWriter;

//Global Vars
var filterIP = null;

//Help Info if -help arg
if (process.argv.includes("-help")) {
    console.log("")
    console.log("Protocol Tools v1.0.0");
    console.log("Help Information:");
    console.log("")
    console.log("Options:")
    console.log("-help: Displays Help Information")
    console.log("-f {ip}: Filter packets by IP address")
    console.log("")
    console.log("Command Example:")
    console.log("node ptool.js capture.pcapng")
    console.log("")
}

if (process.argv.length > 2) {
    if (process.argv[2].includes(".pcapng")) {
        if (process.argv.includes('-f')) {
            let index = process.argv.indexOf('-f');
            filterIP = process.argv[index + 1] || null;
        }
        processFile(process.argv[2]);
    } else {
        if (process.argv.includes("-help")) {
            
        } else {
            console.log("Error: File is not of type .pcapng");
        }
    }
} else {
    console.log("Please pass an option. eg: node ptool.js -help");
}



function processFile(file) {
    let packetArray = [];
    const myFileStream = require('fs').createReadStream(file);
    myFileStream.pipe(pcapNgParser)
        .on('data', parsedPacket => {
            if (parsedPacket.data[23] == '17') { //If Protocol is UDP
                let srcIP = (parsedPacket.data[26] + "." + parsedPacket.data[27] + "." + parsedPacket.data[28] + "." + parsedPacket.data[29]);
                let dstIP = (parsedPacket.data[30] + "." + parsedPacket.data[31] + "." + parsedPacket.data[32] + "." + parsedPacket.data[33]);
                let time = (parsedPacket.timestampHigh * 0x100000000 + parsedPacket.timestampLow);
                let timeobj = new Date(time / 1000);
                let timestamp = timeobj.toLocaleTimeString() + ":" + timeobj.getMilliseconds();
                let length = (parsedPacket.data.readUInt16BE(38));
                let endIndex = ((length - 8) + 42);
                //console.log(length)
                if (filterIP !== null) {
                    if (srcIP === filterIP || dstIP === filterIP) {
                        let packet = {
                            timestamp,
                            srcIP,
                            dstIP,
                            ascii: safeAscii((parsedPacket.data.slice(42, endIndex).toString('ascii'))),
                            hex: parsedPacket.data.slice(42, endIndex).toString('hex'),
                            base64: parsedPacket.data.slice(42, endIndex).toString('base64'),
                            decimal: decimalArray(parsedPacket.data.slice(42, endIndex))
                        }
                        packetArray.push(packet);
                    }
                } else {
                    let packet = {
                        timestamp,
                        srcIP,
                        dstIP,
                        ascii: safeAscii((parsedPacket.data.slice(42, endIndex).toString('ascii'))),
                        hex: parsedPacket.data.slice(42, endIndex).toString('hex'),
                        base64: parsedPacket.data.slice(42, endIndex).toString('base64'),
                        decimal: decimalArray(parsedPacket.data.slice(42, endIndex))
                    }
                    packetArray.push(packet);
                }
            }
        })
        .on('close', () => {
            writeCSV(packetArray)
        })
}

function decimalArray(data) {
    let array = [];
    for (let pair of data.entries()) {
        array.push(pair[1])
    }
      return array.join(" ")
}

function safeAscii(data) {
    let string = data;
    //string = string.replace(',', '');
    string = string.replace(/[\u0000-\u001F\u007F-\u009F]/g, "");
    return string
}

function writeCSV(array) {
    const csvWriter = createCsvWriter({
        path: 'packets.csv',
        header: [
          {id: 'timestamp', title: 'Timestamp'},
          {id: 'srcIP', title: 'Src'},
          {id: 'dstIP', title: 'Dst'},
          {id: 'hex', title: 'Hex'},
          {id: 'ascii', title: 'ASCII'},
          {id: 'decimal', title: 'Decimal'},
          {id: 'base64', title: 'Base64'}
        ]
      });

csvWriter
  .writeRecords(array)
  .then(()=> console.log('Sucess! See "packets.csv" file'));
}