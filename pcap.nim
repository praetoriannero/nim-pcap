import algorithm
import os
import std/times
import strformat
import strutils

const
    pcapMagicNum = 0xD4C3B2A1

type
    EndianAwareReader = object
        file: File
        endian: Endianness
#                            1                   2                   3
#        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     0 |                          Magic Number                         |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     4 |          Major Version        |         Minor Version         |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     8 |                           Reserved1                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    12 |                           Reserved2                           |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    16 |                            SnapLen                            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    20 | FCS |f|                   LinkType                            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    FileHeader = object
        magicNumber: array[4, byte]
        majorVersion: uint16
        minorVersion: uint16
        reserved1: uint32
        reserved2: uint32
        snapLen: uint32
        linkType: uint32
#                           1                   2                   3
#       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     0 |                      Timestamp (Seconds)                      |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     4 |            Timestamp (Microseconds or nanoseconds)            |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#     8 |                    Captured Packet Length                     |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    12 |                    Original Packet Length                     |
#       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    16 /                                                               /
#       /                          Packet Data                          /
#       /                        variable length                        /
#       /                                                               /
#       +---------------------------------------------------------------+
    PacketRecord = object
        timestampSeconds: uint32
        timestampFraction: uint32
        capPacketLength: uint32
        ogPacketLength: uint32


proc swapEndian(buffer: ptr) {.inline.} =
    var tempArr: array[sizeof(buffer[]), byte]
    tempArr = cast[array[sizeof(buffer[]), byte]](buffer[])
    tempArr.reverse()
    buffer[] = cast[typeof(buffer[])](tempArr)


proc readBuffer(reader: EndianAwareReader, buffer: ptr, len: Natural): int {.inline, discardable.} =
    result = readBuffer(reader.file, buffer, len)
    if reader.endian != cpuEndian:
        buffer.swapEndian()


iterator readPackets*(pcapPath: string): seq[byte] =
    var 
        f = open(pcapPath, fmRead)
        reader: EndianAwareReader = EndianAwareReader(file: f, endian: cpuEndian)
        fileHeader: FileHeader
        packetRecord: PacketRecord
        packetData: seq[byte]
        bytesRead: int
        padLen: uint32
        byteDump: array[4, byte]

    reader.readBuffer(addr(fileHeader), sizeof(fileHeader))
    
    while true:
        bytesRead = reader.readBuffer(addr(packetRecord), sizeof(packetRecord))
        if bytesRead != sizeof(packetRecord):
            break
        
        packetData.newSeq(packetRecord.capPacketLength)
        reader.readBuffer(addr(packetData[0]), packetRecord.capPacketLength)
        yield packetData


when isMainModule:
    var args = commandLineParams()
    if len(args) != 1:
        var error: ref IOError
        new(error)
        error.msg = "one argument is allowed: file path"
        raise error

    var
        pcapName = args[0]
        totalPackets: int
        elapsedTime: float
        pktsPerSecond: float

    let time = cpuTime()

    for entry in readPackets(pcapName):
        totalPackets += 1

    elapsedTime = cpuTime() - time
    pktsPerSecond = float(totalPackets) / elapsedTime

    echo(&"Completed in {elapsedTime} seconds")
    echo(&"{pktsPerSecond} blocks read per second")
    echo(&"{totalPackets} total packets found")

