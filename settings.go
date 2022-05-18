package main

const debugFlag = true
const buffSize = 65536
const quicPort = 4242
const udpPort = 9997
const udpClientPort = 9998
const udpServerPort = 9999
const clientCacheCapacity = 10

// http://www.kegel.com/c10k.html
// https://stackoverflow.com/questions/1319965/how-many-requests-per-minute-are-considered-heavy-load-approximation
// LPS - Low-pass filter
const threshold = 5
const alpha = 0.5
const windowSize = 10
