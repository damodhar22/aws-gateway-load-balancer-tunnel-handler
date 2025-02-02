// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Miscellaneous handy utilities.
 */

#include "utils.h"

#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <cstring>

using namespace std::string_literals;

/**
 * Dump the provided object as a hex-formatted output dump.
 *
 * @param os The output stream to send the hex dump to.
 * @param buffer The pointer to the start of the object to dump. nullptr results in no output and an immediate return.
 * @param bufsize The number of bytes in buffer to output
 * @param showPrintableChars Output alongside the hex dump the ASCII strings (unprintable characters are replaced with a '.')
 * @param prefix Any generic string the prefix each line of output with.
 * @return Returns the output stream back. Side effect: The output stream has had the hex dump pushed into it.
 */
std::ostream& hexDump(std::ostream& os, const void *buffer,
                      std::size_t bufsize, bool showPrintableChars, const std::string& prefix)
{
    if (buffer == nullptr) {
        return os;
    }

    char hexBuf[140];
    char printBuf[36];
    unsigned char *cBuffer = (unsigned char *)buffer;
    std::size_t offset;

    for(offset = 0; offset < bufsize; offset ++)
    {
        if(offset % 32 == 0)
        {
            if(offset > 0) os << prefix << hexBuf << printBuf << std::endl;
            bzero(hexBuf, 140);
            bzero(printBuf, 36);
            if(showPrintableChars) strcpy(printBuf, " | ");
            snprintf(hexBuf, 7, "%04zx: ", offset);
        }
        snprintf(&hexBuf[5+((offset % 32)*3)], 4, " %02x", cBuffer[offset]);
        if(showPrintableChars)
            printBuf[3 + (offset % 32)] = (isprint(cBuffer[offset]))?cBuffer[offset]:'.';
    }
    // Add in enough padding to make sure our lines line up.
    for(offset = 5+((offset % 32) * 3); offset < 101; offset ++) hexBuf[offset] = ' ';
    if(offset > 0) os << prefix << hexBuf << printBuf << std::endl;

    return os;
}

/**
 * Perform a printf-like function, but on a std::string and returning a std::string
 *
 * @param fmt_str printf-like formatting string
 * @param ... Parameters for the fmt_str
 * @return A std::string of the formatted output
 */
std::string stringFormat(const std::string& fmt_str, ...) {
    int final_n, n = ((int)fmt_str.size()) * 2; /* Reserve two times as much as the length of the fmt_str */
    std::unique_ptr<char[]> formatted;
    va_list ap;
    while(true) {
        formatted.reset(new char[n]); /* Wrap the plain char array into the unique_ptr */
        strcpy(&formatted[0], fmt_str.c_str());
        va_start(ap, &fmt_str);
        final_n = vsnprintf(&formatted[0], n, fmt_str.c_str(), ap);
        va_end(ap);
        if (final_n < 0 || final_n >= n)
            n += abs(final_n - n + 1);
        else
            break;
    }
    return std::string(formatted.get());
}


/**
 * Send a UDP packet, with control over the source and destination.
 *
 * @param from_addr IP address to send the packet from.
 * @param from_port UDP source port to use
 * @param to_addr IP address to send the packet to.
 * @param to_port UDP destination port
 * @param pktBuf Payload buffer pointer
 * @param pktLen Payload buffer length
 * @return true if packet was sent successfully, false otherwise.
 */
bool sendUdp(struct in_addr from_addr, uint16_t from_port, struct in_addr to_addr, uint16_t to_port, unsigned char *pktBuf, ssize_t pktLen)
{
    struct sockaddr_in sin, sout;
    int sock;

    if (-1==(sock=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))) return false;
    memset(&sin,0,sizeof(sin));

    sin.sin_family = AF_INET;
    sin.sin_port = htobe16(from_port);
    sin.sin_addr.s_addr = from_addr.s_addr;
    if (-1==bind(sock,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))) {
        close(sock);
        return false;
    }

    sout.sin_family = AF_INET;
    sout.sin_port = htobe16(to_port);
    sout.sin_addr.s_addr = to_addr.s_addr;
    if (-1==sendto(sock, pktBuf, pktLen, 0, (struct sockaddr *)&sout, sizeof(struct sockaddr_in)))
    {
        close(sock);
        return false;
    }

    close(sock);
    return true;
}


const std::string base60 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
/**
 * Convert a 64 bit number to base60 notation. Note: With a uint64_t, the maximum return from this is "uur953OEv0f".
 *
 * @param val The value to convert
 * @return The value represented as base60
 */
std::string toBase60(uint64_t val)
{
    std::string ret;
    while(val >= 60)
    {
        ret.insert(0, 1, base60[val % 60]);
        val = val / 60;
    }
    ret = base60[val] + ret;
    return ret;
}

/**
 * Convert the time between two time_points to a human-readable short form duration.
 *
 * @param t1 The earlier timepoint
 * @param t2 The later timepoint
 * @return Human-readable (hours, minutes, seconds, etc) duration between the two time_points.
 */
std::string timepointDelta(std::chrono::steady_clock::time_point t1, std::chrono::steady_clock::time_point t2)
{
    char tbuf[32];
    long delta = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t2).count();
    std::string ret;

    if (delta > 86400000) { ret += std::to_string((long)delta / 86400000) + "d "s; delta = delta % 86400000; }
    if (delta > 3600000) { ret += std::to_string((long)delta / 3600000) + "h"s; delta = delta % 3600000; }
    if (delta > 60000) { ret += std::to_string((long)delta / 60000) + "m"s; delta = delta % 60000; }
    snprintf(tbuf, 31, "%.3f", float(delta / 1000.0));
    ret += tbuf + "s"s;

    return ret;
}

/**
 * Current time as a string.
 *
 * @return The time, in current locale's format.
 */
std::string currentTime()
{
    struct tm localtm;
    auto timepoint = std::chrono::system_clock::now();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(timepoint.time_since_epoch()).count() % 1000;
    std::time_t cur_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    localtime_r(&cur_time, &localtm);
    std::stringstream ss;
    ss << std::put_time(&localtm, "%F %T") << "."s << std::setw(3) << std::setfill('0') << millis;
    return ss.str();
}

/**
 * Convert a sockaddr to a human-readable value. Supports both IPv4 and IPv6.
 *
 * @param sa The sockaddr structure to parse
 * @return The human-readable IP address the sockaddr represents.
 */
std::string sockaddrToName(struct sockaddr *sa)
{
    char tbuf[256];
    if(sa->sa_family == AF_INET)
        inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, tbuf, 256);
    else if(sa->sa_family == AF_INET6)
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, tbuf, 256);
    else
        strcpy(tbuf, "Unknown address family");

    return std::string(tbuf);
}
