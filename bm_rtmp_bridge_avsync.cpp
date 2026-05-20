#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    typedef SOCKET socket_t;
    #define INVALID_SOCK INVALID_SOCKET
    #define close_socket closesocket
    #define sock_error WSAGetLastError()
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>
    typedef int socket_t;
    #define INVALID_SOCK (-1)
    #define close_socket close
    #define sock_error errno
#endif

#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <memory>
#include <unordered_map>
#include <deque>
#include <condition_variable>
#include <deque>
#include <condition_variable>

//  Config 
static constexpr int    RTMP_PORT       = 1935;
static constexpr int    RTMP_CHUNK_SIZE = 4096;

//  Logging 
static std::mutex g_log_mtx;
static std::string ts() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm_buf, "%H:%M:%S");
    return ss.str();
}
#define LOG(m) do { std::lock_guard<std::mutex> _l(g_log_mtx); std::cout << "[" << ts() << "] " << m << "\n" << std::flush; } while(0)
#define ERR(m) do { std::lock_guard<std::mutex> _l(g_log_mtx); std::cout << "[" << ts() << "] ERR " << m << "\n" << std::flush; } while(0)

//  Socket helpers 
static bool send_all(socket_t s, const uint8_t* d, size_t l) {
    size_t sent = 0;
    while (sent < l) {
        int r = ::send(s, reinterpret_cast<const char*>(d+sent), (int)(l-sent), 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}
static bool recv_all(socket_t s, uint8_t* d, size_t l) {
    size_t got = 0;
    while (got < l) {
        int r = ::recv(s, reinterpret_cast<char*>(d+got), (int)(l-got), 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

//  RTMP Handshake 
static bool do_handshake(socket_t s) {
    uint8_t c0 = 0;
    if (!recv_all(s, &c0, 1)) return false;
    uint8_t s0 = 3;
    if (!send_all(s, &s0, 1)) return false;

    std::vector<uint8_t> c1(1536), s1(1536, 0);
    if (!recv_all(s, c1.data(), 1536)) return false;
    for (size_t i = 8; i < 1536; i++) s1[i] = rand() & 0xFF;
    if (!send_all(s, s1.data(), 1536)) return false;  // S1
    if (!send_all(s, c1.data(), 1536)) return false;  // S2 = echo C1

    std::vector<uint8_t> c2(1536);
    if (!recv_all(s, c2.data(), 1536)) return false;  // C2 (ignore)
    return true;
}

//  RTMP Chunk 
struct Chunk {
    uint8_t  fmt=0; uint32_t cs_id=0;
    uint32_t ts=0;  uint32_t msg_len=0;
    uint8_t  type=0; uint32_t sid=0;
    uint32_t delta=0;
};

// Signature
static bool read_chunk_hdr(socket_t s, Chunk& ch, uint32_t& chunk_size,
                            std::vector<std::pair<uint32_t,Chunk>>& prev,
                            std::unordered_map<uint32_t,std::vector<uint8_t>>& parts) {
    uint8_t b0=0;
    if (!recv_all(s,&b0,1)) return false;
    ch.fmt   = (b0>>6)&3;
    uint32_t csid = b0&0x3F;
    if (csid==0) { uint8_t b; if(!recv_all(s,&b,1)) return false; csid=b+64; }
    else if (csid==1) { uint8_t b[2]; if(!recv_all(s,b,2)) return false; csid=(b[1]<<8)|b[0]; csid+=64; }
    ch.cs_id = csid;

    Chunk* p = nullptr;
    for (auto& x : prev) if (x.first==csid) { p=&x.second; break; }

    auto rd3 = [&](uint32_t &v) {
        uint8_t b[3]; if(!recv_all(s,b,3)) return false;
        v=(b[0]<<16)|(b[1]<<8)|b[2]; return true;
    };
    auto ext_ts = [&](uint32_t &v) {
        if (v==0xFFFFFF) { uint8_t b[4]; if(!recv_all(s,b,4)) return false; v=(b[0]<<24)|(b[1]<<16)|(b[2]<<8)|b[3]; }
        return true;
    };

    if (ch.fmt==0) {
        uint8_t mtype, sid[4];
        if (!rd3(ch.ts)) return false;
        if (!rd3(ch.msg_len)) return false;
        if (!recv_all(s,&mtype,1)) return false;
        if (!recv_all(s,sid,4)) return false;
        ch.type = mtype;
        ch.sid = sid[0]|(sid[1]<<8)|(sid[2]<<16)|(sid[3]<<24);
        if (!ext_ts(ch.ts)) return false;
        ch.delta = 0; // Reset Delta
    } else if (ch.fmt==1) {
        uint32_t delta=0;
        if (!rd3(delta)) return false;
        if (!rd3(ch.msg_len)) return false;
        uint8_t mtype; if(!recv_all(s,&mtype,1)) return false;
        ch.type = mtype;
        if (!ext_ts(delta)) return false;
        ch.delta = delta; // save
        ch.ts  = p ? p->ts+delta : delta;
        ch.sid = p ? p->sid : 0;
    } else if (ch.fmt==2) {
        uint32_t delta=0;
        if (!rd3(delta)) return false;
        if (!ext_ts(delta)) return false;
        ch.delta = delta; // save
        ch.ts      = p ? p->ts+delta : delta;
        ch.msg_len = p ? p->msg_len  : 0;
        ch.type    = p ? p->type     : 0;
        ch.sid     = p ? p->sid      : 0;
    } else {
        ch.delta   = p ? p->delta   : 0;
        ch.msg_len = p ? p->msg_len : 0;
        ch.type    = p ? p->type    : 0;
        ch.sid     = p ? p->sid     : 0;
        
        if (parts[csid].empty()) {
            ch.ts = p ? p->ts + ch.delta : 0;
        } else {
            ch.ts = p ? p->ts : 0;
        }
    }

    bool found=false;
    for (auto& x:prev) if(x.first==csid){x.second=ch;found=true;break;}
    if (!found) prev.push_back({csid,ch});
    return true;
}

//  AMF0 
static std::string amf_str(const uint8_t* d, size_t l, size_t& p) {
    if (p>=l || d[p]!=0x02) { p++; return {}; }
    p++;
    if (p+2>l) return {};
    uint16_t sl=(d[p]<<8)|d[p+1]; p+=2;
    if (p+sl>l) return {};
    std::string s(reinterpret_cast<const char*>(d+p),sl); p+=sl;
    return s;
}
static double amf_num(const uint8_t* d, size_t l, size_t& p) {
    if (p>=l || d[p]!=0x00) { p++; return 0; }
    p++;
    if (p+8>l) return 0;
    uint64_t bits=0;
    for(int i=0;i<8;i++) bits=(bits<<8)|d[p++];
    double v; std::memcpy(&v,&bits,8); return v;
}
static void amf_skip(const uint8_t* d, size_t l, size_t& p);
static void amf_skip(const uint8_t* d, size_t l, size_t& p) {
    if (p>=l) return;
    uint8_t t=d[p++];
    switch(t) {
        case 0x00: p+=8; break;
        case 0x01: p+=1; break;
        case 0x02: { if(p+2>l)break; uint16_t sl=(d[p]<<8)|d[p+1]; p+=2+sl; break; }
        case 0x03: while(p+3<=l) { uint16_t kl=(d[p]<<8)|d[p+1]; p+=2; if(kl==0&&p<l&&d[p]==0x09){p++;break;} p+=kl; amf_skip(d,l,p); } break;
        case 0x05: case 0x06: break;
        case 0x0A: { if(p+4>l)break; uint32_t n=(d[p]<<24)|(d[p+1]<<16)|(d[p+2]<<8)|d[p+3]; p+=4; for(uint32_t i=0;i<n;i++) amf_skip(d,l,p); break; }
        default: break;
    }
}

// Build AMF0 values
static std::vector<uint8_t> mk_str(const std::string& s) {
    std::vector<uint8_t> v={0x02};
    v.push_back((s.size()>>8)&0xFF); v.push_back(s.size()&0xFF);
    v.insert(v.end(),s.begin(),s.end()); return v;
}
static std::vector<uint8_t> mk_num(double d) {
    std::vector<uint8_t> v={0x00};
    uint64_t bits; std::memcpy(&bits,&d,8);
    for(int i=7;i>=0;i--) v.push_back((bits>>(i*8))&0xFF);
    return v;
}
static std::vector<uint8_t> mk_null() { return {0x05}; }
static std::vector<uint8_t> mk_obj(const std::vector<std::pair<std::string,std::vector<uint8_t>>>& props) {
    std::vector<uint8_t> v={0x03};
    for (auto& [k,val]:props) {
        v.push_back((k.size()>>8)&0xFF); v.push_back(k.size()&0xFF);
        v.insert(v.end(),k.begin(),k.end());
        v.insert(v.end(),val.begin(),val.end());
    }
    v.insert(v.end(),{0x00,0x00,0x09}); return v;
}

// Build RTMP chunk (fmt=0 header + payload split into chunk_size pieces)
static std::vector<uint8_t> mk_chunk(uint8_t cs, uint8_t type, uint32_t sid,
                                      const std::vector<uint8_t>& pay, uint32_t csize=RTMP_CHUNK_SIZE) {
    std::vector<uint8_t> out;
    out.push_back(cs&0x3F);
    out.insert(out.end(),{0,0,0}); // ts=0
    uint32_t l=pay.size();
    out.push_back((l>>16)&0xFF); out.push_back((l>>8)&0xFF); out.push_back(l&0xFF);
    out.push_back(type);
    out.push_back(sid&0xFF); out.push_back((sid>>8)&0xFF); out.push_back((sid>>16)&0xFF); out.push_back((sid>>24)&0xFF);
    size_t off=0;
    while (off<pay.size()) {
        if (off>0) out.push_back(0xC0|(cs&0x3F));
        size_t n=std::min<size_t>(pay.size()-off,csize);
        out.insert(out.end(),pay.begin()+off,pay.begin()+off+n);
        off+=n;
    }
    return out;
}

//  Relay 
struct RelayPacket {
    uint32_t ts;
    uint8_t type;
    std::vector<uint8_t> data;
};

struct RelayManager {
    std::mutex mtx;
    std::condition_variable cv;

    struct Sub {
        socket_t sock;
        std::atomic<bool> alive{true};
    };

    std::vector<std::shared_ptr<Sub>> subs;

    std::vector<uint8_t> meta;
    std::vector<uint8_t> vid_seq;
    std::vector<uint8_t> aud_seq;

    std::deque<RelayPacket> queue;

    std::thread relay_thread;
    std::atomic<bool> running{true};

    uint32_t first_ts = 0;
    bool first_packet = true;

    std::chrono::steady_clock::time_point start_clock;

    RelayManager() {
        relay_thread = std::thread([this]() { relay_loop(); });
    }

    ~RelayManager() {
        running = false;
        cv.notify_all();
        if (relay_thread.joinable())
            relay_thread.join();
    }

    void add(socket_t s) {
        std::lock_guard<std::mutex> g(mtx);

        auto sub = std::make_shared<Sub>();
        sub->sock = s;

        subs.push_back(sub);

        LOG("OBS connected (" << subs.size() << " subscriber)");
    }

    void remove(socket_t s) {
        std::lock_guard<std::mutex> g(mtx);

        subs.erase(
            std::remove_if(
                subs.begin(),
                subs.end(),
                [s](auto& x) {
                    return x->sock == s;
                }),
            subs.end());

        LOG("OBS disconnected (" << subs.size() << " remaining)");
    }

    void cache(uint8_t type, const std::vector<uint8_t>& p) {
        if (type == 0x12)
            meta = p;
        else if (type == 0x09 && p.size() >= 2 && p[0] == 0x17 && p[1] == 0x00)
            vid_seq = p;
        else if (type == 0x08 && p.size() >= 2 && p[0] == 0xAF && p[1] == 0x00)
            aud_seq = p;
    }

    void send_headers(socket_t s) {
        std::lock_guard<std::mutex> g(mtx);

        if (!meta.empty()) {
            auto c = mk_chunk(0x05, 0x12, 1, meta);
            send_all(s, c.data(), c.size());
        }

        if (!vid_seq.empty()) {
            auto c = mk_chunk(0x06, 0x09, 1, vid_seq);
            send_all(s, c.data(), c.size());
        }

        if (!aud_seq.empty()) {
            auto c = mk_chunk(0x04, 0x08, 1, aud_seq);
            send_all(s, c.data(), c.size());
        }
    }

    void enqueue(uint32_t ts, uint8_t type, std::vector<uint8_t>&& data) {
        {
            std::lock_guard<std::mutex> g(mtx);

            if (first_packet) {
                first_packet = false;
                first_ts = ts;
                start_clock = std::chrono::steady_clock::now();
            }

            queue.push_back({ts, type, std::move(data)});
        }

        cv.notify_one();
    }

    void relay_loop() {
        while (running) {
            RelayPacket pkt;

            {
                std::unique_lock<std::mutex> lk(mtx);

                cv.wait(lk, [&]() {
                    return !running || !queue.empty();
                });

                if (!running)
                    return;

                pkt = std::move(queue.front());
                queue.pop_front();
            }

            uint32_t rel_ts = pkt.ts - first_ts;

            auto target_time = start_clock + std::chrono::milliseconds(rel_ts);

            std::this_thread::sleep_until(target_time);

            broadcast(pkt.data.data(), pkt.data.size());
        }
    }

    void broadcast(const uint8_t* d, size_t l) {

    std::vector<std::shared_ptr<Sub>> current_subs;

    {
        std::lock_guard<std::mutex> g(mtx);
        current_subs = subs;
    }

    for (auto& sub : current_subs) {

        if (!sub->alive)
            continue;

        if (!send_all(sub->sock, d, l))
            sub->alive = false;
    }

    {
        std::lock_guard<std::mutex> g(mtx);

        subs.erase(
            std::remove_if(
                subs.begin(),
                subs.end(),
                [](auto& x) {
                    return !x->alive.load();
                }),
            subs.end());
    }
}
};

RelayManager g_relay;

//  Unified Client Handler 
// Handshake -> parse commands until publish or play -> handle accordingly

static void handle_client(socket_t s, std::string peer_ip) {
    if (!do_handshake(s)) { close_socket(s); return; }

    uint32_t csize = 128;
    std::vector<std::pair<uint32_t,Chunk>> prev;
    std::unordered_map<uint32_t,std::vector<uint8_t>> parts;

    // Helper: send a control AMF response
    auto send_amf = [&](uint8_t cs, uint32_t sid, std::vector<uint8_t> amf) {
        auto c = mk_chunk(cs, 0x14, sid, amf);
        send_all(s, c.data(), c.size());
    };

    auto send_stream_begin = [&](uint32_t stream_id) {
        std::vector<uint8_t> p = {0x00, 0x00, 
                                  uint8_t((stream_id>>24)&0xFF), uint8_t((stream_id>>16)&0xFF), 
                                  uint8_t((stream_id>>8)&0xFF), uint8_t(stream_id&0xFF)};
        auto c = mk_chunk(0x02, 0x04, 0, p);
        send_all(s, c.data(), c.size());
    };


    // Phase 1: negotiate role
    bool is_publisher = false;
    bool decided = false;

    while (!decided) {
        Chunk ch;
        if (!read_chunk_hdr(s, ch, csize, prev, parts)) { close_socket(s); return; }

        auto& part = parts[ch.cs_id];
        size_t need = std::min<size_t>(ch.msg_len - part.size(), csize);
        std::vector<uint8_t> buf(need);
        if (!recv_all(s, buf.data(), need)) { close_socket(s); return; }
        part.insert(part.end(), buf.begin(), buf.end());
        if (part.size() < ch.msg_len) continue;

        std::vector<uint8_t> pay = std::move(part); part.clear();

        if (ch.type == 0x01 && pay.size() >= 4) {
            csize = ((pay[0]&0x7F)<<24)|(pay[1]<<16)|(pay[2]<<8)|pay[3];
            continue;
        }
        if (ch.type != 0x14 && ch.type != 0x11) continue;

        size_t pos = (ch.type == 0x11) ? 1 : 0;
        std::string cmd = amf_str(pay.data(), pay.size(), pos);
        LOG("[" << peer_ip << "] cmd: " << cmd);

        if (cmd == "connect") {
            double txid = amf_num(pay.data(), pay.size(), pos);
            // Window ACK Size
            { std::vector<uint8_t> p={0x00,0x26,0x25,0xA0}; auto c=mk_chunk(0x02,0x05,0,p); send_all(s,c.data(),c.size()); }
            // Set Peer BW
            { std::vector<uint8_t> p={0x00,0x26,0x25,0xA0,0x02}; auto c=mk_chunk(0x02,0x06,0,p); send_all(s,c.data(),c.size()); }
            // Set Chunk Size
            { std::vector<uint8_t> p={uint8_t((RTMP_CHUNK_SIZE>>24)&0x7F),uint8_t((RTMP_CHUNK_SIZE>>16)&0xFF),uint8_t((RTMP_CHUNK_SIZE>>8)&0xFF),uint8_t(RTMP_CHUNK_SIZE&0xFF)}; auto c=mk_chunk(0x02,0x01,0,p); send_all(s,c.data(),c.size()); }
            // _result
            {
                auto props=mk_obj({{"fmsVer",mk_str("FMS/3,5,3,888")},{"capabilities",mk_num(31)},{"mode",mk_num(1)}});
                auto info=mk_obj({{"level",mk_str("status")},{"code",mk_str("NetConnection.Connect.Success")},{"description",mk_str("Connection succeeded.")},{"objectEncoding",mk_num(0)}});
                std::vector<uint8_t> a;
                auto r=mk_str("_result"); a.insert(a.end(),r.begin(),r.end());
                auto n=mk_num(txid);      a.insert(a.end(),n.begin(),n.end());
                a.insert(a.end(),props.begin(),props.end());
                a.insert(a.end(),info.begin(),info.end());
                send_amf(0x03, 0, a);
            }
            {
                std::vector<uint8_t> a;
                auto r=mk_str("onBWDone"); a.insert(a.end(),r.begin(),r.end());
                auto n=mk_num(0);          a.insert(a.end(),n.begin(),n.end());
                auto nil=mk_null();        a.insert(a.end(),nil.begin(),nil.end());
                send_amf(0x03, 0, a);
            }
        }
        else if (cmd == "releaseStream") {
            double txid = amf_num(pay.data(), pay.size(), pos);
            std::vector<uint8_t> a;
            auto r=mk_str("_result"); a.insert(a.end(),r.begin(),r.end());
            auto n=mk_num(txid);      a.insert(a.end(),n.begin(),n.end());
            auto nil=mk_null();       a.insert(a.end(),nil.begin(),nil.end());
            send_amf(0x03, 0, a);
        }
        else if (cmd == "FCPublish") {
            double txid = amf_num(pay.data(), pay.size(), pos);
            std::vector<uint8_t> a;
            auto r=mk_str("onFCPublish"); a.insert(a.end(),r.begin(),r.end());
            auto n=mk_num(txid);           a.insert(a.end(),n.begin(),n.end());
            auto nil=mk_null();            a.insert(a.end(),nil.begin(),nil.end());
            auto info=mk_obj({{"code",mk_str("NetStream.Publish.Start")},{"description",mk_str("FCPublish.")}});
            a.insert(a.end(),info.begin(),info.end());
            send_amf(0x03, 0, a);
        }
        else if (cmd == "createStream") {
            double txid = amf_num(pay.data(), pay.size(), pos);
            std::vector<uint8_t> a;
            auto r=mk_str("_result"); a.insert(a.end(),r.begin(),r.end());
            auto n=mk_num(txid);      a.insert(a.end(),n.begin(),n.end());
            auto nil=mk_null();       a.insert(a.end(),nil.begin(),nil.end());
            auto sid=mk_num(1.0);     a.insert(a.end(),sid.begin(),sid.end());
            send_amf(0x03, 0, a);
        }
        else if (cmd == "getStreamLength") {
            double txid = amf_num(pay.data(), pay.size(), pos);
            std::vector<uint8_t> a;
            auto r=mk_str("_result"); a.insert(a.end(),r.begin(),r.end());
            auto n=mk_num(txid);      a.insert(a.end(),n.begin(),n.end());
            auto nil=mk_null();       a.insert(a.end(),nil.begin(),nil.end());
            auto len=mk_num(0.0);     a.insert(a.end(),len.begin(),len.end());
            send_amf(0x03, 0, a);
        }
        else if (cmd == "publish") {
            is_publisher = true;
            decided = true;
            send_stream_begin(1);
            // onStatus Publish.Start
            std::vector<uint8_t> a;
            auto cn=mk_str("onStatus"); a.insert(a.end(),cn.begin(),cn.end());
            auto n=mk_num(0);           a.insert(a.end(),n.begin(),n.end());
            auto nil=mk_null();         a.insert(a.end(),nil.begin(),nil.end());
            auto info=mk_obj({{"level",mk_str("status")},{"code",mk_str("NetStream.Publish.Start")},{"description",mk_str("Publishing started.")}});
            a.insert(a.end(),info.begin(),info.end());
            send_amf(0x05, 1, a);
            LOG("[SUCCESS] iPhone (Publisher) connected!");
        }
        else if (cmd == "play") {
            is_publisher = false;
            decided = true;
            send_stream_begin(1);
            // onStatus Play.Start
            std::vector<uint8_t> a;
            auto cn=mk_str("onStatus"); a.insert(a.end(),cn.begin(),cn.end());
            auto n=mk_num(0);           a.insert(a.end(),n.begin(),n.end());
            auto nil=mk_null();         a.insert(a.end(),nil.begin(),nil.end());
            auto info=mk_obj({{"level",mk_str("status")},{"code",mk_str("NetStream.Play.Start")},{"description",mk_str("Start live.")}});
            a.insert(a.end(),info.begin(),info.end());
            send_amf(0x05, 1, a);
            // send cached sequence headers if iPhone is live
            g_relay.send_headers(s);
            g_relay.add(s);
            LOG("[SUCCESS] OBS (Subscriber) conntected!");
        }
    }

    // Phase 2: stream loop
    if (is_publisher) {
        // Publisher: recieve AV-data and distribute it to all subscribers
        while (true) {
            Chunk ch;
            if (!read_chunk_hdr(s, ch, csize, prev, parts)) break;

            auto& part = parts[ch.cs_id];
            size_t need = std::min<size_t>(ch.msg_len - part.size(), csize);
            std::vector<uint8_t> buf(need);
            if (!recv_all(s, buf.data(), need)) break;
            part.insert(part.end(), buf.begin(), buf.end());
            if (part.size() < ch.msg_len) continue;

            std::vector<uint8_t> pay = std::move(part); part.clear();

            switch (ch.type) {
                case 0x01: // Set Chunk Size
                    if (pay.size()>=4) csize=((pay[0]&0x7F)<<24)|(pay[1]<<16)|(pay[2]<<8)|pay[3];
                    break;
                case 0x08: case 0x09: case 0x12: case 0x0F: {
                    // Cache + broadcast
                    g_relay.cache(ch.type, pay);
                    // create Relay-Chunk with original timestamps
                    uint8_t cs = (ch.type==0x09) ? 0x06 : (ch.type==0x08) ? 0x04 : 0x05;
                    std::vector<uint8_t> out;
                    out.push_back(cs); // fmt=0
                    uint32_t t = ch.ts;
                    bool ext = t>=0xFFFFFF;
                    out.push_back(ext?0xFF:(t>>16)&0xFF);
                    out.push_back(ext?0xFF:(t>>8)&0xFF);
                    out.push_back(ext?0xFF: t    &0xFF);
                    uint32_t ml=pay.size();
                    out.push_back((ml>>16)&0xFF); out.push_back((ml>>8)&0xFF); out.push_back(ml&0xFF);
                    out.push_back(ch.type);
                    out.insert(out.end(),{0x01,0x00,0x00,0x00}); // stream id 1 LE
                    if (ext) { out.push_back((t>>24)&0xFF); out.push_back((t>>16)&0xFF); out.push_back((t>>8)&0xFF); out.push_back(t&0xFF); }
                    size_t off=0;
                    while (off<pay.size()) {
                        if (off>0) out.push_back(0xC0|cs);
                        size_t n=std::min<size_t>(pay.size()-off,(size_t)RTMP_CHUNK_SIZE);
                        out.insert(out.end(),pay.begin()+off,pay.begin()+off+n);
                        off+=n;
                    }
                    g_relay.enqueue(ch.ts, ch.type, std::move(out));
                    break;
                }
                default: break;
            }
        }
        LOG("iPhone disconnected");
        close_socket(s);
    } else {
        // Subscriber: open, ready to recieve ACK
        uint8_t dummy[256];
        while (recv(s, reinterpret_cast<char*>(dummy), sizeof(dummy), 0) > 0) {}
        g_relay.remove(s);
        close_socket(s);
    }
}

//  Main 
int main() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) { ERR("WSAStartup failed"); return 1; }
#endif

    std::cout << R"(

     Blackmagic Camera - OBS RTMP Bridge  v2.0            

    iPhone  ->  rtmp://ip-addr/live   Key: iphone
    OBS     ->  rtmp://localhost:1935/live/iphone

)" << std::endl;

    socket_t srv = ::socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCK) { ERR("socket() failed: " << sock_error); return 1; }
    int opt=1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(RTMP_PORT);
    if (bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ERR("bind() on port " << RTMP_PORT << " failed (port blocked?): " << sock_error);
        close_socket(srv); return 1;
    }
    listen(srv, 16);
    LOG("RTMP-Server is live on " << RTMP_PORT << " and ready");

    while (true) {
        sockaddr_in ca{}; socklen_t cl=sizeof(ca);
        socket_t c = accept(srv, reinterpret_cast<sockaddr*>(&ca), &cl);
        if (c == INVALID_SOCK) continue;
        char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET,&ca.sin_addr,ip,sizeof(ip));
        std::string peer = std::string(ip)+":"+std::to_string(ntohs(ca.sin_port));
        LOG("Connect form " << peer);
        std::thread(handle_client, c, peer).detach();
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
