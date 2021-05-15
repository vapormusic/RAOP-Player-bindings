/*****************************************************************************
 * bindings.cpp: Python bindings
 *
 * Copyright (C) 2021 David Klopp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111, USA.
 *****************************************************************************/

#include <pybind11/pybind11.h>


extern "C" {
#include "../tools/platform.h"
#include "../src/raop_client.h"
#include "../tools/log_util.h"

// platform.h expects us to implement this function
__u64 get_ntp(struct ntp_s *ntp)
{
    struct timeval ctv;
    struct ntp_s local;

    gettimeofday(&ctv, NULL);
    local.seconds  = ctv.tv_sec + 0x83AA7E80;
    local.fraction = (((__u64) ctv.tv_usec) << 32) / 1000000;

    if (ntp) *ntp = local;

    return (((__u64) local.seconds) << 32) + local.fraction;
}

// debug logging
log_level    util_loglevel;
log_level    raop_loglevel;
log_level    main_log;

log_level *loglevel =&main_log;

struct debug_s {
    log_level main, raop, util;
} debug[] = {
    { lSILENCE, lSILENCE, lSILENCE },
    { lERROR, lERROR, lERROR },
    { lINFO, lERROR, lERROR },
    { lINFO, lINFO, lERROR },
    { lDEBUG, lERROR, lERROR },
    { lDEBUG, lINFO, lERROR },
    { lDEBUG, lDEBUG, lERROR },
    { lSDEBUG, lINFO, lERROR },
    { lSDEBUG, lDEBUG, lERROR },
    { lSDEBUG, lSDEBUG, lERROR },
};
}


#define SEC(ntp) ((__u32) ((ntp) >> 32))
#define FRAC(ntp) ((__u32) (ntp))
#define SECNTP(ntp) SEC(ntp),FRAC(ntp)

#define STRINGIFY(x) #x
#define MACRO_STRINGIFY(x) STRINGIFY(x)


namespace py = pybind11;

class RaopClient {
private:
    struct raopcl_s *raopcl = NULL;
    struct in_addr host = { INADDR_ANY };
    struct hostent *hostent = NULL;

public:
    char *name = NULL;

    static float float_volume(int vol) {
        return raopcl_float_volume(vol);
    }

    RaopClient(char *name, u16_t port_base, u16_t port_range, char *DACP_id, char *active_remote,
               raop_codec_t codec, int frame_len, int latency_frames, raop_crypto_t crypto, bool auth, char *pw,
               char *secret, char *et, char *md, int sample_rate, int sample_size, int channels, float volume)
    {
        if ((this->raopcl = raopcl_create(this->host, port_base, port_range, DACP_id, active_remote, codec, frame_len,
                                          latency_frames, crypto, auth, pw, secret, et, md, sample_rate, sample_size,
                                          channels, volume)) == NULL)
        {
            throw pybind11::value_error("Can not initialize raop client with the given parameters.");
        }

        this->name = name;
        this->hostent = gethostbyname(this->name);
        memcpy(&this->host.s_addr, this->hostent->h_addr_list[0], this->hostent->h_length);
    }

    ~RaopClient()
    {
        if (this->raopcl != NULL) {
            raopcl_disconnect(this->raopcl);
            raopcl_destroy(this->raopcl);
            this->raopcl = NULL;
        }
    }

    bool connect(u16_t destport) {
        return raopcl_connect(this->raopcl, this->host, destport);
    }

    py::tuple pair(char *pin, bool set_volume) {
        if (pin && strlen(pin) < 4) return py::make_tuple(false, NULL);

        bool success = raopcl_pair(this->raopcl, pin, set_volume);
        char *secret = raopcl_secret(this->raopcl);
        py::tuple res = py::make_tuple(success, secret);
        free(secret);
        return res;
    }

    bool repair( bool set_volume) {
        return raopcl_repair(this->raopcl, set_volume);
    }

    bool disconnect() {
        return raopcl_disconnect(this->raopcl);
    }

    bool destroy() {
        bool res = raopcl_destroy(this->raopcl);
        this->raopcl = NULL;
        return res;
    }

    bool flush() {
        return raopcl_flush(this->raopcl);
    }

    bool keepalive() {
        return raopcl_keepalive(this->raopcl);
    }

    bool set_progress(u64_t elapsed, u64_t end) {
        return raopcl_set_progress(this->raopcl, elapsed, end);
    }

    bool set_progress_ms(u32_t elapsed, u32_t duration) {
        return raopcl_set_progress_ms(this->raopcl, elapsed, duration);
    }

    bool set_volume(float vol) {
        return raopcl_set_volume(this->raopcl, vol);
    }

    bool set_daap(py::args args) {
        return raopcl_set_daap(this->raopcl, args.size(), *args);
    }

    bool set_artwork(char *content_type, std::string image) {
        size_t img_size = image.length() + 1;
        char *cstr = new char[img_size];
        strcpy(cstr, image.c_str());
        bool res = raopcl_set_artwork(this->raopcl, content_type, img_size, cstr);
        delete [] cstr;
        return res;
    }

    bool accept_frames() {
        return raopcl_accept_frames(this->raopcl);
    }

    py::tuple send_chunk(py::bytes data) {
        py::buffer_info info(py::buffer(data).request());
        int32_t size = static_cast<int32_t>(info.shape[0] * info.itemsize);

        u64_t playtime;
        bool success = raopcl_send_chunk(this->raopcl, (u8_t *)info.ptr, size, &playtime);
        return py::make_tuple(success, playtime);
    }

    bool start_at(u64_t start_time) {
        return raopcl_start_at(this->raopcl, start_time);
    }

    void pause() {
        raopcl_pause(this->raopcl);
    }

    void stop() {
        raopcl_stop(this->raopcl);
    }

    bool request_pin() {
        return raopcl_request_pin(this->raopcl);
    }

    /*
     These methods are threadsafe.
     */

    u32_t latency() {
        return raopcl_latency(this->raopcl);
    }

    u32_t sample_rate() {
        return raopcl_sample_rate(this->raopcl);
    }

    raop_state_t state() {
        return raopcl_state(this->raopcl);
    }

    bool is_sane() {
        return raopcl_is_sane(this->raopcl);
    }

    bool is_connected() {
        return raopcl_is_connected(this->raopcl);
    }

    bool is_playing() {
        return raopcl_is_playing(this->raopcl);
    }

    bool sanitize() {
        return raopcl_sanitize(this->raopcl);
    }
};

PYBIND11_MODULE(libraop, m) {
    m.doc() = "Python bindings for the RAOP-Player";

    // Export global properties
    m.attr("MAX_SAMPLES_PER_CHUNK") = MAX_SAMPLES_PER_CHUNK;
    m.attr("RAOP_LATENCY_MIN") = RAOP_LATENCY_MIN;
    m.attr("SECRET_SIZE") = SECRET_SIZE;

    // Export macros
    m.def("NTP2MS", [](__u64 ntp) { return NTP2MS(ntp); });
    m.def("MS2NTP", [](long ms) { return MS2NTP(ms); });
    m.def("TS2NTP", [](u32_t ts, u32_t rate) { return TS2NTP(ts, rate); });
    m.def("MS2TS", [](long ms, u32_t rate) { return MS2TS(ms, rate); });
    m.def("TS2MS", [](u32_t ts, u32_t rate) { return TS2MS(ts, rate); });
    m.def("TIME_MS2NTP", [](u32_t time) { return TIME_MS2NTP(time); });
    m.def("SECNTP", [](__u64 ntp) { return SECNTP(ntp); });


    m.def("set_log_level", [](int level) {
        if (level >= sizeof(debug) / sizeof(struct debug_s)) {
            level = sizeof(debug) / sizeof(struct debug_s) - 1;
        }

        level = level > 0 ? level : 0;
        
        util_loglevel = debug[level].util;
        raop_loglevel = debug[level].raop;
        main_log = debug[level].main;
    });

    /*py::class_<ntp_t>(m, "ntp")
     .def_readwrite("seconds", &ntp_s::seconds)
     .def_readwrite("fraction", &ntp_s::fraction);*/

    // Export helper functions
    m.def("get_ntp", []() { return get_ntp(NULL); });

    // Export enums
    py::enum_<raop_codec_t>(m, "codec")
    .value("RAOP_PCM", RAOP_PCM)
    .value("RAOP_ALAC_RAW", RAOP_ALAC_RAW)
    .value("RAOP_ALAC", RAOP_ALAC)
    .value("RAOP_AAC", RAOP_AAC)
    .value("RAOP_AAL_ELC", RAOP_AAL_ELC)
    .export_values();

    py::enum_<raop_crypto_t>(m, "crypto")
    .value("RAOP_CLEAR", RAOP_CLEAR)
    .value("RAOP_RSA", RAOP_RSA)
    .value("RAOP_FAIRPLAY", RAOP_FAIRPLAY)
    .value("RAOP_MFISAP", RAOP_MFISAP)
    .value("RAOP_FAIRPLAYSAP", RAOP_FAIRPLAYSAP)
    .export_values();

    py::enum_<raop_state_t>(m, "state")
    .value("RAOP_DOWN", RAOP_DOWN)
    .value("RAOP_FLUSHING", RAOP_FLUSHING)
    .value("RAOP_FLUSHED", RAOP_FLUSHED)
    .value("RAOP_STREAMING", RAOP_STREAMING)
    .export_values();

    // Export RaopClient class.
    py::class_<RaopClient>(m, "RaopClient")
    .def(py::init<char *, u16_t, u16_t, char *, char *, raop_codec_t, int, int, raop_crypto_t, bool, char *, char *, char *, char *, int, int, int, float>())
    .def_readonly("name", &RaopClient::name)
    .def("float_volume", &RaopClient::float_volume)
    .def("connect", &RaopClient::connect)
    .def("pair", &RaopClient::pair)
    .def("request_pin", &RaopClient::request_pin)
    .def("repair", &RaopClient::repair)
    .def("disconnect", &RaopClient::disconnect)
    .def("destroy", &RaopClient::destroy)
    .def("flush", &RaopClient::flush)
    .def("keepalive", &RaopClient::keepalive)
    .def("set_progress", &RaopClient::set_progress)
    .def("set_progress_ms", &RaopClient::set_progress_ms)
    .def("set_volume", &RaopClient::set_volume)
    .def("set_daap", &RaopClient::set_daap)
    .def("set_artwork", &RaopClient::set_artwork)
    .def("accept_frames", &RaopClient::accept_frames)
    .def("send_chunk", &RaopClient::send_chunk)
    .def("start_at", &RaopClient::start_at)
    .def("pause", &RaopClient::pause)
    .def("stop", &RaopClient::stop)
    .def_property_readonly("latency", &RaopClient::latency)
    .def_property_readonly("sample_rate", &RaopClient::sample_rate)
    .def_property_readonly("state", &RaopClient::state)
    .def_property_readonly("is_sane", &RaopClient::is_sane)
    .def_property_readonly("is_connected", &RaopClient::is_connected)
    .def_property_readonly("is_playing", &RaopClient::is_playing)
    .def("sanitize", &RaopClient::sanitize);

#ifdef VERSION_INFO
    m.attr("__version__") = MACRO_STRINGIFY(VERSION_INFO);
#else
    m.attr("__version__") = "dev";
#endif
}
