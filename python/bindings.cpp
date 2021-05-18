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

#include "../src/dmap.h"
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

// #define TO_CHAR(arg) TO_STRING(arg)[0]
#define TO_STRING(arg) arg.cast<std::string>()
#define TO_CHAR_ARRAY(arg) &(std::vector<char>(TO_STRING(arg).begin(), TO_STRING(arg).end())[0])
#define TO_DMAP_KEY(arg) (dmap_key_t)arg.cast<int>()

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

    bool repair(bool set_volume) {
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

    bool set_daap(dmap_entry_t *entry) {
        return raopcl_set_daap(this->raopcl, entry);
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
    m.def("NTP2MS", [](__u64 ntp) { return NTP2MS(ntp); }, py::arg("ntp"));
    m.def("MS2NTP", [](long ms) { return MS2NTP(ms); }, py::arg("ms"));
    m.def("TS2NTP", [](u32_t ts, u32_t rate) { return TS2NTP(ts, rate); }, py::arg("timestamp"), py::arg("rate"));
    m.def("MS2TS", [](long ms, u32_t rate) { return MS2TS(ms, rate); }, py::arg("ms"), py::arg("rate"));
    m.def("TS2MS", [](u32_t ts, u32_t rate) { return TS2MS(ts, rate); }, py::arg("timestamp"), py::arg("rate"));
    m.def("TIME_MS2NTP", [](u32_t time) { return TIME_MS2NTP(time); }, py::arg("time"));
    m.def("SECNTP", [](__u64 ntp) { return SECNTP(ntp); }, py::arg("ntp"));


    m.def("set_log_level", [](int level) {
        if (level >= sizeof(debug) / sizeof(struct debug_s)) {
            level = sizeof(debug) / sizeof(struct debug_s) - 1;
        }

        level = level > 0 ? level : 0;
        
        util_loglevel = debug[level].util;
        raop_loglevel = debug[level].raop;
        main_log = debug[level].main;
    }, py::arg("level"));

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

    py::enum_<dmap_key_t>(m, "dmap")
    .value("BROWSEALBUMLISTING", BROWSEALBUMLISTING)
    .value("BROWSEARTISTLISTING", BROWSEARTISTLISTING)
    .value("BROWSECOMPOSERLISTING", BROWSECOMPOSERLISTING)
    .value("BROWSEGENRELISTING", BROWSEGENRELISTING)
    .value("BASEPLAYLIST", BASEPLAYLIST)
    .value("DATABASEBROWSE", DATABASEBROWSE)
    .value("DATABASESONGS", DATABASESONGS)
    .value("ITMS_ARTISTID", ITMS_ARTISTID)
    .value("ITMS_COMPOSERID", ITMS_COMPOSERID)
    .value("EPISODE_NUM_STR", EPISODE_NUM_STR)
    .value("EPISODE_SORT", EPISODE_SORT)
    .value("ITMS_GENREID", ITMS_GENREID)
    .value("HAS_VIDEO", HAS_VIDEO)
    .value("EXTENDED_MEDIA_KIND", EXTENDED_MEDIA_KIND)
    .value("MEDIAKIND", MEDIAKIND)
    .value("NETWORK_NAME", NETWORK_NAME)
    .value("NORM_VOLUME", NORM_VOLUME)
    .value("IS_PODCAST", IS_PODCAST)
    .value("ITMS_PLAYLISTID", ITMS_PLAYLISTID)
    .value("IS_PODCAST_PLAYLIST", IS_PODCAST_PLAYLIST)
    .value("SPECIAL_PLAYLIST", SPECIAL_PLAYLIST)
    .value("ITMS_STOREFRONTID", ITMS_STOREFRONTID)
    .value("ITMS_SONGID", ITMS_SONGID)
    .value("SERIES_NAME", SERIES_NAME)
    .value("SMART_PLAYLIST", SMART_PLAYLIST)
    .value("SEASON_NUM", SEASON_NUM)
    .value("MUSIC_SHARING_VERSION", MUSIC_SHARING_VERSION)
    .value("GROUPALBUMCOUNT", GROUPALBUMCOUNT)
    .value("SONGGROUPING", SONGGROUPING)
    .value("DATABASEPLAYLISTS", DATABASEPLAYLISTS)
    .value("PLAYLISTREPEATMODE", PLAYLISTREPEATMODE)
    .value("DAAP_PROTOCOLVERSION", DAAP_PROTOCOLVERSION)
    .value("PLAYLISTSHUFFLEMODE", PLAYLISTSHUFFLEMODE)
    .value("PLAYLISTSONGS", PLAYLISTSONGS)
    .value("RESOLVEINFO", RESOLVEINFO)
    .value("RESOLVE", RESOLVE)
    .value("SONGALBUMARTIST", SONGALBUMARTIST)
    .value("SONGARTWORKCOUNT", SONGARTWORKCOUNT)
    .value("SONGALBUMID", SONGALBUMID)
    .value("SONGALBUM", SONGALBUM)
    .value("SONGARTIST", SONGARTIST)
    .value("SONGARTISTID", SONGARTISTID)
    .value("SONGBITRATE", SONGBITRATE)
    .value("SONGBEATSPERMINUTE", SONGBEATSPERMINUTE)
    .value("SONGCODECTYPE", SONGCODECTYPE)
    .value("SONGCOMMENT", SONGCOMMENT)
    .value("SONGCONTENTDESCRIPTION", SONGCONTENTDESCRIPTION)
    .value("SONGCOMPILATION", SONGCOMPILATION)
    .value("SONGCOMPOSER", SONGCOMPOSER)
    .value("SONGCONTENTRATING", SONGCONTENTRATING)
    .value("SONGCODECSUBTYPE", SONGCODECSUBTYPE)
    .value("SONGCATEGORY", SONGCATEGORY)
    .value("SONGDATEADDED", SONGDATEADDED)
    .value("SONGDISABLED", SONGDISABLED)
    .value("SONGDISCCOUNT", SONGDISCCOUNT)
    .value("SONGDATAKIND", SONGDATAKIND)
    .value("SONGDATEMODIFIED", SONGDATEMODIFIED)
    .value("SONGDISCNUMBER", SONGDISCNUMBER)
    .value("SONGDATERELEASED", SONGDATERELEASED)
    .value("SONGDESCRIPTION", SONGDESCRIPTION)
    .value("SONGEXTRADATA", SONGEXTRADATA)
    .value("SONGEQPRESET", SONGEQPRESET)
    .value("SONGFORMAT", SONGFORMAT)
    .value("SONGGENRE", SONGGENRE)
    .value("SONGHASBEENPLAYED", SONGHASBEENPLAYED)
    .value("SONGLASTSKIPDATE", SONGLASTSKIPDATE)
    .value("SONGUSERSKIPCOUNT", SONGUSERSKIPCOUNT)
    .value("SONGKEYWORDS", SONGKEYWORDS)
    .value("SONGLONGCONTENTDESCRIPTION", SONGLONGCONTENTDESCRIPTION)
    .value("SONGUSERPLAYCOUNT", SONGUSERPLAYCOUNT)
    .value("SONGDATEPLAYED", SONGDATEPLAYED)
    .value("SONGRELATIVEVOLUME", SONGRELATIVEVOLUME)
    .value("SORTARTIST", SORTARTIST)
    .value("SORTCOMPOSER", SORTCOMPOSER)
    .value("SORTALBUMARTIST", SORTALBUMARTIST)
    .value("SORTNAME", SORTNAME)
    .value("SONGSTOPTIME", SONGSTOPTIME)
    .value("SONGSAMPLERATE", SONGSAMPLERATE)
    .value("SONGSTARTTIME", SONGSTARTTIME)
    .value("SORTALBUM", SORTALBUM)
    .value("SONGSIZE", SONGSIZE)
    .value("SONGTRACKCOUNT", SONGTRACKCOUNT)
    .value("SONGTIME", SONGTIME)
    .value("SONGTRACKNUMBER", SONGTRACKNUMBER)
    .value("SONGDATAURL", SONGDATAURL)
    .value("SONGUSERRATING", SONGUSERRATING)
    .value("SONGYEAR", SONGYEAR)
    .value("SERVERDATABASES", SERVERDATABASES)
    .value("BAG", BAG)
    .value("CONTENTCODESRESPONSE", CONTENTCODESRESPONSE)
    .value("CONTENTCODESNAME", CONTENTCODESNAME)
    .value("CONTENTCODESNUMBER", CONTENTCODESNUMBER)
    .value("CONTAINER", CONTAINER)
    .value("CONTAINERCOUNT", CONTAINERCOUNT)
    .value("CONTAINERITEMID", CONTAINERITEMID)
    .value("CONTENTCODESTYPE", CONTENTCODESTYPE)
    .value("DICTIONARY", DICTIONARY)
    .value("ITEMID", ITEMID)
    .value("ITEMKIND", ITEMKIND)
    .value("ITEMCOUNT", ITEMCOUNT)
    .value("ITEMNAME", ITEMNAME)
    .value("LISTING", LISTING)
    .value("SESSIONID", SESSIONID)
    .value("LISTINGITEM", LISTINGITEM)
    .value("LOGINRESPONSE", LOGINRESPONSE)
    .value("PARENTCONTAINERID", PARENTCONTAINERID)
    .value("PERSISTENTID", PERSISTENTID)
    .value("DMAP_PROTOCOLVERSION", DMAP_PROTOCOLVERSION)
    .value("RETURNEDCOUNT", RETURNEDCOUNT)
    .value("SUPPORTSAUTOLOGOUT", SUPPORTSAUTOLOGOUT)
    .value("AUTHENTICATIONSCHEMES", AUTHENTICATIONSCHEMES)
    .value("AUTHENTICATIONMETHOD", AUTHENTICATIONMETHOD)
    .value("SUPPORTSBROWSE", SUPPORTSBROWSE)
    .value("DATABASESCOUNT", DATABASESCOUNT)
    .value("SUPPORTSEXTENSIONS", SUPPORTSEXTENSIONS)
    .value("SUPPORTSINDEX", SUPPORTSINDEX)
    .value("LOGINREQUIRED", LOGINREQUIRED)
    .value("SUPPORTSPERSISTENTIDS", SUPPORTSPERSISTENTIDS)
    .value("SUPPORTSQUERY", SUPPORTSQUERY)
    .value("SUPPORTSRESOLVE", SUPPORTSRESOLVE)
    .value("SERVERINFORESPONSE", SERVERINFORESPONSE)
    .value("TIMEOUTINTERVAL", TIMEOUTINTERVAL)
    .value("STATUSSTRING", STATUSSTRING)
    .value("STATUS", STATUS)
    .value("SUPPORTSUPDATE", SUPPORTSUPDATE)
    .value("SPECIFIEDTOTALCOUNT", SPECIFIEDTOTALCOUNT)
    .value("DELETEDIDLISTING", DELETEDIDLISTING)
    .value("UPDATERESPONSE", UPDATERESPONSE)
    .value("SERVERREVISION", SERVERREVISION)
    .value("UPDATETYPE", UPDATETYPE)
    .value("SORTINGHEADERLISTING", SORTINGHEADERLISTING)
    .value("SORTINGHEADERCHAR", SORTINGHEADERCHAR)
    .value("SORTINGHEADERINDEX", SORTINGHEADERINDEX)
    .value("SORTINGHEADERNUMBER", SORTINGHEADERNUMBER)
    .value("ADAM_IDS_ARRAY", ADAM_IDS_ARRAY)
    .value("CONTENT_RATING", CONTENT_RATING)
    .value("DRM_PLATFORM_ID", DRM_PLATFORM_ID)
    .value("DRM_USER_ID", DRM_USER_ID)
    .value("DRM_VERSIONS", DRM_VERSIONS)
    .value("GAPLESS_ENC_DR", GAPLESS_ENC_DR)
    .value("GAPLESS_ENC_DEL", GAPLESS_ENC_DEL)
    .value("GAPLESS_HEUR", GAPLESS_HEUR)
    .value("GAPLESS_RESY", GAPLESS_RESY)
    .value("GAPLESS_DUR", GAPLESS_DUR)
    .value("IS_HD_VIDEO", IS_HD_VIDEO)
    .value("DRM_KEY1_ID", DRM_KEY1_ID)
    .value("DRM_KEY2_ID", DRM_KEY2_ID)
    .value("NON_DRM_USER_ID", NON_DRM_USER_ID)
    .value("STORE_PERS_ID", STORE_PERS_ID)
    .value("SAVED_GENIUS", SAVED_GENIUS)
    .value("XID", XID)
    .value("BOOKMARKABLE", BOOKMARKABLE)
    .value("SONGBOOKMARK", SONGBOOKMARK)
    .value("SONGDATEPURCHASED", SONGDATEPURCHASED)
    .value("SONGGAPLESS", SONGGAPLESS)
    .value("SONGLONGSIZE", SONGLONGSIZE)
    .value("SONGPODCASTURL", SONGPODCASTURL)
    .value("SORTSERIESNAME", SORTSERIESNAME)
    .value("SUPPORTSEXTRADATA", SUPPORTSEXTRADATA)
    .value("JUKEBOX_CLIENT_VOTE", JUKEBOX_CLIENT_VOTE)
    .value("JUKEBOX_CURRENT", JUKEBOX_CURRENT)
    .value("JUKEBOX_SCORE", JUKEBOX_SCORE)
    .value("JUKEBOX_VOTE", JUKEBOX_VOTE)
    .value("EDITCOMMANDSSUPPORTED", EDITCOMMANDSSUPPORTED)
    .value("UTCTIME", UTCTIME)
    .value("UTCOFFSET", UTCOFFSET)
    .export_values();

    // We use shared_ptr, since the c struct does not define a destructor.
    // The shared_ptr allows us to define a custom destructor for the object.
    py::class_<dmap_entry_t, std::shared_ptr<dmap_entry_t>>(m, "DmapEntry")
    .def((py::init([](dmap_key_t key, py::list dmap_entries) {
        // Create a new container with all chidren
        dmap_entry_t *container = dmap_listing_create(LISTING, dmap_entries.size());
        for (int i=0; i<dmap_entries.size(); ++i) {
            // This entry is owned by python via the shared_ptr and is therefore freed
            // when this function ends.
            // Make a copy and let the container manage the freeing.
            dmap_entry_t *entry = dmap_entries[i].cast<dmap_entry_t *>();
            container->childs[i] = dmap_entry_copy(entry);
        }
        return std::shared_ptr<dmap_entry_t>(container, &dmap_entry_free);
    })), py::arg("type"), py::arg("dmap_entries"), py::return_value_policy::take_ownership)
    .def((py::init([](dmap_key_t key, char *data) {
        dmap_entry_t *entry = dmap_entry_create(key, data);
        return std::shared_ptr<dmap_entry_t>(entry, &dmap_entry_free);
    })), py::arg("type"), py::arg("data"))
    .def((py::init([](dmap_key_t key, int number) {
        int n = log10(number) + 1;
        char *numberArray = (char *)calloc(n, sizeof(char));
        for (int i = n-1; i >= 0; --i, number /= 10)
            numberArray[i] = (number % 10) + '0';
        dmap_entry_t *entry = dmap_entry_create(key, numberArray);
        return std::shared_ptr<dmap_entry_t>(entry, &dmap_entry_free);
    })), py::arg("type"), py::arg("data"))
    .def("__getitem__", [](dmap_entry_t *entry, int index) {
        return entry->childs[index];
    }, py::arg("index"), py::return_value_policy::reference)
    .def_property_readonly("key", [](dmap_entry_t *entry){
        return entry->key;
    })
    .def_property("data", [](dmap_entry_t *entry) {
        return entry->data;
    }, [](dmap_entry_t *entry, char *new_data) {
        entry->data = strdup(new_data);
    });

    // Export RaopClient class.
    py::class_<RaopClient>(m, "RaopClient")
    .def(py::init<char *, u16_t, u16_t, char *, char *, raop_codec_t, int, int, raop_crypto_t, bool, char *, char *,
         char *, char *, int, int, int, float>(),
         py::arg("name"), py::arg("port_base"), py::arg("port_range"), py::arg("DACP_id"), py::arg("active_remote"),
         py::arg("codec"), py::arg("frame_len"), py::arg("latency_frames"), py::arg("crypto"), py::arg("auth"),
         py::arg("password"), py::arg("secret"), py::arg("encryption_type_string"), py::arg("metadata_type_string"),
         py::arg("sample_rate"), py::arg("sample_size"), py::arg("channels"), py::arg("volume")
         )
    .def_readonly("name", &RaopClient::name)
    .def("float_volume", &RaopClient::float_volume)//, py::arg("volume"))
    .def("connect", &RaopClient::connect, py::arg("dest_port"))
    .def("pair", &RaopClient::pair, py::arg("pin"), py::arg("set_volume"))
    .def("request_pin", &RaopClient::request_pin)
    .def("repair", &RaopClient::repair, py::arg("set_volume") = true)
    .def("disconnect", &RaopClient::disconnect)
    .def("destroy", &RaopClient::destroy)
    .def("flush", &RaopClient::flush)
    .def("keepalive", &RaopClient::keepalive)
    .def("set_progress", &RaopClient::set_progress, py::arg("elapsed"), py::arg("end"))
    .def("set_progress_ms", &RaopClient::set_progress_ms, py::arg("elapsed"), py::arg("duration"))
    .def("set_volume", &RaopClient::set_volume, py::arg("volume"))
    .def("set_daap", &RaopClient::set_daap)//, py::arg("vargs"))
    .def("set_artwork", &RaopClient::set_artwork, py::arg("content_type"), py::arg("image_data"))
    .def("accept_frames", &RaopClient::accept_frames)
    .def("send_chunk", &RaopClient::send_chunk, py::arg("audio_data"))
    .def("start_at", &RaopClient::start_at, py::arg("start_time"))
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
