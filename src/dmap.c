/*****************************************************************************
 * dmap.c: Dmap
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

#include "dmap.h"

#include <string.h>
#include <stdlib.h>

#include "platform.h"

enum dmap_type_s {
    DMAP_TYPE_UBYTE   = 0x01,
    DMAP_TYPE_BYTE    = 0x02,
    DMAP_TYPE_USHORT  = 0x03,
    DMAP_TYPE_SHORT   = 0x04,
    DMAP_TYPE_UINT    = 0x05,
    DMAP_TYPE_INT     = 0x06,
    DMAP_TYPE_ULONG   = 0x07,
    DMAP_TYPE_LONG    = 0x08,
    DMAP_TYPE_STRING  = 0x09,
    DMAP_TYPE_DATE    = 0x0a,
    DMAP_TYPE_VERSION = 0x0b,
    DMAP_TYPE_LIST    = 0x0c,
} dmap_type_t;

const static struct dmap_field_s {
  char *desc;
  char tag[4];
  enum dmap_type_s type;
} dmap_fields[] = {
    {"daap.browsealbumlisting", "abal", DMAP_TYPE_LIST},
    {"daap.browseartistlisting", "abar", DMAP_TYPE_LIST},
    {"daap.browsecomposerlisting", "abcp", DMAP_TYPE_LIST},
    {"daap.browsegenrelisting", "abgn", DMAP_TYPE_LIST},
    {"daap.baseplaylist", "abpl", DMAP_TYPE_UBYTE},
    {"daap.databasebrowse", "abro", DMAP_TYPE_LIST},
    {"daap.databasesongs", "adbs", DMAP_TYPE_LIST},
    {"com.apple.itunes.itms-artistid", "aeAI", DMAP_TYPE_UINT},
    {"com.apple.itunes.itms-composerid", "aeCI", DMAP_TYPE_UINT},
    {"com.apple.itunes.episode-num-str", "aeEN", DMAP_TYPE_STRING},
    {"com.apple.itunes.episode-sort", "aeES", DMAP_TYPE_UINT},
    {"com.apple.itunes.itms-genreid", "aeGI", DMAP_TYPE_UINT},
    {"com.apple.itunes.has-video", "aeHV", DMAP_TYPE_UBYTE},
    {"com.apple.itunes.extended-media-kind", "aeMk", DMAP_TYPE_UINT},
    {"com.apple.itunes.mediakind", "aeMK", DMAP_TYPE_UBYTE},
    {"com.apple.itunes.network-name", "aeNN", DMAP_TYPE_STRING},
    {"com.apple.itunes.norm-volume", "aeNV", DMAP_TYPE_UINT},
    {"com.apple.itunes.is-podcast", "aePC", DMAP_TYPE_UBYTE},
    {"com.apple.itunes.itms-playlistid", "aePI", DMAP_TYPE_UINT},
    {"com.apple.itunes.is-podcast-playlist", "aePP", DMAP_TYPE_UBYTE},
    {"com.apple.itunes.special-playlist", "aePS", DMAP_TYPE_UBYTE},
    {"com.apple.itunes.itms-storefrontid", "aeSF", DMAP_TYPE_UINT},
    {"com.apple.itunes.itms-songid", "aeSI", DMAP_TYPE_UINT},
    {"com.apple.itunes.series-name", "aeSN", DMAP_TYPE_STRING},
    {"com.apple.itunes.smart-playlist", "aeSP", DMAP_TYPE_UBYTE},
    {"com.apple.itunes.season-num", "aeSU", DMAP_TYPE_UINT},
    {"com.apple.itunes.music-sharing-version", "aeSV", DMAP_TYPE_UINT},
    {"daap.groupalbumcount", "agac", DMAP_TYPE_UINT},
    {"daap.songgrouping", "agrp", DMAP_TYPE_STRING},
    {"daap.databaseplaylists", "aply", DMAP_TYPE_LIST},
    {"daap.playlistrepeatmode", "aprm", DMAP_TYPE_UBYTE},
    {"daap.protocolversion", "apro", DMAP_TYPE_VERSION},
    {"daap.playlistshufflemode", "apsm", DMAP_TYPE_UBYTE},
    {"daap.playlistsongs", "apso", DMAP_TYPE_LIST},
    {"daap.resolveinfo", "arif", DMAP_TYPE_LIST},
    {"daap.resolve", "arsv", DMAP_TYPE_LIST},
    {"daap.songalbumartist", "asaa", DMAP_TYPE_STRING},
    {"daap.songartworkcount", "asac", DMAP_TYPE_USHORT},
    {"daap.songalbumid", "asai", DMAP_TYPE_ULONG},
    {"daap.songalbum", "asal", DMAP_TYPE_STRING},
    {"daap.songartist", "asar", DMAP_TYPE_STRING},
    {"daap.songartistid", "asri", DMAP_TYPE_ULONG},
    {"daap.songbitrate", "asbr", DMAP_TYPE_USHORT},
    {"daap.songbeatsperminute", "asbt", DMAP_TYPE_USHORT},
    {"daap.songcodectype", "ascd", DMAP_TYPE_UINT},
    {"daap.songcomment", "ascm", DMAP_TYPE_STRING},
    {"daap.songcontentdescription", "ascn", DMAP_TYPE_STRING},
    {"daap.songcompilation", "asco", DMAP_TYPE_UBYTE},
    {"daap.songcomposer", "ascp", DMAP_TYPE_STRING},
    {"daap.songcontentrating", "ascr", DMAP_TYPE_UBYTE},
    {"daap.songcodecsubtype", "ascs", DMAP_TYPE_UINT},
    {"daap.songcategory", "asct", DMAP_TYPE_STRING},
    {"daap.songdateadded", "asda", DMAP_TYPE_DATE},
    {"daap.songdisabled", "asdb", DMAP_TYPE_UBYTE},
    {"daap.songdisccount", "asdc", DMAP_TYPE_USHORT},
    {"daap.songdatakind", "asdk", DMAP_TYPE_UBYTE},
    {"daap.songdatemodified", "asdm", DMAP_TYPE_DATE},
    {"daap.songdiscnumber", "asdn", DMAP_TYPE_USHORT},
    {"daap.songdatereleased", "asdr", DMAP_TYPE_DATE},
    {"daap.songdescription", "asdt", DMAP_TYPE_STRING},
    {"daap.songextradata", "ased", DMAP_TYPE_USHORT},
    {"daap.songeqpreset", "aseq", DMAP_TYPE_STRING},
    {"daap.songformat", "asfm", DMAP_TYPE_STRING},
    {"daap.songgenre", "asgn", DMAP_TYPE_STRING},
    {"daap.songhasbeenplayed", "ashp", DMAP_TYPE_UBYTE},
    {"daap.songlastskipdate", "askd", DMAP_TYPE_DATE},
    {"daap.songuserskipcount", "askp", DMAP_TYPE_UINT},
    {"daap.songkeywords", "asky", DMAP_TYPE_STRING},
    {"daap.songlongcontentdescription", "aslc", DMAP_TYPE_STRING},
    {"daap.songuserplaycount", "aspc", DMAP_TYPE_UINT},
    {"daap.songdateplayed", "aspl", DMAP_TYPE_DATE},
    {"daap.songrelativevolume", "asrv", DMAP_TYPE_BYTE},
    {"daap.sortartist", "assa", DMAP_TYPE_STRING},
    {"daap.sortcomposer", "assc", DMAP_TYPE_STRING},
    {"daap.sortalbumartist", "assl", DMAP_TYPE_STRING},
    {"daap.sortname", "assn", DMAP_TYPE_STRING},
    {"daap.songstoptime", "assp", DMAP_TYPE_UINT},
    {"daap.songsamplerate", "assr", DMAP_TYPE_UINT},
    {"daap.songstarttime", "asst", DMAP_TYPE_UINT},
    {"daap.sortalbum", "assu", DMAP_TYPE_STRING},
    {"daap.songsize", "assz", DMAP_TYPE_UINT},
    {"daap.songtrackcount", "astc", DMAP_TYPE_USHORT},
    {"daap.songtime", "astm", DMAP_TYPE_UINT},
    {"daap.songtracknumber", "astn", DMAP_TYPE_USHORT},
    {"daap.songdataurl", "asul", DMAP_TYPE_STRING},
    {"daap.songuserrating", "asur", DMAP_TYPE_UBYTE},
    {"daap.songyear", "asyr", DMAP_TYPE_USHORT},
    {"daap.serverdatabases", "avdb", DMAP_TYPE_LIST},
    {"dmap.bag", "mbcl", DMAP_TYPE_LIST},
    {"dmap.contentcodesresponse", "mccr", DMAP_TYPE_LIST},
    {"dmap.contentcodesname", "mcna", DMAP_TYPE_STRING},
    {"dmap.contentcodesnumber", "mcnm", DMAP_TYPE_UINT},
    {"dmap.container", "mcon", DMAP_TYPE_LIST},
    {"dmap.containercount", "mctc", DMAP_TYPE_UINT},
    {"dmap.containeritemid", "mcti", DMAP_TYPE_UINT},
    {"dmap.contentcodestype", "mcty", DMAP_TYPE_USHORT},
    {"dmap.dictionary", "mdcl", DMAP_TYPE_LIST},
    {"dmap.itemid", "miid", DMAP_TYPE_UINT},
    {"dmap.itemkind", "mikd", DMAP_TYPE_UBYTE},
    {"dmap.itemcount", "mimc", DMAP_TYPE_UINT},
    {"dmap.itemname", "minm", DMAP_TYPE_STRING},
    {"dmap.listing", "mlcl", DMAP_TYPE_LIST},
    {"dmap.sessionid", "mlid", DMAP_TYPE_UINT},
    {"dmap.listingitem", "mlit", DMAP_TYPE_LIST},
    {"dmap.loginresponse", "mlog", DMAP_TYPE_LIST},
    {"dmap.parentcontainerid", "mpco", DMAP_TYPE_UINT},
    {"dmap.persistentid", "mper", DMAP_TYPE_ULONG},
    {"dmap.protocolversion", "mpro", DMAP_TYPE_VERSION},
    {"dmap.returnedcount", "mrco", DMAP_TYPE_UINT},
    {"dmap.supportsautologout", "msal", DMAP_TYPE_UBYTE},
    {"dmap.authenticationschemes", "msas", DMAP_TYPE_UINT},
    {"dmap.authenticationmethod", "msau", DMAP_TYPE_UBYTE},
    {"dmap.supportsbrowse", "msbr", DMAP_TYPE_UBYTE},
    {"dmap.databasescount", "msdc", DMAP_TYPE_UINT},
    {"dmap.supportsextensions", "msex", DMAP_TYPE_UBYTE},
    {"dmap.supportsindex", "msix", DMAP_TYPE_UBYTE},
    {"dmap.loginrequired", "mslr", DMAP_TYPE_UBYTE},
    {"dmap.supportspersistentids", "mspi", DMAP_TYPE_UBYTE},
    {"dmap.supportsquery", "msqy", DMAP_TYPE_UBYTE},
    {"dmap.supportsresolve", "msrs", DMAP_TYPE_UBYTE},
    {"dmap.serverinforesponse", "msrv", DMAP_TYPE_LIST},
    {"dmap.timeoutinterval", "mstm", DMAP_TYPE_UINT},
    {"dmap.statusstring", "msts", DMAP_TYPE_STRING},
    {"dmap.status", "mstt", DMAP_TYPE_UINT},
    {"dmap.supportsupdate", "msup", DMAP_TYPE_UBYTE},
    {"dmap.specifiedtotalcount", "mtco", DMAP_TYPE_UINT},
    {"dmap.deletedidlisting", "mudl", DMAP_TYPE_LIST},
    {"dmap.updateresponse", "mupd", DMAP_TYPE_LIST},
    {"dmap.serverrevision", "musr", DMAP_TYPE_UINT},
    {"dmap.updatetype", "muty", DMAP_TYPE_UBYTE},
    {"dmap.sortingheaderlisting", "mshl", DMAP_TYPE_UINT},
    {"dmap.sortingheaderchar", "mshc", DMAP_TYPE_SHORT},
    {"dmap.sortingheaderindex", "mshi", DMAP_TYPE_UINT},
    {"dmap.sortingheadernumber", "mshn", DMAP_TYPE_UINT},
    {"com.apple.itunes.adam-ids-array", "aeAD", DMAP_TYPE_LIST},
    {"com.apple.itunes.content-rating", "aeCR", DMAP_TYPE_STRING},
    {"com.apple.itunes.drm-platform-id", "aeDP", DMAP_TYPE_UINT},
    {"com.apple.itunes.drm-user-id", "aeDR", DMAP_TYPE_ULONG},
    {"com.apple.itunes.drm-versions", "aeDV", DMAP_TYPE_UINT},
    {"com.apple.itunes.gapless-enc-dr", "aeGD", DMAP_TYPE_UINT},
    {"com.apple.itunes.gapless-enc-del", "aeGE", DMAP_TYPE_UINT},
    {"com.apple.itunes.gapless-heur", "aeGH", DMAP_TYPE_UINT},
    {"com.apple.itunes.gapless-resy", "aeGR", DMAP_TYPE_ULONG},
    {"com.apple.itunes.gapless-dur", "aeGU", DMAP_TYPE_ULONG},
    {"com.apple.itunes.is-hd-video", "aeHD", DMAP_TYPE_UBYTE},
    {"com.apple.itunes.drm-key1-id", "aeK1", DMAP_TYPE_ULONG},
    {"com.apple.itunes.drm-key2-id", "aeK2", DMAP_TYPE_ULONG},
    {"com.apple.itunes.non-drm-user-id", "aeND", DMAP_TYPE_ULONG},
    {"com.apple.itunes.store-pers-id", "aeSE", DMAP_TYPE_ULONG},
    {"com.apple.itunes.saved-genius", "aeSG", DMAP_TYPE_UBYTE},
    {"com.apple.itunes.xid", "aeXD", DMAP_TYPE_STRING},
    {"daap.bookmarkable", "asbk", DMAP_TYPE_UBYTE},
    {"daap.songbookmark", "asbo", DMAP_TYPE_UINT},
    {"daap.songdatepurchased", "asdp", DMAP_TYPE_DATE},
    {"daap.songgapless", "asgp", DMAP_TYPE_UBYTE},
    {"daap.songlongsize", "asls", DMAP_TYPE_ULONG},
    {"daap.songpodcasturl", "aspu", DMAP_TYPE_STRING},
    {"daap.sortseriesname", "asss", DMAP_TYPE_STRING},
    {"daap.supportsextradata", "ated", DMAP_TYPE_USHORT},
    {"com.apple.itunes.jukebox-client-vote", "ceJC", DMAP_TYPE_BYTE},
    {"com.apple.itunes.jukebox-current", "ceJI", DMAP_TYPE_UINT},
    {"com.apple.itunes.jukebox-score", "ceJS", DMAP_TYPE_SHORT},
    {"com.apple.itunes.jukebox-vote", "ceJV", DMAP_TYPE_UINT},
    {"dmap.editcommandssupported", "meds", DMAP_TYPE_UINT},
    {"dmap.utctime", "mstc", DMAP_TYPE_DATE},
    {"dmap.utcoffset", "msto", DMAP_TYPE_INT},
};

static inline int dmap_add_container(char *dest, const char *tag, int len)
{
    char *buf = dest;
    buf = (char*) memcpy(buf, tag, 4) + 4;
    *buf++ = (len >> 24) & 0xff;
    *buf++ = (len >> 16) & 0xff;
    *buf++ = (len >> 8)  & 0xff;
    *buf++ = (len >> 0)  & 0xff;
    return buf-dest;
}

static inline int dmap_add_char(char *dest, const char *tag, char data)
{
    char *buf = dest;
    buf = (char*) memcpy(buf, tag, 4) + 4;
    *buf++ = 0;
    *buf++ = 0;
    *buf++ = 0;
    *buf++ = 1;
    *buf++ = data;
    return buf-dest;
}

static inline int dmap_add_short(char *dest, const char *tag, short data)
{
    char *buf = dest;
    buf = (char*) memcpy(buf, tag, 4) + 4;
    *buf++ = 0;
    *buf++ = 0;
    *buf++ = 0;
    *buf++ = 2;
    *buf++ = (data >> 8) & 0xff;
    *buf++ = (data & 0xff);
    return buf-dest;
}

static inline int dmap_add_int(char *dest, const char *tag, int data)
{
    char *buf = dest;
    buf = (char*) memcpy(buf, tag, 4) + 4;
    *buf++ = 0;
    *buf++ = 0;
    *buf++ = 0;
    *buf++ = 4;
    *buf++ = (data >> 24) & 0xff;
    *buf++ = (data >> 16) & 0xff;
    *buf++ = (data >> 8)  & 0xff;
    *buf++ = (data >> 0)  & 0xff;
    return buf-dest;
}

static inline int dmap_add_long(char *dest, const char *tag, s64_t data)
{
    char *buf = dest;
    buf = (char*) memcpy(buf, tag, 4) + 4;

    *buf++ = 0;
    *buf++ = 0;
    *buf++ = 0;
    *buf++ = 8;

    *buf++ = (data >> 56) & 0xff;
    *buf++ = (data >> 48) & 0xff;
    *buf++ = (data >> 40) & 0xff;
    *buf++ = (data >> 32) & 0xff;
    *buf++ = (data >> 24) & 0xff;
    *buf++ = (data >> 16) & 0xff;
    *buf++ = (data >> 8)  & 0xff;
    *buf++ = (data >> 0)  & 0xff;

    return buf-dest;
}


static inline int dmap_add_string(char *dest, const char *tag, const char *data)
{
    char *buf = dest;
    buf = (char*) memcpy(buf, tag, 4) + 4;
    u32_t len = strlen(data);
    *buf++ = (len >> 24) & 0xff;
    *buf++ = (len >> 16) & 0xff;
    *buf++ = (len >> 8)  & 0xff;
    *buf++ = (len >> 0)  & 0xff;
    buf = (char*) memcpy(buf, data, len) + len;
    return buf-dest;
}

/**
 Calculate the required size for a dmap_entry_t.
 */
size_t dmap_entry_size(dmap_entry_t *entry)
{
    // size of the tag + size field
    size_t size = 8;
    dmap_entry_t **child;
    struct dmap_field_s field = dmap_fields[entry->key];

    switch (field.type) {
        case DMAP_TYPE_UBYTE:
        case DMAP_TYPE_BYTE:
            size += 1;
            break;
        case DMAP_TYPE_USHORT:
        case DMAP_TYPE_SHORT:
            size += 2;
            break;
        case DMAP_TYPE_DATE:
        case DMAP_TYPE_UINT:
        case DMAP_TYPE_INT:
            size += 4;
            break;
        case DMAP_TYPE_STRING:
            size += strlen(entry->data);
            break;
        case DMAP_TYPE_ULONG:
        case DMAP_TYPE_LONG:
            size += 8;
            break;
        case DMAP_TYPE_LIST:
            child = entry->childs;
            while (child != NULL && *child != NULL) {
                size += dmap_entry_size(*child);
                child++;
            }
            break;
        default:
            break;
    }
    return size;
}

/**
 Write all the dmap_entry data to a buffer and return the size of the written data.
 Note: You need to make sure, that your buffer size is big enough.
 */
int dmap_entry_to_bin(char *buf, dmap_entry_t *entry)
{
    int i = 0;
    char *end;
    s32_t v_i32;
    u32_t v_u32;
    s64_t v_i64;
    u64_t v_u64;
    dmap_entry_t **child;

    char *q = buf;

    struct dmap_field_s field = dmap_fields[entry->key];

    switch (field.type) {
        case DMAP_TYPE_UBYTE:
            v_u32 = (u32_t)strtoul(entry->data, &end, 10);
            q += dmap_add_char(q, field.tag, v_u32);
            break;
        case DMAP_TYPE_BYTE:
            v_i32 = (s32_t)strtoul(entry->data, &end, 10);
            q += dmap_add_char(q, field.tag, v_i32);
            break;
        case DMAP_TYPE_USHORT:
            v_u32 = (u32_t)strtoul(entry->data, &end, 10);
            q += dmap_add_short(q, field.tag, v_u32);
            break;
        case DMAP_TYPE_SHORT:
            v_i32 = (s32_t)strtoul(entry->data, &end, 10);
            q += dmap_add_short(q, field.tag, v_i32);
            break;
        case DMAP_TYPE_DATE:
        case DMAP_TYPE_UINT:
            v_u32 = (u32_t)strtoul(entry->data, &end, 10);
            q += dmap_add_int(q, field.tag, v_u32);
        case DMAP_TYPE_INT:
            v_i32 = (s32_t)strtoul(entry->data, &end, 10);
            q += dmap_add_int(q, field.tag, v_i32);
        case DMAP_TYPE_ULONG:
            v_u64 = (u64_t)strtoul(entry->data, &end, 10);
            q += dmap_add_long(q, field.tag, v_u64);
        case DMAP_TYPE_LONG:
            v_i64 = (s64_t)strtoul(entry->data, &end, 10);
            q += dmap_add_long(q, field.tag, v_i64);
        case DMAP_TYPE_STRING:
            q += dmap_add_string(q, field.tag, entry->data);
            break;
        case DMAP_TYPE_LIST:
            // make room for the container
            q += 8;
            // add all list sub entries
            child = entry->childs;
            while (child != NULL && *child != NULL) {
                q += dmap_entry_to_bin(q, *child);
                child++;
            }
            dmap_add_container(buf, field.tag, q-buf-8);
            break;
        default:
            break;
    }

    return q-buf;
}

static inline dmap_entry_t *dmap_create(dmap_key_t key, char *data, int num_children)
{
    dmap_entry_t *entry = (dmap_entry_t *)malloc(sizeof(dmap_entry_t));
    entry->key = key;
    entry->data = (data != NULL) ? strdup(data) : NULL;
    if (num_children <= 0) {
        entry->childs = NULL;
    } else {
        entry->childs = (dmap_entry_t **)malloc(sizeof(dmap_entry_t *)*(num_children+1));
        entry->childs[num_children] = NULL;
    }
    return entry;
}

dmap_entry_t *dmap_entry_create(dmap_key_t key, char *data)
{
    if (dmap_fields[key].type == DMAP_TYPE_LIST) {
        printf("Can not create dmap entry. %s is a list type.", dmap_fields[key].desc);
        return NULL;
    }
    return dmap_create(key, data, 0);
}

dmap_entry_t *dmap_listing_create(dmap_key_t key, int num_children)
{
    if (dmap_fields[key].type != DMAP_TYPE_LIST) {
        printf("Can not create dmap list. %s is not a list type.", dmap_fields[key].desc);
        return NULL;
    }
    return dmap_create(key, NULL, num_children);
}

void dmap_entry_free(dmap_entry_t *entry) {
    int i = 0;
    dmap_entry_t **child = entry->childs;
    while (child != NULL && *child != NULL) {
        dmap_entry_free(*child);
        child++;
    }
    entry->childs = NULL;
    if (entry->data != NULL) free(entry->data);
    if (entry->childs != NULL) free(entry->childs);
    free(entry);
}

dmap_entry_t *dmap_entry_copy(dmap_entry_t *entry)
{
    if (dmap_fields[entry->key].type == DMAP_TYPE_LIST) {
        // Count the children inside the container.
        int i=0;
        int size = 0;
        dmap_entry_t **child = entry->childs;
        for (;child != NULL && *child != NULL; ++child) size++;

        // Copy the listing
        dmap_entry_t *listing = dmap_listing_create(entry->key, size);
        for (i=0; i<size; i++) {
            listing->childs[i] = dmap_entry_copy(entry->childs[i]);
        }
        return listing;
    }

    return dmap_entry_create(entry->key, entry->data);
}
