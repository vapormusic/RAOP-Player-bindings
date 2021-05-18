/*****************************************************************************
 * dmap.h: Dmap
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

#ifndef dmap_h
#define dmap_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// This enum contains all available metadata informations
// that can be send using the daap protocol.
typedef enum dmap_key_s {
    BROWSEALBUMLISTING = 0,
    BROWSEARTISTLISTING,
    BROWSECOMPOSERLISTING,
    BROWSEGENRELISTING,
    BASEPLAYLIST,
    DATABASEBROWSE,
    DATABASESONGS,
    ITMS_ARTISTID,
    ITMS_COMPOSERID,
    EPISODE_NUM_STR,
    EPISODE_SORT,
    ITMS_GENREID,
    HAS_VIDEO,
    EXTENDED_MEDIA_KIND,
    MEDIAKIND,
    NETWORK_NAME,
    NORM_VOLUME,
    IS_PODCAST,
    ITMS_PLAYLISTID,
    IS_PODCAST_PLAYLIST,
    SPECIAL_PLAYLIST,
    ITMS_STOREFRONTID,
    ITMS_SONGID,
    SERIES_NAME,
    SMART_PLAYLIST,
    SEASON_NUM,
    MUSIC_SHARING_VERSION,
    GROUPALBUMCOUNT,
    SONGGROUPING,
    DATABASEPLAYLISTS,
    PLAYLISTREPEATMODE,
    DAAP_PROTOCOLVERSION,
    PLAYLISTSHUFFLEMODE,
    PLAYLISTSONGS,
    RESOLVEINFO,
    RESOLVE,
    SONGALBUMARTIST,
    SONGARTWORKCOUNT,
    SONGALBUMID,
    SONGALBUM,
    SONGARTIST,
    SONGARTISTID,
    SONGBITRATE,
    SONGBEATSPERMINUTE,
    SONGCODECTYPE,
    SONGCOMMENT,
    SONGCONTENTDESCRIPTION,
    SONGCOMPILATION,
    SONGCOMPOSER,
    SONGCONTENTRATING,
    SONGCODECSUBTYPE,
    SONGCATEGORY,
    SONGDATEADDED,
    SONGDISABLED,
    SONGDISCCOUNT,
    SONGDATAKIND,
    SONGDATEMODIFIED,
    SONGDISCNUMBER,
    SONGDATERELEASED,
    SONGDESCRIPTION,
    SONGEXTRADATA,
    SONGEQPRESET,
    SONGFORMAT,
    SONGGENRE,
    SONGHASBEENPLAYED,
    SONGLASTSKIPDATE,
    SONGUSERSKIPCOUNT,
    SONGKEYWORDS,
    SONGLONGCONTENTDESCRIPTION,
    SONGUSERPLAYCOUNT,
    SONGDATEPLAYED,
    SONGRELATIVEVOLUME,
    SORTARTIST,
    SORTCOMPOSER,
    SORTALBUMARTIST,
    SORTNAME,
    SONGSTOPTIME,
    SONGSAMPLERATE,
    SONGSTARTTIME,
    SORTALBUM,
    SONGSIZE,
    SONGTRACKCOUNT,
    SONGTIME,
    SONGTRACKNUMBER,
    SONGDATAURL,
    SONGUSERRATING,
    SONGYEAR,
    SERVERDATABASES,
    BAG,
    CONTENTCODESRESPONSE,
    CONTENTCODESNAME,
    CONTENTCODESNUMBER,
    CONTAINER,
    CONTAINERCOUNT,
    CONTAINERITEMID,
    CONTENTCODESTYPE,
    DICTIONARY,
    ITEMID,
    ITEMKIND,
    ITEMCOUNT,
    ITEMNAME,
    LISTING,
    SESSIONID,
    LISTINGITEM,
    LOGINRESPONSE,
    PARENTCONTAINERID,
    PERSISTENTID,
    DMAP_PROTOCOLVERSION,
    RETURNEDCOUNT,
    SUPPORTSAUTOLOGOUT,
    AUTHENTICATIONSCHEMES,
    AUTHENTICATIONMETHOD,
    SUPPORTSBROWSE,
    DATABASESCOUNT,
    SUPPORTSEXTENSIONS,
    SUPPORTSINDEX,
    LOGINREQUIRED,
    SUPPORTSPERSISTENTIDS,
    SUPPORTSQUERY,
    SUPPORTSRESOLVE,
    SERVERINFORESPONSE,
    TIMEOUTINTERVAL,
    STATUSSTRING,
    STATUS,
    SUPPORTSUPDATE,
    SPECIFIEDTOTALCOUNT,
    DELETEDIDLISTING,
    UPDATERESPONSE,
    SERVERREVISION,
    UPDATETYPE,
    SORTINGHEADERLISTING,
    SORTINGHEADERCHAR,
    SORTINGHEADERINDEX,
    SORTINGHEADERNUMBER,
    ADAM_IDS_ARRAY,
    CONTENT_RATING,
    DRM_PLATFORM_ID,
    DRM_USER_ID,
    DRM_VERSIONS,
    GAPLESS_ENC_DR,
    GAPLESS_ENC_DEL,
    GAPLESS_HEUR,
    GAPLESS_RESY,
    GAPLESS_DUR,
    IS_HD_VIDEO,
    DRM_KEY1_ID,
    DRM_KEY2_ID,
    NON_DRM_USER_ID,
    STORE_PERS_ID,
    SAVED_GENIUS,
    XID,
    BOOKMARKABLE,
    SONGBOOKMARK,
    SONGDATEPURCHASED,
    SONGGAPLESS,
    SONGLONGSIZE,
    SONGPODCASTURL,
    SORTSERIESNAME,
    SUPPORTSEXTRADATA,
    JUKEBOX_CLIENT_VOTE,
    JUKEBOX_CURRENT,
    JUKEBOX_SCORE,
    JUKEBOX_VOTE,
    EDITCOMMANDSSUPPORTED,
    UTCTIME,
    UTCOFFSET
} dmap_key_t;


typedef struct dmap_entry_s {
    dmap_key_t key;
    char *data;
    struct dmap_entry_s **childs;
} dmap_entry_t;

/**
 * Normally when sending dmap data, all entries are contained inside one root listing. All information fields are
 * contained inside the root listing. It is possible to nest listings (even with the same key) if required.
 * A simple example to send dmap data:
 *
 * #include "dmap.h"
 *
 * dmap_entry_t *container = dmap_listing_create(LISTINGITEM, 4);
 * container->childs[0] = dmap_entry_create(ITEMKIND, "2");
 * container->childs[1] = dmap_entry_create(ITEMNAME, "Help!");
 * container->childs[2] = dmap_entry_create(SONGARTIST, "The Beatles");
 * container->childs[3] = dmap_entry_create(SONGALBUM, "Help!");
 *
 * raopcl_set_daap(raopcl, container);
 *
 * dmap_entry_free(container);
 *
 */

// Create a new listing with a fixed number of children.
dmap_entry_t *dmap_listing_create(dmap_key_t key, int num_children);

// Create a new entry.
dmap_entry_t *dmap_entry_create(dmap_key_t key, char *data);

// Calculate the required binary data size for this entry, including the size of all children.
size_t dmap_entry_size(dmap_entry_t *entry);

// Convert an entry to binary data and write it into a buffer.
int dmap_entry_to_bin(char *buf, dmap_entry_t *entry);

// Free the memory of this entry. If the entry contains children, they are freed as well.
void dmap_entry_free(dmap_entry_t *entry);

// Deep copy and existing entry.
dmap_entry_t *dmap_entry_copy(dmap_entry_t *entry);

#endif /* dmap_h */
