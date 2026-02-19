/*
 * Wi-Fi Aware - NAN module
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_common.h"
#include "nan.h"
#include "nan_i.h"

#define NAN_MAX_PEERS 32
#define NAN_MAX_NAF_LEN 1024

#define NAN_NDP_SETUP_TIMEOUT_LONG  30
#define NAN_NDP_SETUP_TIMEOUT_SHORT 2

static void nan_peer_state_timeout(void *eloop_ctx, void *timeout_ctx);
static void nan_ndp_disconnected(struct nan_data *nan, struct nan_peer *peer,
				 enum nan_reason reason);


struct nan_data * nan_init(const struct nan_config *cfg)
{
	struct nan_data *nan;

	if (!cfg->start || !cfg->stop)
		return NULL;

	nan = os_zalloc(sizeof(*nan));
	if (!nan)
		return NULL;

	nan->cfg = os_memdup(cfg, sizeof(*cfg));
	if (!nan->cfg) {
		os_free(nan);
		return NULL;
	}

	dl_list_init(&nan->peer_list);

	wpa_printf(MSG_DEBUG, "NAN: Initialized");

	return nan;
}


static void nan_peer_flush_avail(struct nan_peer_info *info)
{
	nan_flush_avail_entries(&info->avail_entries);
}


static void nan_peer_flush_dev_capa(struct nan_peer_info *info)
{
	struct nan_dev_capa_entry *cur, *next;

	dl_list_for_each_safe(cur, next, &info->dev_capa,
			      struct nan_dev_capa_entry, list) {
		dl_list_del(&cur->list);
		os_free(cur);
	}
}


static void nan_peer_flush_elem_container(struct nan_peer_info *info)
{
	struct nan_elem_container_entry *cur, *next;

	dl_list_for_each_safe(cur, next, &info->element_container,
			      struct nan_elem_container_entry, list) {
		dl_list_del(&cur->list);
		os_free(cur);
	}
}


static void nan_ndp_setup_stop(struct nan_data *nan, struct nan_peer *peer)
{
	eloop_cancel_timeout(nan_peer_state_timeout, nan, peer);
	nan_ndp_setup_reset(nan, peer);

	/* Need to also remove the NDL if no active NDPs */
	if (dl_list_empty(&peer->ndps))
		nan_ndl_reset(nan, peer);
}


static void nan_peer_flush_sec(struct nan_peer_info *info)
{
	struct nan_peer_sec_info_entry *cur, *next;

	dl_list_for_each_safe(cur, next, &info->sec,
			      struct nan_peer_sec_info_entry, list) {
		dl_list_del(&cur->list);
		os_free(cur);
	}
}


static void nan_del_peer(struct nan_data *nan, struct nan_peer *peer)
{
	if (!peer)
		return;

	wpa_printf(MSG_DEBUG, "NAN: Removing peer: " MACSTR,
		   MAC2STR(peer->nmi_addr));

	if (!dl_list_empty(&peer->ndps)) {
		struct nan_ndp *ndp, *tndp;

		/* TODO: tear down active NDPs */
		wpa_printf(MSG_DEBUG,
			   "NAN: Peer delete while there are active NDPs");

		dl_list_for_each_safe(ndp, tndp, &peer->ndps,
				      struct nan_ndp, list) {
			dl_list_del(&ndp->list);
			os_free(ndp);
		}
	}

	if (peer->ndp_setup.ndp) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Peer delete while NDP setup is WIP");
		nan_ndp_setup_stop(nan, peer);
	}

	dl_list_del(&peer->list);
	nan_peer_flush_avail(&peer->info);
	nan_peer_flush_dev_capa(&peer->info);
	nan_peer_flush_elem_container(&peer->info);

	nan_ndl_reset(nan, peer);
	nan_peer_flush_sec(&peer->info);
	eloop_cancel_timeout(nan_peer_state_timeout, nan, peer);
	os_free(peer);
}


static void nan_peer_clear_all(struct nan_data *nan)
{
	struct nan_peer *peer, *n_peer;

	dl_list_for_each_safe(peer, n_peer, &nan->peer_list,
			      struct nan_peer, list)
		nan_del_peer(nan, peer);
}


void nan_deinit(struct nan_data *nan)
{
	wpa_printf(MSG_DEBUG, "NAN: Deinit");
	nan_peer_clear_all(nan);
	os_free(nan->cfg);
	os_free(nan);
}


int nan_start(struct nan_data *nan, const struct nan_cluster_config *config)
{
	int ret;

	wpa_printf(MSG_DEBUG, "NAN: Starting/joining NAN cluster");

	if (nan->nan_started) {
		wpa_printf(MSG_DEBUG, "NAN: Already started");
		return -1;
	}

	ret = nan->cfg->start(nan->cfg->cb_ctx, config);
	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: Failed to start - ret=%d", ret);
		return ret;
	}
	nan->nan_started = 1;

	return 0;
}


int nan_update_config(struct nan_data *nan,
		      const struct nan_cluster_config *config)
{
	int ret;

	wpa_printf(MSG_DEBUG, "NAN: Update configuration");

	if (!nan->nan_started) {
		wpa_printf(MSG_DEBUG, "NAN: Not started yet");
		return -1;
	}

	ret = nan->cfg->update_config(nan->cfg->cb_ctx, config);
	if (ret)
		wpa_printf(MSG_DEBUG, "NAN: Failed to update config. ret=%d",
			   ret);

	return ret;
}


void nan_flush(struct nan_data *nan)
{
	wpa_printf(MSG_DEBUG, "NAN: Reset internal state");

	if (!nan->nan_started) {
		wpa_printf(MSG_DEBUG, "NAN: Already stopped");
		return;
	}

	nan->nan_started = 0;
	nan_peer_clear_all(nan);
}


void nan_stop(struct nan_data *nan)
{
	wpa_printf(MSG_DEBUG, "NAN: Stopping");

	if (!nan->nan_started) {
		wpa_printf(MSG_DEBUG, "NAN: Already stopped");
		return;
	}

	nan_flush(nan);
	nan->cfg->stop(nan->cfg->cb_ctx);
}


struct nan_peer * nan_get_peer(struct nan_data *nan, const u8 *addr)
{
	struct nan_peer *peer;

	dl_list_for_each(peer, &nan->peer_list, struct nan_peer, list) {
		if (ether_addr_equal(peer->nmi_addr, addr))
			return peer;
	}

	return NULL;
}


/*
 * nan_parse_tbm - Parse NAN Time Bitmap attribute
 *
 * @nan: NAN module context from nan_init()
 * @tbm: On return would hold the parsed time bitmap
 * @buf: Buffer holding the time bitmap
 * @buf_len: Length of &buf
 * Return 0 on success; otherwise -1
 */
static int nan_parse_tbm(struct nan_data *nan, struct nan_time_bitmap *tbm,
			 const u8 *buf, u16 buf_len)
{
	u32 period;
	u16 ctrl;
	const struct nan_tbm *bm;
	u8 duration_bit;

	if (buf_len < sizeof(*bm)) {
		wpa_printf(MSG_DEBUG, "NAN: Too short time bitmap length (%u)",
			   buf_len);
		return -1;
	}

	bm = (const struct nan_tbm *) buf;
	if (!bm->len || bm->len + sizeof(*bm) > buf_len) {
		wpa_printf(MSG_DEBUG, "NAN: Invalid tbm length (%hu)",
			   bm->len);
		return -1;
	}

	if (bm->len > sizeof(tbm->bitmap)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: tbm len=%hu exceeds supported len=%zu",
			   bm->len, sizeof(tbm->bitmap));
		return -1;
	}

	ctrl = le_to_host16(bm->ctrl);

	duration_bit = BITS(ctrl, NAN_TIME_BM_CTRL_BIT_DURATION_MASK,
			    NAN_TIME_BM_CTRL_BIT_DURATION_POS);

	if (duration_bit > NAN_TIME_BM_CTRL_BIT_DURATION_128_TU) {
		wpa_printf(MSG_DEBUG, "NAN: Invalid time bitmap duration");
		return -1;
	}

	tbm->duration = duration_bit;

	tbm->period = BITS(ctrl, NAN_TIME_BM_CTRL_PERIOD_MASK,
			   NAN_TIME_BM_CTRL_PERIOD_POS);
	if (tbm->period) {
		period = BIT(6 + tbm->period);
	} else {
		wpa_printf(MSG_DEBUG,
			   "NAN: Bitmap with period=0 is not supported");
		return -1;
	}

	tbm->offset = BITS(ctrl, NAN_TIME_BM_CTRL_START_OFFSET_MASK,
			   NAN_TIME_BM_CTRL_START_OFFSET_POS);

	if (bm->len * 8 * BIT(4 + tbm->duration) > period) {
		wpa_printf(MSG_DEBUG,
			   "NAN: tbm is longer than the repeat period");
		return -1;
	}

	if (tbm->offset * 16 > period) {
		wpa_printf(MSG_DEBUG,
			   "NAN: tbm offset %u exceeds period %u",
			   tbm->offset, period);
		return -1;
	}

	tbm->len = bm->len;
	os_memcpy(tbm->bitmap, bm->bitmap, tbm->len);
	return 0;
}


/*
 * nan_parse_band_chan_list - Parse NAN Band/Channel List entry
 *
 * @nan: NAN module context from nan_init()
 * @entry: On return would hold the parsed band/channel list
 * @list: Buffer holding the band/channel list
 * @len: Length of &list
 * Return 0 on success; otherwise -1
 */
static int nan_parse_band_chan_list(struct nan_data *nan,
				    struct nan_avail_entry *entry,
				    const struct nan_band_chan_list *list,
				    u16 len)
{
	u8 band_chan_size, i;
	bool non_cont;
	const u8 *pos;

	if (len < sizeof(*list)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Too short channel/band list=%hu", len);
		return -1;
	}

	entry->band_chan_type = list->ctrl & NAN_BAND_CHAN_CTRL_TYPE;
	entry->n_band_chan = BITS(list->ctrl,
				  NAN_BAND_CHAN_CTRL_NUM_ENTRIES_MASK,
				  NAN_BAND_CHAN_CTRL_NUM_ENTRIES_POS);

	len -= sizeof(*list);
	pos = list->entries;

	if (entry->band_chan_type == NAN_TYPE_BAND) {
		if (!len || !entry->n_band_chan || len < entry->n_band_chan) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Truncated band list. len=%u, band_chan=%u",
				   len, entry->n_band_chan);
			return -1;
		}

		entry->band_chan = os_zalloc(sizeof(*entry->band_chan) *
					     entry->n_band_chan);
		if (!entry->band_chan) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Failed to allocate band list");
			return -1;
		}

		for (i = 0; i < entry->n_band_chan; i++)
			entry->band_chan[i].u.band_id = pos[i];

		return 0;
	}

	non_cont = list->ctrl & NAN_BAND_CHAN_CTRL_NON_CONT_BW;
	band_chan_size = non_cont ? NAN_CHAN_ENTRY_80P80_LEN :
		NAN_CHAN_ENTRY_MIN_LEN;

	if (len < entry->n_band_chan * band_chan_size) {
		wpa_printf(MSG_DEBUG, "NAN: Truncated channel list");
		return -1;
	}

	entry->band_chan = os_zalloc(sizeof(*entry->band_chan) *
				     entry->n_band_chan);
	if (!entry->band_chan) {
		wpa_printf(MSG_DEBUG, "NAN: Failed to allocate channel list");
		return -1;
	}

	for (i = 0; i < entry->n_band_chan; i++) {
		struct nan_band_chan *curr = &entry->band_chan[i];
		const struct nan_chan_entry *chan =
			(const struct nan_chan_entry *) pos;

		curr->u.chan.op_class = chan->op_class;
		curr->u.chan.chan_bitmap = chan->chan_bitmap;
		curr->u.chan.pri_chan_bitmap = chan->pri_chan_bitmap;
		if (non_cont)
			curr->u.chan.aux_chan_bitmap = chan->aux_chan_bitmap;

		pos += band_chan_size;
	}

	return 0;
}


/*
 * nan_split_avail_entry - Split an availability entry
 *
 * @nan: NAN module context from nan_init()
 * @entry: Original entry to split
 * Returns a newly allocated potential entry on success, otherwise NULL.
 *
 * The function expects an availability entry which is both
 * committed/conditional and potential and has more than one channel entry. It
 * splits the original entry such that:
 *
 * - The original entry is only committed/conditional with one channel entry
 * - A new potential entry with the rest of the channels specified in the
 *   original entry.
 */
static struct nan_avail_entry *
nan_split_avail_entry(struct nan_data *nan,
		      struct nan_avail_entry *entry)
{
	struct nan_avail_entry *pot;
	struct nan_band_chan *tmp;

	wpa_printf(MSG_DEBUG,
		   "NAN: Split Committed/Conditional and potential entry");

	pot = os_zalloc(sizeof(*pot));
	if (!pot) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Failed to allocate availability entry");
		return NULL;
	}

	pot->map_id = entry->map_id;
	pot->type = NAN_AVAIL_ENTRY_CTRL_TYPE_POTENTIAL;
	pot->preference = entry->preference;
	pot->utilization = entry->utilization;
	pot->rx_nss = entry->rx_nss;

	dl_list_init(&pot->list);

	pot->tbm.duration = entry->tbm.duration;
	pot->tbm.period = entry->tbm.period;
	pot->tbm.offset = entry->tbm.offset;
	pot->tbm.len = entry->tbm.len;

	os_memcpy(pot->tbm.bitmap, entry->tbm.bitmap, pot->tbm.len);

	pot->band_chan_type = entry->band_chan_type;
	pot->n_band_chan = entry->n_band_chan - 1;
	pot->band_chan = os_zalloc(sizeof(*pot->band_chan) *
				   pot->n_band_chan);
	if (!pot->band_chan) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Failed to allocate channel list: potential");
		os_free(pot);
		return NULL;
	}

	os_memcpy(pot->band_chan, &entry->band_chan[1],
		  sizeof(*pot->band_chan) * pot->n_band_chan);

	tmp = entry->band_chan;

	/* Clear potential from the original entry */
	entry->type &= ~NAN_AVAIL_ENTRY_CTRL_TYPE_POTENTIAL;
	entry->band_chan = os_memdup(tmp, sizeof(*entry->band_chan));
	if (!entry->band_chan) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Failed to allocate channel list: committed");
		os_free(pot->band_chan);
		os_free(pot);
		return NULL;
	}

	entry->n_band_chan = 1;

	os_free(tmp);
	return pot;
}


/*
 * nan_parse_avail_entry - Parse a NAN availability entry
 *
 * @nan: NAN module context from nan_init()
 * @peer_info: Peer info where the parsed entry would be added
 * @avail_entry: Pointer to the availability entry
 * @entry_len: Length of the availability entry
 * @map_id: Map ID of the availability attribute that this entry belongs to
 * Returns: 0 on success, -1 on failure, or 0 to skip the entry
 */
static int nan_parse_avail_entry(struct nan_data *nan,
				 struct nan_peer_info *peer_info,
				 const struct nan_avail_ent *avail_entry,
				 u16 entry_len, u8 map_id)
{
	struct nan_avail_entry *entry;
	const u8 *pos;
	u16 ctrl, len;
	u8 type, preference, utilization;

	if (entry_len < MIN_AVAIL_ENTRY_LEN) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Too short availability entry len=%hu",
			   entry_len);
		return -1;
	}

	ctrl = le_to_host16(avail_entry->ctrl);

	type = ctrl & NAN_AVAIL_ENTRY_CTRL_TYPE_MASK;
	if (!type ||
	    ((type & NAN_AVAIL_ENTRY_CTRL_TYPE_COMMITTED) &&
	     (type & NAN_AVAIL_ENTRY_CTRL_TYPE_COND))) {
		wpa_printf(MSG_DEBUG, "NAN: Invalid entry type=0x%x", type);
		return -1;
	}

	preference = BITS(ctrl, NAN_AVAIL_ENTRY_CTRL_USAGE_PREF_MASK,
			  NAN_AVAIL_ENTRY_CTRL_USAGE_PREF_POS);
	if (!preference && type == NAN_AVAIL_ENTRY_CTRL_TYPE_POTENTIAL) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Skip potential entry with 0 usage preference");
		return 0;
	}

	utilization = BITS(ctrl, NAN_AVAIL_ENTRY_CTRL_UTIL_MASK,
			   NAN_AVAIL_ENTRY_CTRL_UTIL_POS);

	if (utilization > NAN_AVAIL_ENTRY_CTRL_UTIL_MAX &&
	    utilization != NAN_AVAIL_ENTRY_CTRL_UTIL_UNKNOWN) {
		wpa_printf(MSG_DEBUG, "NAN: Invalid tbm utilization");
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN: Avail entry: map_id=%u, ctrl=0x%04x, entry_len=%u, type=0x%x, pref=0x%x",
		   map_id, ctrl, entry_len, type, preference);

	entry = os_zalloc(sizeof(*entry));
	if (!entry) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Failed to allocate availability entry");
		return -1;
	}

	entry->map_id = map_id;
	entry->type = type;
	entry->preference = preference;
	entry->utilization = utilization;
	dl_list_init(&entry->list);

	entry->rx_nss = BITS(ctrl, NAN_AVAIL_ENTRY_CTRL_RX_NSS_MASK,
			     NAN_AVAIL_ENTRY_CTRL_RX_NSS_POS);
	if (!entry->rx_nss) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Avail entry with rx_nss=0. Override to 1");
		entry->rx_nss = 1;
	}

	len = entry_len - MIN_AVAIL_ENTRY_LEN;
	pos = avail_entry->optional;

	if (ctrl & NAN_AVAIL_ENTRY_CTRL_TBM_PRESENT) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Availability entry: Time bitmap is set");

		if (len < sizeof(struct nan_tbm)) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Time bitmap set: length too short");
			goto out;
		}

		if (nan_parse_tbm(nan, &entry->tbm, pos, len))
			goto out;

		pos += entry->tbm.len + sizeof(struct nan_tbm);
		len -= entry->tbm.len + sizeof(struct nan_tbm);
	} else {
		entry->tbm.len = 0;
		os_memset(entry->tbm.bitmap, 0, sizeof(entry->tbm.bitmap));
	}

	if (nan_parse_band_chan_list(nan, entry,
				     (const struct nan_band_chan_list *) pos,
				     len))
		goto out;

	/*
	 * An entry with committed/conditional can either have a single channel
	 * entry, or multiple channel entries. The latter case is allowed only
	 * if the entry is also potential, in which case the first channel entry
	 * belongs to the committed entry and the other channels are potential.
	 */
	if (entry->type & (NAN_AVAIL_ENTRY_CTRL_TYPE_COMMITTED |
			   NAN_AVAIL_ENTRY_CTRL_TYPE_COND)) {
		if (entry->band_chan_type != NAN_TYPE_CHANNEL) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Committed/cond avail entry with band");
			goto out;
		}

		if (entry->n_band_chan < 1) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Committed/cond avail entry: no channels");
			goto out;
		}

		if (entry->n_band_chan > 1) {
			struct nan_avail_entry *pot_avail;

			if (!(entry->type &
			      NAN_AVAIL_ENTRY_CTRL_TYPE_POTENTIAL)) {
				wpa_printf(MSG_DEBUG,
					   "NAN: Committed/cond avail entry: %u chans",
					   entry->n_band_chan);
				goto out;
			}

			pot_avail = nan_split_avail_entry(nan, entry);
			if (!pot_avail)
				goto out;

			dl_list_add(&peer_info->avail_entries,
				    &pot_avail->list);
		} else {
			/*
			 * Committed/conditional with single channel entry.
			 * Clear the potential in case that it is set.
			 */
			entry->type &= ~NAN_AVAIL_ENTRY_CTRL_TYPE_POTENTIAL;
		}
	}

	dl_list_add(&peer_info->avail_entries, &entry->list);
	return 0;

out:
	nan_del_avail_entry(entry);
	return -1;
}


/*
 * nan_parse_avail_attr - Parse NAN Availability attribute
 *
 * @nan: NAN module context from nan_init()
 * @peer_info: Peer info where the parsed entries would be added
 * @avail_attr: Pointer to the availability attribute
 *
 * Parse availability attribute as defined in Wi-Fi Aware Specification
 * v4.0, section 9.5.17.1.
 */
static int nan_parse_avail_attr(struct nan_data *nan,
				struct nan_peer_info *peer_info,
				const struct nan_avail *avail_attr,
				u16 attr_len)
{
	u8 map_id;
	const u8 *entries;
	u16 ctrl, entries_len;

	wpa_printf(MSG_DEBUG, "NAN: Parse avail attr: len=%u", attr_len);
	if (attr_len < sizeof(*avail_attr))
		return -1;

	ctrl = le_to_host16(avail_attr->ctrl);
	map_id = ctrl & NAN_AVAIL_CTRL_MAP_ID_MASK;

	entries = avail_attr->optional;
	entries_len = attr_len - sizeof(*avail_attr);
	if (!entries_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Availability attribute without any entries");
		return -1;
	}

	while (entries_len > 2) {
		u16 entry_len = WPA_GET_LE16(entries);
		const struct nan_avail_ent *avail_entry =
			(const struct nan_avail_ent *) entries;

		if (entry_len + 2 > entries_len) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Truncated availability entry");
			return -1;
		}

		if (nan_parse_avail_entry(nan, peer_info, avail_entry,
					  entry_len, map_id))
			return -1;

		entries += entry_len + 2;
		entries_len -= entry_len + 2;
	}

	if (entries_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Availability entries list truncated");
		return -1;
	}

	return 0;
}


static void nan_peer_dump_info(struct nan_data *nan, struct nan_peer_info *info)
{
	struct nan_avail_entry *entry;

	wpa_printf(MSG_DEBUG,
		   "NAN: info: seen=%lu.%lu, seq_id=%u",
		   info->last_seen.sec, info->last_seen.usec,
		   info->seq_id);

	dl_list_for_each(entry, &info->avail_entries, struct nan_avail_entry,
			 list) {
		unsigned int i;

		wpa_printf(MSG_DEBUG,
			   "NAN: entry: map_id=%u, type=0x%x, pref=%u, util=%u",
			   entry->map_id, entry->type, entry->preference,
			   entry->utilization);
		wpa_printf(MSG_DEBUG,
			   "NAN: entry: band_channel_type=%u, n_band_chan=%u",
			   entry->band_chan_type, entry->n_band_chan);

		for (i = 0; i < entry->n_band_chan; i++) {
			struct nan_band_chan *bc = &entry->band_chan[i];

			if (entry->type == NAN_TYPE_BAND)
				wpa_printf(MSG_DEBUG,
					   "NAN: band: %u", bc->u.band_id);
			else
				wpa_printf(MSG_DEBUG,
					   "NAN: channel: oc=%u, cbtm=0x%x, pcbtm=0x%x",
					   bc->u.chan.op_class,
					   bc->u.chan.chan_bitmap,
					   bc->u.chan.pri_chan_bitmap);
		}
	}
}


static void nan_peer_dump(struct nan_data *nan, struct nan_peer *peer)
{
	wpa_printf(MSG_DEBUG,
		   "NAN: peer: " MACSTR " last_seen=%lu.%lu",
		   MAC2STR(peer->nmi_addr), peer->last_seen.sec,
		   peer->last_seen.usec);

	nan_peer_dump_info(nan, &peer->info);
}


/*
 * Update the old peer info with information from the new peer info.
 * Information that is available in the old peer info but is not available
 * in the new peer info will not be changed.
 */
static void nan_merge_peer_info(struct nan_peer_info *old,
				struct nan_peer_info *new)
{
	if (!dl_list_empty(&new->avail_entries)) {
		struct nan_avail_entry *avail, *tmp;

		nan_peer_flush_avail(old);
		dl_list_init(&old->avail_entries);

		dl_list_for_each_safe(avail, tmp, &new->avail_entries,
				      struct nan_avail_entry, list) {
			dl_list_del(&avail->list);
			dl_list_add(&old->avail_entries, &avail->list);
		}
		old->seq_id = new->seq_id;
	}

	old->last_seen = new->last_seen;
}


static int nan_avail_info(struct nan_data *nan, struct nan_peer *peer,
			  struct nan_attrs *attrs, struct nan_peer_info *info)
{
	const struct nan_avail *avail_attr;
	const struct nan_attrs_entry *attr;

	attr = dl_list_first(&attrs->avail, struct nan_attrs_entry, list);
	if (!attr)
		return 0;

	avail_attr = (const struct nan_avail *) attr->ptr;

	/*
	 * The sequence ID may wrap around, so if the received sequence iD is
	 * much smaller than the sequence ID of the last update, assume it has
	 * wrapped around and accept the new schedule. Otherwise, ignore it as
	 * an old schedule.
	 */
	if (!dl_list_empty(&peer->info.avail_entries) &&
	    peer->info.seq_id >= avail_attr->seq_id &&
	    peer->info.seq_id - avail_attr->seq_id < 128) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Ignore peer avail update: seq_id=%hhu, seq_id=%hhu",
			   avail_attr->seq_id, peer->info.seq_id);
		return 0;
	}

	info->seq_id = avail_attr->seq_id;

	dl_list_for_each(attr, &attrs->avail, struct nan_attrs_entry, list) {
		avail_attr = (const struct nan_avail *) attr->ptr;

		if (avail_attr->seq_id != info->seq_id) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Not all avail attributes have the same seq_id");
			goto out;
		}

		if (nan_parse_avail_attr(nan, info, avail_attr, attr->len))
			goto out;
	}

	return 0;
out:
	nan_peer_flush_avail(info);
	return -1;
}


static struct nan_dev_capa_entry * nan_get_dev_capa_entry(struct nan_peer *peer,
							  u8 map_id)
{
	struct nan_dev_capa_entry *entry;

	dl_list_for_each(entry, &peer->info.dev_capa,
			 struct nan_dev_capa_entry, list) {
		if (entry->map_id == map_id)
			return entry;
	}

	return NULL;
}


static void nan_parse_peer_device_capa_attr(struct nan_data *nan,
					    struct nan_peer *peer,
					    const struct nan_attrs_entry *attr)
{
	const struct nan_device_capa *capa;
	struct nan_dev_capa_entry *entry;

	capa = (const struct nan_device_capa *) attr->ptr;

	/* See if we already have an entry for this map ID */
	entry = nan_get_dev_capa_entry(peer, capa->map_id);
	if (!entry) {
		entry = os_zalloc(sizeof(*entry));
		if (!entry) {
			wpa_printf(MSG_INFO,
				   "NAN: Failed to allocate device capability entry");
			return;
		}

		dl_list_init(&entry->list);
		dl_list_add(&peer->info.dev_capa, &entry->list);
	}

	entry->map_id = capa->map_id;
	entry->capa.cdw_info = le_to_host16(capa->cdw_info);
	entry->capa.supported_bands = capa->supported_bands;
	entry->capa.op_mode = capa->op_mode;
	entry->capa.n_antennas = capa->ant;
	entry->capa.channel_switch_time =
		le_to_host16(capa->channel_switch_time);
	entry->capa.capa = capa->capa;
}


static void nan_parse_peer_device_capa(struct nan_data *nan,
				       struct nan_peer *peer,
				       const struct nan_attrs *attrs)
{
	const struct nan_attrs_entry *attr;

	dl_list_for_each(attr, &attrs->dev_capa, struct nan_attrs_entry, list)
		nan_parse_peer_device_capa_attr(nan, peer, attr);
}


static void nan_parse_peer_elem_container_attr(
	struct nan_data *nan, struct nan_peer *peer,
	const struct nan_attrs_entry *attr)
{
	struct nan_elem_container_entry *entry, *next;
	u8 map_id = *attr->ptr;

	/* Guarantee that there is only a single entry for each map ID */
	dl_list_for_each_safe(entry, next, &peer->info.element_container,
			      struct nan_elem_container_entry, list) {
		if (entry->map_id == map_id) {
			dl_list_del(&entry->list);
			os_free(entry);
			break;
		}
	}

	entry = os_zalloc(sizeof(*entry) + attr->len - 1);
	if (!entry) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Failed to allocate element container entry");
		return;
	}

	dl_list_init(&entry->list);
	dl_list_add(&peer->info.element_container, &entry->list);

	entry->map_id = map_id;
	entry->len = attr->len - 1;
	os_memcpy(entry->data, attr->ptr + 1, entry->len);
}


static void nan_parse_peer_elem_container(struct nan_data *nan,
					  struct nan_peer *peer,
					  const struct nan_attrs *attrs)
{
	const struct nan_attrs_entry *attr;

	dl_list_for_each(attr, &attrs->element_container,
			 struct nan_attrs_entry, list)
		nan_parse_peer_elem_container_attr(nan, peer, attr);
}


/*
 * nan_parse_device_attrs - Parse device attributes and build availability info
 *
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer
 * @attrs_data: Buffer holding the device attributes
 * @attrs_len: Length of &attrs_data in octets
 * Return 0 on success; -1 otherwise.
 */
int nan_parse_device_attrs(struct nan_data *nan, struct nan_peer *peer,
			   const u8 *attrs_data, size_t attrs_len)
{
	struct nan_peer_info info;
	struct nan_attrs attrs;
	int ret;

	os_memset(&info, 0, sizeof(info));
	dl_list_init(&info.avail_entries);
	os_get_reltime(&info.last_seen);

	if (nan_parse_attrs(nan, attrs_data, attrs_len, &attrs)) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Failed to parse peer " MACSTR " attributes",
			   MAC2STR(peer->nmi_addr));
		return -1;
	}

	if (nan_avail_info(nan, peer, &attrs, &info)) {
		ret = -1;
		goto out;
	}

	nan_merge_peer_info(&peer->info, &info);
	nan_parse_peer_device_capa(nan, peer, &attrs);
	nan_parse_peer_elem_container(nan, peer, &attrs);

	nan_peer_dump(nan, peer);
	ret = 0;
out:
	nan_attrs_clear(nan, &attrs);
	return ret;
}


static struct nan_peer * nan_alloc_peer(struct nan_data *nan)
{
	struct nan_peer *peer, *oldest = NULL;
	size_t count = 0;

	dl_list_for_each(peer, &nan->peer_list, struct nan_peer, list) {
		count++;

		/* Do not expire peers that we have NDPs with */
		if (!dl_list_empty(&peer->ndps) || peer->ndp_setup.ndp)
			continue;

		if (!oldest ||
		    os_reltime_before(&peer->last_seen, &oldest->last_seen))
			oldest = peer;
	}

	if (count >= NAN_MAX_PEERS) {
		if (!oldest) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Cannot remove any of the peers");
			return NULL;
		}

		wpa_printf(MSG_DEBUG,
			   "NAN: Remove peer=" MACSTR " to make room",
			   MAC2STR(oldest->nmi_addr));

		nan_del_peer(nan, oldest);
	}

	peer = os_zalloc(sizeof(*peer));
	if (!peer)
		return NULL;

	dl_list_init(&peer->info.avail_entries);
	dl_list_init(&peer->info.dev_capa);
	dl_list_init(&peer->info.element_container);
	dl_list_init(&peer->info.sec);

	dl_list_add(&nan->peer_list, &peer->list);
	dl_list_init(&peer->ndps);
	return peer;
}


int nan_add_peer(struct nan_data *nan, const u8 *addr,
		 const u8 *device_attrs, size_t device_attrs_len)
{
	struct nan_peer *peer;

	/* Allow adding peer devices even if NAN was not started, to support
	 * discovery during USD, etc. */
	if (!nan)
		return -1;

	/* TODO: parse the device attributes to update the peer information */
	if (!device_attrs || !device_attrs_len) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Ignore add_peer with no device attributes");
		return -1;
	}

	peer = nan_get_peer(nan, addr);
	if (!peer) {
		peer = nan_alloc_peer(nan);
		if (!peer)
			return -1;

		os_memcpy(peer->nmi_addr, addr, ETH_ALEN);
	}

	os_get_reltime(&peer->last_seen);
	return 0;
}


static void nan_action_build_header(struct nan_data *nan, struct wpabuf *buf,
				    enum nan_subtype subtype)
{
	/* TODO: need to also support protected dual */
	wpabuf_put_u8(buf, WLAN_ACTION_PUBLIC);
	wpabuf_put_u8(buf, WLAN_PA_VENDOR_SPECIFIC);
	wpabuf_put_be24(buf, OUI_WFA);
	wpabuf_put_u8(buf, NAN_NAF_OUI_TYPE);
	wpabuf_put_u8(buf, subtype);
}


static int nan_action_build(struct nan_data *nan, struct nan_peer *peer,
			    enum nan_subtype subtype, struct wpabuf *buf)
{
	int ret;

	wpa_printf(MSG_DEBUG, "NAN: Build NAF");

	nan_action_build_header(nan, buf, subtype);

	nan_add_dev_capa_attr(nan, buf);

	ret = nan_ndp_add_ndp_attr(nan, peer, buf);
	if (ret)
		return ret;

	ret = nan_sec_add_attrs(nan, peer, subtype, buf);
	if (ret)
		return ret;

	ret = nan_ndl_add_avail_attrs(nan, peer, buf);
	if (ret)
		return ret;

	ret = nan_ndl_add_ndc_attr(nan, peer, buf);
	if (ret)
		return ret;

	ret = nan_ndl_add_ndl_attr(nan, peer, buf);
	if (ret)
		return ret;

	ret = nan_ndl_add_qos_attr(nan, peer, buf);
	if (ret)
		return ret;

	nan_ndl_add_elem_container_attr(nan, peer, buf);

	wpa_printf(MSG_DEBUG, "NAN: Build NAF: Done");

	return 0;
}


static int nan_action_send(struct nan_data *nan, struct nan_peer *peer,
			   enum nan_subtype subtype)
{
	struct wpabuf *buf;
	int ret;

	buf = wpabuf_alloc(NAN_MAX_NAF_LEN);
	if (!buf)
		return -1;

	ret = nan_action_build(nan, peer, subtype, buf);
	if (ret)
		goto out;

	ret = nan_sec_pre_tx(nan, peer, buf);
	if (ret)
		goto out;

	if (!nan->cfg->send_naf)
		goto out;
	ret = nan->cfg->send_naf(nan->cfg->cb_ctx, peer->nmi_addr, NULL,
				 nan->cluster_id, buf);

out:
	wpa_printf(MSG_DEBUG, "NAN: send_naf: ret=%d", ret);
	wpabuf_free(buf);
	return ret;
}


static bool nan_ndp_supported(struct nan_data *nan)
{
	if (nan->cfg->ndp_action_notif && nan->cfg->ndp_connected &&
	    nan->cfg->ndp_disconnected &&
	    nan->cfg->send_naf && nan->cfg->get_chans &&
	    nan->cfg->is_valid_publish_id)
		return true;

	wpa_printf(MSG_DEBUG, "NAN: NDP operations are not supported");
	return false;
}


static void nan_peer_state_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct nan_data *nan = eloop_ctx;
	struct nan_peer *peer = timeout_ctx;

	wpa_printf(MSG_DEBUG, "NAN: Timeout expired: " MACSTR,
		   MAC2STR(peer->nmi_addr));

	if (!peer->ndp_setup.ndp)
		return;

	nan_ndp_disconnected(nan, peer, NAN_REASON_UNSPECIFIED_REASON);
}


static void nan_set_peer_timeout(struct nan_data *nan, struct nan_peer *peer,
				 unsigned int sec, unsigned int usec)
{
	wpa_printf(MSG_DEBUG, "NAN: Set timeout: " MACSTR " %u.%06u sec",
		   MAC2STR(peer->nmi_addr), sec, usec);

	eloop_cancel_timeout(nan_peer_state_timeout, nan, peer);
	eloop_register_timeout(sec, usec, nan_peer_state_timeout, nan, peer);
}


static void nan_ndp_action_notif(struct nan_data *nan, struct nan_peer *peer)
{
	struct nan_ndp_action_notif_params notify;

	os_memset(&notify, 0, sizeof(notify));

	os_memcpy(notify.ndp_id.peer_nmi, peer->nmi_addr, ETH_ALEN);
	os_memcpy(notify.ndp_id.init_ndi, peer->ndp_setup.ndp->init_ndi,
		  ETH_ALEN);
	notify.ndp_id.id = peer->ndp_setup.ndp->ndp_id;
	notify.publish_inst_id = peer->ndp_setup.publish_inst_id;

	notify.is_request = peer->ndp_setup.state == NAN_NDP_STATE_REQ_RECV;
	notify.ndp_status = peer->ndp_setup.status;

	if (peer->ndl)
		notify.ndl_status = peer->ndl->status;
	else
		notify.ndl_status = NAN_NDL_STATUS_REJECTED;

	notify.ssi = peer->ndp_setup.ssi;
	notify.ssi_len = peer->ndp_setup.ssi_len;

	if (peer->ndp_setup.sec.present) {
		notify.csid = peer->ndp_setup.sec.i_csid;
		notify.pmkid = peer->ndp_setup.sec.i_pmkid;
	} else {
		notify.csid = NAN_CS_NONE;
		notify.pmkid = NULL;
	}

	wpa_printf(MSG_DEBUG,
		   "NAN: NDP action notification peer=" MACSTR
		   ", ndp_status=%u, ndl_status=%u",
		   MAC2STR(peer->nmi_addr), notify.ndp_status,
		   notify.ndl_status);

	if (nan->cfg->ndp_action_notif)
		nan->cfg->ndp_action_notif(nan->cfg->cb_ctx, &notify);
	nan_set_peer_timeout(nan, peer, NAN_NDP_SETUP_TIMEOUT_LONG, 0);
}


static void nan_ndp_connected(struct nan_data *nan, struct nan_peer *peer)
{
	struct nan_ndp_connection_params params;

	os_memset(&params, 0, sizeof(params));

	wpa_printf(MSG_DEBUG, "NAN: NDP connected notification peer=" MACSTR,
		   MAC2STR(peer->nmi_addr));

	os_memcpy(params.ndp_id.peer_nmi, peer->nmi_addr, ETH_ALEN);
	os_memcpy(params.ndp_id.init_ndi, peer->ndp_setup.ndp->init_ndi,
		  ETH_ALEN);
	params.ndp_id.id = peer->ndp_setup.ndp->ndp_id;
	params.ssi = peer->ndp_setup.ssi;
	params.ssi_len = peer->ndp_setup.ssi_len;

	if (peer->ndp_setup.ndp->initiator) {
		params.local_ndi = peer->ndp_setup.ndp->init_ndi;
		params.peer_ndi = peer->ndp_setup.ndp->resp_ndi;
	} else {
		params.local_ndi = peer->ndp_setup.ndp->resp_ndi;
		params.peer_ndi = peer->ndp_setup.ndp->init_ndi;
	}

	nan_sec_ndp_store_keys(nan, peer, params.peer_ndi, params.local_ndi);

	if (nan->cfg->ndp_connected)
		nan->cfg->ndp_connected(nan->cfg->cb_ctx, &params);

	/* Move the NDP to the list of tracked NDPs */
	dl_list_add(&peer->ndps, &peer->ndp_setup.ndp->list);
	peer->ndp_setup.ndp = NULL;

	nan_ndp_setup_stop(nan, peer);
}


static void nan_ndp_disconnected(struct nan_data *nan, struct nan_peer *peer,
				 enum nan_reason reason)
{
	const u8 *local_ndi, *peer_ndi;
	struct nan_ndp_id ndp_id;

	os_memset(&ndp_id, 0, sizeof(ndp_id));

	wpa_printf(MSG_DEBUG,
		   "NAN: NDP disconnected notification peer=" MACSTR,
		   MAC2STR(peer->nmi_addr));

	os_memcpy(ndp_id.peer_nmi, peer->nmi_addr, ETH_ALEN);
	os_memcpy(ndp_id.init_ndi, peer->ndp_setup.ndp->init_ndi, ETH_ALEN);
	ndp_id.id = peer->ndp_setup.ndp->ndp_id;

	if (peer->ndp_setup.ndp->initiator) {
		local_ndi = peer->ndp_setup.ndp->init_ndi;
		peer_ndi = peer->ndp_setup.ndp->resp_ndi;
	} else {
		local_ndi = peer->ndp_setup.ndp->resp_ndi;
		peer_ndi = peer->ndp_setup.ndp->init_ndi;
	}

	if (nan->cfg->ndp_disconnected)
		nan->cfg->ndp_disconnected(nan->cfg->cb_ctx, &ndp_id,
					   local_ndi, peer_ndi, reason);

	nan_ndp_setup_stop(nan, peer);
}


/**
 * nan_action_rx_ndp - Process a received NAN Data Path Action Frame
 * @nan: NAN module context from nan_init()
 * @peer: NAN peer
 * @msg: Parsed NAN message
 * @resp_oui: OUI subtype to use in case a response is needed
 * Returns: 0 on success; -1 on failure.
 */
static int nan_action_rx_ndp(struct nan_data *nan, struct nan_peer *peer,
			     struct nan_msg *msg, enum nan_subtype resp_oui)
{
	int ret;

	ret = nan_ndp_handle_ndp_attr(nan, peer, msg);
	if (ret) {
		if (ret > 0)
			ret = 0;
		return ret;
	}

	/*
	 * NDP request: Also process the NDL/NDC/QoS attributes and store the
	 * data without actually scheduling. Send an indication to the
	 * encapsulating logic.
	 */
	if (peer->ndp_setup.state == NAN_NDP_STATE_REQ_RECV) {
		wpa_printf(MSG_DEBUG, "NAN: NDP request");

		ret = nan_ndl_handle_ndl_attr(nan, peer, msg);
		if (ret || !peer->ndl) {
			nan_ndp_setup_stop(nan, peer);
			return -1;
		}

		nan_ndp_action_notif(nan, peer);
		return 0;
	}

	/*
	 * NDP was rejected by the peer. Clear the ongoing setup and send an
	 * event. There is no need to send an NAF in this case.
	 */
	if (peer->ndp_setup.status == NAN_NDP_STATUS_REJECTED) {
		wpa_printf(MSG_DEBUG, "NAN: NAF: NDP rejected");

		nan_ndp_disconnected(nan, peer, peer->ndp_setup.reason);
		return 0;
	}

	/*
	 * NDP state machine is either done or continued, need to trigger NDL
	 * state machine.
	 */
	ret = nan_ndl_handle_ndl_attr(nan, peer, msg);
	if (ret || !peer->ndl)
		return ret;

	if (peer->ndl->status == NAN_NDL_STATUS_REJECTED) {
		enum nan_reason reason = peer->ndl->reason;

		if (reason == NAN_REASON_RESERVED)
			reason = NAN_REASON_UNSPECIFIED_REASON;

		wpa_printf(MSG_DEBUG,
			   "NAN: NAF: NDL rejected(ret=%d, reason=%u)",
			   ret, reason);

		/* NDL handling failure on local side */
		if (peer->ndl->send_naf_on_error) {
			nan_ndp_setup_failure(nan, peer, reason, 0);
			ret = nan_action_send(nan, peer, resp_oui);
		}

		nan_ndp_disconnected(nan, peer, reason);
		return 0;
	}

	if (peer->ndl->status == NAN_NDL_STATUS_CONTINUED) {
		wpa_printf(MSG_DEBUG, "NAN: NAF: NDL continues");
		nan_ndp_action_notif(nan, peer);
		return 0;
	}

	/* Both state machines are done */
	if (peer->ndp_setup.state == NAN_NDP_STATE_DONE &&
	    peer->ndl->state == NAN_NDL_STATE_DONE) {
		wpa_printf(MSG_DEBUG, "NAN: NAF: NDP setup done");

		nan_ndp_connected(nan, peer);
		return 0;
	}

	wpa_printf(MSG_DEBUG, "NAN: NAF: NDP setup continues");
	ret = nan_action_send(nan, peer, resp_oui);
	if (ret) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NAF: Failed to send NAF. Resetting..");
		nan_ndp_disconnected(nan, peer, NAN_REASON_UNSPECIFIED_REASON);
	}

	nan_set_peer_timeout(nan, peer, NAN_NDP_SETUP_TIMEOUT_SHORT, 0);

	return 0;
}


/*
 * nan_action_rx - Process a received NAN Action Frame
 * @nan: NAN module context from nan_init()
 * @mgmt: Pointer to the IEEE 802.11 Management frame
 * @len: Length of the Management frame in octets
 * Return 0 on success; -1 on failure.
 */
int nan_action_rx(struct nan_data *nan, const struct ieee80211_mgmt *mgmt,
		  size_t len)
{
	struct nan_msg msg;
	struct nan_peer *peer;
	enum nan_subtype resp_oui = NAN_SUBTYPE_INVALID;
	int ret;

	if (!nan_ndp_supported(nan))
		return -1;

	/* Parse the NAF and validate its general structure */
	ret = nan_parse_naf(nan, mgmt, len, &msg);
	if (ret)
		return ret;

	ret = nan_add_peer(nan, mgmt->sa, mgmt->u.action.u.naf.variable,
			   len - IEEE80211_MIN_ACTION_LEN(naf));
	if (ret)
		wpa_printf(MSG_DEBUG, "NAN: Failed to parse peer from NAF");

	peer = nan_get_peer(nan, mgmt->sa);
	if (!peer) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Failed to get a peer that was just added");
		goto done;
	}

	wpa_printf(MSG_DEBUG, "NAN: NAF: oui_subtype=%u", msg.oui_subtype);

	ret = nan_parse_device_attrs(nan, peer, mgmt->u.action.u.naf.variable,
				     len - IEEE80211_MIN_ACTION_LEN(naf));
	if (ret) {
		wpa_printf(MSG_DEBUG,
			   "NAN: NAF: Failed to parse device attributes");
		goto done;
	}

	switch (msg.oui_subtype) {
	case NAN_SUBTYPE_DATA_PATH_REQUEST:
		resp_oui = NAN_SUBTYPE_DATA_PATH_RESPONSE;
		break;
	case NAN_SUBTYPE_DATA_PATH_RESPONSE:
		resp_oui = NAN_SUBTYPE_DATA_PATH_CONFIRM;
		break;
	case NAN_SUBTYPE_DATA_PATH_CONFIRM:
		resp_oui = NAN_SUBTYPE_DATA_PATH_KEY_INSTALL;
		break;
	case NAN_SUBTYPE_DATA_PATH_KEY_INSTALL:
	case NAN_SUBTYPE_DATA_PATH_TERMINATION:
		break;
	case NAN_SUBTYPE_RANGING_REQUEST:
	case NAN_SUBTYPE_RANGING_RESPONSE:
	case NAN_SUBTYPE_RANGING_TERMINATION:
	case NAN_SUBTYPE_RANGING_REPORT:
	case NAN_SUBTYPE_SCHEDULE_REQUEST:
	case NAN_SUBTYPE_SCHEDULE_RESPONSE:
	case NAN_SUBTYPE_SCHEDULE_CONFIRM:
	case NAN_SUBTYPE_SCHEDULE_UPDATE_NOTIF:
		ret = 0;
		goto done;
	default:
		ret = -1;
		goto done;
	}

	ret = nan_action_rx_ndp(nan, peer, &msg, resp_oui);
done:
	nan_attrs_clear(nan, &msg.attrs);
	return ret;
}


/*
 * nan_publish_instance_id_valid - Check if instance ID is a valid publish ID
 * @nan: NAN module context from nan_init()
 * @instance_id: Instance ID to check
 * @service_id: On return, holds the service ID if the instance ID is valid
 * Returns: true if there is a local publish service ID with the given instance
 * ID; false otherwise
 */
bool nan_publish_instance_id_valid(struct nan_data *nan, u8 instance_id,
				   u8 *service_id)
{
	if (!nan->cfg->is_valid_publish_id) {
		wpa_printf(MSG_INFO,
			   "NAN: is_valid_publish_id callback not defined");
		return false;
	}

	return nan->cfg->is_valid_publish_id(nan->cfg->cb_ctx, instance_id,
					     service_id);
}


/*
 * nan_set_cluster_id - Set the cluster ID
 * @nan: NAN module context from nan_init()
 * @cluster_id: The cluster ID (6 bytes)
 */
void nan_set_cluster_id(struct nan_data *nan, const u8 *cluster_id)
{
	os_memcpy(nan->cluster_id, cluster_id, sizeof(nan->cluster_id));
}


/*
 * nan_tx_status - Notification of the result of a transmitted NAN Action frame
 * @nan: NAN module context from nan_init()
 * @dst: Destination address of the transmitted frame
 * @data: The transmitted frame
 * @data_len: Length of the transmitted frame in octets
 * @acked: Whether the frame was acknowledged
 * Returns: 0 if the frame is a NAF and -1 if not.
 */
int nan_tx_status(struct nan_data *nan, const u8 *dst, const u8 *data,
		  size_t data_len, bool acked)
{
	struct nan_peer *peer;
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *)data;
	u8 subtype;
	int ret;

	if (!nan_is_naf(mgmt, data_len) || !dst)
		return -1;

	wpa_printf(MSG_DEBUG, "NAN: TX status: peer=" MACSTR ", acked=%u",
		   MAC2STR(dst), acked);

	peer = nan_get_peer(nan, dst);
	if (!peer) {
		wpa_printf(MSG_DEBUG, "NAN: TX status: peer not found");
		return 0;
	}

	subtype = mgmt->u.action.u.naf.subtype;

	ret = nan_ndp_naf_sent(nan, peer, subtype);
	ret |= nan_ndl_naf_sent(nan, peer, subtype);

	if (ret || peer->ndp_setup.status == NAN_NDP_STATUS_REJECTED ||
	    !peer->ndl || peer->ndl->status == NAN_NDL_STATUS_REJECTED) {
		wpa_printf(MSG_DEBUG,
			   "NAN: TX status: Stopping NDP establishment. ret=%d",
			   ret);

		if (peer->ndp_setup.ndp)
			nan_ndp_disconnected(nan, peer, peer->ndp_setup.reason);
		return 0;
	}

	/* Both state machines are done */
	if (peer->ndp_setup.state == NAN_NDP_STATE_DONE &&
	    peer->ndl->state == NAN_NDL_STATE_DONE) {
		wpa_printf(MSG_DEBUG, "NAN: TX status: NDP setup done");
		nan_ndp_connected(nan, peer);
	}

	return 0;
}


int nan_handle_ndp_setup(struct nan_data *nan, struct nan_ndp_params *params)
{
	struct nan_peer *peer;
	enum nan_subtype naf_oui = NAN_SUBTYPE_INVALID;
	unsigned int timeout;
	int ret;

	if (!nan_ndp_supported(nan))
		return -1;

	peer = nan_get_peer(nan, params->ndp_id.peer_nmi);
	if (!peer) {
		wpa_printf(MSG_DEBUG, "NAN: NDP peer not found");
		return -1;
	}

	switch (params->type) {
	case NAN_NDP_ACTION_REQ:
		params->ndp_id.id = nan_get_next_ndp_id(nan);
		ret = nan_ndp_setup_req(nan, peer, params);
		if (ret)
			return ret;

		ret = nan_ndl_setup(nan, peer, params);
		if (ret) {
			nan_ndp_setup_stop(nan, peer);
			return ret;
		}

		naf_oui = NAN_SUBTYPE_DATA_PATH_REQUEST;
		timeout = NAN_NDP_SETUP_TIMEOUT_LONG;
		break;
	case NAN_NDP_ACTION_RESP:
		/*
		 * NDL establishment as part of the NDP establishment. It is
		 * possible that this would use an already existing NDL or start
		 * a new NDL setup.
		 */
		ret = nan_ndp_setup_resp(nan, peer, params);
		if (ret) {
			nan_ndp_setup_stop(nan, peer);
			return ret;
		}

		if (peer->ndp_setup.status != NAN_NDP_STATUS_REJECTED) {
			ret = nan_ndl_setup(nan, peer, params);
			if (ret) {
				if (peer->ndl && peer->ndl->send_naf_on_error) {
					nan_ndp_setup_failure(
						nan, peer,
						NAN_REASON_NDL_UNACCEPTABLE, 0);
				} else {
					nan_ndp_setup_stop(nan, peer);
					return ret;
				}
			}
		} else if (peer->ndl && dl_list_empty(&peer->ndps)) {
			peer->ndl->status = NAN_NDL_STATUS_REJECTED;
		}

		naf_oui = NAN_SUBTYPE_DATA_PATH_RESPONSE;
		timeout = NAN_NDP_SETUP_TIMEOUT_SHORT;
		break;
	case NAN_NDP_ACTION_CONF:
		ret = nan_ndl_setup(nan, peer, params);
		if (ret) {
			if (peer->ndl && peer->ndl->send_naf_on_error) {
				nan_ndp_setup_failure(
					nan, peer,
					NAN_REASON_NDL_UNACCEPTABLE, 0);
			} else {
				nan_ndp_setup_stop(nan, peer);
				return ret;
			}
		}

		naf_oui = NAN_SUBTYPE_DATA_PATH_CONFIRM;
		timeout = NAN_NDP_SETUP_TIMEOUT_SHORT;
		break;

	case NAN_NDP_ACTION_TERM:
		naf_oui = NAN_SUBTYPE_DATA_PATH_TERMINATION;
		timeout = NAN_NDP_SETUP_TIMEOUT_SHORT;
		ret = nan_ndp_term_req(nan, peer, &params->ndp_id);
		if (ret)
			return ret;
		break;
	default:
		wpa_printf(MSG_DEBUG, "NAN: Unsupported NDP setup type=%u",
			   params->type);
		return -1;
	}

	ret = nan_action_send(nan, peer, naf_oui);
	if (ret) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Failed sending NAF. Resetting: ret=%d", ret);
		nan_ndp_disconnected(nan, peer, peer->ndp_setup.reason);
		return 0;
	}

	nan_set_peer_timeout(nan, peer, timeout, 0);
	return ret;
}


void nan_ndp_terminated(struct nan_data *nan, struct nan_peer *peer,
			struct nan_ndp_id *ndp_id, const u8 *local_ndi,
			const u8 *peer_ndi, enum nan_reason reason)
{
	if (nan->cfg->ndp_disconnected)
		nan->cfg->ndp_disconnected(nan->cfg->cb_ctx, ndp_id, local_ndi,
					   peer_ndi, reason);

	/* Need to also remove the NDL if it is not needed */
	if (dl_list_empty(&peer->ndps) && !peer->ndp_setup.ndp)
		nan_ndl_reset(nan, peer);
}


struct nan_device_capabilities *
nan_peer_get_device_capabilities(struct nan_data *nan, const u8 *addr,
				 u8 map_id)
{
	struct nan_dev_capa_entry *cur;
	struct nan_peer *peer;

	peer = nan_get_peer(nan, addr);
	if (!peer)
		return NULL;

	dl_list_for_each(cur, &peer->info.dev_capa, struct nan_dev_capa_entry,
			 list) {
		if (cur->map_id == map_id)
			return &cur->capa;
	}

	return NULL;
}


int nan_peer_get_tk(struct nan_data *nan, const u8 *addr,
		    const u8 *peer_ndi, const u8 *local_ndi,
		    u8 *tk, size_t *tk_len, enum nan_cipher_suite_id *csid)
{
	struct nan_peer *peer;

	if (!nan || !tk || !tk_len || !csid)
		return -1;

	peer = nan_get_peer(nan, addr);
	if (!peer)
		return -1;

	return nan_sec_get_tk(nan, peer, peer_ndi, local_ndi, tk, tk_len, csid);
}


static void
nan_peer_get_committed_avail_add(const struct nan_data *nan,
				 const struct nan_peer *peer,
				 const struct nan_avail_entry *avail,
				 struct nan_peer_schedule *sched)
{
	struct nan_map *map;
	struct nan_map_chan *chan;
	struct nan_sched_chan schan;
	const struct oper_class_map *op;
	u8 chan_id;
	bool committed;
	int freq, bw, center_freq1, center_freq2, idx;
	u8 i;
	const struct nan_band_chan *band_chan;
	const struct nan_chan_entry *bc_chan;

	if (avail->type != NAN_AVAIL_ENTRY_CTRL_TYPE_COMMITTED &&
	    avail->type != NAN_AVAIL_ENTRY_CTRL_TYPE_COND)
		return;

	/*
	 * This should not happen in practice as committed and conditional
	 * entries should have only a single channel entry.
	 */
	if (avail->n_band_chan != 1) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Skip availability entry with n_band_chan=%u",
			   avail->n_band_chan);
		return;
	}

	band_chan = &avail->band_chan[0];
	bc_chan = &band_chan->u.chan;

	/* Get all the channel parameters */
	op = get_oper_class(NULL, band_chan->u.chan.op_class);
	if (!op) {
		wpa_printf(MSG_DEBUG, "NAN: Unknown operating class %u",
			   band_chan->u.chan.op_class);
		return;
	}

	idx = ffs(le_to_host16(bc_chan->chan_bitmap)) - 1;
	if (idx < 0) {
		wpa_printf(MSG_DEBUG,
			   "NAN: No channel found in chan_bitmap 0x%04x for oper_class %u",
			   le_to_host16(bc_chan->chan_bitmap),
			   bc_chan->op_class);
		return;
	}

	chan_id = op_class_idx_to_chan(op, idx);
	if (!chan_id) {
		wpa_printf(MSG_DEBUG,
			   "NAN: No channel found for oper_class %u idx %u",
			   bc_chan->op_class, idx);
		return;
	}

	freq = ieee80211_chan_to_freq(NULL, bc_chan->op_class, chan_id);
	bw = oper_class_bw_to_int(op);

	center_freq2 = 0;
	if (op->op_class < 128) {
		center_freq1 = ieee80211_get_center_freq(freq, op->bw);
	} else if (op->op_class > 130) {
		wpa_printf(MSG_DEBUG, "NAN: Missing support for op_class %u",
			   op->op_class);
		return;
	} else {
		idx = ffs(bc_chan->pri_chan_bitmap) - 1;
		if (idx < 0) {
			wpa_printf(MSG_DEBUG,
				   "NAN: No primary channel found in pri_chan_bitmap 0x%04x",
				   le_to_host16(bc_chan->pri_chan_bitmap));
			return;
		}

		center_freq1 = freq;
		if (op->bw == BW80 || op->bw == BW80P80)
			freq = freq - 30 + idx * 20;
		else if (op->bw == BW160)
			freq = freq - 70 + idx * 20;

		/* TODO: Missing support for 80 + 80 */
	}

	/* Assume committed for conditional slots if setup is done */
	committed = (avail->type == NAN_AVAIL_ENTRY_CTRL_TYPE_COMMITTED) ||
		(avail->type == NAN_AVAIL_ENTRY_CTRL_TYPE_COND &&
		 peer->ndl->state == NAN_NDL_STATE_DONE &&
		 peer->ndl->status == NAN_NDL_STATUS_ACCEPTED);

	/* Find map ID entry if already exists */
	for (i = 0; i < sched->n_maps; i++)
		if (sched->maps[i].map_id == avail->map_id)
			break;

	map = &sched->maps[i];
	if (i == sched->n_maps) {
		if (sched->n_maps == NAN_MAX_MAPS) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Too many map entries in schedule");
			return;
		}
		sched->n_maps++;
	}

	map->map_id = avail->map_id;

	os_memset(&schan, 0, sizeof(schan));

	/* Find channel entry if already exists */
	for (i = 0; i < map->n_chans; i++) {
		if (map->chans[i].committed != committed)
			return;

		if (map->chans[i].chan.freq == freq &&
		    map->chans[i].chan.bandwidth == bw &&
		    map->chans[i].chan.center_freq1 == center_freq1 &&
		    map->chans[i].chan.center_freq2 == center_freq2)
			break;
	}

	chan = &map->chans[i];
	if (i == map->n_chans) {
		if (map->n_chans == NAN_MAX_CHAN_ENTRIES) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Too many channel entries in schedule map_id=%u",
				   map->map_id);
			return;
		}
		map->n_chans++;
	}

	chan->committed = committed;
	chan->rx_nss = avail->rx_nss;
	chan->chan.freq = freq;
	chan->chan.bandwidth = bw;
	chan->chan.center_freq1 = center_freq1;
	chan->chan.center_freq2 = center_freq2;

	os_memcpy(&chan->tbm, &avail->tbm, sizeof(avail->tbm));
}


static void nan_peer_get_committed_avail(const struct nan_data *nan,
					 const struct nan_peer *peer,
					 struct nan_peer_schedule *sched)
{
	const struct nan_avail_entry *avail;

	dl_list_for_each(avail, &peer->info.avail_entries,
			 struct nan_avail_entry, list)
		nan_peer_get_committed_avail_add(nan, peer, avail, sched);
}


static void nan_peer_set_sched(struct nan_data *nan, struct nan_peer *peer,
			       struct nan_peer_schedule *sched,
			       const u8 *sched_buf, size_t sched_buf_len,
			       bool ndc)
{
	struct dl_list sched_entries;
	struct nan_avail_entry *cur;
	int ret;

	if (!sched->n_maps)
		return;

	if (!sched_buf || !sched_buf_len)
		return;

	if (sched_buf_len < sizeof(struct nan_sched_entry)) {
		wpa_printf(MSG_DEBUG, "NAN: Schedule buffer too short=%zu",
			   sched_buf_len);
		return;
	}

	/* Convert the schedule the availability entries */
	ret = nan_sched_entries_to_avail_entries(nan, &sched_entries,
						 sched_buf, sched_buf_len);
	if (ret) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Failed to parse peer schedule entries");
		return;
	}

	/*
	 * For each schedule entry find the corresponding map in the committed
	 * schedule and store the copy of the time bitmap.
	 */
	dl_list_for_each(cur, &sched_entries, struct nan_avail_entry, list) {
		struct nan_map *map;
		unsigned int i;

		for (i = 0; i < sched->n_maps; i++) {
			map = &sched->maps[i];

			if (map->map_id == cur->map_id)
				break;
		}

		if (i == sched->n_maps) {
			wpa_printf(MSG_DEBUG,
				   "NAN: No map entry found for map_id=%u in peer schedule",
				   cur->map_id);
			continue;
		}

		if (ndc)
			os_memcpy(&map->ndc, &cur->tbm, sizeof(cur->tbm));
		else
			os_memcpy(&map->immutable, &cur->tbm, sizeof(cur->tbm));
	}

	nan_flush_avail_entries(&sched_entries);
}


static void nan_peer_get_ndc_sched(struct nan_data *nan,
				   struct nan_peer *peer,
				   struct nan_peer_schedule *sched)
{
	if (!peer->ndl)
		return;

	nan_peer_set_sched(nan, peer, sched,
			   peer->ndl->ndc_sched,
			   peer->ndl->ndc_sched_len, true);
}


static void nan_peer_get_immut_sched(struct nan_data *nan,
				     struct nan_peer *peer,
				     struct nan_peer_schedule *sched)
{
	if (!peer->ndl)
		return;

	nan_peer_set_sched(nan, peer, sched,
			   peer->ndl->immut_sched,
			   peer->ndl->immut_sched_len, false);
}



/*
 * nan_peer_get_schedule_info - Get peer's schedule information
 * @nan: NAN module context from nan_init()
 * @addr: NAN MAC address of the peer
 * @sched: on return would hold the schedule information.
 * Returns: 0 on success; -1 otherwise.
 */
int nan_peer_get_schedule_info(struct nan_data *nan, const u8 *addr,
			       struct nan_peer_schedule *sched)
{
	struct nan_peer *peer;

	if (!nan || !sched)
		return -1;

	os_memset(sched, 0, sizeof(*sched));

	peer = nan_get_peer(nan, addr);
	if (!peer)
		return -1;

	nan_peer_get_committed_avail(nan, peer, sched);
	nan_peer_get_ndc_sched(nan, peer, sched);
	nan_peer_get_immut_sched(nan, peer, sched);

	return 0;
}


/*
 * nan_peer_get_pot_avail - Get peer's potential availability entries
 * @nan: NAN module context from nan_init()
 * @addr: NAN MAC address of the peer
 * @pot_avail: On return, holds the potential availability entries.
 * Returns 0 on success, -1 on failure
 */
int nan_peer_get_pot_avail(struct nan_data *nan, const u8 *addr,
			   struct nan_peer_potential_avail *pot_avail)
{
	struct nan_avail_entry *avail;
	struct nan_peer *peer;
	u8 i;

	if (!nan || !pot_avail)
		return -1;

	os_memset(pot_avail, 0, sizeof(*pot_avail));

	peer = nan_get_peer(nan, addr);
	if (!peer)
		return -1;

	dl_list_for_each(avail, &peer->info.avail_entries,
			 struct nan_avail_entry, list) {
		struct pot_entry *pot;

		if (avail->type != NAN_AVAIL_ENTRY_CTRL_TYPE_POTENTIAL)
			continue;

		if (pot_avail->n_maps == NAN_MAX_MAPS) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Too many potential maps stored");
			break;
		}

		pot = &pot_avail->maps[pot_avail->n_maps++];
		pot->rx_nss = avail->rx_nss;
		pot->preference = avail->preference;
		pot->utilization = avail->utilization;
		pot->is_band = avail->band_chan_type == NAN_TYPE_BAND;

		for (i = 0; i < avail->n_band_chan; i++, pot->n_band_chan++) {
			const struct nan_band_chan *band_chan;

			if (pot->n_band_chan == NAN_MAX_CHAN_ENTRIES) {
				wpa_printf(MSG_DEBUG,
					   "NAN: Too many band_chan entries stored for potential entry");
				break;
			}

			band_chan = &avail->band_chan[i];

			if (pot->is_band) {
				pot->entries[i].band_id =
					band_chan->u.band_id;
			} else {
				const struct nan_chan_entry *bc_chan;

				bc_chan = &band_chan->u.chan;
				pot->entries[i].op_class = bc_chan->op_class;
				pot->entries[i].chan_bitmap =
					le_to_host16(bc_chan->chan_bitmap);
			}
		}
	}

	return 0;
}
