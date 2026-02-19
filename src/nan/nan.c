/*
 * Wi-Fi Aware - NAN module
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "nan.h"
#include "nan_i.h"

#define NAN_MAX_PEERS 32


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
		nan_ndp_setup_reset(nan, peer);
	}

	dl_list_del(&peer->list);
	nan_peer_flush_avail(&peer->info);
	nan_peer_flush_dev_capa(&peer->info);
	nan_peer_flush_elem_container(&peer->info);

	nan_ndl_reset(nan, peer);
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
	/* TODO: Need implement this logic */
	wpa_printf(MSG_DEBUG,
		   "NAN: TODO: Publish instance ID validation not implemented");
	return true;
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
