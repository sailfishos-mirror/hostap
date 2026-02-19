/*
 * Wi-Fi Aware - NAN module utils
 * Copyright (C) 2025 Intel Corporation
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"
#include "common.h"
#include "common/wpa_common.h"
#include "common/ieee802_11_common.h"
#include "nan_i.h"


static void nan_attrs_clear_list(struct nan_data *nan,
				 struct dl_list *list)
{
	struct nan_attrs_entry *entry, *pentry;

	dl_list_for_each_safe(entry, pentry, list, struct nan_attrs_entry,
			      list) {
		dl_list_del(&entry->list);
		os_free(entry);
	}
}


/*
 * nan_attrs_clear - Free data from NAN parsing
 * @nan: NAN module context from nan_init()
 * @attrs: Parsed nan_attrs
 */
void nan_attrs_clear(struct nan_data *nan, struct nan_attrs *attrs)
{
	nan_attrs_clear_list(nan, &attrs->serv_desc_ext);
	nan_attrs_clear_list(nan, &attrs->avail);
	nan_attrs_clear_list(nan, &attrs->ndc);
	nan_attrs_clear_list(nan, &attrs->dev_capa);
	nan_attrs_clear_list(nan, &attrs->element_container);

	os_memset(attrs, 0, sizeof(*attrs));
}


/*
 * nan_parse_attrs - Parse NAN attributes
 * @nan: NAN module context from nan_init()
 * @data: Buffer holding the attributes
 * @len: Length of &data
 * @attrs: On return would hold the parsed attributes
 * Returns: 0 on success; positive or negative indicate an error
 *
 * Note: In case of success, the caller must free temporary memory allocations
 * by calling nan_attrs_clear() when the parsed data is not needed anymore.
 */
int nan_parse_attrs(struct nan_data *nan, const u8 *data, size_t len,
		    struct nan_attrs *attrs)
{
	struct nan_attrs_entry *entry;
	const u8 *pos = data;
	const u8 *end = pos + len;

	os_memset(attrs, 0, sizeof(*attrs));

	dl_list_init(&attrs->serv_desc_ext);
	dl_list_init(&attrs->avail);
	dl_list_init(&attrs->ndc);
	dl_list_init(&attrs->dev_capa);
	dl_list_init(&attrs->element_container);

	while (end - pos > 3) {
		u8 id = *pos++;
		u16 attr_len = WPA_GET_LE16(pos);

		pos += 2;
		if (attr_len > end - pos)
			goto fail;

		switch (id) {
		case NAN_ATTR_SDEA:
			entry = os_zalloc(sizeof(*entry));
			if (!entry)
				goto fail;

			entry->ptr = pos;
			entry->len = attr_len;
			dl_list_add_tail(&attrs->serv_desc_ext, &entry->list);
			break;
		case NAN_ATTR_DEVICE_CAPABILITY:
			/* Validate Device Capability attribute length */
			if (attr_len < sizeof(struct nan_device_capa))
				break;

			entry = os_zalloc(sizeof(*entry));
			if (!entry)
				goto fail;

			entry->ptr = pos;
			entry->len = attr_len;
			dl_list_add_tail(&attrs->dev_capa, &entry->list);
			break;
		case NAN_ATTR_NDP:
			/* Validate minimal NDP attribute length */
			if (attr_len < sizeof(struct ieee80211_ndp))
				break;

			attrs->ndp = pos;
			attrs->ndp_len = attr_len;
			break;
		case NAN_ATTR_NAN_AVAILABILITY:
			/* Validate minimal Availability attribute length */
			if (attr_len < sizeof(struct nan_avail))
				break;

			entry = os_zalloc(sizeof(*entry));
			if (!entry)
				goto fail;

			entry->ptr = pos;
			entry->len = attr_len;
			dl_list_add_tail(&attrs->avail, &entry->list);
			break;
		case NAN_ATTR_NDC:
			/* Validate minimal NDC attribute length */
			if (attr_len < sizeof(struct ieee80211_ndc))
				break;

			entry = os_zalloc(sizeof(*entry));
			if (!entry)
				goto fail;

			entry->ptr = pos;
			entry->len = attr_len;
			dl_list_add_tail(&attrs->ndc, &entry->list);
			break;
		case NAN_ATTR_NDL:
			/* Validate minimal NDL attribute length */
			if (attr_len < sizeof(struct ieee80211_ndl))
				break;

			attrs->ndl = pos;
			attrs->ndl_len = attr_len;
			break;
		case NAN_ATTR_NDL_QOS:
			/* Validate QoS attribute length */
			if (attr_len < sizeof(struct ieee80211_nan_qos))
				break;

			attrs->ndl_qos = pos;
			attrs->ndl_qos_len = attr_len;
			break;
		case NAN_ATTR_ELEM_CONTAINER:
			/* Validate minimal Element Container attribute length
			 */
			if (attr_len < 1)
				break;

			entry = os_zalloc(sizeof(*entry));
			if (!entry)
				goto fail;

			entry->ptr = pos;
			entry->len = attr_len;
			dl_list_add_tail(&attrs->element_container,
					 &entry->list);
			break;
		case NAN_ATTR_CSIA:
			if (attr_len < sizeof(struct nan_cipher_suite_info) +
			    sizeof(struct nan_cipher_suite))
				break;

			attrs->cipher_suite_info = pos;
			attrs->cipher_suite_info_len = attr_len;
			break;
		case NAN_ATTR_SCIA:
			if (attr_len < sizeof(struct nan_sec_ctxt))
				break;

			attrs->sec_ctxt_info = pos;
			attrs->sec_ctxt_info_len = attr_len;
			break;
		case NAN_ATTR_SHARED_KEY_DESCR:
			if (attr_len < sizeof(struct nan_shared_key) +
			    sizeof(struct wpa_eapol_key))
				break;

			attrs->shared_key_desc = pos;
			attrs->shared_key_desc_len = attr_len;
			break;
		case NAN_ATTR_MASTER_INDICATION:
		case NAN_ATTR_CLUSTER:
		case NAN_ATTR_NAN_ATTR_SERVICE_ID_LIST:
		case NAN_ATTR_SDA:
		case NAN_ATTR_CONN_CAPA:
		case NAN_ATTR_WLAN_INFRA:
		case NAN_ATTR_P2P_OPER:
		case NAN_ATTR_IBSS:
		case NAN_ATTR_MESH:
		case NAN_ATTR_FURTHER_NAN_SD:
		case NAN_ATTR_FURTHER_AVAIL_MAP:
		case NAN_ATTR_COUNTRY_CODE:
		case NAN_ATTR_RANGING:
		case NAN_ATTR_CLUSTER_DISCOVERY:
		case NAN_ATTR_UNALIGNED_SCHEDULE:
		case NAN_ATTR_RANGING_INFO:
		case NAN_ATTR_RANGING_SETUP:
		case NAN_ATTR_FTM_RANGING_REPORT:
		case NAN_ATTR_EXT_WLAN_INFRA:
		case NAN_ATTR_EXT_P2P_OPER:
		case NAN_ATTR_EXT_IBSS:
		case NAN_ATTR_EXT_MESH:
		case NAN_ATTR_PUBLIC_AVAILABILITY:
		case NAN_ATTR_SUBSC_SERVICE_ID_LIST:
		case NAN_ATTR_NDP_EXT:
		case NAN_ATTR_DCEA:
		case NAN_ATTR_NIRA:
		case NAN_ATTR_BPBA:
		case NAN_ATTR_S3:
		case NAN_ATTR_TPEA:
		case NAN_ATTR_VENDOR_SPECIFIC:
			wpa_printf(MSG_DEBUG, "NAN: ignore attr=%u", id);
			break;
		default:
			wpa_printf(MSG_DEBUG, "NAN: unknown attr=%u", id);
			break;
		}

		pos += attr_len;
	}

	/* Parsing is considered success only if all attributes were consumed */
	if (pos == end)
		return 0;

fail:
	nan_attrs_clear(nan, attrs);
	return -1;
}


/*
 * nan_is_naf - Check if a given frame is a NAN Action frame
 * @mgmt: NAN Action frame
 * @len: Length of the Management frame in octets
 * Returns: true if NAF; otherwise false
 */
bool nan_is_naf(const struct ieee80211_mgmt *mgmt, size_t len)
{
	u8 subtype;

	/*
	 * 802.11 header + category + NAN Action frame minimal + subtype (1)
	 */
	if (len < IEEE80211_MIN_ACTION_LEN(naf)) {
		wpa_printf(MSG_DEBUG, "NAN: Too short NAN frame");
		return false;
	}

	if (mgmt->u.action.u.naf.action != WLAN_PA_VENDOR_SPECIFIC ||
	    WPA_GET_BE24(mgmt->u.action.u.naf.oui) != OUI_WFA ||
	    mgmt->u.action.u.naf.oui_type != NAN_NAF_OUI_TYPE)
		return false;

	subtype = mgmt->u.action.u.naf.subtype;

	if (mgmt->u.action.category != WLAN_ACTION_PUBLIC &&
	    !(subtype >= NAN_SUBTYPE_DATA_PATH_REQUEST &&
	      subtype <= NAN_SUBTYPE_DATA_PATH_TERMINATION &&
	      mgmt->u.action.category == WLAN_ACTION_PROTECTED_DUAL)) {
		wpa_printf(MSG_DEBUG, "NAN: Invalid action category for NAF");
		return false;
	}

	return true;
}


/*
 * nan_parse_naf - Parse a NAN Action frame content
 * @nan: NAN module context from nan_init()
 * @mgmt: NAN action frame
 * @len: Length of the management frame in octets
 * @msg: Buffer for returning parsed attributes
 * Returns: 0 on success; positive or negative indicate an error
 *
 * Note: in case of success, the caller must free temporary memory allocations
 * by calling nan_attrs_clear() when the parsed data is not needed anymore. In
 * addition, as the &mgmt is referenced from the returned structure, the caller
 * must ensure that the frame buffer remains valid and unmodified as long as the
 * &msg object is used.
 */
int nan_parse_naf(struct nan_data *nan, const struct ieee80211_mgmt *mgmt,
		  size_t len, struct nan_msg *msg)
{
	if (!nan_is_naf(mgmt, len))
		return -1;

	wpa_printf(MSG_DEBUG, "NAN: Parse NAF");

	msg->oui_type = mgmt->u.action.u.naf.oui_type;
	msg->oui_subtype = mgmt->u.action.u.naf.subtype;

	msg->mgmt = mgmt;
	msg->len = len;

	return nan_parse_attrs(nan,
			       mgmt->u.action.u.naf.variable,
			       len - IEEE80211_MIN_ACTION_LEN(naf),
			       &msg->attrs);
}


/*
 * nan_add_dev_capa_attr - Add Device Capability attribute
 * @nan: NAN module context from nan_init()
 * @buf: wpabuf to which the attribute would be added
 */
void nan_add_dev_capa_attr(struct nan_data *nan, struct wpabuf *buf)
{
	wpabuf_put_u8(buf, NAN_ATTR_DEVICE_CAPABILITY);
	wpabuf_put_le16(buf, sizeof(struct nan_device_capa));

	/* Device capabilities apply to the device, so set map ID = 0 */
	wpabuf_put_u8(buf, 0);
	wpabuf_put_le16(buf, nan->cfg->dev_capa.cdw_info);
	wpabuf_put_u8(buf, nan->cfg->dev_capa.supported_bands);
	wpabuf_put_u8(buf, nan->cfg->dev_capa.op_mode);
	wpabuf_put_u8(buf, nan->cfg->dev_capa.n_antennas);
	wpabuf_put_le16(buf, nan->cfg->dev_capa.channel_switch_time);
	wpabuf_put_u8(buf, nan->cfg->dev_capa.capa);
}


/**
 * nan_chan_to_chan_idx_map - Convert an op_class and chan to channel bitmap
 * @nan: NAN module context from nan_init()
 * @op_class: the operating class
 * @channel: channel number
 * @chan_idx_map: On success, would hold the channel index bitmap
 * Returns: 0 on success, otherwise a negative value
 */
int nan_chan_to_chan_idx_map(struct nan_data *nan,
			     u8 op_class, u8 channel, u16 *chan_idx_map)
{
	int ret;
	const struct oper_class_map *op_c;

	if (!chan_idx_map)
		return -1;

	op_c = get_oper_class(NULL, op_class);
	if (!op_c)
		return -1;

	ret = op_class_chan_to_idx(op_c, channel);
	if (ret < 0)
		return ret;

	if ((size_t) ret >= (sizeof(*chan_idx_map) * 8))
		return -1;

	*chan_idx_map = BIT(ret);
	return 0;
}


static u16 nan_add_avail_entry(struct nan_data *nan,
			       struct nan_time_bitmap *tbm,
			       u8 type, u8 op_class, u16 chan_bm,
			       u8 prim_chan_bm, struct wpabuf *buf)
{
	u16 ctrl;
	u8 chan_ctrl;
	u8 *len_ptr;
	u8 nss = BITS(nan->cfg->dev_capa.n_antennas, NAN_DEV_CAPA_RX_ANT_MASK,
		      NAN_DEV_CAPA_RX_ANT_POS);

	len_ptr = wpabuf_put(buf, 2);

	/*
	 * TODO: Need to also add potential entries as otherwise the peer would
	 * not be able to counter.
	 */
	if (type != NAN_AVAIL_ENTRY_CTRL_TYPE_COMMITTED &&
	    type != NAN_AVAIL_ENTRY_CTRL_TYPE_COND) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Cannot add non committed/conditional entry");
		return 0;
	}

	/*
	 * Add the entry control field
	 * - usage preference is not set for committed and conditional
	 * - utilization is max.
	 */
	ctrl = type;
	ctrl |= NAN_AVAIL_ENTRY_DEF_UTIL << NAN_AVAIL_ENTRY_CTRL_UTIL_POS;
	ctrl |= nss << NAN_AVAIL_ENTRY_CTRL_RX_NSS_POS;
	ctrl |= NAN_AVAIL_ENTRY_CTRL_TBM_PRESENT;
	wpabuf_put_le16(buf, ctrl);

	/* Add the time bitmap control field */
	ctrl = tbm->duration << NAN_TIME_BM_CTRL_BIT_DURATION_POS;
	ctrl |= tbm->period << NAN_TIME_BM_CTRL_PERIOD_POS;
	ctrl |= tbm->offset << NAN_TIME_BM_CTRL_START_OFFSET_POS;
	wpabuf_put_le16(buf, ctrl);

	wpabuf_put_u8(buf, tbm->len);
	wpabuf_put_data(buf, tbm->bitmap, tbm->len);

	/* Add the channel entry: single contiguous channel entry */
	chan_ctrl = NAN_BAND_CHAN_CTRL_TYPE;
	chan_ctrl |= 1 << NAN_BAND_CHAN_CTRL_NUM_ENTRIES_POS;
	wpabuf_put_u8(buf, chan_ctrl);
	wpabuf_put_u8(buf, op_class);
	wpabuf_put_le16(buf, chan_bm);
	wpabuf_put_u8(buf, prim_chan_bm);

	WPA_PUT_LE16(len_ptr, (u8 *) wpabuf_put(buf, 0) - len_ptr - 2);
	return (u8 *) wpabuf_put(buf, 0) - len_ptr;
}


int nan_get_chan_bm(struct nan_data *nan, struct nan_sched_chan *chan,
		    u8 *op_class, u16 *chan_bm, u16 *pri_chan_bm)
{
	u8 channel;
	enum hostapd_hw_mode mode;
	int ret, sec_channel_offset;
	int freq_offsset = chan->freq - chan->center_freq1;
	u32 idx;
	enum oper_chan_width bandwidth;

	switch (chan->bandwidth) {
	case 20:
	case 40:
	default:
		bandwidth = CONF_OPER_CHWIDTH_USE_HT;
		break;
	case 80:
		bandwidth = CONF_OPER_CHWIDTH_80MHZ;

		idx = (freq_offsset + 30) / 20;
		*pri_chan_bm = BIT(idx);
		break;
	case 160:
		if (chan->center_freq2) {
			bandwidth = CONF_OPER_CHWIDTH_80P80MHZ;

			/* TODO: Need to support auxiliary channel bitmap */
			idx = (freq_offsset + 30) / 20;
			*pri_chan_bm = BIT(idx);
		} else {
			bandwidth = CONF_OPER_CHWIDTH_160MHZ;
			idx = (freq_offsset + 70) / 20;
			*pri_chan_bm = BIT(idx);
		}
		break;
	}

	if (freq_offsset > 0)
		sec_channel_offset = 1;
	else if (freq_offsset < 0)
		sec_channel_offset = -1;
	else
		sec_channel_offset = 0;

	wpa_printf(MSG_DEBUG,
		   "NAN: Get chan bm: freq=%d, center_freq1=%d, bandwidth=%u, sec_channel_offset=%d",
		   chan->freq, chan->center_freq1, chan->bandwidth,
		   freq_offsset);

	/* For bandwidths >= 80 need to use the center frequency */
	mode = ieee80211_freq_to_channel_ext(bandwidth ==
					     CONF_OPER_CHWIDTH_USE_HT ?
					     chan->freq : chan->center_freq1,
					     sec_channel_offset,
					     bandwidth, op_class, &channel);
	if (mode == NUM_HOSTAPD_MODES) {
		wpa_printf(MSG_DEBUG,
			   "NAN: Cannot get channel and op_class");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "NAN: Derived op_class=%u, channel=%u",
		   *op_class, channel);

	ret = nan_chan_to_chan_idx_map(nan, *op_class, channel, chan_bm);
	if (ret) {
		wpa_printf(MSG_DEBUG, "NAN: Failed to derive channel bitmap");
		return -1;
	}

	return 0;
}


/**
 * nan_add_avail_attrs - Add NAN availability attributes
 * @nan: NAN module context from nan_init()
 * @sequence_id: Sequence ID to be used in the availability attributes
 * @map_ids_bitmap: Bitmap of map IDs to be included in the availability
 *	attributes
 * @type_for_conditional: Type field to be used for conditional entries
 * @n_chans: Number of channels in chans
 * @chans: Channel schedules
 * @buf: Frame buffer to which the attribute would be added
 * Returns: 0 on success, negative on failure.
 *
 * An availability attribute is added for each map (identified by map ID) in the
 * schedule. All channels with the same map ID are added to the same
 * availability attribute. Each attribute will hold an availability entry for
 * committed slots and an availability entry for conditional slots.
 */
int nan_add_avail_attrs(struct nan_data *nan, u8 sequence_id,
			u32 map_ids_bitmap, u8 type_for_conditional,
			size_t n_chans, struct nan_chan_schedule *chans,
			struct wpabuf *buf)
{
	u8 last_map_id = NAN_INVALID_MAP_ID;
	u8 *len_ptr = NULL;
	u8 i;

	wpa_printf(MSG_DEBUG, "NAN: Add availability attrs. n_chans=%zu",
		   n_chans);

	for (i = 0; i < n_chans; i++) {
		struct nan_chan_schedule *chan = &chans[i];
		u8 op_class;
		u16 chan_bm, pri_chan_bm;
		int ret;

		if (!chan->conditional.len && !chan->committed.len) {
			wpa_printf(MSG_DEBUG,
				   "NAN: committed and conditional are empty");
			continue;
		}

		ret = nan_get_chan_bm(nan, &chan->chan, &op_class,
				      &chan_bm, &pri_chan_bm);
		if (ret)
			continue;

		/*
		 * All channels with the same map ID should be added to the same
		 * availability attribute, so verify that the map IDs are
		 * sorted.
		 */
		if (last_map_id != NAN_INVALID_MAP_ID &&
		    last_map_id > chan->map_id) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Map IDs not sorted properly");
			return -1;
		}

		if (!(map_ids_bitmap & BIT(chan->map_id))) {
			wpa_printf(MSG_DEBUG,
				   "NAN: Skip adding availability for map_id=%u",
				   chan->map_id);
			continue;
		}

		if (last_map_id != chan->map_id) {
			u16 ctrl;

			if (last_map_id != NAN_INVALID_MAP_ID) {
				wpa_printf(MSG_DEBUG,
					   "NAN: Add avail attr done: map_id=%u",
					   last_map_id);

				WPA_PUT_LE16(len_ptr,
					     (u8 *) wpabuf_put(buf, 0) -
					     len_ptr - 2);
			}

			last_map_id = chan->map_id;
			map_ids_bitmap &= ~BIT(last_map_id);

			wpa_printf(MSG_DEBUG, "NAN: Add avail attr map_id=%u",
				   last_map_id);

			wpabuf_put_u8(buf, NAN_ATTR_NAN_AVAILABILITY);
			len_ptr = wpabuf_put(buf, 2);
			wpabuf_put_u8(buf, sequence_id);

			ctrl = last_map_id << NAN_AVAIL_CTRL_MAP_ID_POS;

			/*
			 * The spec states that this bit should be set if the
			 * committed changed or if conditional is included. Set
			 * it anyway, as it is not known what information the
			 * peer has on our schedule.
			 */
			ctrl |= NAN_AVAIL_CTRL_COMMITTED_CHANGED;
			wpabuf_put_le16(buf, ctrl);
		}

		/* TODO: handle primary channel configuration */
		if (chan->committed.len)
			nan_add_avail_entry(nan, &chan->committed,
					    NAN_AVAIL_ENTRY_CTRL_TYPE_COMMITTED,
					    op_class, chan_bm, pri_chan_bm,
					    buf);

		if (chan->conditional.len)
			nan_add_avail_entry(nan, &chan->conditional,
					    type_for_conditional,
					    op_class, chan_bm, 0, buf);
	}

	if (last_map_id == NAN_INVALID_MAP_ID) {
		wpa_printf(MSG_DEBUG,
			   "NAN: No valid availability entries added");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "NAN: Add avail attr done: map_id=%u",
		   last_map_id);

	WPA_PUT_LE16(len_ptr, (u8 *) wpabuf_put(buf, 0) - len_ptr - 2);

	return 0;
}
