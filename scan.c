#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nl80211.h"
#include "iw.h"

#include "json/iw_json_print.h"

#define WLAN_CAPABILITY_ESS		(1<<0)
#define WLAN_CAPABILITY_IBSS		(1<<1)
#define WLAN_CAPABILITY_CF_POLLABLE	(1<<2)
#define WLAN_CAPABILITY_CF_POLL_REQUEST	(1<<3)
#define WLAN_CAPABILITY_PRIVACY		(1<<4)
#define WLAN_CAPABILITY_SHORT_PREAMBLE	(1<<5)
#define WLAN_CAPABILITY_PBCC		(1<<6)
#define WLAN_CAPABILITY_CHANNEL_AGILITY	(1<<7)
#define WLAN_CAPABILITY_SPECTRUM_MGMT	(1<<8)
#define WLAN_CAPABILITY_QOS		(1<<9)
#define WLAN_CAPABILITY_SHORT_SLOT_TIME	(1<<10)
#define WLAN_CAPABILITY_APSD		(1<<11)
#define WLAN_CAPABILITY_RADIO_MEASURE	(1<<12)
#define WLAN_CAPABILITY_DSSS_OFDM	(1<<13)
#define WLAN_CAPABILITY_DEL_BACK	(1<<14)
#define WLAN_CAPABILITY_IMM_BACK	(1<<15)
/* DMG (60gHz) 802.11ad */
/* type - bits 0..1 */
#define WLAN_CAPABILITY_DMG_TYPE_MASK		(3<<0)

#define WLAN_CAPABILITY_DMG_TYPE_IBSS		(1<<0) /* Tx by: STA */
#define WLAN_CAPABILITY_DMG_TYPE_PBSS		(2<<0) /* Tx by: PCP */
#define WLAN_CAPABILITY_DMG_TYPE_AP		(3<<0) /* Tx by: AP */

#define WLAN_CAPABILITY_DMG_CBAP_ONLY		(1<<2)
#define WLAN_CAPABILITY_DMG_CBAP_SOURCE		(1<<3)
#define WLAN_CAPABILITY_DMG_PRIVACY		(1<<4)
#define WLAN_CAPABILITY_DMG_ECPAC		(1<<5)

#define WLAN_CAPABILITY_DMG_SPECTRUM_MGMT	(1<<8)
#define WLAN_CAPABILITY_DMG_RADIO_MEASURE	(1<<12)

static unsigned char ms_oui[3]		= { 0x00, 0x50, 0xf2 };
static unsigned char ieee80211_oui[3]	= { 0x00, 0x0f, 0xac };
static unsigned char wfa_oui[3]		= { 0x50, 0x6f, 0x9a };

struct scan_params {
	bool unknown;
	enum print_ie_type type;
	bool show_both_ie_sets;
};

#define IEEE80211_COUNTRY_EXTENSION_ID 201

union ieee80211_country_ie_triplet {
	struct {
		__u8 first_channel;
		__u8 num_channels;
		__s8 max_power;
	} __attribute__ ((packed)) chans;
	struct {
		__u8 reg_extension_id;
		__u8 reg_class;
		__u8 coverage_class;
	} __attribute__ ((packed)) ext;
} __attribute__ ((packed));

int parse_sched_scan(struct nl_msg *msg, int *argc, char ***argv)
{
	struct nl_msg *matchset = NULL, *freqs = NULL, *ssids = NULL;
	struct nl_msg *scan_plans = NULL;
	struct nlattr *match = NULL, *plan = NULL;
	enum {
		ND_TOPLEVEL,
		ND_MATCH,
		ND_FREQS,
		ND_ACTIVE,
		ND_PLANS,
	} parse_state = ND_TOPLEVEL;
	int c  = *argc;
	char *end, **v = *argv;
	int err = 0, i = 0;
	unsigned int freq, interval = 0, delay = 0, iterations = 0;
	bool have_matchset = false, have_freqs = false, have_ssids = false;
	bool have_active = false, have_passive = false, have_plans = false;
	uint32_t flags = 0;

	matchset = nlmsg_alloc();
	if (!matchset) {
		err = -ENOBUFS;
		goto out;
	}

	freqs = nlmsg_alloc();
	if (!freqs) {
		err = -ENOBUFS;
		goto out;
	}

	ssids = nlmsg_alloc();
	if (!ssids) {
		err = -ENOMEM;
		goto out;
	}

	scan_plans = nlmsg_alloc();
	if (!scan_plans) {
		err = -ENOBUFS;
		goto out;
	}

	while (c) {
		switch (parse_state) {
		case ND_TOPLEVEL:
			if (!strcmp(v[0], "interval")) {
				c--; v++;
				if (c == 0) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				if (interval || have_plans) {
					err = -EINVAL;
					goto nla_put_failure;
				}
				interval = strtoul(v[0], &end, 10);
				if (*end || !interval) {
					err = -EINVAL;
					goto nla_put_failure;
				}
				NLA_PUT_U32(msg,
					    NL80211_ATTR_SCHED_SCAN_INTERVAL,
					    interval);
			} else if (!strcmp(v[0], "scan_plans")) {
				parse_state = ND_PLANS;
				if (have_plans || interval) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				have_plans = true;
				i = 0;
			} else if (!strcmp(v[0], "delay")) {
				c--; v++;
				if (c == 0) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				if (delay) {
					err = -EINVAL;
					goto nla_put_failure;
				}
				delay = strtoul(v[0], &end, 10);
				if (*end) {
					err = -EINVAL;
					goto nla_put_failure;
				}
				NLA_PUT_U32(msg,
					    NL80211_ATTR_SCHED_SCAN_DELAY,
					    delay);
			} else if (!strcmp(v[0], "matches")) {
				parse_state = ND_MATCH;
				if (have_matchset) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				i = 0;
			} else if (!strcmp(v[0], "freqs")) {
				parse_state = ND_FREQS;
				if (have_freqs) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				have_freqs = true;
				i = 0;
			} else if (!strcmp(v[0], "active")) {
				parse_state = ND_ACTIVE;
				if (have_active || have_passive) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				have_active = true;
				i = 0;
			} else if (!strcmp(v[0], "passive")) {
				if (have_active || have_passive) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				have_passive = true;
			} else if (!strncmp(v[0], "randomise", 9) ||
				   !strncmp(v[0], "randomize", 9)) {
				flags |= NL80211_SCAN_FLAG_RANDOM_ADDR;
				err = parse_random_mac_addr(msg, v[0] + 9);
				if (err)
					goto nla_put_failure;
			} else if (!strncmp(v[0], "coloc", 5)) {
				flags |= NL80211_SCAN_FLAG_COLOCATED_6GHZ;
			} else if (!strncmp(v[0], "flush", 5)) {
				flags |= NL80211_SCAN_FLAG_FLUSH;
			} else {
				/* this element is not for us, so
				 * return to continue parsing.
				 */
				goto nla_put_failure;
			}
			c--; v++;

			break;
		case ND_MATCH:
			if (!strcmp(v[0], "ssid")) {
				c--; v++;
				if (c == 0) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				/* TODO: for now we can only have an
				 * SSID in the match, so we can start
				 * the match nest here.
				 */
				match = nla_nest_start(matchset, i);
				if (!match) {
					err = -ENOBUFS;
					goto nla_put_failure;
				}

				NLA_PUT(matchset,
					NL80211_SCHED_SCAN_MATCH_ATTR_SSID,
					strlen(v[0]), v[0]);
				nla_nest_end(matchset, match);
				match = NULL;

				have_matchset = true;
				i++;
				c--; v++;
			} else {
				/* other element that cannot be part
				 * of a match indicates the end of the
				 * match. */
				/* need at least one match in the matchset */
				if (i == 0) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				parse_state = ND_TOPLEVEL;
			}

			break;
		case ND_FREQS:
			freq = strtoul(v[0], &end, 10);
			if (*end) {
				if (i == 0) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				parse_state = ND_TOPLEVEL;
			} else {
				NLA_PUT_U32(freqs, i, freq);
				i++;
				c--; v++;
			}
			break;
		case ND_ACTIVE:
			if (!strcmp(v[0], "ssid")) {
				c--; v++;
				if (c == 0) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				NLA_PUT(ssids,
					NL80211_SCHED_SCAN_MATCH_ATTR_SSID,
					strlen(v[0]), v[0]);

				have_ssids = true;
				i++;
				c--; v++;
			} else {
				/* other element that cannot be part
				 * of a match indicates the end of the
				 * active set. */
				/* need at least one item in the set */
				if (i == 0) {
					err = -EINVAL;
					goto nla_put_failure;
				}

				parse_state = ND_TOPLEVEL;
			}
			break;
		case ND_PLANS:
			iterations = 0;
			interval = strtoul(v[0], &end, 10);
			if (*end) {
				char *iter;

				if (*end != ':') {
					err = -EINVAL;
					goto nla_put_failure;
				}

				iter = ++end;
				iterations = strtoul(iter, &end, 10);
				if (*end || !iterations) {
					err = -EINVAL;
					goto nla_put_failure;
				}
			}

			plan = nla_nest_start(scan_plans, i + 1);
			if (!plan) {
				err = -ENOBUFS;
				goto nla_put_failure;
			}

			NLA_PUT_U32(scan_plans,
				    NL80211_SCHED_SCAN_PLAN_INTERVAL,
				    interval);

			if (iterations)
				NLA_PUT_U32(scan_plans,
					    NL80211_SCHED_SCAN_PLAN_ITERATIONS,
					    iterations);
			else
				parse_state = ND_TOPLEVEL;

			nla_nest_end(scan_plans, plan);
			plan = NULL;
			i++;
			c--; v++;
			break;
		}
	}

	if (!have_ssids)
		NLA_PUT(ssids, 1, 0, "");
	if (!have_passive)
		nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);
	if (have_freqs)
		nla_put_nested(msg, NL80211_ATTR_SCAN_FREQUENCIES, freqs);
	else
		flags |= NL80211_SCAN_FLAG_COLOCATED_6GHZ;
	if (have_matchset)
		nla_put_nested(msg, NL80211_ATTR_SCHED_SCAN_MATCH, matchset);
	if (have_plans)
		nla_put_nested(msg, NL80211_ATTR_SCHED_SCAN_PLANS, scan_plans);
	if (flags)
		NLA_PUT_U32(msg, NL80211_ATTR_SCAN_FLAGS, flags);

nla_put_failure:
	if (match)
		nla_nest_end(msg, match);
out:
	nlmsg_free(freqs);
	nlmsg_free(matchset);
	nlmsg_free(scan_plans);
	nlmsg_free(ssids);

	*argc = c;
	*argv = v;
	return err;
}

static int handle_scan(struct nl80211_state *state,
		       struct nl_msg *msg,
		       int argc, char **argv,
		       enum id_input id)
{
	struct nl_msg *ssids = NULL, *freqs = NULL;
	char *eptr;
	int err = -ENOBUFS;
	int i;
	enum {
		NONE,
		FREQ,
		IES,
		SSID,
		MESHID,
		DURATION,
		DONE,
	} parse = NONE;
	int freq;
	unsigned int duration = 0;
	bool passive = false, have_ssids = false, have_freqs = false;
	bool duration_mandatory = false;
	size_t ies_len = 0, meshid_len = 0;
	unsigned char *ies = NULL, *meshid = NULL, *tmpies = NULL;
	unsigned int flags = 0;

	ssids = nlmsg_alloc();
	if (!ssids)
		return -ENOMEM;

	freqs = nlmsg_alloc();
	if (!freqs) {
		nlmsg_free(ssids);
		return -ENOMEM;
	}

	for (i = 0; i < argc; i++) {
		switch (parse) {
		case NONE:
			if (strcmp(argv[i], "freq") == 0) {
				parse = FREQ;
				have_freqs = true;
				break;
			} else if (strcmp(argv[i], "ies") == 0) {
				parse = IES;
				break;
			} else if (strcmp(argv[i], "lowpri") == 0) {
				flags |= NL80211_SCAN_FLAG_LOW_PRIORITY;
				break;
			} else if (strcmp(argv[i], "flush") == 0) {
				flags |= NL80211_SCAN_FLAG_FLUSH;
				break;
			} else if (strcmp(argv[i], "ap-force") == 0) {
				flags |= NL80211_SCAN_FLAG_AP;
				break;
			} else if (strcmp(argv[i], "coloc") == 0) {
				flags |= NL80211_SCAN_FLAG_COLOCATED_6GHZ;
				break;
			} else if (strcmp(argv[i], "duration-mandatory") == 0) {
				duration_mandatory = true;
				break;
			} else if (strncmp(argv[i], "randomise", 9) == 0 ||
				   strncmp(argv[i], "randomize", 9) == 0) {
				flags |= NL80211_SCAN_FLAG_RANDOM_ADDR;
				err = parse_random_mac_addr(msg, argv[i] + 9);
				if (err)
					goto nla_put_failure;
				break;
			} else if (strcmp(argv[i], "ssid") == 0) {
				parse = SSID;
				have_ssids = true;
				break;
			} else if (strcmp(argv[i], "passive") == 0) {
				parse = DONE;
				passive = true;
				break;
			} else if (strcmp(argv[i], "meshid") == 0) {
				parse = MESHID;
				break;
			} else if (strcmp(argv[i], "duration") == 0) {
				parse = DURATION;
				break;
			}
			/* fall through - this is an error */
		case DONE:
			err = 1;
			goto nla_put_failure;
		case FREQ:
			freq = strtoul(argv[i], &eptr, 10);
			if (eptr != argv[i] + strlen(argv[i])) {
				/* failed to parse as number -- maybe a tag? */
				i--;
				parse = NONE;
				continue;
			}
			NLA_PUT_U32(freqs, i, freq);
			break;
		case IES:
			if (ies)
				free(ies);
			ies = parse_hex(argv[i], &ies_len);
			if (!ies)
				goto nla_put_failure;
			parse = NONE;
			break;
		case SSID:
			NLA_PUT(ssids, i, strlen(argv[i]), argv[i]);
			break;
		case MESHID:
			meshid_len = strlen(argv[i]);
			meshid = (unsigned char *) malloc(meshid_len + 2);
			if (!meshid)
				goto nla_put_failure;
			meshid[0] = 114; /* mesh element id */
			meshid[1] = meshid_len;
			memcpy(&meshid[2], argv[i], meshid_len);
			meshid_len += 2;
			parse = NONE;
			break;
		case DURATION:
			duration = strtoul(argv[i], &eptr, 10);
			parse = NONE;
			break;
		}
	}

	if (ies || meshid) {
		tmpies = (unsigned char *) malloc(ies_len + meshid_len);
		if (!tmpies)
			goto nla_put_failure;
		if (ies)
			memcpy(tmpies, ies, ies_len);
		if (meshid)
			memcpy(&tmpies[ies_len], meshid, meshid_len);
		if (nla_put(msg, NL80211_ATTR_IE, ies_len + meshid_len, tmpies) < 0)
			goto nla_put_failure;
	}

	if (!have_ssids)
		NLA_PUT(ssids, 1, 0, "");
	if (!passive)
		nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);

	if (have_freqs)
		nla_put_nested(msg, NL80211_ATTR_SCAN_FREQUENCIES, freqs);
	else
		flags |=  NL80211_SCAN_FLAG_COLOCATED_6GHZ;
	if (flags)
		NLA_PUT_U32(msg, NL80211_ATTR_SCAN_FLAGS, flags);
	if (duration)
		NLA_PUT_U16(msg, NL80211_ATTR_MEASUREMENT_DURATION, duration);
	if (duration_mandatory) {
		if (duration) {
			NLA_PUT_FLAG(msg,
				     NL80211_ATTR_MEASUREMENT_DURATION_MANDATORY);
		} else {
			err = -EINVAL;
			goto nla_put_failure;
		}
	}

	err = 0;
 nla_put_failure:
	nlmsg_free(ssids);
	nlmsg_free(freqs);
	if (meshid)
		free(meshid);
	if (ies)
		free(ies);
	if (tmpies)
		free(tmpies);
	return err;
}

struct print_ies_data {
	unsigned char *ie;
	int ielen;
};

static void print_ssid(const uint8_t type, uint8_t len, const uint8_t *data,
		       const struct print_ies_data *ie_buffer)
{
		print_ssid_escaped(len, data);
}

#define BSS_MEMBERSHIP_SELECTOR_VHT_PHY 126
#define BSS_MEMBERSHIP_SELECTOR_HT_PHY 127

static void print_supprates(const uint8_t type, uint8_t len,
			    const uint8_t *data,
			    const struct print_ies_data *ie_buffer)
{
	int i;

	iw_arr_openf("Rates");
	for (i = 0; i < len; i++) {
		int r = data[i] & 0x7f;
		if (r == BSS_MEMBERSHIP_SELECTOR_VHT_PHY && data[i] & 0x80){
			iw_printf(NULL, "VHT%s", data[i] & 0x80 ? "*" : "");
		} else if (r == BSS_MEMBERSHIP_SELECTOR_HT_PHY && data[i] & 0x80){
			iw_printf(NULL, "HT%s", data[i] & 0x80 ? "*" : "");
		} else {
			iw_printf(NULL, "%d.%d%s", r/2, 5*(r&1), data[i] & 0x80 ? "*" : "");
		}
	}
	iw_arr_close();
}

static void print_rm_enabled_capabilities(const uint8_t type, uint8_t len,
			    const uint8_t *data,
			    const struct print_ies_data *ie_buffer)
{
	__u64 capa = ((__u64) data[0]) |
		     ((__u64) data[1]) << 8 |
		     ((__u64) data[2]) << 16 |
		     ((__u64) data[3]) << 24 |
		     ((__u64) data[4]) << 32;

	iw_printf("Capabilities Raw value", "0x%02x 0x%02x 0x%02x 0x%02x 0x%02x", data[0], data[1], data[2], data[3], data[4]);
	iw_arr_openf("Capabilities");


#define PRINT_RM_CAPA(_bit, _str) \
	do { \
		if (capa & BIT(_bit)) \
			iw_printf(NULL, _str); \
	} while (0)

	PRINT_RM_CAPA(0, "Link Measurement");
	PRINT_RM_CAPA(1, "Neighbor Report");
	PRINT_RM_CAPA(2, "Parallel Measurements");
	PRINT_RM_CAPA(3, "Repeated Measurements");
	PRINT_RM_CAPA(4, "Beacon Passive Measurement");
	PRINT_RM_CAPA(5, "Beacon Active Measurement");
	PRINT_RM_CAPA(6, "Beacon Table Measurement");
	PRINT_RM_CAPA(7, "Beacon Measurement Reporting Conditions");
	PRINT_RM_CAPA(8, "Frame Measurement");
	PRINT_RM_CAPA(9, "Channel Load");
	PRINT_RM_CAPA(10, "Noise Histogram Measurement");
	PRINT_RM_CAPA(11, "Statistics Measurement");
	PRINT_RM_CAPA(12, "LCI Measurement");
	PRINT_RM_CAPA(13, "LCI Azimuth");
	PRINT_RM_CAPA(14, "Transmit Stream/Category Measurement");
	PRINT_RM_CAPA(15, "Triggered Transmit Stream/Category");
	PRINT_RM_CAPA(16, "AP Channel Report");
	PRINT_RM_CAPA(17, "RM MIB Capability");

	PRINT_RM_CAPA(27, "Measurement Pilot Transmission Information");
	PRINT_RM_CAPA(28, "Neighbor Report TSF Offset");
	PRINT_RM_CAPA(29, "RCPI Measurement");
	PRINT_RM_CAPA(30, "RSNI Measurement");
	PRINT_RM_CAPA(31, "BSS Average Access Delay");
	PRINT_RM_CAPA(32, "BSS Available Admission");
	PRINT_RM_CAPA(33, "Antenna");
	PRINT_RM_CAPA(34, "FTM Range Report");
	PRINT_RM_CAPA(35, "Civic Location Measurement");

	iw_arr_close();
	iw_printf("Non operating Channel Max Measurement Duration", "%d", data[3] >> 5);
	iw_printf("Measurement Pilot Capability", "%d", data[4] & 7);

}

static void print_ds(const uint8_t type, uint8_t len, const uint8_t *data,
		     const struct print_ies_data *ie_buffer)
{
	iw_printf("Channel", "%d", data[0]);
}

static const char *country_env_str(char environment)
{
	switch (environment) {
	case 'I':
		return "Indoor only";
	case 'O':
		return "Outdoor only";
	case ' ':
		return "Indoor/Outdoor";
	default:
		return "bogus";
	}
}

static void print_country(const uint8_t type, uint8_t len, const uint8_t *data,
			  const struct print_ies_data *ie_buffer)
{
	iw_printf("Country", "%.*s", 2, data);
	iw_printf("Environment", "%s", country_env_str(data[2]));

	data += 3;
	len -= 3;

	if (len < 3) {
		iw_printf("No Country IE Triplets Present", "true");
		return;
	}

	iw_obj_openf("Channels");
	while (len >= 3) {
		int end_channel;
		union ieee80211_country_ie_triplet *triplet = (void *) data;

		if (triplet->ext.reg_extension_id >= IEEE80211_COUNTRY_EXTENSION_ID) {
			iw_printf("Extension ID", "%d", triplet->ext.reg_extension_id);
			iw_printf("Regulatory Class", "%d", triplet->ext.reg_class);
			iw_printf("Coverage Class", "%d", triplet->ext.coverage_class);
			iw_printf("Coverage Class Up To, dBm", "%d", triplet->ext.coverage_class * 450);

			data += 3;
			len -= 3;
			continue;
		}

		/* 2 GHz */
		if (triplet->chans.first_channel <= 14)
			end_channel = triplet->chans.first_channel + (triplet->chans.num_channels - 1);
		else
			end_channel =  triplet->chans.first_channel + (4 * (triplet->chans.num_channels - 1));

		iw_obj_openf("%d", triplet->chans.first_channel);
		iw_printf("First", "%d", triplet->chans.first_channel);
		iw_printf("End", "%d", end_channel);
		iw_printf("Max power, dBm", "%d", triplet->chans.max_power);
		iw_obj_close();
		data += 3;
		len -= 3;
	}
	iw_obj_close();

	return;
}

static void print_powerconstraint(const uint8_t type, uint8_t len,
				  const uint8_t *data,
				  const struct print_ies_data *ie_buffer)
{
	iw_printf("dB", "%d", data[0]);
}

static void print_tpcreport(const uint8_t type, uint8_t len,
			    const uint8_t *data,
			    const struct print_ies_data *ie_buffer)
{
	iw_printf("TX power, dBm", "%d", data[0]);
}

static void print_erp(const uint8_t type, uint8_t len, const uint8_t *data,
		      const struct print_ies_data *ie_buffer)
{
	if (data[0] == 0x00)
		iw_printf("No Flags", "true");
	if (data[0] & 0x01)
		iw_printf("Non ERP Present", "true");
	if (data[0] & 0x02)
		iw_printf("Use Protection", "true");
	if (data[0] & 0x04)
		iw_printf("Barker Preamble Mode", "true");
}

static void print_ap_channel_report(const uint8_t type, uint8_t len, const uint8_t *data,
				    const struct print_ies_data *ie_buffer)
{
	uint8_t oper_class = data[0];
	int i;

	iw_printf("Operating Class", "%d", oper_class);
	iw_arr_openf("Channels");
	for (i = 1; i < len; ++i) {
		iw_printf(NULL, "%d", data[i]);
	}
	iw_arr_close();

}

static void print_cipher(const uint8_t *data)
{
	if (memcmp(data, ms_oui, 3) == 0) {
		switch (data[3]) {
		case 0:
			iw_printf(NULL, "Use group cipher suite");
			break;
		case 1:
			iw_printf(NULL, "WEP-40");
			break;
		case 2:
			iw_printf(NULL, "TKIP");
			break;
		case 4:
			iw_printf(NULL, "CCMP");
			break;
		case 5:
			iw_printf(NULL, "WEP-104");
			break;
		default:
			iw_printf(NULL, "%.02x-%.02x-%.02x:%d", data[0], data[1] ,data[2], data[3]);
			break;
		}
	} else if (memcmp(data, ieee80211_oui, 3) == 0) {
		switch (data[3]) {
		case 0:
			iw_printf(NULL, "Use group cipher suite");
			break;
		case 1:
			iw_printf(NULL, "WEP-40");
			break;
		case 2:
			iw_printf(NULL, "TKIP");
			break;
		case 4:
			iw_printf(NULL, "CCMP");
			break;
		case 5:
			iw_printf(NULL, "WEP-104");
			break;
		case 6:
			iw_printf(NULL, "AES-128-CMAC");
			break;
		case 7:
			iw_printf(NULL, "NO-GROUP");
			break;
		case 8:
			iw_printf(NULL, "GCMP");
			break;
		default:
			iw_printf(NULL, "%.02x-%.02x-%.02x:%d", data[0], data[1] ,data[2], data[3]);
			break;
		}
	} else
		iw_printf(NULL, "%.02x-%.02x-%.02x:%d", data[0], data[1] ,data[2], data[3]);
}

static void print_auth(const uint8_t *data)
{
	if (memcmp(data, ms_oui, 3) == 0) {
		switch (data[3]) {
		case 1:
			iw_printf(NULL, "IEEE 802.1X");
			break;
		case 2:
			iw_printf(NULL, "PSK");
			break;
		default:
			iw_printf(NULL, "%.02x-%.02x-%.02x:%d", data[0], data[1] ,data[2], data[3]);
			break;
		}
	} else if (memcmp(data, ieee80211_oui, 3) == 0) {
		switch (data[3]) {
		case 1:
			iw_printf(NULL, "IEEE 802.1X");
			break;
		case 2:
			iw_printf(NULL, "PSK");
			break;
		case 3:
			iw_printf(NULL, "FT/IEEE 802.1X");
			break;
		case 4:
			iw_printf(NULL, "FT/PSK");
			break;
		case 5:
			iw_printf(NULL, "IEEE 802.1X/SHA-256");
			break;
		case 6:
			iw_printf(NULL, "PSK/SHA-256");
			break;
		case 7:
			iw_printf(NULL, "TDLS/TPK");
			break;
		case 8:
			iw_printf(NULL, "SAE");
			break;
		case 9:
			iw_printf(NULL, "FT/SAE");
			break;
		case 11:
			iw_printf(NULL, "IEEE 802.1X/SUITE-B");
			break;
		case 12:
			iw_printf(NULL, "IEEE 802.1X/SUITE-B-192");
			break;
		case 13:
			iw_printf(NULL, "FT/IEEE 802.1X/SHA-384");
			break;
		case 14:
			iw_printf(NULL, "FILS/SHA-256");
			break;
		case 15:
			iw_printf(NULL, "FILS/SHA-384");
			break;
		case 16:
			iw_printf(NULL, "FT/FILS/SHA-256");
			break;
		case 17:
			iw_printf(NULL, "FT/FILS/SHA-384");
			break;
		case 18:
			iw_printf(NULL, "OWE");
			break;
		default:
			iw_printf(NULL, "%.02x-%.02x-%.02x:%d", data[0], data[1] ,data[2], data[3]);
			break;
		}
	} else if (memcmp(data, wfa_oui, 3) == 0) {
		switch (data[3]) {
		case 1:
			iw_printf(NULL, "OSEN");
			break;
		case 2:
			iw_printf(NULL, "DPP");
			break;
		default:
			iw_printf(NULL, "%.02x-%.02x-%.02x:%d", data[0], data[1] ,data[2], data[3]);
			break;
		}
	} else
		iw_printf(NULL, "%.02x-%.02x-%.02x:%d", data[0], data[1] ,data[2], data[3]);
}

static void _print_rsn_ie(const char *defcipher, const char *defauth,
			  uint8_t len, const uint8_t *data, int is_osen)
{
	__u16 count, capa;
	int i;

	if (!is_osen) {
		__u16 version;
		version = data[0] + (data[1] << 8);
		iw_printf("version", "%d", version);
		data += 2;
		len -= 2;
	}

	if (len < 4) {
		iw_printf("group_cipher", "%s", defcipher);
		iw_printf("Pairwise ciphers", "%s", defcipher);
		return;
	}

	iw_arr_openf("group_cipher_data");
	print_cipher(data);
	iw_arr_close();

	data += 4;
	len -= 4;

	if (len < 2) {
		iw_printf("pairwise_ciphers", "%s", defcipher);
		return;
	}

	count = data[0] | (data[1] << 8);
	if (2 + (count * 4) > len)
		goto invalid;

	iw_arr_openf("Pairwise Ciphers Data");
	for (i = 0; i < count; i++) {
		print_cipher(data + 2 + (i * 4));
	}
	iw_arr_close();

	data += 2 + (count * 4);
	len -= 2 + (count * 4);

	if (len < 2) {
		iw_printf("Authentication Suites", "%s", defauth);
		return;
	}

	count = data[0] | (data[1] << 8);
	if (2 + (count * 4) > len)
		goto invalid;

	iw_arr_openf("Authentication Suites Data");
	for (i = 0; i < count; i++) {
		print_auth(data + 2 + (i * 4));
	}
	iw_arr_close();

	data += 2 + (count * 4);
	len -= 2 + (count * 4);

	if (len >= 2) {
		capa = data[0] | (data[1] << 8);
		iw_printf("Capabilities Raw Value", "0x%.4x", capa);

		iw_arr_openf("Capabilities");
		if (capa & 0x0001)
			iw_printf(NULL, "PreAuth");
		if (capa & 0x0002)
			iw_printf(NULL, "NoPairwise");
		switch ((capa & 0x000c) >> 2) {
		case 0:
			iw_printf(NULL, "1-PTKSA-RC");
			break;
		case 1:
			iw_printf(NULL, "2-PTKSA-RC");
			break;
		case 2:
			iw_printf(NULL, "4-PTKSA-RC");
			break;
		case 3:
			iw_printf(NULL, "16-PTKSA-RC");
			break;
		}
		switch ((capa & 0x0030) >> 4) {
		case 0:
			iw_printf(NULL, "1-GTKSA-RC");
			break;
		case 1:
			iw_printf(NULL, "2-GTKSA-RC");
			break;
		case 2:
			iw_printf(NULL, "4-GTKSA-RC");
			break;
		case 3:
			iw_printf(NULL, "16-GTKSA-RC");
			break;
		}
		if (capa & 0x0040)
			iw_printf(NULL, "MFP-required");
		if (capa & 0x0080)
			iw_printf(NULL, "MFP-capable");
		if (capa & 0x0200)
			iw_printf(NULL, "Peerkey-enabled");
		if (capa & 0x0400)
			iw_printf(NULL, "SPP-AMSDU-capable");
		if (capa & 0x0800)
			iw_printf(NULL, "SPP-AMSDU-required");
		if (capa & 0x2000)
			iw_printf(NULL, "Extended-Key-ID");
		iw_arr_close();

		data += 2;
		len -= 2;
	}

	if (len >= 2) {
		int pmkid_count = data[0] | (data[1] << 8);

		if (len >= 2 + 16 * pmkid_count) {
			iw_printf("PMKIDs Count", "%d", pmkid_count);
			/* not printing PMKID values */
			data += 2 + 16 * pmkid_count;
			len -= 2 + 16 * pmkid_count;
		} else
			goto invalid;
	}

	if (len >= 4) {
		iw_arr_openf("Group MGMT Cipher Suite Data");
		print_cipher(data);
		iw_arr_close();
		data += 4;
		len -= 4;
	}

 invalid:
	if (len != 0) {
		iw_printf("Bogus Tail Data Length", "%d", len);
		iw_arr_openf("Bogus Tail Data");
		while (len) {
			iw_printf(NULL, "%.2x", *data);
			data++;
			len--;
		}
		iw_arr_close();
	}
}

static void print_rsn_ie(const char *defcipher, const char *defauth,
			 uint8_t len, const uint8_t *data)
{
	_print_rsn_ie(defcipher, defauth, len, data, 0);
}

static void print_osen_ie(const char *defcipher, const char *defauth,
			  uint8_t len, const uint8_t *data)
{
	_print_rsn_ie(defcipher, defauth, len, data, 1);
}

static void print_rsn(const uint8_t type, uint8_t len, const uint8_t *data,
		      const struct print_ies_data *ie_buffer)
{
	print_rsn_ie("CCMP", "IEEE 802.1X", len, data);
}

static void print_ht_capa(const uint8_t type, uint8_t len, const uint8_t *data,
			  const struct print_ies_data *ie_buffer)
{
	print_ht_capability(data[0] | (data[1] << 8));
	print_ampdu_length(data[2] & 3);
	print_ampdu_spacing((data[2] >> 2) & 7);
	print_ht_mcs(data + 3);
}

static const char* ntype_11u(uint8_t t)
{
	switch (t) {
	case 0: return "Private";
	case 1: return "Private with Guest";
	case 2: return "Chargeable Public";
	case 3: return "Free Public";
	case 4: return "Personal Device";
	case 5: return "Emergency Services Only";
	case 14: return "Test or Experimental";
	case 15: return "Wildcard";
	default: return "Reserved";
	}
}

static const char* vgroup_11u(uint8_t t)
{
	switch (t) {
	case 0: return "Unspecified";
	case 1: return "Assembly";
	case 2: return "Business";
	case 3: return "Educational";
	case 4: return "Factory and Industrial";
	case 5: return "Institutional";
	case 6: return "Mercantile";
	case 7: return "Residential";
	case 8: return "Storage";
	case 9: return "Utility and Miscellaneous";
	case 10: return "Vehicular";
	case 11: return "Outdoor";
	default: return "Reserved";
	}
}

static void print_interworking(const uint8_t type, uint8_t len,
			       const uint8_t *data,
			       const struct print_ies_data *ie_buffer)
{
	/* See Section 7.3.2.92 in the 802.11u spec. */
	if (len >= 1) {
		uint8_t ano = data[0];
		iw_printf("Network Options", "0x%hx", (unsigned short)(ano));
		iw_printf("Network type, least significant 4 bits", "%i", (int)(ano & 0xf));
		iw_printf("Network Type", "%s", ntype_11u(ano & 0xf));
		iw_arr_openf("Data");
		if (ano & (1<<4))
			iw_printf(NULL, "Internet");
		if (ano & (1<<5))
			iw_printf(NULL, "ASRA");
		if (ano & (1<<6))
			iw_printf(NULL, "ESR");
		if (ano & (1<<7))
			iw_printf(NULL, "UESA");
		iw_arr_close();
	}
	if ((len == 3) || (len == 9)) {
		iw_printf("Venue Group Raw Value", "%i", (int)(data[1]));
		iw_printf("Venue Group", "%s", vgroup_11u(data[1]));
		iw_printf("Venue Type", "%i", (int)(data[2]));
	}
	if (len == 9)
		iw_printf("HESSID", "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		       data[3], data[4], data[5], data[6], data[7], data[8]);
	else if (len == 7)
		iw_printf("HESSID", "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		       data[1], data[2], data[3], data[4], data[5], data[6]);
}

static void print_11u_advert(const uint8_t type, uint8_t len,
			     const uint8_t *data,
			     const struct print_ies_data *ie_buffer)
{
	/* See Section 7.3.2.93 in the 802.11u spec. */
	/* TODO: This code below does not decode private protocol IDs */
	int idx = 0;
	while (idx < (len - 1)) {
		uint8_t qri = data[idx];
		uint8_t proto_id = data[idx + 1];
		iw_printf("Query Response Info", "0x%hx", (unsigned short)(qri));
		iw_printf("Query Response Length Limit", "%i", (qri & 0x7f));
		if (qri & (1<<7))
			iw_printf("PAME-BI", "true");
		switch(proto_id) {
		case 0:
			iw_printf("Protocol ID", "ANQP"); break;
		case 1:
			iw_printf("Protocol ID", "MIH Information Service"); break;
		case 2:
			iw_printf("Protocol ID", "MIH Command and Event Services Capability Discovery"); break;
		case 3:
			iw_printf("Protocol ID", "Emergency Alert System (EAS)"); break;
		case 221:
			iw_printf("Protocol ID", "Vendor Specific"); break;
		default:
			iw_printf("Protocol ID", "Reserved: %i", proto_id); break;
		}
		idx += 2;
	}
}

static void print_11u_rcon(const uint8_t type, uint8_t len, const uint8_t *data,
			   const struct print_ies_data *ie_buffer)
{
	/* See Section 7.3.2.96 in the 802.11u spec. */
	int idx = 0;
	int ln0 = data[1] & 0xf;
	int ln1 = ((data[1] & 0xf0) >> 4);
	int ln2 = 0;

	if (ln1)
		ln2 = len - 2 - ln0 - ln1;

	iw_printf("ANQP OIs", "%i", data[0]);

	if (ln0 > 0) {
		iw_arr_openf("OI 1");
		if (2 + ln0 > len) {
			iw_printf(NULL, "Invalid IE length len: %d 2+ln0: %d", len, 2 + ln0);
		} else {
			for (idx = 0; idx < ln0; idx++) {
				iw_printf(NULL, "%02hhx", data[2 + idx]);
			}
		}
		iw_arr_close();
	}

	if (ln1 > 0) {
		iw_arr_openf("OI 2");
		if (2 + ln0 + ln1 > len) {
			iw_printf(NULL, "Invalid IE length len: %d 2 + ln0 + ln1: %d", len, 2 + ln0 + ln1);
		} else {
			for (idx = 0; idx < ln1; idx++) {
				iw_printf(NULL, "%02hhx", data[2 + ln0 + idx]);
			}
		}
		iw_arr_close();
	}

	if (ln2 > 0) {
		iw_arr_openf("OI 3");
		if (2 + ln0 + ln1 + ln2 > len) {
			iw_printf(NULL, "Invalid IE length len: %d 2+ln0+ln1+ln2: %d", len, 2 + ln0 + ln1 + ln2);
		} else {
			for (idx = 0; idx < ln2; idx++) {
				iw_printf(NULL, "%02hhx", data[2 + ln0 + ln1 + idx]);
			}
		}
		iw_arr_close();
	}
}

static void print_tx_power_envelope(const uint8_t type, uint8_t len,
				    const uint8_t *data,
				    const struct print_ies_data *ie_buffer)
{
	const uint8_t local_max_tx_power_count = data[0] & 7;
	const uint8_t local_max_tx_power_unit_interp = (data[0] >> 3) & 7;
	int i;
	static const char *power_names[] = {
		"Local Maximum Transmit Power For 20 MHz",
		"Local Maximum Transmit Power For 40 MHz",
		"Local Maximum Transmit Power For 80 MHz",
		"Local Maximum Transmit Power For 160/80+80 MHz",
	};

	if (local_max_tx_power_count + 2 != len)
		return;
	if (local_max_tx_power_unit_interp != 0)
		return;
	for (i = 0; i < local_max_tx_power_count + 1; ++i) {
		int8_t power_val = ((int8_t)data[1 + i]) >> 1;
		int8_t point5 = data[1 + i] & 1;
		char power_name[64];
		size_t power_name_size = sizeof(power_name);
		snprintf(power_name, power_name_size, "%s, dBm", power_names[i]);
		if (point5)
			iw_printf(power_name, "%i.%i", power_val, 5);
		else
			iw_printf(power_name, "%i", power_val);
	}
}

static const char *ht_secondary_offset[4] = {
	"no secondary",
	"above",
	"[reserved!]",
	"below",
};

static void print_ht_op(const uint8_t type, uint8_t len, const uint8_t *data,
			const struct print_ies_data *ie_buffer)
{
	static const char *protection[4] = {
		"no",
		"nonmember",
		"20 MHz",
		"non-HT mixed",
	};
	static const char *sta_chan_width[2] = {
		"20 MHz",
		"any",
	};
	iw_printf("Primary Channel", "%d", data[0]);
	iw_printf("Secondary Channel Offset", "%s", ht_secondary_offset[data[1] & 0x3]);
	iw_printf("STA Channel Width", "%s", sta_chan_width[(data[1] & 0x4)>>2]);
	iw_printf("RIFS", "%d", (data[1] & 0x8)>>3);
	iw_printf("HT Protection", "%s", protection[data[2] & 0x3]);
	iw_printf("Non-GF Present", "%d", (data[2] & 0x4) >> 2);
	iw_printf("OBSS Non-GF Present", "%d", (data[2] & 0x10) >> 4);
	iw_printf("Dual Beacon", "%d", (data[4] & 0x40) >> 6);
	iw_printf("Dual CTS Protection", "%d", (data[4] & 0x80) >> 7);
	iw_printf("STBC Beacon", "%d", data[5] & 0x1);
	iw_printf("L-SIG TXOP Protection", "%d", (data[5] & 0x2) >> 1);
	iw_printf("PCO Active", "%d", (data[5] & 0x4) >> 2);
	iw_printf("PCO Phase", "%d", (data[5] & 0x8) >> 3);
}

static void print_capabilities(const uint8_t type, uint8_t len,
			       const uint8_t *data,
			       const struct print_ies_data *ie_buffer)
{
	int i, base, bit, si_duration = 0, max_amsdu = 0;
	bool s_psmp_support = false, is_vht_cap = false;
	unsigned char *ie = ie_buffer->ie;
	int ielen = ie_buffer->ielen;

	while (ielen >= 2 && ielen >= ie[1]) {
		if (ie[0] == 191) {
			is_vht_cap = true;
			break;
		}
		ielen -= ie[1] + 2;
		ie += ie[1] + 2;
	}

	iw_arr_openf("Capabilities");
	for (i = 0; i < len; i++) {
		base = i * 8;

		for (bit = 0; bit < 8; bit++) {
			if (!(data[i] & (1 << bit)))
				continue;

#define CAPA(bit, name)		case bit: iw_printf(NULL, name); break

/* if the capability 'cap' exists add 'val' to 'sum'
 * otherwise print 'Reserved' */
#define ADD_BIT_VAL(bit, cap, sum, val)	case (bit): do {	\
	if (!(cap)) {						\
		iw_printf(NULL, "Reserved");				\
		break;						\
	}							\
	sum += val;						\
	break;							\
} while (0)

			switch (bit + base) {
			CAPA(0, "HT Information Exchange Supported");
			CAPA(1, "reserved (On-demand Beacon)");
			CAPA(2, "Extended Channel Switching");
			CAPA(3, "reserved (Wave Indication)");
			CAPA(4, "PSMP Capability");
			CAPA(5, "reserved (Service Interval Granularity)");

			case 6:
				s_psmp_support = true;
				iw_printf(NULL, "S-PSMP Capability");
				break;

			CAPA(7, "Event");
			CAPA(8, "Diagnostics");
			CAPA(9, "Multicast Diagnostics");
			CAPA(10, "Location Tracking");
			CAPA(11, "FMS");
			CAPA(12, "Proxy ARP Service");
			CAPA(13, "Collocated Interference Reporting");
			CAPA(14, "Civic Location");
			CAPA(15, "Geospatial Location");
			CAPA(16, "TFS");
			CAPA(17, "WNM-Sleep Mode");
			CAPA(18, "TIM Broadcast");
			CAPA(19, "BSS Transition");
			CAPA(20, "QoS Traffic Capability");
			CAPA(21, "AC Station Count");
			CAPA(22, "Multiple BSSID");
			CAPA(23, "Timing Measurement");
			CAPA(24, "Channel Usage");
			CAPA(25, "SSID List");
			CAPA(26, "DMS");
			CAPA(27, "UTC TSF Offset");
			CAPA(28, "TDLS Peer U-APSD Buffer STA Support");
			CAPA(29, "TDLS Peer PSM Support");
			CAPA(30, "TDLS channel switching");
			CAPA(31, "Interworking");
			CAPA(32, "QoS Map");
			CAPA(33, "EBR");
			CAPA(34, "SSPN Interface");
			CAPA(35, "Reserved");
			CAPA(36, "MSGCF Capability");
			CAPA(37, "TDLS Support");
			CAPA(38, "TDLS Prohibited");
			CAPA(39, "TDLS Channel Switching Prohibited");
			CAPA(40, "Reject Unadmitted Frame");

			ADD_BIT_VAL(41, s_psmp_support, si_duration, 1);
			ADD_BIT_VAL(42, s_psmp_support, si_duration, 2);
			ADD_BIT_VAL(43, s_psmp_support, si_duration, 4);

			CAPA(44, "Identifier Location");
			CAPA(45, "U-APSD Coexistence");
			CAPA(46, "WNM-Notification");
			CAPA(47, "Reserved");
			CAPA(48, "UTF-8 SSID");
			CAPA(49, "QMFActivated");
			CAPA(50, "QMFReconfigurationActivated");
			CAPA(51, "Robust AV Streaming");
			CAPA(52, "Advanced GCR");
			CAPA(53, "Mesh GCR");
			CAPA(54, "SCS");
			CAPA(55, "QLoad Report");
			CAPA(56, "Alternate EDCA");
			CAPA(57, "Unprotected TXOP Negotiation");
			CAPA(58, "Protected TXOP Negotiation");
			CAPA(59, "Reserved");
			CAPA(60, "Protected QLoad Report");
			CAPA(61, "TDLS Wider Bandwidth");
			CAPA(62, "Operating Mode Notification");

			ADD_BIT_VAL(63, is_vht_cap, max_amsdu, 1);
			ADD_BIT_VAL(64, is_vht_cap, max_amsdu, 2);

			CAPA(65, "Channel Schedule Management");
			CAPA(66, "Geodatabase Inband Enabling Signal");
			CAPA(67, "Network Channel Control");
			CAPA(68, "White Space Map");
			CAPA(69, "Channel Availability Query");
			CAPA(70, "FTM Responder");
			CAPA(71, "FTM Initiator");
			CAPA(72, "Reserved");
			CAPA(73, "Extended Spectrum Management Capable");
			CAPA(74, "Reserved");
			CAPA(77, "TWT Requester Support");
			CAPA(78, "TWT Responder Support");
			CAPA(79, "OBSS Narrow Bandwith RU in UL OFDMA Tolerance Support");

			default:
				iw_printf(NULL, "Bit: %d", bit);
				break;
			}

#undef ADD_BIT_VAL
#undef CAPA
		} //inner for loop
	} //outer for loop
	iw_arr_close();


	if (s_psmp_support)
		iw_printf("Service Interval Granularity, ms", "%d", (si_duration + 1) * 5);

	if (is_vht_cap) {
		int max_amsdu_ = 0;
		switch (max_amsdu) {
			case 0: max_amsdu_ = -1; break;
			case 1: max_amsdu_ = 32; break;
			case 2: max_amsdu_ = 16; break;
			case 3: max_amsdu_ = 8; break;
			default: break;
		}
		iw_printf("Max Number Of MSSDUs In A-MSDU", "%d", max_amsdu_);
	}
}

static void print_tim(const uint8_t type, uint8_t len, const uint8_t *data,
		      const struct print_ies_data *ie_buffer)
{
	iw_printf("Value", "DTIM Count %u DTIM Period %u Bitmap Control 0x%x Bitmap[0] 0x%x", data[0], data[1], data[2], data[3]);
	if (len - 4)
		iw_printf("Octets", "%u", len - 4);
}

static void print_ibssatim(const uint8_t type, uint8_t len, const uint8_t *data,
			   const struct print_ies_data *ie_buffer)
{
	iw_printf("TUs", "%d", (data[1] << 8) + data[0]);
}

static void print_vht_capa(const uint8_t type, uint8_t len, const uint8_t *data,
			   const struct print_ies_data *ie_buffer)
{
	print_vht_info((__u32) data[0] | ((__u32)data[1] << 8) |
		       ((__u32)data[2] << 16) | ((__u32)data[3] << 24),
		       data + 4);
}

static void print_vht_oper(const uint8_t type, uint8_t len, const uint8_t *data,
			   const struct print_ies_data *ie_buffer)
{
	const char *chandwidths[] = {
		[0] = "20 or 40 MHz",
		[1] = "80 MHz",
		[3] = "80+80 MHz",
		[2] = "160 MHz",
	};

	iw_printf("Channel Width", "%d (%s)", data[0],
		data[0] < ARRAY_SIZE(chandwidths) ? chandwidths[data[0]] : "unknown");
	iw_printf("Center Freq Segment 1", "%d", data[1]);
	iw_printf("Center freq Segment 2", "%d", data[2]);
	iw_printf("VHT Basic MCS Set", "0x%.2x%.2x", data[4], data[3]);

}

static void print_supp_op_classes(const uint8_t type, uint8_t len,
				  const uint8_t *data,
				  const struct print_ies_data *ie_buffer)
{
	uint8_t *p = (uint8_t*) data;
	const uint8_t *next_data = p + len;
	int zero_delimiter = 0;
	int one_hundred_thirty_delimiter = 0;

	iw_printf("Current Operating Class", "%d", *p);
	iw_arr_openf("Operating Class");
	while (++p < next_data) {
		if (*p == 130) {
			one_hundred_thirty_delimiter = 1;
			break;
		}
		if (*p == 0) {
			zero_delimiter = 0;
			break;
		}
		iw_printf(NULL, "%d", *p);
	}
	iw_arr_close();

	iw_arr_openf("Current Operating Class Extension");
	if (one_hundred_thirty_delimiter){
		while (++p < next_data) {
			iw_printf(NULL, "%d", *p);
		}
	}
	iw_arr_close();

	iw_arr_openf("Operating Class Tuple");
	if (zero_delimiter){
		while (++p < next_data - 1) {
			iw_printf(NULL, "%d %d", p[0], p[1]);
			if (*p == 0)
				break;
		}
	}
	iw_arr_close();

}

static void print_measurement_pilot_tx(const uint8_t type, uint8_t len,
				       const uint8_t *data,
				       const struct print_ies_data *ie_buffer)
{
	uint8_t *p, len_remaining;

	iw_printf("Interval, TUs", "%d", data[0]);

	if (len <= 1)
		return;

	p = (uint8_t *) data + 1;
	len_remaining = len - 1;

	while (len_remaining >=5) {
		uint8_t subelement_id = *p, len, *end;

		p++;
		len = *p;
		p++;
		end = p + len;

		len_remaining -= 2;

		/* 802.11-2016 only allows vendor specific elements */
		if (subelement_id != 221) {
			iw_printf("Invalid Subelement ID", "%d", subelement_id);
			return;
		}

		if (len < 3 || len > len_remaining) {
			iw_printf("Invalid Subelement ID", "%d", subelement_id);
			return;
		}

		iw_arr_openf("Vendor Specific OUI");

		while (++p < end){
			iw_printf(NULL, "0x%.2x", *p);
		}
		iw_arr_close();

		len_remaining -= len;
	}
}

static void print_obss_scan_params(const uint8_t type, uint8_t len,
				   const uint8_t *data,
				   const struct print_ies_data *ie_buffer)
{
	iw_printf("Passive dwell, TUs", "%d", (data[1] << 8) | data[0]);
	iw_printf("Active dwell, TUs", "%d", (data[3] << 8) | data[2]);
	iw_printf("Channel Width Trigger Scan Interval, s", "%d", (data[5] << 8) | data[4]);
	iw_printf("Scan Passive Total Per Channel, TUs", "%d", (data[7] << 8) | data[6]);
	iw_printf("Scan Active Total Per Channel, TUs", "%d", (data[9] << 8) | data[8]);
	iw_printf("BSS Width Channel Transition Delay Factor", "%d", (data[11] << 8) | data[10]);
	iw_printf("OBSS Scan Activity Threshold", "%d.%02d %%\n", ((data[13] << 8) | data[12]) / 100, ((data[13] << 8) | data[12]) % 100);
}

static void print_secchan_offs(const uint8_t type, uint8_t len,
			       const uint8_t *data,
			       const struct print_ies_data *ie_buffer)
{
	if (data[0] < ARRAY_SIZE(ht_secondary_offset))
		iw_printf("Value", "%s (%d)", ht_secondary_offset[data[0]], data[0]);
	else
		iw_printf("Value", "%d", data[0]);
}

static void print_bss_load(const uint8_t type, uint8_t len, const uint8_t *_data,
			   const struct print_ies_data *ie_buffer)
{
	const int8_t *data = (int8_t *)_data;
	iw_printf("Station Count", "%d", (data[1] << 8) | data[0]);
	iw_printf("Channel Utilisation", "%d", data[2]);
	iw_printf("Available Admission Capacity", "%d", (data[4] << 8) | data[3]);
}

static void print_mesh_conf(const uint8_t type, uint8_t len,
			    const uint8_t *data,
			    const struct print_ies_data *ie_buffer)
{
	iw_printf("Active Path Selection Protocol ID", "%d", data[0]);
	iw_printf("Active Path Selection Metric ID", "%d", data[1]);
	iw_printf("Congestion Control Mode ID", "%d", data[2]);
	iw_printf("Synchronization Method ID", "%d", data[3]);
	iw_printf("Authentication Protocol ID", "%d", data[4]);
	iw_arr_openf("Mesh Formation Info");
	iw_printf("Number of Peerings", "%d", (data[5] & 0x7E) >> 1);
	if (data[5] & 0x01)
		iw_printf(NULL, "Connected to Mesh Gate");
	if (data[5] & 0x80)
		iw_printf(NULL, "Connected to AS");
	iw_arr_close();
	iw_arr_openf("Mesh Capability");
	if (data[6] & 0x01)
		iw_printf(NULL, "Accepting Additional Mesh Peerings");
	if (data[6] & 0x02)
		iw_printf(NULL, "MCCA Supported");
	if (data[6] & 0x04)
		iw_printf(NULL, "MCCA Enabled");
	if (data[6] & 0x08)
		iw_printf(NULL, "Forwarding");
	if (data[6] & 0x10)
		iw_printf(NULL, "MBCA Supported");
	if (data[6] & 0x20)
		iw_printf(NULL, "TBTT Adjusting");
	if (data[6] & 0x40)
		iw_printf(NULL, "Mesh Power Save Level");
	iw_arr_close();
}

static void print_s1g_capa(const uint8_t type, uint8_t len,
			    const uint8_t *data,
			    const struct print_ies_data *ie_buffer)
{
	print_s1g_capability(data);
}

static void print_short_beacon_int(const uint8_t type, uint8_t len,
			    const uint8_t *data,
			    const struct print_ies_data *ie_buffer)
{
	iw_printf("Value", "%d", (data[1] << 8) | data[0]);
}

static void print_s1g_oper(const uint8_t type, uint8_t len,
			    const uint8_t *data,
			    const struct print_ies_data *ie_buffer)
{
	int oper_ch_width, prim_ch_width;
	int prim_ch_width_subfield = data[0] & 0x1;

	prim_ch_width = 2;

	/* B1-B4 BSS channel width subfield */
	switch ((data[0] >> 1) & 0xf) {
	case 0:
		oper_ch_width = 1;
		prim_ch_width = 1;
		if (!prim_ch_width_subfield) {
			oper_ch_width = -1;
			prim_ch_width = -1;
		}
	break;
	case 1:
		oper_ch_width = 2;
		if (prim_ch_width_subfield)
			prim_ch_width = 1;
		break;
	case 3:
		oper_ch_width = 4;
		if (prim_ch_width_subfield)
			prim_ch_width = 1;
		break;
	case 7:
		oper_ch_width = 8;
		if (prim_ch_width_subfield)
			prim_ch_width = 1;
		break;
	case 15:
		oper_ch_width = 16;
		if (prim_ch_width_subfield)
			prim_ch_width = 1;
		break;
	default:
		oper_ch_width = -1;
		prim_ch_width = -1;
		break;
	}

	iw_arr_openf("Channel Width Info");
	if (oper_ch_width == -1 || prim_ch_width == -1) {
		iw_printf(NULL, "BSS primary channel width: invalid");
		iw_printf(NULL, "BSS operating channel width: invalid");
	} else {
		iw_printf(NULL, "BSS primary channel width: %d MHz", prim_ch_width);
		iw_printf(NULL, "BSS operating channel width: %d MHz", oper_ch_width);
	}
	if (data[0] & BIT(5))
		iw_printf(NULL, "1 MHz primary channel located at the lower side of 2 MHz");
	else
		iw_printf(NULL, "1 MHz primary channel located at the upper side of 2 MHz");

	if (data[0] & BIT(7))
		iw_printf(NULL, "MCS 10 not recommended");
	iw_arr_close();

	iw_printf("Operating Class", "%d", data[1]);
	iw_printf("Primary Channel Number", "%d", data[2]);

	iw_printf("channel index", "%d", data[3]);

	iw_obj_openf("Max S1G MCS Map");
	iw_printf("For 1 SS", "%s", s1g_ss_max_support((data[4] >> 2) & 0x3));
	iw_printf("For 2 SS", "%s", s1g_ss_max_support((data[4] >> 6) & 0x3));
	iw_printf("For 3 SS", "%s", s1g_ss_max_support((data[5] >> 2) & 0x3));
	iw_printf("For 4 SS", "%s", s1g_ss_max_support((data[5] >> 6) & 0x3));
	iw_obj_close();

	iw_obj_openf("Min S1G MCS Map");
	iw_printf("For 1 SS", "%s", s1g_ss_min_support(data[4] & 0x3));
	iw_printf("For 2 SS", "%s", s1g_ss_min_support((data[4] >> 4) & 0x3));
	iw_printf("For 3 SS", "%s", s1g_ss_min_support(data[5] & 0x3));
	iw_printf("For 4 SS", "%s", s1g_ss_min_support((data[5] >> 4) & 0x3));
	iw_obj_close();
}

struct ie_print {
	const char *name;
	void (*print)(const uint8_t type, uint8_t len, const uint8_t *data,
		      const struct print_ies_data *ie_buffer);
	uint8_t minlen, maxlen;
	uint8_t flags;
};

static void print_ie(const struct ie_print *p, const uint8_t type, uint8_t len,
                     const uint8_t *data,
                     const struct print_ies_data *ie_buffer)
{
    int i;

    if (!p->print) return;

	iw_obj_openf(p->name);
	if (len < p->minlen || len > p->maxlen) {
		iw_printf("Invalid Length", "%d", len);
		if (len > 1) {
			iw_arr_openf("Invalid Data");
			for (i = 0; i < len; i++)
				iw_printf(NULL, "%.02x", data[i]);
			iw_arr_close();
		} else if (len) {
			iw_printf("1 byte", "%d", data[0]);
		} else {
			iw_printf("No data", "true");
		}
	} else {
		// print callback
		p->print(type, len, data, ie_buffer);
	}
	iw_obj_close();
}


#define PRINT_IGN {		\
	.name = "IGNORE",	\
	.print = NULL,		\
	.minlen = 0,		\
	.maxlen = 255,		\
}

static const struct ie_print ieprinters[] = {
	[0] = { "SSID", print_ssid, 0, 32,
		 BIT(PRINT_SCAN) | BIT(PRINT_LINK) | BIT(PRINT_LINK_MLO_MLD), },
	[1] = { "Supported rates", print_supprates, 0, 255, BIT(PRINT_SCAN), },
	[3] = { "DS Parameter set", print_ds, 1, 1, BIT(PRINT_SCAN), },
	[5] = { "TIM", print_tim, 4, 255, BIT(PRINT_SCAN), },
	[6] = { "IBSS ATIM window", print_ibssatim, 2, 2, BIT(PRINT_SCAN), },
	[7] = { "Country", print_country, 3, 255, BIT(PRINT_SCAN), },
	[11] = { "BSS Load", print_bss_load, 5, 5, BIT(PRINT_SCAN), },
	[32] = { "Power constraint", print_powerconstraint, 1, 1, BIT(PRINT_SCAN), },
	[35] = { "TPC report", print_tpcreport, 2, 2, BIT(PRINT_SCAN), },
	[42] = { "ERP", print_erp, 1, 255, BIT(PRINT_SCAN), },
	[45] = { "HT capabilities", print_ht_capa, 26, 26, BIT(PRINT_SCAN), },
	[47] = { "ERP D4.0", print_erp, 1, 255, BIT(PRINT_SCAN), },
	[51] = { "AP Channel Report", print_ap_channel_report, 1, 255, BIT(PRINT_SCAN), },
	[59] = { "Supported operating classes", print_supp_op_classes, 1, 255, BIT(PRINT_SCAN), },
	[66] = { "Measurement Pilot Transmission", print_measurement_pilot_tx, 1, 255, BIT(PRINT_SCAN), },
	[74] = { "Overlapping BSS scan params", print_obss_scan_params, 14, 255, BIT(PRINT_SCAN), },
	[61] = { "HT operation", print_ht_op, 22, 22, BIT(PRINT_SCAN), },
	[62] = { "Secondary Channel Offset", print_secchan_offs, 1, 1, BIT(PRINT_SCAN), },
	[191] = { "VHT capabilities", print_vht_capa, 12, 255, BIT(PRINT_SCAN), },
	[192] = { "VHT operation", print_vht_oper, 5, 255, BIT(PRINT_SCAN), },
	[48] = { "RSN", print_rsn, 2, 255, BIT(PRINT_SCAN), },
	[50] = { "Extended supported rates", print_supprates, 0, 255, BIT(PRINT_SCAN), },
	[70] = { "RM enabled capabilities", print_rm_enabled_capabilities, 5, 5, BIT(PRINT_SCAN), },
	[113] = { "MESH Configuration", print_mesh_conf, 7, 7, BIT(PRINT_SCAN), },
	[114] = { "MESH ID", print_ssid, 0, 32, BIT(PRINT_SCAN) | BIT(PRINT_LINK), },
	[127] = { "Extended capabilities", print_capabilities, 0, 255, BIT(PRINT_SCAN), },
	[107] = { "802.11u Interworking", print_interworking, 0, 255, BIT(PRINT_SCAN), },
	[108] = { "802.11u Advertisement", print_11u_advert, 0, 255, BIT(PRINT_SCAN), },
	[111] = { "802.11u Roaming Consortium", print_11u_rcon, 2, 255, BIT(PRINT_SCAN), },
	[195] = { "Transmit Power Envelope", print_tx_power_envelope, 2, 5, BIT(PRINT_SCAN), },
	[214] = { "Short beacon interval", print_short_beacon_int, 2, 2, BIT(PRINT_SCAN), },
	[217] = { "S1G capabilities", print_s1g_capa, 15, 15, BIT(PRINT_SCAN), },
	[232] = { "S1G operation", print_s1g_oper, 6, 6, BIT(PRINT_SCAN), },
};

static void print_wifi_wpa(const uint8_t type, uint8_t len, const uint8_t *data,
			   const struct print_ies_data *ie_buffer)
{
	print_rsn_ie("TKIP", "IEEE 802.1X", len, data);
}

static void print_wifi_osen(const uint8_t type, uint8_t len,
			    const uint8_t *data,
			    const struct print_ies_data *ie_buffer)
{
	print_osen_ie("OSEN", "OSEN", len, data);
}

static bool print_wifi_wmm_param(const uint8_t *data, uint8_t len)
{
	int i;
	static const char *aci_tbl[] = { "BE", "BK", "VI", "VO" };

	if (len < 19){
		iw_printf("Invalid Length", "len < 19, len: %d", len);
		return false;
	}


	iw_printf("Version", "%d", data[0]);

	if (data[0] != 1) {
		return false;
	}

	data++;

	if (data[0] & 0x80){
		iw_printf("u-APSD", "%s", "true");
	}
	data += 2;

	for (i = 0; i < 4; i++) {
		iw_obj_openf("%s", aci_tbl[(data[0] >> 5) & 3]);
		if (data[0] & 0x10) iw_printf("acm", "%s", "true");
		iw_printf("CW", "%d-%d", (1 << (data[1] & 0xf)) - 1, (1 << (data[1] >> 4)) - 1);
		iw_printf("AIFSN", "%d", data[0] & 0xf);

		if (data[2] | data[3]) iw_printf("TXOP_usec", "%d", (data[2] + (data[3] << 8)) * 32);
		data += 4;
		iw_obj_close();
	}
	return true;
}

static void print_wifi_wmm(const uint8_t type, uint8_t len, const uint8_t *data,
			   const struct print_ies_data *ie_buffer)
{
	int i;

	switch (data[0]) {
	case 0x00:
		iw_arr_openf("Information");
		break;
	case 0x01:
		if (print_wifi_wmm_param(data + 1, len - 1))
			return;
		break;
	default:
		char buf[32];
		snprintf(buf, sizeof(buf), "type %d", data[0]);
		iw_arr_openf(buf);
		break;
	}

	for(i = 1; i < len; i++)
		iw_printf(NULL, "%.02x", data[i]);
	iw_arr_close();
}

static const char * wifi_wps_dev_passwd_id(uint16_t id)
{
	switch (id) {
	case 0:
		return "Default (PIN)";
	case 1:
		return "User-specified";
	case 2:
		return "Machine-specified";
	case 3:
		return "Rekey";
	case 4:
		return "PushButton";
	case 5:
		return "Registrar-specified";
	default:
		return "??";
	}
}

static void print_wifi_wps(const uint8_t type, uint8_t len, const uint8_t *data,
			   const struct print_ies_data *ie_buffer)
{
	__u16 subtype, sublen;

	while (len >= 4) {
		subtype = (data[0] << 8) + data[1];
		sublen = (data[2] << 8) + data[3];
		if (sublen > len - 4)
			break;

		switch (subtype) {
			case 0x104a:
				if (sublen < 1) {
					iw_printf("Version invalid length", "%d", sublen);
					break;
				}
				iw_printf("Version",  "%d.%d", data[4] >> 4, data[4] & 0xF);
				break;
			case 0x1011:
				iw_printf("Device name", "%.*s", sublen, data + 4);
				break;
			case 0x1012: {
				uint16_t id;
				if (sublen != 2) {
					iw_printf("Device password ID", "%d", sublen);
					break;
				}
				id = data[4] << 8 | data[5];
				iw_printf("Device Password ID",  "%u (%s)", id, wifi_wps_dev_passwd_id(id));
				break;
			}
			case 0x1021:
				iw_printf("Manufacturer", "%.*s", sublen, data + 4);
				break;
			case 0x1023:
				iw_printf("Model", "%.*s", sublen, data + 4);
				break;
			case 0x1024:
				iw_printf("Model Number", "%.*s", sublen, data + 4);
				break;
			case 0x103b: {
				__u8 val;

				if (sublen < 1) {
					iw_printf("Response Type Invalid Length", "%d", sublen);
					break;
				}
				val = data[4];
				iw_printf("Response Type", "%d%s", val, val == 3 ? " (AP)" : "");
				break;
			}
			case 0x103c: {
				__u8 val;

				if (sublen < 1) {
					iw_printf("RF Bands Invalid Length", "%d", sublen);
					break;
				}
				val = data[4];
				iw_printf("RF bands", "0x%x", val);
				break;
			}
			case 0x1041: {
				__u8 val;

				if (sublen < 1) {
					iw_printf("Selected Registrar Invalid Length", "%d", sublen);
					break;
				}
				val = data[4];
				iw_printf("Selected Registrar", "0x%x", val);
				break;
			}
			case 0x1042:
				iw_printf("Serial Number", "%.*s", sublen, data + 4);
				break;
			case 0x1044: {
				__u8 val;

				if (sublen < 1) {
					iw_printf("Wi-Fi Protected Setup State Invalid Length", "%d", sublen);
					break;
				}
				val = data[4];
				iw_printf("Wi-Fi Protected Setup State", "%d%s%s", val, val == 1 ? " (Unconfigured)" : "", val == 2 ? " (Configured)" : "");
					break;
			}
			case 0x1047:
				if (sublen != 16) {
					iw_printf("UUID Invalid Length", "%d", sublen);
					break;
				}
				iw_printf("UUID", "%02x%02x-%02x%02x%02x%02x%02x%02x",
					"%02x%02x-%02x%02x%02x%02x%02x%02x",
					data[4], data[5], data[6], data[7],
					data[8], data[9], data[10], data[11],
					data[12], data[13], data[14], data[15],
					data[16], data[17], data[18], data[19]);
				break;
			case 0x1049:
				if (sublen == 6 &&
					data[4] == 0x00 &&
					data[5] == 0x37 &&
					data[6] == 0x2a &&
					data[7] == 0x00 &&
					data[8] == 0x01) {
					uint8_t v2 = data[9];
					iw_printf("Version2", "%d.%d", v2 >> 4, v2 & 0xf);
				} else {
					iw_printf("Unknown Vendor Extension Length", "%u", sublen);
				}
				break;
			case 0x1054: {
				if (sublen != 8) {
					iw_printf("Primary Device Type Invalid Length", "%d", sublen);
					break;
				}
				iw_printf("Primary Device Type",
					"%u-%02x%02x%02x%02x-%u",
					data[4] << 8 | data[5],
					data[6], data[7], data[8], data[9],
					data[10] << 8 | data[11]);
				break;
			}
			case 0x1057: {
				__u8 val;
				if (sublen < 1) {
					iw_printf("AP Setup Locked Invalid Length", "%d", sublen);
					break;
				}
				val = data[4];
				iw_printf("AP Setup Locked", "0x%.2x", val);
				break;
			}
			case 0x1008:
			case 0x1053: {
				__u16 meth;

				if (sublen < 2) {
					iw_printf("Config Methods Invalid Length", "%d", sublen);
					break;
				}
				meth = (data[4] << 8) + data[5];
				iw_printf("Config Methods Selected Registrar", "%s", "true");
				iw_arr_openf("Config Methods");

#define T(bit, name) do {		\
	if (meth & (1<<bit)) {		\
		iw_printf(NULL, name); \
	} \
} while (0)

				T(0, "USB");
				T(1, "Ethernet");
				T(2, "Label");
				T(3, "Display");
				T(4, "Ext. NFC");
				T(5, "Int. NFC");
				T(6, "NFC Intf.");
				T(7, "PBC");
				T(8, "Keypad");
				iw_arr_close();
				break;
#undef T
			} //case 0x1053
			default: {
				const __u8 *subdata = data + 4;
				__u16 tmplen = sublen;

				iw_printf("Unknown TLV", "%#.4x, %d bytes", subtype, tmplen);
				iw_arr_openf("Unknown TLV Data");

				while (tmplen) {
					iw_printf(NULL, "%.2x", *subdata);
					subdata++;
					tmplen--;
				}
				iw_arr_close();
				break;
			}
		}

		data += sublen + 4;
		len -= sublen + 4;
	}

	if (len != 0) {
		iw_printf("Bogus Tail Data Length", "%d", len);
		iw_arr_openf("Bogus Tail Data");

		while (len) {
			iw_printf(NULL, "%.2x", *data);
			data++;
			len--;
		}
		iw_arr_close();
	}
}

static const struct ie_print wifiprinters[] = {
	[1] = { "WPA", print_wifi_wpa, 2, 255, BIT(PRINT_SCAN), },
	[2] = { "WMM", print_wifi_wmm, 1, 255, BIT(PRINT_SCAN), },
	[4] = { "WPS", print_wifi_wps, 0, 255, BIT(PRINT_SCAN), },
};

static inline void print_p2p(const uint8_t type, uint8_t len,
			     const uint8_t *data,
			     const struct print_ies_data *ie_buffer)
{
	__u8 subtype;
	__u16 sublen;

	while (len >= 3) {
		subtype = data[0];
		sublen = (data[2] << 8) + data[1];

		if (sublen > len - 3)
			break;

		switch (subtype) {
		case 0x02: /* capability */
			if (sublen < 2) {
				iw_printf("Malformed Capability", "true");
				break;
			}
			iw_printf("Group capa", "0x%.2x", data[3]);
			iw_printf("Device capa", "0x%.2x", data[4]);
			break;
		case 0x0d: /* device info */
			if (sublen < 6 + 2 + 8 + 1) {
				iw_printf("Malformed Device Info", "true");
				break;
			}
			/* fall through */
		case 0x00: /* status */
		case 0x01: /* minor reason */
		case 0x03: /* device ID */
		case 0x04: /* GO intent */
		case 0x05: /* configuration timeout */
		case 0x06: /* listen channel */
		case 0x07: /* group BSSID */
		case 0x08: /* ext listen timing */
		case 0x09: /* intended interface address */
		case 0x0a: /* manageability */
		case 0x0b: /* channel list */
		case 0x0c: /* NoA */
		case 0x0e: /* group info */
		case 0x0f: /* group ID */
		case 0x10: /* interface */
		case 0x11: /* operating channel */
		case 0x12: /* invitation flags */
		case 0xdd: /* vendor specific */
		default: {
			const __u8 *subdata = data + 3;
			__u16 tmplen = sublen;

			iw_obj_openf("Unknown TLV");
			iw_printf("Type", "%#.2x", subtype);
			iw_printf("Length", "%d", tmplen);
			iw_arr_openf("Data");
			while (tmplen) {
				iw_printf(NULL, "%.2x", *subdata);
				subdata++;
				tmplen--;
			}
			iw_arr_close();
			iw_obj_close();
			break;
		}
		}

		data += sublen + 3;
		len -= sublen + 3;
	}

	if (len != 0) {
		iw_obj_openf("Bogus Tail Data");
		iw_printf("Length", "%d", len);
		iw_arr_openf("Data");
		while (len) {
			iw_printf(NULL, "%.2x", *data);
			data++;
			len--;
		}
		iw_arr_close();
		iw_obj_close();
	}
}

static inline void print_hs20_ind(const uint8_t type, uint8_t len,
				  const uint8_t *data,
				  const struct print_ies_data *ie_buffer)
{
	/* I can't find the spec for this...just going off what wireshark uses. */
	if (len > 0)
		iw_printf("DGAF", "%i", (int)(data[0] & 0x1));
	else
		iw_printf("Unexpected Length", "%i", len);
}

static void print_wifi_owe_tarns(const uint8_t type, uint8_t len,
				 const uint8_t *data,
				 const struct print_ies_data *ie_buffer)
{
	char mac_addr[20];
	int ssid_len;

	if (len < 7)
		return;

	mac_addr_n2a(mac_addr, data);
	iw_printf("BSSID", "%s", mac_addr);

	ssid_len = data[6];
	if (ssid_len > len - 7)
		return;
	print_ssid_escaped(ssid_len, data + 7);

	/* optional elements */
	if (len >= ssid_len + 9) {
		iw_printf("Band Info", "%u", data[ssid_len + 7]);
		iw_printf("Channel Info", "%u", data[ssid_len + 8]);
	}
}

static const struct ie_print wfa_printers[] = {
	[9] = { "P2P", print_p2p, 2, 255, BIT(PRINT_SCAN), },
	[16] = { "HotSpot 2.0 Indication", print_hs20_ind, 1, 255, BIT(PRINT_SCAN), },
	[18] = { "HotSpot 2.0 OSEN", print_wifi_osen, 1, 255, BIT(PRINT_SCAN), },
	[28] = { "OWE Transition Mode", print_wifi_owe_tarns, 7, 255, BIT(PRINT_SCAN), },
};

static void print_vendor(unsigned char len, unsigned char *data,
			 bool unknown, enum print_ie_type ptype)
{
	int i;
	if (len < 3) {
		iw_arr_openf("vendor specific too short");
		for(i = 0; i < len; i++){
			iw_printf(NULL, "%.02x", data[i]);
		}
		iw_arr_close();
		return;
	}

	if (len >= 4 && memcmp(data, ms_oui, 3) == 0) {
		if (data[3] < ARRAY_SIZE(wifiprinters) &&
			wifiprinters[data[3]].name &&
			wifiprinters[data[3]].flags & BIT(ptype)) {
			print_ie(&wifiprinters[data[3]],
				data[3], len - 4, data + 4,
				NULL);
			return;
		}
		if (!unknown) return;

		iw_printf("MS/WiFi", "%#.2x", data[3]);
		iw_arr_openf("Data");
		for(i = 0; i < len - 4; i++){
			iw_printf(NULL, "%.02x", data[i + 4]);
		}
		iw_arr_close();
		return;
	}

	if (len >= 4 && memcmp(data, wfa_oui, 3) == 0) {
		if (data[3] < ARRAY_SIZE(wfa_printers) &&
		    wfa_printers[data[3]].name &&
		    wfa_printers[data[3]].flags & BIT(ptype)) {
			print_ie(&wfa_printers[data[3]],
				 data[3], len - 4, data + 4,
				 NULL);
			return;
		}
		if (!unknown)
			return;
		char buf[32];
		snprintf(buf, sizeof(buf), "WFA %#.2x, data", data[3]);
		iw_arr_openf(buf, NULL);
		for(i = 0; i < len - 4; i++)
			iw_printf(NULL, "%.02x", data[i + 4]);
		iw_arr_close();
		return;
	}

	if (!unknown)
		return;

	iw_obj_openf("Vendor specific");
	iw_printf("OUI", "%.2x:%.2x:%.2x", data[0], data[1], data[2]);

	iw_arr_openf("Data");
	for (i = 3; i < len; i++)
		iw_printf(NULL, "%.2x", data[i]);
	iw_arr_close();
	iw_obj_close();
}

static void print_he_capa(const uint8_t type, uint8_t len, const uint8_t *data,
			  const struct print_ies_data *ie_buffer)
{
	print_he_capability(data, len);
}

static const struct ie_print ext_printers[] = {
	[35] = { "HE capabilities", print_he_capa, 21, 54, BIT(PRINT_SCAN), },
};

static void print_extension(unsigned char len, unsigned char *ie,
			    bool unknown, enum print_ie_type ptype)
{
	unsigned char tag;

	if (len < 1) {
		iw_printf("Extension IE empty", "true");
		return;
	}

	tag = ie[0];
	if (tag < ARRAY_SIZE(ext_printers) && ext_printers[tag].name &&
	    ext_printers[tag].flags & BIT(ptype)) {
		print_ie(&ext_printers[tag], tag, len - 1, ie + 1, NULL);
		return;
	}

	if (unknown) {
		int i;

		iw_obj_openf("Unknown Extension ID");
		iw_printf("ID", "%d", ie[0]);
		iw_arr_openf("Data");
		for (i = 1; i < len; i++)
			iw_printf(NULL, "%.2x", ie[i]);
		iw_arr_close();
		iw_obj_close();
	}
}

void print_ies(unsigned char *ie, int ielen, bool unknown,
	       enum print_ie_type ptype)
{
	struct print_ies_data ie_buffer = {
		.ie = ie,
		.ielen = ielen };

	if (ie == NULL || ielen < 0)
		return;

	while (ielen >= 2 && ielen - 2 >= ie[1]) {
		if (ie[0] < ARRAY_SIZE(ieprinters) &&
		    ieprinters[ie[0]].name &&
		    ieprinters[ie[0]].flags & BIT(ptype) &&
			    ie[1] > 0) {
			print_ie(&ieprinters[ie[0]],
				 ie[0], ie[1], ie + 2, &ie_buffer);
		} else if (ie[0] == 221 /* vendor */) {
			print_vendor(ie[1], ie + 2, unknown, ptype);
		} else if (ie[0] == 255 /* extension */) {
			print_extension(ie[1], ie + 2, unknown, ptype);
		} else if (unknown) {
			int i;

			iw_obj_openf("Unknown IE");
			iw_printf("IE", "%d", ie[0]);
			iw_arr_openf("Data");
			for (i=0; i<ie[1]; i++)
				iw_printf(NULL, "%.2x", ie[2+i]);
			iw_arr_close();
			iw_obj_close();
		}
		ielen -= ie[1] + 2;
		ie += ie[1] + 2;
	}
}

static void print_capa_dmg(__u16 capa)
{
	switch (capa & WLAN_CAPABILITY_DMG_TYPE_MASK) {
	case WLAN_CAPABILITY_DMG_TYPE_AP:
		iw_printf(NULL, "DMG_ESS");
		break;
	case WLAN_CAPABILITY_DMG_TYPE_PBSS:
		iw_printf(NULL, "DMG_PCP");
		break;
	case WLAN_CAPABILITY_DMG_TYPE_IBSS:
		iw_printf(NULL, "DMG_IBSS");
		break;
	}

	if (capa & WLAN_CAPABILITY_DMG_CBAP_ONLY)
		iw_printf(NULL, "CBAP_Only");
	if (capa & WLAN_CAPABILITY_DMG_CBAP_SOURCE)
		iw_printf(NULL, "CBAP_Src");
	if (capa & WLAN_CAPABILITY_DMG_PRIVACY)
		iw_printf(NULL, "Privacy");
	if (capa & WLAN_CAPABILITY_DMG_ECPAC)
		iw_printf(NULL, "ECPAC");
	if (capa & WLAN_CAPABILITY_DMG_SPECTRUM_MGMT)
		iw_printf(NULL, "SpectrumMgmt");
	if (capa & WLAN_CAPABILITY_DMG_RADIO_MEASURE)
		iw_printf(NULL, "RadioMeasure");
}

static void print_capa_non_dmg(__u16 capa)
{
	if (capa & WLAN_CAPABILITY_ESS)
		iw_printf(NULL, "ESS");
	if (capa & WLAN_CAPABILITY_IBSS)
		iw_printf(NULL, "IBSS");
	if (capa & WLAN_CAPABILITY_CF_POLLABLE)
		iw_printf(NULL, "CfPollable");
	if (capa & WLAN_CAPABILITY_CF_POLL_REQUEST)
		iw_printf(NULL, "CfPollReq");
	if (capa & WLAN_CAPABILITY_PRIVACY)
		iw_printf(NULL, "Privacy");
	if (capa & WLAN_CAPABILITY_SHORT_PREAMBLE)
		iw_printf(NULL, "ShortPreamble");
	if (capa & WLAN_CAPABILITY_PBCC)
		iw_printf(NULL, "PBCC");
	if (capa & WLAN_CAPABILITY_CHANNEL_AGILITY)
		iw_printf(NULL, "ChannelAgility");
	if (capa & WLAN_CAPABILITY_SPECTRUM_MGMT)
		iw_printf(NULL, "SpectrumMgmt");
	if (capa & WLAN_CAPABILITY_QOS)
		iw_printf(NULL, "QoS");
	if (capa & WLAN_CAPABILITY_SHORT_SLOT_TIME)
		iw_printf(NULL, "ShortSlotTime");
	if (capa & WLAN_CAPABILITY_APSD)
		iw_printf(NULL, "APSD");
	if (capa & WLAN_CAPABILITY_RADIO_MEASURE)
		iw_printf(NULL, "RadioMeasure");
	if (capa & WLAN_CAPABILITY_DSSS_OFDM)
		iw_printf(NULL, "DSSS-OFDM");
	if (capa & WLAN_CAPABILITY_DEL_BACK)
		iw_printf(NULL, "DelayedBACK");
	if (capa & WLAN_CAPABILITY_IMM_BACK)
		iw_printf(NULL, "ImmediateBACK");
}

static int print_bss_handler(struct nl_msg *msg, void *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *bss[NL80211_BSS_MAX + 1];
	char mac_addr[20], dev[20];
	static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
		[NL80211_BSS_TSF] = { .type = NLA_U64 },
		[NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
		[NL80211_BSS_FREQUENCY_OFFSET] = { .type = NLA_U32 },
		[NL80211_BSS_BSSID] = { },
		[NL80211_BSS_BEACON_INTERVAL] = { .type = NLA_U16 },
		[NL80211_BSS_CAPABILITY] = { .type = NLA_U16 },
		[NL80211_BSS_INFORMATION_ELEMENTS] = { },
		[NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
		[NL80211_BSS_SIGNAL_UNSPEC] = { .type = NLA_U8 },
		[NL80211_BSS_STATUS] = { .type = NLA_U32 },
		[NL80211_BSS_SEEN_MS_AGO] = { .type = NLA_U32 },
		[NL80211_BSS_BEACON_IES] = { },
	};
	struct scan_params *params = arg;
	int show = params->show_both_ie_sets ? 2 : 1;
	bool is_dmg = false;

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_BSS]) {
		fprintf(stderr, "bss info missing!\n");
		return NL_SKIP;
	}
	if (nla_parse_nested(bss, NL80211_BSS_MAX,
				tb[NL80211_ATTR_BSS],
				bss_policy)) {
		fprintf(stderr, "failed to parse nested attributes!\n");
		return NL_SKIP;
	}

	if (!bss[NL80211_BSS_BSSID])
		return NL_SKIP;

	mac_addr_n2a(mac_addr, nla_data(bss[NL80211_BSS_BSSID]));
	iw_obj_openf(mac_addr);

	if (tb[NL80211_ATTR_IFINDEX]) {
		if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);
		iw_printf("Ifname", "%s", dev);
	}

	char buf[32] = {0};
	if (bss[NL80211_BSS_STATUS]) {
		switch (nla_get_u32(bss[NL80211_BSS_STATUS])) {
		case NL80211_BSS_STATUS_AUTHENTICATED:
			snprintf(buf, sizeof(buf), "authenticated");
			break;
		case NL80211_BSS_STATUS_ASSOCIATED:
			snprintf(buf, sizeof(buf), "associated");
			break;
		case NL80211_BSS_STATUS_IBSS_JOINED:
			snprintf(buf, sizeof(buf), "joined");
			break;
		default:
			snprintf(buf, sizeof(buf), "unknown status: %d", nla_get_u32(bss[NL80211_BSS_STATUS]));
			break;
		}
	}
	iw_printf("Status", "%s", buf);

	if (bss[NL80211_BSS_LAST_SEEN_BOOTTIME]) {
		unsigned long long bt;
		bt = (unsigned long long)nla_get_u64(bss[NL80211_BSS_LAST_SEEN_BOOTTIME]);
		iw_printf("Last Seen", "%llu.%.3llus [boottime]", bt/1000000000, (bt%1000000000)/1000000);
	}

	if (bss[NL80211_BSS_TSF]) {
		unsigned long long tsf;
		tsf = (unsigned long long)nla_get_u64(bss[NL80211_BSS_TSF]);

		iw_obj_openf("TSF");
		iw_printf("usec", "%llu", tsf);
		iw_printf("dd", "%llu", tsf/1000/1000/60/60/24);
		iw_printf("hh", "%llu", (tsf/1000/1000/60/60) % 24);
		iw_printf("mm", "%llu", (tsf/1000/1000/60) % 60);
		iw_printf("ss", "%llu", (tsf/1000/1000) % 60);
		iw_obj_close();
	}
	if (bss[NL80211_BSS_FREQUENCY]) {
		int freq = nla_get_u32(bss[NL80211_BSS_FREQUENCY]);
		if (bss[NL80211_BSS_FREQUENCY_OFFSET])
			iw_printf("Frequency, MHz", "%d.%d", freq, nla_get_u32(bss[NL80211_BSS_FREQUENCY_OFFSET]));
		else
			iw_printf("Frequency, MHz", "%d", freq);

		if (freq > 45000)
			is_dmg = true;
	}
	if (bss[NL80211_BSS_BEACON_INTERVAL])
		iw_printf("Beacon Interval, TUs", "%d", nla_get_u16(bss[NL80211_BSS_BEACON_INTERVAL]));
	if (bss[NL80211_BSS_CAPABILITY]) {
		__u16 capa = nla_get_u16(bss[NL80211_BSS_CAPABILITY]);
		iw_arr_openf("Capability");
		if (is_dmg){
			print_capa_dmg(capa);
		}else{
			print_capa_non_dmg(capa);
		}
		iw_arr_close();

		iw_printf("Capability Raw Value", "0x%.4x", capa);
	}
	if (bss[NL80211_BSS_SIGNAL_MBM]) {
		int s = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
		iw_printf("Signal", "%d.%.2d dBm", s/100, s%100);
	}
	if (bss[NL80211_BSS_SIGNAL_UNSPEC]) {
		unsigned char s = nla_get_u8(bss[NL80211_BSS_SIGNAL_UNSPEC]);
		iw_printf("Signal, Dbm", "%d/100", s);
	}
	if (bss[NL80211_BSS_SEEN_MS_AGO]) {
		int age = nla_get_u32(bss[NL80211_BSS_SEEN_MS_AGO]);
		iw_printf("Last Seen Ago, ms", "%d", age);
	}

	if (bss[NL80211_BSS_INFORMATION_ELEMENTS] && show--) {
		struct nlattr *ies = bss[NL80211_BSS_INFORMATION_ELEMENTS];
		struct nlattr *bcnies = bss[NL80211_BSS_BEACON_IES];

		if (bss[NL80211_BSS_PRESP_DATA] ||
			(bcnies && (nla_len(ies) != nla_len(bcnies) ||
				memcmp(nla_data(ies), nla_data(bcnies),
					nla_len(ies))))){
			iw_obj_openf("BSS Probe Response Data Frame");
			print_ies(nla_data(ies), nla_len(ies), params->unknown, params->type);
			iw_obj_close();
		}
	}
	if (bss[NL80211_BSS_BEACON_IES] && show--) {
		iw_obj_openf("BSS Beacon Frame");
		print_ies(nla_data(bss[NL80211_BSS_BEACON_IES]),
			nla_len(bss[NL80211_BSS_BEACON_IES]),
			params->unknown, params->type);
		iw_obj_close();
	}

	iw_obj_close();

	return NL_SKIP;
}

static struct scan_params scan_params;

static int handle_scan_dump(struct nl80211_state *state,
			    struct nl_msg *msg,
			    int argc, char **argv,
			    enum id_input id)
{
	if (argc > 1)
		return 1;

	memset(&scan_params, 0, sizeof(scan_params));

	if (argc == 1 && !strcmp(argv[0], "-u"))
		scan_params.unknown = true;
	else if (argc == 1 && !strcmp(argv[0], "-b"))
		scan_params.show_both_ie_sets = true;

	scan_params.type = PRINT_SCAN;

	register_handler(print_bss_handler, &scan_params);
	return 0;
}

static int handle_scan_combined(struct nl80211_state *state,
				struct nl_msg *msg,
				int argc, char **argv,
				enum id_input id)
{
	char **trig_argv;
	static char *dump_argv[] = {
		NULL,
		"scan",
		"dump",
		NULL,
	};
	static const __u32 cmds[] = {
		NL80211_CMD_NEW_SCAN_RESULTS,
		NL80211_CMD_SCAN_ABORTED,
	};
	int trig_argc, dump_argc, err;
	int i;

	if (argc >= 3 && !strcmp(argv[2], "-u")) {
		dump_argc = 4;
		dump_argv[3] = "-u";
	} else if (argc >= 3 && !strcmp(argv[2], "-b")) {
		dump_argc = 4;
		dump_argv[3] = "-b";
	} else
		dump_argc = 3;

	trig_argc = 3 + (argc - 2) + (3 - dump_argc);
	trig_argv = calloc(trig_argc, sizeof(*trig_argv));
	if (!trig_argv)
		return -ENOMEM;
	trig_argv[0] = argv[0];
	trig_argv[1] = "scan";
	trig_argv[2] = "trigger";

	for (i = 0; i < argc - 2 - (dump_argc - 3); i++)
		trig_argv[i + 3] = argv[i + 2 + (dump_argc - 3)];
	err = handle_cmd(state, id, trig_argc, trig_argv);
	free(trig_argv);
	if (err)
		return err;

	/*
	 * WARNING: DO NOT COPY THIS CODE INTO YOUR APPLICATION
	 *
	 * This code has a bug, which requires creating a separate
	 * nl80211 socket to fix:
	 * It is possible for a NL80211_CMD_NEW_SCAN_RESULTS or
	 * NL80211_CMD_SCAN_ABORTED message to be sent by the kernel
	 * before (!) we listen to it, because we only start listening
	 * after we send our scan request.
	 *
	 * Doing it the other way around has a race condition as well,
	 * if you first open the events socket you may get a notification
	 * for a previous scan.
	 *
	 * The only proper way to fix this would be to listen to events
	 * before sending the command, and for the kernel to send the
	 * scan request along with the event, so that you can match up
	 * whether the scan you requested was finished or aborted (this
	 * may result in processing a scan that another application
	 * requested, but that doesn't seem to be a problem).
	 *
	 * Alas, the kernel doesn't do that (yet).
	 */

	if (listen_events(state, ARRAY_SIZE(cmds), cmds) ==
					NL80211_CMD_SCAN_ABORTED) {
		iw_printf("scan aborted", "true");
		return 0;
	}

	dump_argv[0] = argv[0];
	return handle_cmd(state, id, dump_argc, dump_argv);
}
TOPLEVEL(scan, "[-u] [freq <freq>*] [duration <dur>] [ies <hex as 00:11:..>] [meshid <meshid>] [lowpri,flush,ap-force,duration-mandatory] [randomise[=<addr>/<mask>]] [ssid <ssid>*|passive]", 0, 0,
	 CIB_NETDEV, handle_scan_combined,
	 "Scan on the given frequencies and probe for the given SSIDs\n"
	 "(or wildcard if not given) unless passive scanning is requested.\n"
	 "If -u is specified print unknown data in the scan results.\n"
	 "Specified (vendor) IEs must be well-formed.");
COMMAND(scan, dump, "[-u]",
	NL80211_CMD_GET_SCAN, NLM_F_DUMP, CIB_NETDEV, handle_scan_dump,
	"Dump the current scan results. If -u is specified, print unknown\n"
	"data in scan results.");
COMMAND(scan, trigger, "[freq <freq>*] [duration <dur>] [ies <hex as 00:11:..>] [meshid <meshid>] [lowpri,flush,ap-force,duration-mandatory,coloc] [randomise[=<addr>/<mask>]] [ssid <ssid>*|passive]",
	NL80211_CMD_TRIGGER_SCAN, 0, CIB_NETDEV, handle_scan,
	 "Trigger a scan on the given frequencies with probing for the given\n"
	 "SSIDs (or wildcard if not given) unless passive scanning is requested.\n"
	 "Duration(in TUs), if specified, will be used to set dwell times.\n");


static int handle_scan_abort(struct nl80211_state *state,
			     struct nl_msg *msg,
			     int argc, char **argv,
			     enum id_input id)
{
	return 0;
}
COMMAND(scan, abort, "",
	NL80211_CMD_ABORT_SCAN, 0, CIB_NETDEV, handle_scan_abort,
	"Abort ongoing scan");

static int handle_start_sched_scan(struct nl80211_state *state,
				   struct nl_msg *msg,
				   int argc, char **argv, enum id_input id)
{
	return parse_sched_scan(msg, &argc, &argv);
}

static int handle_stop_sched_scan(struct nl80211_state *state,
				  struct nl_msg *msg, int argc, char **argv,
				  enum id_input id)
{
	if (argc != 0)
		return 1;

	return 0;
}

COMMAND(scan, sched_start,
	SCHED_SCAN_OPTIONS,
	NL80211_CMD_START_SCHED_SCAN, 0, CIB_NETDEV, handle_start_sched_scan,
	"Start a scheduled scan at the specified interval on the given frequencies\n"
	"with probing for the given SSIDs (or wildcard if not given) unless passive\n"
	"scanning is requested.  If matches are specified, only matching results\n"
	"will be returned.");
COMMAND(scan, sched_stop, "",
	NL80211_CMD_STOP_SCHED_SCAN, 0, CIB_NETDEV, handle_stop_sched_scan,
	"Stop an ongoing scheduled scan.");
