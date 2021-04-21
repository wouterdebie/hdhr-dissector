/* packet-hdhr.c
 * Routines for HDHomeRun dissection
 * Copyright 2013, Paul Sbarra <sbarra.paul@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>
#include <epan/tvbuff.h>

#define HDHR_PORT 65001
#define HDHR_MIN_LENGTH 8

/* Initialize the protocol and registered fields */
static int proto_hdhr = -1;
static int hf_hdhr_type = -1;
static int hf_hdhr_len = -1;
static int hf_hdhr_chk = -1;
static int hf_payload = -1;
static int hf_pay_tag = -1;
static int hf_pay_len = -1;
static int hf_pay_disc_type = -1;
static int hf_pay_disc_id = -1;
static int hf_pay_getset_name = -1;
static int hf_pay_getset_value = -1;
static int hf_pay_getset_error = -1;
static int hf_pay_base_url = -1;
static int hf_pay_lineup_url = -1;
static int hf_pay_tuner_count = -1;
static int hf_upgrade_offset = -1;
static int hf_upgrade_data = -1;

/* Initialize the subtree pointers */
static gint ett_hdhr = -1;
static gint ett_payload = -1;

#define DISCOVER_REQ 0x0002
#define DISCOVER_RPY 0x0003
#define GETSET_REQ 0x0004
#define GETSET_RPY 0x0005
#define UPGRADE_REQ 0x0006
#define UPGRADE_RPY 0x0007
static const value_string packet_type_names[] = {
    {DISCOVER_REQ, "Discover Request"},
    {DISCOVER_RPY, "Discover Reply"},
    {GETSET_REQ, "Get/Set Request"},
    {GETSET_RPY, "Get/Set Reply"},
    {UPGRADE_REQ, "Upgrade Request"},
    {UPGRADE_RPY, "Upgrade Reply"},
    {0, NULL}};

#define DEVICE_TYPE 0x01
#define DEVICE_ID 0x02
#define GETSET_NAME 0x03
#define GETSET_VALUE 0x04
#define GETSET_LOCKKEY 0x15
#define ERROR_MSG 0x05
#define TUNER_COUNT 0x10
#define BASE_URL 0x2A
#define LINEUP_URL 0x27
static const value_string payload_tag_names[] = {
    {DEVICE_TYPE, "Device Type"},
    {DEVICE_ID, "Device Id"},
    {GETSET_NAME, "Get/Set Name"},
    {GETSET_VALUE, "Get/Set Value"},
    {GETSET_LOCKKEY, "Get/Set Lock Key"},
    {ERROR_MSG, "Error Message"},
    {TUNER_COUNT, "Tuner Count"},
    {BASE_URL, "Base URL"},
    {LINEUP_URL, "Lineup URL"},
    {0, NULL}};

#define DEVICE_TYPE_TUNER 0x00000001
#define DEVICE_TYPE_WILD 0xFFFFFFFF
static const value_string discover_type_names[] = {
    {DEVICE_TYPE_TUNER, "Tuner"},
    {DEVICE_TYPE_WILD, "Any"},
    {0, NULL}};

static int
dissect_hdhr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *hdhr_tree;
    proto_tree *pay_tree;

    guint offset = 0;
    guint length = tvb_captured_length(tvb);
    guint checksum_off = length - 4;

    guint16 packet_type = tvb_get_ntohs(tvb, 0);
    const gchar *packet_type_str;

    guint8 pay_tag;
    guint16 pay_len;
    guint32 upgrade_offset;

    /*** HEURISTICS ***/
    if (tvb_captured_length(tvb) < HDHR_MIN_LENGTH)
        return 0;
    // if (pinfo->ipproto == IP_PROTO_UDP &&
    //     !(packet_type == DISCOVER_REQ ||
    //       packet_type == DISCOVER_RPY))
    //     return 0;
    // if (pinfo->ipproto == IP_PROTO_TCP &&
    //     !(packet_type == GETSET_REQ ||
    //       packet_type == GETSET_RPY ||
    //       packet_type == UPGRADE_REQ ||
    //       packet_type == UPGRADE_RPY))
    //     return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HDHR");

    col_clear(pinfo->cinfo, COL_INFO);
    packet_type = tvb_get_ntohs(tvb, 0);
    packet_type_str = val_to_str(packet_type, packet_type_names, "Unknown (%d)");
    col_add_fstr(pinfo->cinfo, COL_INFO, "[%s]", packet_type_str);

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_hdhr, tvb, 0, -1, ENC_NA);
    proto_item_append_text(ti, ", %s", packet_type_str);
    hdhr_tree = proto_item_add_subtree(ti, ett_hdhr);

    proto_tree_add_item(hdhr_tree, hf_hdhr_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(hdhr_tree, hf_hdhr_len, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    switch (packet_type)
    {
    case DISCOVER_REQ:
    case DISCOVER_RPY:
    case GETSET_REQ:
    case GETSET_RPY:
        while (offset < checksum_off)
        {
            ti = proto_tree_add_item(hdhr_tree, hf_payload, tvb, offset, -1, ENC_NA);
            pay_tree = proto_item_add_subtree(ti, ett_payload);
            pay_tag = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(pay_tree, hf_pay_tag, tvb, offset, 1, pay_tag);
            offset++;

            pay_len = (guint16)tvb_get_guint8(tvb, offset);
            if ((pay_len & 0x80) == 0)
            {
                proto_tree_add_uint(pay_tree, hf_pay_len, tvb, offset, 1, pay_len);
                proto_item_set_len(ti, 2 + pay_len);
                offset++;
            }
            else
            {
                pay_len = (pay_len & 0x7F) + ((guint16)tvb_get_guint8(tvb, offset + 1) << 7);
                proto_tree_add_uint(pay_tree, hf_pay_len, tvb, offset, 2, pay_len);
                proto_item_set_len(ti, 3 + pay_len);
                offset += 2;
            }

            if (offset + pay_len <= checksum_off)
            {
                switch (pay_tag)
                {
                case DEVICE_TYPE:
                    proto_tree_add_item(pay_tree, hf_pay_disc_type, tvb, offset, pay_len, ENC_BIG_ENDIAN);
                    break;
                case DEVICE_ID:
                    proto_tree_add_item(pay_tree, hf_pay_disc_id, tvb, offset, pay_len, ENC_BIG_ENDIAN);
                    break;
                case GETSET_NAME:
                    proto_tree_add_item(pay_tree, hf_pay_getset_name, tvb, offset, pay_len, ENC_NA);
                    break;
                case GETSET_VALUE:
                    proto_tree_add_item(pay_tree, hf_pay_getset_value, tvb, offset, pay_len, ENC_NA);
                    break;
                case ERROR_MSG:
                    proto_tree_add_item(pay_tree, hf_pay_getset_error, tvb, offset, pay_len, ENC_NA);
                    break;
                case BASE_URL:
                    proto_tree_add_item(pay_tree, hf_pay_base_url, tvb, offset, pay_len, ENC_NA);
                    break;
                case LINEUP_URL:
                    proto_tree_add_item(pay_tree, hf_pay_lineup_url, tvb, offset, pay_len, ENC_NA);
                    break;
                case TUNER_COUNT:
                    proto_tree_add_item(pay_tree, hf_pay_tuner_count, tvb, offset, pay_len, ENC_BIG_ENDIAN);
                    break;
                } // end switch (pay_tag)
                offset += pay_len;
            }
            else
            {
                // todo: malformed packet
                offset = checksum_off;
            }
        } // end while (offset < checksum_off)
        break;

    case UPGRADE_REQ:
        upgrade_offset = tvb_get_ntohl(tvb, offset);
        proto_tree_add_uint(hdhr_tree, hf_upgrade_offset, tvb, offset, 4, upgrade_offset);
        offset += 4;
        if (upgrade_offset != 0xFFFFFFFF)
        {
            proto_tree_add_item(hdhr_tree, hf_upgrade_data, tvb, offset, 256, ENC_BIG_ENDIAN);
            offset += 256;
        }
        break;

    case UPGRADE_RPY:
        // todo...
        break;
    } // end switch (packet_type)

    proto_tree_add_item(hdhr_tree, hf_hdhr_chk, tvb, checksum_off, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    return offset;
}

void proto_register_hdhr(void)
{
    static hf_register_info hf[] = {
        {&hf_hdhr_type,
         {"Type", "hdhr.type",
          FT_UINT16, BASE_DEC, VALS(packet_type_names), 0x0,
          NULL, HFILL}},
        {&hf_hdhr_len,
         {"Length", "hdhr.len",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_hdhr_chk,
         {"Checksum", "hdhr.crc",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},
        {&hf_payload,
         {"Payload", "hdhr.pay",
          FT_NONE, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},
        {&hf_pay_tag,
         {"Tag", "hdhr.pay.tag",
          FT_UINT8, BASE_DEC, VALS(payload_tag_names), 0x0,
          NULL, HFILL}},
        {&hf_pay_len,
         {"Length", "hdhr.pay.len",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL}},
        {&hf_pay_disc_type,
         {"Type", "hdhr.pay.disc.type",
          FT_UINT32, BASE_HEX, VALS(discover_type_names), 0x0,
          NULL, HFILL}},
        {&hf_pay_disc_id,
         {"Type", "hdhr.pay.disc.id",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},
        {&hf_pay_getset_name,
         {"Name", "hdhr.pay.gs.name",
          FT_STRINGZ, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},
        {&hf_pay_getset_value,
         {"Value", "hdhr.pay.gs.value",
          FT_STRINGZ, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},
        {&hf_pay_getset_error,
         {"Error", "hdhr.pay.gs.err",
          FT_STRINGZ, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},
        {&hf_pay_base_url,
         {"Value", "hdhr.pay.gs.base_url",
          FT_STRINGZ, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},
        {&hf_pay_lineup_url,
         {"Value", "hdhr.pay.gs.lineup_url",
          FT_STRINGZ, BASE_NONE, NULL, 0x0,
          NULL, HFILL}},
        {&hf_upgrade_offset,
         {"Position", "hdhr.up.off",
          FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},
        {&hf_pay_tuner_count,
         {"Value", "hdhr.pay.gs.tuner_count",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          NULL, HFILL}},
        {&hf_upgrade_data,
         {"Data", "hdhr.up.data",
          FT_BYTES, BASE_NONE, NULL, 0x0,
          NULL, HFILL}}};

    static gint *ett[] = {
        &ett_hdhr,
        &ett_payload};

    proto_hdhr = proto_register_protocol("HDHomeRun", "HDHR", "hdhr");

    proto_register_field_array(proto_hdhr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    prefs_register_protocol(proto_hdhr, NULL);
}

void proto_reg_handoff_hdhr(void)
{
    dissector_handle_t hdhr_handle = create_dissector_handle(dissect_hdhr, proto_hdhr);
    dissector_add_uint("tcp.port", HDHR_PORT, hdhr_handle);
    dissector_add_uint("udp.port", HDHR_PORT, hdhr_handle);
}
