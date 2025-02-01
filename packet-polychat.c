/* packet-polychat.c
 * Routines for Polychat dissection
 * Copyright 2025, Stephen Ludin <sludin@ludin.org>
 *
 * SPDX-License-Identifier: MIT
 */


#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/value_string.h>

#define POLYCHAT_PORT 8000
static int proto_polychat = -1;

static int hf_polychat_pdu_type;
static int hf_polychat_flag;
static int hf_polychat_handle;
static int hf_polychat_sender;
static int hf_polychat_handle_count;
static int hf_polychat_list_length;
static int hf_polychat_msg;


static int ett_polychat;

#define CMD_TYPE_NONE               0
#define CMD_TYPE_REGISTER           1
#define CMD_TYPE_REGISTER_SUCCESS   2
#define CMD_TYPE_REGISTER_FAIL      3
#define CMD_TYPE_BROADCAST          4
#define CMD_TYPE_DIRECT             5
#define CMD_TYPE_MULTICAST          6
#define CMD_TYPE_BAD_HANDLE         7
#define CMD_TYPE_LIST_HANDLES      10
#define CMD_TYPE_LIST_LEN          11
#define CMD_TYPE_HANDLE            12
#define CMD_TYPE_HANDLES_LIST_DONE 13


static const value_string flag_names[] = {
    { CMD_TYPE_NONE,              "None" },
    { CMD_TYPE_REGISTER,          "Register" },
    { CMD_TYPE_REGISTER_SUCCESS,  "Register Success" },
    { CMD_TYPE_REGISTER_FAIL,     "Register Failure" },
    { CMD_TYPE_BROADCAST,         "Broadcast" },
    { CMD_TYPE_DIRECT,            "Direct" },
    { CMD_TYPE_MULTICAST,         "Multicast" },
    { CMD_TYPE_BAD_HANDLE,        "Unknown Handle" },
    { CMD_TYPE_LIST_HANDLES,      "List" },
    { CMD_TYPE_LIST_LEN,          "List Length" },
    { CMD_TYPE_HANDLE,            "Handle" },
    { CMD_TYPE_HANDLES_LIST_DONE, "List Comlete" },
    { 0, NULL }
};

static int dissect_polychat_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCHAT");
    col_clear(pinfo->cinfo,COL_INFO);

    int pos = 0;


    proto_item *ti = proto_tree_add_item(tree, proto_polychat, tvb, 0, -1, ENC_BIG_ENDIAN);
    proto_tree *polychat_tree = proto_item_add_subtree(ti, ett_polychat);

    uint16_t len = tvb_get_ntohs(tvb, pos);
    proto_tree_add_item(polychat_tree, hf_polychat_pdu_type, tvb, pos, 2, ENC_BIG_ENDIAN);
    pos += 2;

    uint8_t flag = tvb_get_int8(tvb, pos);
    proto_tree_add_item(polychat_tree, hf_polychat_flag, tvb, pos, 1, ENC_BIG_ENDIAN);
    pos += 1;


    col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                 val_to_str(flag, flag_names, "Unknown (0x%02x)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, " Length=%d", len );


    switch( flag ) {
    case CMD_TYPE_BROADCAST:
    case CMD_TYPE_DIRECT:
    case CMD_TYPE_MULTICAST: {
        uint8_t slen = tvb_get_int8(tvb, pos);
        proto_tree_add_item(polychat_tree, hf_polychat_sender, tvb, pos + 1, slen, ENC_ASCII);

        uint8_t *sender = tvb_get_string_enc( pinfo->pool, tvb, pos + 1, slen, ENC_ASCII);
        col_append_fstr(pinfo->cinfo, COL_INFO, " Sender=%s", sender );

        pos += 1 + slen;

        uint8_t hcount = 0;

        if ( flag != CMD_TYPE_BROADCAST ) {
            hcount = tvb_get_int8(tvb, pos );
            proto_tree_add_item(polychat_tree, hf_polychat_handle_count, tvb, pos, 1, ENC_BIG_ENDIAN);
            pos++;
        }

        for ( int i = 0; i < hcount; i++ ) {
            uint8_t hlen = tvb_get_int8(tvb, pos);
            proto_tree_add_item(polychat_tree, hf_polychat_handle, tvb, pos + 1, hlen, ENC_ASCII);

            /* Add the first recipent in the info column */
            if ( i == 0 ) {
                uint8_t *recipient = tvb_get_string_enc( pinfo->pool, tvb, pos + 1, hlen, ENC_ASCII);
                col_append_fstr(pinfo->cinfo, COL_INFO, " Recipient%s=%s%s",
                                (hcount == 1 ? "" : "s"),
                                recipient,
                                (hcount == 1 ? "" : "...") );
            }

            pos += 1 + hlen;
        }

        proto_tree_add_item(polychat_tree, hf_polychat_msg, tvb, pos, -1, ENC_ASCII);
        pos += tvb_strsize(tvb, pos);


    }
        break;

    case CMD_TYPE_REGISTER:
    case CMD_TYPE_HANDLE: {
        uint8_t hlen = tvb_get_int8(tvb, pos);
        proto_tree_add_item(polychat_tree, hf_polychat_handle, tvb, pos + 1, hlen, ENC_ASCII);
        uint8_t *handle = tvb_get_string_enc( pinfo->pool, tvb, pos + 1, hlen, ENC_ASCII);
        col_append_fstr(pinfo->cinfo, COL_INFO, " Handle=%s", handle );

        pos += 1 + hlen;
    }
        break;

    case CMD_TYPE_LIST_LEN: {

        proto_tree_add_item(polychat_tree, hf_polychat_list_length, tvb, pos, 4, ENC_BIG_ENDIAN);
        uint32_t list_len = tvb_get_int32( tvb, pos, ENC_BIG_ENDIAN );
        col_append_fstr(pinfo->cinfo, COL_INFO, " List_Length=%u", list_len );


        pos += 4;
    }




    break;

    }



    return tvb_captured_length(tvb);
}

static guint get_polychat_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    if (tvb_reported_length_remaining(tvb, offset) < 2) {
        return 0;
    }

    return tvb_get_ntohs(tvb, offset);
}


static int dissect_polychat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data )
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PolyChat");

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 2, get_polychat_pdu_len, dissect_polychat_pdu, data);

    return tvb_captured_length(tvb);
}



void proto_register_polychat(void)
{
    static hf_register_info hf[] = {
        { &hf_polychat_pdu_type,
            { "Length", "polychat.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_polychat_flag,
            { "Flag", "polychat.flag",
            FT_UINT8, BASE_DEC,
            VALS(flag_names), 0x0,
            NULL, HFILL }
        },
        { &hf_polychat_sender,
            { "Sender", "polychat.sender",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_polychat_handle,
            { "Recipient", "polychat.handle",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_polychat_handle_count,
            { "Recipient Count", "polychat.handle_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_polychat_msg,
            { "Message", "polychat.msg",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_polychat_list_length,
            { "Count", "polychat.list_length",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

    };

    static int *ett[] = {
        &ett_polychat
    };

    proto_polychat = proto_register_protocol (
        "POLYCHAT Protocol", /* name */
        "PCHAT",          /* short name */
        "polychat"           /* abbrev */
                                              );

    proto_register_field_array(proto_polychat, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

void proto_reg_handoff_polychat(void)
{
    static dissector_handle_t polychat_handle;

    polychat_handle = create_dissector_handle(dissect_polychat, proto_polychat);
    dissector_add_uint("tcp.port", POLYCHAT_PORT, polychat_handle);
}
