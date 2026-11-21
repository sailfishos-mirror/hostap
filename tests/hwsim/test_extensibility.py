# Test cases for IEEE 802.11 protocol extensibility
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import hostapd

def test_extensibility_ext_capab(dev, apdev):
    """Extenibility of the Extended Capabilities element"""
    params = {"ssid": "open"}
    # Maximum length Extended Capabilities element
    params["ext_capa"] = 254*"00" + "01"
    hapd = hostapd.add_ap(apdev[0], params)
    dev[0].connect("open", key_mgmt="NONE", scan_freq="2412")
