# Test cases for Wi-Fi Aware (NAN)
# Copyright (c) 2025 Intel Corporation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from wpasupplicant import WpaSupplicant
import logging
logger = logging.getLogger()
from utils import *
import string
from hwsim import HWSimRadio
from contextlib import contextmanager, ExitStack

@contextmanager
def hwsim_nan_radios(count=2, n_channels=3):
    """
    Context manager to create NAN-capable HWSimRadios with
    WpaSupplicant instances.
    """
    global_ifaces = ("/tmp/wpas-wlan5", "/tmp/wpas-wlan6", "/tmp/wpas-wlan7")
    if not 1 <= count <= len(global_ifaces):
        raise ValueError(f"count must be in [1, {len(global_ifaces)}]")

    with ExitStack() as stack:
        wpas_list = []
        for global_iface in global_ifaces[:count]:
            _, ifname = stack.enter_context(HWSimRadio(n_channels=n_channels,
                                                       use_nan=True))
            wpas = WpaSupplicant(global_iface=global_iface)
            wpas.interface_add(ifname)
            wpas_list.append(wpas)

        yield wpas_list

def check_nan_capab(dev):
    capa = dev.request("GET_CAPABILITY nan")
    logger.info(f"NAN capabilities: {capa}")

    if "NAN" not in capa:
        raise HwsimSkip(f"NAN not supported: {capa}")

class NanDevice:
    def __init__(self, dev, ifname):
        self.dev = dev
        self.ifname = ifname
        self.wpas = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop()

    def start(self):
        check_nan_capab(self.dev)

        logger.info(f"NAN device starting on {self.ifname}")
        self.dev.interface_add(self.ifname, if_type="nan", create=True)
        self.wpas = WpaSupplicant(ifname=self.ifname)
        self.set("master_pref", "10")
        self.set("dual_band", "0")

        if "OK" not in self.wpas.request("NAN_START"):
            raise Exception(f"Failed to start NAN functionality on {self.ifname}")

        ev = self.wpas.wait_event(["NAN-CLUSTER-JOIN"], timeout=5)
        if ev is None:
            raise Exception(f"NAN-CLUSTER-JOIN event not received on {self.ifname}")

        logger.info(f"NAN device started on {self.ifname}")

    def stop(self):
        logger.info(f"NAN device stopping on {self.ifname}")

        if "OK" not in self.wpas.request("NAN_STOP"):
            raise Exception(f"Failed to stop NAN functionality on {self.ifname}")

        self.dev.global_request(f"INTERFACE_REMOVE {self.ifname}")
        self.wpas.remove_ifname()

        logger.info(f"NAN device stopped on {self.ifname}")

    def publish(self, service_name, ssi=None, unsolicited=1, solicited=1,
                sync=1, match_filter_rx=None, match_filter_tx=None,
                close_proximity=0):

        cmd = f"NAN_PUBLISH service_name={service_name} sync={sync} srv_proto_type=2 fsd=0"

        if solicited == 0:
            cmd += " solicited=0"

        if unsolicited == 0:
            cmd += " unsolicited=0"

        if ssi is not None:
            cmd += f" ssi={ssi}"

        if match_filter_rx:
            cmd += f" match_filter_rx={match_filter_rx}"

        if match_filter_tx:
            cmd += f" match_filter_tx={match_filter_tx}"

        return self.wpas.request(cmd)

    def subscribe(self, service_name, ssi=None, active=1,
                  sync=1, match_filter_rx=None, match_filter_tx=None,
                  srf_include=0, srf_mac_list=None, srf_bf_len=0,
                  srf_bf_idx=0, close_proximity=0):

        cmd = f"NAN_SUBSCRIBE service_name={service_name} sync={sync} srv_proto_type=2"

        if active == 1:
            cmd += " active=1"

        if ssi is not None:
            cmd += f" ssi={ssi}"

        if match_filter_rx:
            cmd += f" match_filter_rx={match_filter_rx}"

        if match_filter_tx:
            cmd += f" match_filter_tx={match_filter_tx}"

        if srf_include:
            cmd += f" srf_include={srf_include}"

        if srf_mac_list:
            cmd += f" srf_mac_list={srf_mac_list}"

        if srf_bf_len > 0:
            cmd += f" srf_bf_len={srf_bf_len} srf_bf_idx={srf_bf_idx}"

        if close_proximity:
            cmd += " close_proximity=1"

        return self.wpas.request(cmd)

    def cancel_publish(self, publish_id):
        logger.info(f"Cancelling publish with ID {publish_id} on {self.ifname}")
        if "OK" not in self.wpas.request(f"NAN_CANCEL_PUBLISH publish_id={publish_id}"):
            raise Exception(f"{self.ifname}: failed to cancel publish id={publish_id}")

    def cancel_subscribe(self, subscribe_id):
        logger.info(f"Cancelling subscribe with ID {subscribe_id} on {self.ifname}")
        if "OK" not in self.wpas.request(f"NAN_CANCEL_SUBSCRIBE subscribe_id={subscribe_id}"):
            raise Exception(f"{self.ifname}: failed to cancel subscribe id={subscribe_id}")

    def set(self, param, value, ok=True):
        logger.info(f"Setting {param} to {value} on {self.ifname}")

        ret = self.wpas.request(f"NAN_SET {param} {value}")

        if ok and "OK" not in ret:
            raise Exception(f"{self.ifname}: failed to set {param}={value}")

        if not ok and "OK" in ret:
            raise Exception(f"{self.ifname}: expected failure for {param}={value}, got OK")

    def update_config(self):
        logger.info(f"Updating NAN configuration on {self.ifname}")
        if "OK" not in self.wpas.request("NAN_UPDATE_CONFIG"):
            raise Exception(f"{self.ifname}: failed to update NAN configuration")

    def transmit(self, handle, req_instance_id, address, ssi=None):
        logger.info(f"Transmitting followup on {self.ifname}")
        cmd = f"NAN_TRANSMIT handle={handle} req_instance_id={req_instance_id} address={address}"
        if ssi is not None:
            cmd += f" ssi={ssi}"
        if "OK" not in self.wpas.request(cmd):
            raise Exception(f"{self.ifname}: failed to transmit NAN followup")

def split_nan_event(ev):
    vals = dict()
    for p in ev.split(' ')[1:]:
        name, val = p.split('=')
        vals[name] = val
    return vals

def nan_sync_verify_event(ev, addr, pid, sid, ssi):
    data = split_nan_event(ev)

    if data['srv_proto_type'] != '2':
        raise Exception("Unexpected srv_proto_type: " + ev)

    if data['ssi'] != ssi:
        raise Exception("Unexpected ssi: " + ev)

    if data['subscribe_id'] != sid:
        raise Exception("Unexpected subscribe_id: " + ev)

    if data['publish_id'] != pid:
        raise Exception("Unexpected publish_id: " + ev)

    if data['address'] != addr:
        raise Exception("Unexpected peer_addr: " + ev)

def nan_sync_discovery(pub, sub, service_name, pssi, sssi,
                       unsolicited=1, solicited=1, active=1,
                       expect_discovery=True,
                       timeout=2):
    paddr = pub.wpas.own_addr()
    saddr = sub.wpas.own_addr()

    pid = pub.publish(service_name, ssi=pssi, unsolicited=unsolicited,
                      solicited=solicited)
    sid = sub.subscribe(service_name, ssi=sssi, active=active)

    logger.info(f"Publish ID: {pid}, Subscribe ID: {sid}")

    ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=timeout)
    if expect_discovery:
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT event not seen")
        nan_sync_verify_event(ev, paddr, pid, sid, pssi)
    else:
        if ev is not None:
            raise Exception("Unexpected NAN-DISCOVERY-RESULT event")

    ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=timeout)
    if active and solicited:
        if ev is None:
            raise Exception("NAN-REPLIED event not seen")
        nan_sync_verify_event(ev, saddr, pid, sid, sssi)
    else:
        if ev is not None:
            raise Exception("Unexpected NAN-REPLIED event")

    return pid, sid, paddr, saddr

def test_nan_sync_active_subscribe(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        nan_sync_discovery(pub, sub, "test_service",
                           pssi="aabbccdd", sssi="ddbbccaa",
                           unsolicited=0)

def test_nan_sync_followup(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        pid, sid, paddr, _ = nan_sync_discovery(pub, sub, "test_service",
                                                pssi="aabbccdd",
                                                sssi="ddbbccaa",
                                                unsolicited=0, timeout=2)
        sub.transmit(handle=sid, req_instance_id=pid, address=paddr,
                     ssi="11223344")
        ev = pub.wpas.wait_event(["NAN-RECEIVE"], timeout=2)
        if ev is None or f"id={pid}" not in ev or f"peer_instance_id={sid}" not in ev or "ssi=11223344" not in ev:
            raise Exception("NAN-RECEIVE followup event not seen or invalid format")

def test_nan_sync_active_subscribe_two_publishers(dev, apdev, params):
    """NAN synchronized active subscribe and 2 publishers"""
    with hwsim_nan_radios(count=3) as [wpas1, wpas2, wpas3], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub, \
        NanDevice(wpas3, "nan2") as ext:
        eaddr = ext.wpas.own_addr()

        essi = "ddbbccaa1212121212121212"

        # Start with the first publisher which is solicited only
        pid, sid, _, _ = nan_sync_discovery(pub, sub, "test_service",
                                            pssi="aabbccdd", sssi="ddbbccaa",
                                            unsolicited=0)

        pub.cancel_publish(pid)

        # And second publisher which is unsolicited only
        sub.wpas.dump_monitor()
        eid = ext.publish("test_service", ssi=essi, solicited=0)

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT event not seen")

        nan_sync_verify_event(ev, eaddr, eid, sid, essi)

        ev = ext.wpas.wait_event(["NAN-REPLIED"], timeout=1)
        if ev is not None:
            raise Exception("NAN-REPLIED event not expected for unsolicited publish")

def test_nan_sync_passive_subscribe(dev, apdev, params):
    """NAN synchronized passive Subscribe and unsolicited publish"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        nan_sync_discovery(pub, sub, "test_service",
                           pssi="aabbccdd001122334455667788",
                           sssi="ddbbccaa001122334455667788",
                           active=0)

def test_nan_sync_active_subscribe_no_match(dev, apdev, params):
    """NAN synchronized active subscribe and with 2 Publishes: no match"""
    with hwsim_nan_radios(count=3) as [wpas1, wpas2, wpas3], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub, \
        NanDevice(wpas3, "nan2") as ext:
        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()
        eaddr = ext.wpas.own_addr()

        pssi = "aabbccdd"
        sssi = "ddbbccaa"
        essi = "ddbbccaa1212121212121212"

        pid = pub.publish("test_dummy", ssi=pssi, unsolicited=0)
        eid = ext.publish("test_dummy", ssi=essi, solicited=0)
        sid = sub.subscribe("test_service", ssi=sssi)

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=5)
        if ev is not None:
            raise Exception("Got unexpected NAN-DISCOVERY-RESULT event")

        ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is not None:
            raise Exception("Unexpected NAN-REPLIED event on solicited publish")

        ev = ext.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is not None:
            raise Exception("Unexpected NAN-REPLIED event on unsolicited publish")

def _nan_sync_publisher_match_filter(sub_tx_filter=None, pub_rx_filter=None,
                                     match=True):
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()

        pssi = "aabbccdd001122334455667788"
        sssi = "ddbbccaa001122334455667788"

        pid = pub.publish("test_pub_match_filter", ssi=pssi, unsolicited=0,
                          match_filter_rx=pub_rx_filter)
        sid = sub.subscribe("test_pub_match_filter", ssi=sssi,
                            match_filter_tx=sub_tx_filter)

        sub_ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
        pub_ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=1)

        pub.cancel_publish(pid)
        sub.cancel_subscribe(sid)

        if match:
            if sub_ev is None:
                raise Exception("NAN-DISCOVERY-RESULT event not seen")
            nan_sync_verify_event(sub_ev, paddr, pid, sid, pssi)

            if pub_ev is None:
                raise Exception("NAN-REPLIED event not seen")
            nan_sync_verify_event(pub_ev, saddr, pid, sid, sssi)
        else:
            if sub_ev is not None:
                raise Exception("Unexpected NAN-DISCOVERY-RESULT event")
            if pub_ev is not None:
                raise Exception("Unexpected NAN-REPLIED event")

def test_nan_sync_publisher_match_filter_1(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter()

def test_nan_sync_publisher_match_filter_2(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="0000000000")

def test_nan_sync_publisher_match_filter_3(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(sub_tx_filter="0000000000")

def test_nan_sync_publisher_match_filter_4(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010301040105")

def test_nan_sync_publisher_match_filter_5(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(sub_tx_filter="01010102010301040105", match=False)

def test_nan_sync_publisher_match_filter_6(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="0000000000",
                                     sub_tx_filter="01010102010301040105")

def test_nan_sync_publisher_match_filter_7(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010301040105",
                                     sub_tx_filter="0000000000")

def test_nan_sync_publisher_match_filter_8(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010301040105",
                                     sub_tx_filter="01010102010301040105")

def test_nan_sync_publisher_match_filter_9(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010101040105",
                                     sub_tx_filter="01010102010301040105",
                                     match=False)

def test_nan_sync_publisher_match_filter_10(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010301040105",
                                     sub_tx_filter="0101000103000105")

def test_nan_sync_publisher_match_filter_11(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="0001020103000105",
                                     sub_tx_filter="01010102010301040105")

def test_nan_sync_publisher_match_filter_12(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="01010102010301040105",
                                     sub_tx_filter="000102000104")

def test_nan_sync_publisher_match_filter_13(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="010100010300",
                                     sub_tx_filter="01010102010301040105",
                                     match=False)

def test_nan_sync_publisher_match_filter_14(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="051122334455",
                                     sub_tx_filter="051122334455")

def test_nan_sync_publisher_match_filter_15(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="0411223344",
                                     sub_tx_filter="051122334455", match=False)

def test_nan_sync_publisher_match_filter_16(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with match filter"""
    _nan_sync_publisher_match_filter(pub_rx_filter="051122334455",
                                     sub_tx_filter="03112233", match=False)

def _nan_sync_subscriber_match_filter(pub_tx_filter=None, sub_rx_filter=None,
                                      match=True):
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()

        pssi = "aabbccdd001122334455667788"
        sssi = "ddbbccaa001122334455667788"

        pid = pub.publish("test_sub_match_filter", ssi=pssi, solicited=0,
                          match_filter_tx=pub_tx_filter)
        sid = sub.subscribe("test_sub_match_filter", active=0, ssi=sssi,
                            match_filter_rx=sub_rx_filter)

        sub_ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)

        pub.cancel_publish(pid)
        sub.cancel_subscribe(sid)

        if match:
            if sub_ev is None:
                raise Exception("NAN-DISCOVERY-RESULT event not seen")
            nan_sync_verify_event(sub_ev, paddr, pid, sid, pssi)
        else:
            if sub_ev is not None:
                raise Exception("Unexpected NAN-DISCOVERY-RESULT event")

def test_nan_sync_subscriber_match_filter_1(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter()

def test_nan_sync_subscriber_match_filter_2(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(sub_rx_filter="0000000000")

def test_nan_sync_subscriber_match_filter_3(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="0000000000")

def test_nan_sync_subscriber_match_filter_4(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(sub_rx_filter="01010102010301040105", match=False)

def test_nan_sync_subscriber_match_filter_5(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105")

def test_nan_sync_subscriber_match_filter_6(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="0000000000",
                                      sub_rx_filter="01010102010301040105")

def test_nan_sync_subscriber_match_filter_7(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105",
                                      sub_rx_filter="0000000000")

def test_nan_sync_subscriber_match_filter_8(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105",
                                      sub_rx_filter="01010102010301040105")

def test_nan_sync_subscriber_match_filter_9(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105",
                                      sub_rx_filter="01010102010101040105", match=False)

def test_nan_sync_subscriber_match_filter_10(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="0101000103000105",
                                      sub_rx_filter="01010102010301040105")

def test_nan_sync_subscriber_match_filter_11(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105",
                                      sub_rx_filter="0001020103000105")

def test_nan_sync_subscriber_match_filter_12(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="0001020104",
                                      sub_rx_filter="01010102010301040105",
                                      match=False)

def test_nan_sync_subscriber_match_filter_13(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="01010102010301040105",
                                      sub_rx_filter="010100010300")

def test_nan_sync_subscriber_match_filter_14(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="051122334455",
                                      sub_rx_filter="051122334455")

def test_nan_sync_subscriber_match_filter_15(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="021122",
                                      sub_rx_filter="051122334455", match=False)

def test_nan_sync_subscriber_match_filter_16(dev, apdev, params):
    """NAN synchronized passive subscribe and unsolicited publish with match filter"""
    _nan_sync_subscriber_match_filter(pub_tx_filter="051122334455",
                                      sub_rx_filter="03112233", match=False)

def _nan_sync_srf(wpas, pub, srf_mac_list=None, srf_include=1,
                  srf_bf_len=0, srf_bf_idx=0, match=True):
    with NanDevice(wpas, "nan1") as sub:
        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()

        pssi = "aabbccdd001122334455667788"
        sssi = "ddbbccaa001122334455667788"

        pid = pub.publish("test_srf", ssi=pssi, unsolicited=0)
        sid = sub.subscribe("test_srf", ssi=sssi, srf_include=srf_include,
                            srf_mac_list=srf_mac_list)

        sub_ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
        pub_ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=1)

        pub.cancel_publish(pid)
        sub.cancel_subscribe(sid)

        if match:
            if sub_ev is None:
                raise Exception("NAN-DISCOVERY-RESULT event not seen")
            nan_sync_verify_event(sub_ev, paddr, pid, sid, pssi)

            if pub_ev is None:
                raise Exception("NAN-REPLIED event not seen")
            nan_sync_verify_event(pub_ev, saddr, pid, sid, sssi)
        else:
            if sub_ev is not None:
                raise Exception("Unexpected NAN-DISCOVERY-RESULT event")
            if pub_ev is not None:
                raise Exception("Unexpected NAN-REPLIED event")

def test_nan_sync_srf_mac_addr_1(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        _nan_sync_srf(wpas2, pub)

def test_nan_sync_srf_mac_addr_2(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        paddr = pub.wpas.own_addr()
        srf = paddr.replace(':', '')

        _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf)
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf,
                          srf_bf_len=1, srf_bf_idx=i)

def test_nan_sync_srf_mac_addr_3(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        paddr = pub.wpas.own_addr()
        srf = paddr.replace(':', '')

        _nan_sync_srf(wpas2, pub, srf_include=0, srf_mac_list=srf, match=False)

        # Test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=0, srf_mac_list=srf,
                          srf_bf_len=1, srf_bf_idx=i, match=False)

def test_nan_sync_srf_mac_addr_4(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        paddr = pub.wpas.own_addr()
        srf = "030303030303" + paddr.replace(':', '')

        _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf)

        # test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf,
                          srf_bf_len=2, srf_bf_idx=i)

def test_nan_sync_srf_mac_addr_5(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        paddr = pub.wpas.own_addr()
        srf = "030303030303" + paddr.replace(':', '') + "040404040404"

        _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf)

        # test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf,
                          srf_bf_len=5, srf_bf_idx=i)

def test_nan_sync_srf_mac_addr_6(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        paddr = pub.wpas.own_addr()
        srf = paddr.replace(':', '') + "040404040404"

        _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf)

        # Test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf,
                          srf_bf_len=3, srf_bf_idx=i)

def test_nan_sync_srf_mac_addr_7(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        srf = "030303030303040404040404"

        _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf, match=False)

        # Test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=1, srf_mac_list=srf,
                          srf_bf_len=3, srf_bf_idx=i, match=False)

def test_nan_sync_srf_mac_addr_8(dev, apdev, params):
    """NAN synchronized active subscribe and solicited publish with MAC address in SRF"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub:
        srf = "030303030303040404040404"

        _nan_sync_srf(wpas2, pub, srf_include=0, srf_mac_list=srf)

        # Test with different SRF BF indexes
        for i in range(4):
            _nan_sync_srf(wpas2, pub, srf_include=0, srf_mac_list=srf,
                          srf_bf_len=3, srf_bf_idx=i)

def _nan_sync_multi_services(params, n_services=10):
    services = []
    for i in range(n_services):
        service_name = f"srv_test_{i}"
        sssi = (i + 1) * "00"
        pssi = (i + 1) * "11"
        services.append({"service_name": service_name, "sssi": sssi,
                         "pssi": pssi})

    with hwsim_nan_radios(count=2) as [wpas1, wpas2], \
        NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        paddr = pub.wpas.own_addr()
        saddr = sub.wpas.own_addr()

        pids = []
        sids = []
        for entry in params:
            service = services[entry["service_id"]]
            if "pub" in entry:
                unsolicited = entry["pub"].get("unsolicited", 1)
                solicited = entry["pub"].get("solicited", 1)
                pub_tx_filter = entry["pub"].get("pub_tx_filter", None)
                pub_rx_filter = entry["pub"].get("pub_rx_filter", None)
                pid = pub.publish(service["service_name"],
                                  ssi=service["pssi"],
                                  unsolicited=unsolicited,
                                  match_filter_rx=pub_rx_filter,
                                  match_filter_tx=pub_tx_filter)

                if entry["pub"].get("replied", False):
                    pids.append({"pid": pid, "replied": False})

            if "sub" in entry:
                active = entry["sub"].get("active", 1)
                sub_tx_filter = entry["sub"].get("sub_tx_filter", None)
                sub_rx_filter = entry["sub"].get("sub_rx_filter", None)
                sid = sub.subscribe(service["service_name"],
                                    ssi=service["sssi"],
                                    active=active,
                                    match_filter_rx=sub_rx_filter,
                                    match_filter_tx=sub_tx_filter)

                if entry["sub"].get("discovered", False):
                    sids.append({"sid": sid, "discovered": False})

        # Now wait for the events. Limit the loop to avoid infinite waiting
        max_loops = 2 * (len(sids) + len(pids))
        loop_count = 0
        while (any(not sid["discovered"] for sid in sids) or
               any(not pid["replied"] for pid in pids)) and loop_count < max_loops:
            loop_count += 1

            if any(not sid["discovered"] for sid in sids):
                ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
                if ev:
                    data = split_nan_event(ev)
                    for sid in sids:
                        if sid["sid"] == data["subscribe_id"]:
                            sid["discovered"] = True
                            break
            if any(not pid["replied"] for pid in pids):
                ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=1)
                if ev:
                    data = split_nan_event(ev)
                    for pid in pids:
                        if pid["pid"] == data["publish_id"]:
                            pid["replied"] = True
                            break

        if any(not sid["discovered"] for sid in sids):
            raise Exception("Not all services where discovered")

        if any(not pid["replied"] for pid in pids):
            raise Exception("Not all services where replied to")

def test_nan_sync_multi_services_1(dev, apdev, params):
    """NAN synchronized service discovery with multiple services: active subscribe"""
    test_params = []
    for i in range(10):
        test_params.append({
            "service_id": i,
            "pub": { "unsolicited": 0, "replied": True},
            "sub": { "active": 1, "discovered": True},
        })

    _nan_sync_multi_services(test_params)

def test_nan_sync_multi_services_2(dev, apdev, params):
    """NAN synchronized service discovery with multiple services: passive subscribe"""
    test_params = []
    for i in range(10):
        test_params.append({
            "service_id": i,
            "pub": { "unsolicited": 1, "replied": False},
            "sub": { "active": 0, "discovered": True},
        })

    _nan_sync_multi_services(test_params)

def test_nan_sync_multi_services_3(dev, apdev, params):
    """NAN synchronized service discovery with multiple services: active subscribe (subset)"""
    test_params = []
    for i in range(0, 10, 2):
        test_params.append({
            "service_id": i,
            "sub": { "active": 1, "discovered": False},
        })

    for i in range(1, 10, 2):
        test_params.append({
            "service_id": i,
            "pub": { "unsolicited": 0, "replied": True,
                     "pub_rx_filter": "01010102010301040105"},
            "sub": { "active": 1, "discovered": True,
                     "sub_tx_filter": "01010102010301040105"},
        })

    _nan_sync_multi_services(test_params)

def test_nan_sync_multi_services_4(dev, apdev, params):
    """NAN synchronized service discovery with multiple services: passive subscribe (subset)"""
    test_params = []
    for i in range(0, 10, 2):
        test_params.append({
            "service_id": i,
            "pub": { "unsolicited": 1, "replied": False,
                     "pub_tx_filter": "01010102010301040105"},
            "sub": { "active": 0, "discovered": True,
                     "sub_rx_filter": "01010102010301040105"},
        })

    for i in range(1, 10, 2):
        test_params.append({
            "service_id": i,
            "pub": { "unsolicited": 1, "replied": False},
        })

    _nan_sync_multi_services(test_params)

def test_nan_config(dev, apdev, params):
    """NAN configuration testing"""
    with hwsim_nan_radios(count=1) as [wpas1], \
        NanDevice(wpas1, "nan0") as nan:
        # Start with some invalid values
        nan.set("master_pre", "20", ok=False)
        nan.set("cluser_id", "12", ok=False)
        nan.set("scan_peod", "30", ok=False)
        nan.set("can_dwell_time", "150", ok=False)
        nan.set("discovery_beaconl", "1", ok=False)
        nan.set("low_band_cfg", "-70,-85,", ok=False)
        nan.set("high_band_cfg", "75,,2", ok=False)

        # And then set the valid values
        nan.set("master_pref", "20")
        nan.set("cluster_id", "50:6f:9a:01:01:01")
        nan.set("scan_period", "30")
        nan.set("scan_dwell_time", "150")
        nan.set("discovery_beacon_interval", "100")

        nan.set("low_band_cfg", "-59,-65,1,0")
        nan.set("high_band_cfg", "-59,-65,2,0")

        # and finally update the configuration
        logger.info("Updating NAN configuration")
        nan.update_config()
