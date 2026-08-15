# Test cases for NAN IEEE Data Path (IDP) with NAN integration
# Copyright (c) Qualcomm Technologies, Inc.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

from remotehost import remote_compatible
from contextlib import contextmanager
import time
import logging
logger = logging.getLogger()

import hwsim_utils
from wpasupplicant import WpaSupplicant
from utils import *
from hwsim import HWSimRadio

from test_nan import (NanDevice, nan_sync_discovery, nan_sync_verify_event,
                      split_nan_event, check_nan_capab, hwsim_nan_radios,
                      run_nan_pairing)
from test_p2p_channel import set_country

def check_idp_support(dev):
    res = dev.request("IDP_LIST")
    if "UNKNOWN COMMAND" in res or "FAIL" in res:
        raise HwsimSkip("IDP not supported")

def check_pasn_capab(dev):
    if "PASN" not in dev.get_capability("auth_alg"):
        raise HwsimSkip("PASN not supported")

def nan_idp_setup_devices(dev0, dev1):
    check_idp_support(dev0)
    check_idp_support(dev1)
    check_pasn_capab(dev0)
    check_pasn_capab(dev1)

    # A plain FLUSH does not touch IDP sessions or NAN core state, so a
    # session left over from an earlier case would still be listed here.
    dev0.request("IDP_FLUSH")
    dev1.request("IDP_FLUSH")
    dev0.request("NAN_FLUSH")
    dev1.request("NAN_FLUSH")
    time.sleep(0.1)

    return dev0.own_addr(), dev1.own_addr()

def _idp_interfaces(dev):
    res = dev.global_request("INTERFACES")
    return [line.split()[0] for line in res.splitlines() if line]

def _wait_for_idp_interfaces_removed(devices, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if all(not any(ifname.startswith(("nan-ap", "nan-sta"))
                       for ifname in _idp_interfaces(dev))
               for dev in devices):
            return
        time.sleep(0.1)

    remaining = [ifname for dev in devices for ifname in _idp_interfaces(dev)
                 if ifname.startswith(("nan-sap", "nan-sta"))]
    raise Exception(f"IDP interfaces not removed: {remaining}")

@contextmanager
def nan_idp_devices(wpas1, wpas2):
    """Tear IDP down before the NAN interface that set it up.

    An IDP link runs on its own interface created off the NAN one, so letting
    NanDevice remove the NAN interface first leaves those behind. Asserting
    they are gone turns that leak into a failure here rather than an unrelated
    failure in whichever case runs next."""

    with NanDevice(wpas1, "nan0") as pub, NanDevice(wpas2, "nan1") as sub:
        try:
            yield pub, sub
        finally:
            for nan in (pub, sub):
                try:
                    nan.wpas.request("IDP_FLUSH")
                except Exception as e:
                    logger.warning("IDP_FLUSH during cleanup failed: %s", e)
            for nan in (pub, sub):
                try:
                    nan.wpas.request("NAN_FLUSH")
                except Exception as e:
                    logger.warning("NAN_FLUSH during cleanup failed: %s", e)
            _wait_for_idp_interfaces_removed((wpas1, wpas2))

def get_idp_local_session_id(dev):
    """Get the local session index from IDP_LIST output.

    This is the first column, which each device assigns independently, so the
    two ends of a link have no reason to report the same value. The IDP
    Session ID that both ends do agree on is a separate column; see
    get_idp_negotiated_session_id()."""

    res = dev.request("IDP_LIST")
    lines = res.split('\n')
    for line in lines:
        if line and not line.startswith('id'):
            parts = line.split()
            if len(parts) >= 1:
                return parts[0]
    return None

def get_idp_session_info(dev):
    res = dev.request("IDP_LIST")
    lines = res.split('\n')
    sessions = []
    for line in lines:
        if line and not line.startswith('id'):
            parts = line.split()
            if len(parts) >= 3:
                sessions.append({
                    'id': parts[0],
                    'peer': parts[1],
                    'role': parts[2],
                    'state': parts[3] if len(parts) > 3 else 'UNKNOWN',
                    'idp_session_id': parts[4] if len(parts) > 4 else None
                })
    return sessions

def get_idp_negotiated_session_id(dev):
    """Get the IDP Session ID carried in the IDP ID attribute.

    The IDP AP creates it and is the only side that sends it, so both ends of
    a link report the same value once setup is complete. Returns None if
    wpa_supplicant does not report the column at all."""

    for session in get_idp_session_info(dev):
        return session['idp_session_id']
    return None

def check_idp_session_id_agreement(ap_dev, sta_dev):
    """Check that both ends of a link name the IDP by the same Session ID.

    The identifier travels in one direction only, in the IDP ID attribute that
    just the AP sends, so this is what shows it reached the station: in PASN M1
    when the initiator is the AP, in PASN M2 when it is not."""

    ap_sid = get_idp_negotiated_session_id(ap_dev)
    sta_sid = get_idp_negotiated_session_id(sta_dev)

    if ap_sid is None or sta_sid is None:
        raise Exception("IDP_LIST did not report an IDP Session ID "
                        f"(ap={ap_sid} sta={sta_sid})")

    if ap_sid == '0':
        raise Exception("IDP AP did not assign an IDP Session ID")

    if ap_sid != sta_sid:
        raise Exception(f"IDP Session ID mismatch: ap={ap_sid} sta={sta_sid}")

    logger.info(f"Both ends agree on IDP Session ID {ap_sid}")

def terminate_all_idp_sessions(dev, peer_dev=None):
    """Terminate all IDP sessions on a device.

    If peer_dev is given, also handle the IDP-TERM-REQUEST that the peer
    receives (2-way termination)."""

    sessions = get_idp_session_info(dev)
    for session in sessions:
        dev.request(f"IDP_TERMINATE peer={session['peer']}")

    if peer_dev and sessions:
        ev = peer_dev.wait_event(["IDP-TERM-REQUEST"], timeout=5)
        if ev:
            term_peer = None
            for token in ev.split():
                if token.startswith("peer="):
                    term_peer = token[5:]
                    break
            if term_peer:
                peer_dev.request(f"IDP_TERM_RESPONSE peer={term_peer} accept")

    time.sleep(2)

def terminate_idp_session(initiator, peer, peer_addr, mode=2):
    """Terminate an IDP session (2-way or 3-way) and handle peer TERM-REQUEST.

    Returns (ev_initiator, ev_peer) - either may be None on timeout."""

    if mode == 3:
        res = initiator.request(f"IDP_TERMINATE peer={peer_addr} mode=3")
    else:
        res = initiator.request(f"IDP_TERMINATE peer={peer_addr}")
    if "OK" not in res:
        raise Exception(f"IDP_TERMINATE (mode={mode}) failed: {res}")

    ev = peer.wait_event(["IDP-TERM-REQUEST"], timeout=5)
    if ev:
        term_peer = None
        for token in ev.split():
            if token.startswith("peer="):
                term_peer = token[5:]
                break
        if term_peer:
            peer.request(f"IDP_TERM_RESPONSE peer={term_peer} accept")

    ev_init = initiator.wait_event(["IDP-TERMINATED"], timeout=5)
    ev_peer = peer.wait_event(["IDP-TERMINATED"], timeout=5)
    return ev_init, ev_peer

def wait_idp_pending_accept(dev, timeout=10):
    ev = dev.wait_event(["IDP-REQUEST"], timeout=timeout)
    if ev is None:
        return None
    peer = None
    role = None
    for token in ev.split():
        if token.startswith("peer="):
            peer = token[5:]
        elif token.startswith("role="):
            role = token[5:]
    return {'peer': peer, 'role': role, 'event': ev}

def accept_idp_request(dev, peer_addr, channel=None, freq=None):
    chan_args = ""
    if channel is not None:
        chan_args += f" channel={channel}"
    if freq is not None:
        chan_args += f" freq={freq}"
    res = dev.request(f"IDP_RESPONSE peer={peer_addr} accept{chan_args}")
    if "FAIL" in res:
        raise Exception(f"IDP_RESPONSE accept failed: {res}")
    return res

def nan_idp_discovery_and_pair(pub, sub, service_name, pub_role="ap",
                               sub_role="sta", pub_cipher_suites=None,
                               channel=None, freq=None):
    """
    Perform NAN discovery and initiate IDP pairing.
    The publisher initiates IDP_REQUEST; the subscriber receives IDP-REQUEST
    event and must respond with IDP_RESPONSE accept.
    channel/freq: optional channel hint passed to IDP_REQUEST (e.g., channel=6
    freq=2437) to force 2.4 GHz in hwsim when the initiator is STA role and
    the responder would otherwise pick an unsupported 5 GHz channel.
    Returns: (pid, sid, paddr, saddr, pub_session_id, sub_session_id)
    """
    pub.set("npk_caching", "1")
    sub.set("npk_caching", "1")
    pub.set("pairing_verification", "1")
    sub.set("pairing_verification", "1")

    paddr = pub.wpas.own_addr()
    saddr = sub.wpas.own_addr()
    if pub_cipher_suites is None:
        pid, sid, paddr, saddr = nan_sync_discovery(pub, sub, service_name,
                                                    pssi="aabbccdd",
                                                    sssi="ddbbccaa",
                                                    unsolicited=0)
    else:
        pid = pub.publish(service_name, ssi="aabbccdd", unsolicited=0,
                          cipher_suites=pub_cipher_suites)
        sid = sub.subscribe(service_name, ssi="ddbbccaa", active=1)

        ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
        if ev is None:
            raise Exception("NAN-DISCOVERY-RESULT event not seen")
        nan_sync_verify_event(ev, paddr, pid, sid, "aabbccdd")

        ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
        if ev is None:
            raise Exception("NAN-REPLIED event not seen")
        nan_sync_verify_event(ev, saddr, pid, sid, "ddbbccaa")

    logger.info(f"NAN discovery complete: pub_id={pid}, sub_id={sid}")

    pairing_password = "password123"
    run_nan_pairing(sub, pub, pid, sid, "SAE", password=pairing_password)
    logger.info("NAN Pairing complete")

    # Discovery has served its purpose. Leaving it running keeps queuing
    # service frame radio work, which competes with the scan the IDP station
    # needs to find the AP and can starve it.
    pub.cancel_publish(pid)
    sub.cancel_subscribe(sid)
    time.sleep(1)

    logger.info(f"Publisher initiating IDP session as {pub_role}...")
    chan_args = ""
    if channel is not None:
        chan_args += f" channel={channel}"
    if freq is not None:
        chan_args += f" freq={freq}"
    res = pub.wpas.request(f"IDP_REQUEST peer={saddr} role={pub_role} handle={pid} instance_id={sid}{chan_args}")
    if "FAIL" in res:
        raise Exception(f"Failed to start IDP on publisher as {pub_role}: {res}")

    logger.info("Waiting for IDP-REQUEST event on subscriber...")
    req = wait_idp_pending_accept(sub.wpas, timeout=15)
    if req is None:
        raise Exception("Subscriber did not receive IDP-REQUEST event")

    # When the subscriber is AP (pub_role=sta), pass the channel hint so the
    # responder-AP picks 2.4 GHz instead of 5 GHz (which hwsim cannot use).
    if sub_role == "ap" and channel is not None and freq is not None:
        accept_idp_request(sub.wpas, req['peer'], channel=channel, freq=freq)
    else:
        accept_idp_request(sub.wpas, req['peer'])

    ev = pub.wpas.wait_event(["IDP-NEGOTIATION-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("IDP-NEGOTIATION-SUCCESS not seen on publisher")

    ev = sub.wpas.wait_event(["IDP-NEGOTIATION-SUCCESS"], timeout=15)
    if ev is None:
        raise Exception("IDP-NEGOTIATION-SUCCESS not seen on subscriber")

    # The STA may need to rescan (5 s interval) before finding the AP beacon.
    ev = sub.wpas.wait_event(["IDP-ESTABLISHED"], timeout=30)
    if ev is None:
        raise Exception("IDP-ESTABLISHED not seen on subscriber (STA side)")
    logger.info(f"Subscriber IDP established: {ev.strip()}")

    ev = pub.wpas.wait_event(["IDP-ESTABLISHED"], timeout=30)
    if ev is None:
        raise Exception("IDP-ESTABLISHED not seen on publisher (AP side)")
    logger.info(f"Publisher IDP established: {ev.strip()}")

    # Allow the data path to stabilize before the caller proceeds
    # (avoids hwsim TX-w/o-channel kernel warnings on immediate teardown,
    # and gives the radio work queue time to process pending scans).
    time.sleep(7)

    pub_session_id = get_idp_local_session_id(pub.wpas)
    sub_session_id = get_idp_local_session_id(sub.wpas)

    return pid, sid, paddr, saddr, pub_session_id, sub_session_id

@remote_compatible
def test_nan_idp_basic_ap_sta(dev, apdev, params):
    """NAN + IDP test - NAN discovery followed by IDP pairing (AP/STA)"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2]:
        nan_idp_setup_devices(wpas1, wpas2)

        with nan_idp_devices(wpas1, wpas2) as (pub, sub):
            logger.info("=== NAN + IDP Basic AP/STA Test ===")

            pid, sid, paddr, saddr, pub_sid, sub_sid = \
                nan_idp_discovery_and_pair(pub, sub, "test_service",
                                           pub_role="ap", sub_role="sta")

            sessions_pub = get_idp_session_info(pub.wpas)
            sessions_sub = get_idp_session_info(sub.wpas)

            if len(sessions_pub) != 1 or \
               sessions_pub[0]['role'].lower() != 'ap':
                raise Exception(f"Unexpected session info on publisher: {sessions_pub}")

            if len(sessions_sub) != 1 or \
               sessions_sub[0]['role'].lower() != 'sta':
                raise Exception(f"Unexpected session info on subscriber: {sessions_sub}")

            # The publisher is the AP here, so the IDP Session ID it assigned
            # had to reach the subscriber in PASN M1.
            check_idp_session_id_agreement(pub.wpas, sub.wpas)

            logger.info("IDP sessions established successfully")

            terminate_all_idp_sessions(pub.wpas, peer_dev=sub.wpas)
            logger.info("=== Test Completed Successfully ===")

@remote_compatible
def test_nan_idp_with_two_cipher(dev, apdev, params):
    """NAN + IDP test aligned to WTS roles with two cipher suites (1,8)"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2]:
        nan_idp_setup_devices(wpas1, wpas2)

        with nan_idp_devices(wpas1, wpas2) as (pub, sub):
            logger.info("=== NAN + IDP WTS-style roles Test (Cipher Suites 1,8) ===")

            pub.set("npk_caching", "1")
            sub.set("npk_caching", "1")
            pub.set("pairing_verification", "1")
            sub.set("pairing_verification", "1")

            paddr = pub.wpas.own_addr()
            saddr = sub.wpas.own_addr()
            pid = pub.publish("test_service_two_cipher", ssi="aabbccdd",
                              unsolicited=0, cipher_suites="1,8")
            sid = sub.subscribe("test_service_two_cipher", ssi="ddbbccaa",
                                active=1)

            ev = sub.wpas.wait_event(["NAN-DISCOVERY-RESULT"], timeout=2)
            if ev is None:
                raise Exception("NAN-DISCOVERY-RESULT event not seen")

            ev = pub.wpas.wait_event(["NAN-REPLIED"], timeout=2)
            if ev is None:
                raise Exception("NAN-REPLIED event not seen")

            run_nan_pairing(sub, pub, pid, sid, "SAE", password="password123")

            pub.cancel_publish(pid)
            sub.cancel_subscribe(sid)
            time.sleep(1)

            res = sub.wpas.request(
                f"IDP_REQUEST peer={paddr} role=sta handle={sid} instance_id={pid}"
                f" channel=6 freq=2437")
            if "FAIL" in res:
                raise Exception(f"Failed to start IDP on subscriber as sta: {res}")

            req = wait_idp_pending_accept(pub.wpas, timeout=15)
            if req is None:
                raise Exception("Publisher did not receive IDP-REQUEST event")
            # Publisher is AP-responder; force 2.4 GHz so hwsim can set the
            # channel.
            accept_idp_request(pub.wpas, req['peer'], channel=6, freq=2437)

            ev = sub.wpas.wait_event(["IDP-NEGOTIATION-SUCCESS"], timeout=15)
            if ev is None:
                raise Exception(f"IDP-NEGOTIATION-SUCCESS not seen on subscriber")

            ev = pub.wpas.wait_event(["IDP-NEGOTIATION-SUCCESS"], timeout=15)
            if ev is None:
                raise Exception(f"IDP-NEGOTIATION-SUCCESS not seen on publisher")

            ev = sub.wpas.wait_event(["IDP-ESTABLISHED"], timeout=30)
            if ev is None:
                raise Exception("IDP-ESTABLISHED not seen on subscriber (STA side)")
            logger.info(f"Subscriber IDP established: {ev.strip()}")

            ev = pub.wpas.wait_event(["IDP-ESTABLISHED"], timeout=30)
            if ev is None:
                raise Exception("IDP-ESTABLISHED not seen on publisher (AP side)")
            logger.info(f"Publisher IDP established: {ev.strip()}")

            # Allow the data path to stabilize before teardown.
            time.sleep(7)

            sessions_pub = get_idp_session_info(pub.wpas)
            sessions_sub = get_idp_session_info(sub.wpas)

            if len(sessions_pub) != 1 or sessions_pub[0]['role'].lower() != 'ap':
                raise Exception(f"Unexpected session info on publisher: {sessions_pub}")

            if len(sessions_sub) != 1 or sessions_sub[0]['role'].lower() != 'sta':
                raise Exception(f"Unexpected session info on subscriber: {sessions_sub}")

            terminate_all_idp_sessions(pub.wpas, peer_dev=sub.wpas)
            logger.info("=== Two-cipher IDP test completed successfully ===")

@remote_compatible
def test_nan_idp_basic_sta_ap(dev, apdev, params):
    """NAN + IDP test - NAN discovery followed by IDP pairing (STA/AP - reverse roles)"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2]:
        nan_idp_setup_devices(wpas1, wpas2)

        with nan_idp_devices(wpas1, wpas2) as (pub, sub):
            logger.info("=== NAN + IDP Basic STA/AP Test (Reverse Roles) ===")

            pid, sid, paddr, saddr, pub_sid, sub_sid = \
                nan_idp_discovery_and_pair(pub, sub, "test_service",
                                           pub_role="sta", sub_role="ap",
                                           channel=6, freq=2437)

            sessions_pub = get_idp_session_info(pub.wpas)
            sessions_sub = get_idp_session_info(sub.wpas)

            if len(sessions_pub) != 1 or \
               sessions_pub[0]['role'].lower() != 'sta':
                raise Exception(f"Unexpected session info on publisher: {sessions_pub}")

            if len(sessions_sub) != 1 or \
               sessions_sub[0]['role'].lower() != 'ap':
                raise Exception(f"Unexpected session info on subscriber: {sessions_sub}")

            # The initiator asked for the station role, so the subscriber is the
            # AP and its IDP Session ID had to reach the publisher in PASN M2.
            check_idp_session_id_agreement(sub.wpas, pub.wpas)

            logger.info("IDP sessions established successfully with reversed roles")

            terminate_all_idp_sessions(pub.wpas, peer_dev=sub.wpas)
            logger.info("=== Test Completed Successfully ===")

@remote_compatible
def test_nan_idp_2way_termination(dev, apdev, params):
    """NAN + IDP test - 2-way termination handshake"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2]:
        nan_idp_setup_devices(wpas1, wpas2)

        with nan_idp_devices(wpas1, wpas2) as (pub, sub):
            logger.info("=== NAN + IDP 2-way termination test ===")

            pid, sid, paddr, saddr, pub_sid, sub_sid = \
                nan_idp_discovery_and_pair(pub, sub, "test_service")

            logger.info("Initiating 2-way termination from AP side")
            res = pub.wpas.request(f"IDP_TERMINATE peer={saddr}")
            if "OK" not in res:
                raise Exception(f"Failed to terminate session: {res}")

            ev = sub.wpas.wait_event(["IDP-TERM-REQUEST"], timeout=5)
            if ev is None:
                raise Exception("Subscriber did not receive IDP-TERM-REQUEST")

            term_peer = None
            for field in ev.split():
                if field.startswith("peer="):
                    term_peer = field.split("=", 1)[1]
                    break
            if not term_peer:
                raise Exception(f"Could not parse peer from IDP-TERM-REQUEST: {ev}")

            res = sub.wpas.request(f"IDP_TERM_RESPONSE peer={term_peer} accept")
            if "OK" not in res:
                raise Exception(f"IDP_TERM_RESPONSE failed: {res}")

            ev_pub = pub.wpas.wait_event(["IDP-TERMINATED"], timeout=5)
            ev_sub = sub.wpas.wait_event(["IDP-TERMINATED"], timeout=5)

            sessions_pub = get_idp_session_info(pub.wpas)
            sessions_sub = get_idp_session_info(sub.wpas)

            if len(sessions_pub) > 0:
                logger.warning(f"Publisher still has {len(sessions_pub)} session(s)")

            if len(sessions_sub) > 0:
                logger.warning(f"Subscriber still has {len(sessions_sub)} session(s)")

            logger.info("=== Test Completed Successfully ===")


@remote_compatible
def test_nan_idp_3way_termination_ap_initiates(dev, apdev, params):
    """NAN + IDP test - 3-way termination initiated by AP"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2]:
        nan_idp_setup_devices(wpas1, wpas2)

        with nan_idp_devices(wpas1, wpas2) as (pub, sub):
            logger.info("=== NAN + IDP 3-way termination (AP initiates) test ===")

            pid, sid, paddr, saddr, pub_sid, sub_sid = \
                nan_idp_discovery_and_pair(pub, sub, "test_service")

            logger.info("Initiating 3-way termination from AP side")
            terminate_idp_session(pub.wpas, sub.wpas, saddr, mode=3)

            sessions_pub = get_idp_session_info(pub.wpas)
            sessions_sub = get_idp_session_info(sub.wpas)

            if len(sessions_pub) > 0:
                raise Exception("Session not terminated on publisher")

            if len(sessions_sub) > 0:
                raise Exception("Session not terminated on subscriber")

            logger.info("=== Test Completed Successfully ===")

@remote_compatible
def test_nan_idp_3way_termination_sta_initiates(dev, apdev, params):
    """NAN + IDP test - 3-way termination initiated by STA"""
    with hwsim_nan_radios(count=2) as [wpas1, wpas2]:
        nan_idp_setup_devices(wpas1, wpas2)

        with nan_idp_devices(wpas1, wpas2) as (pub, sub):
            logger.info("=== NAN + IDP 3-way termination (STA initiates) test ===")

            pid, sid, paddr, saddr, pub_sid, sub_sid = \
                nan_idp_discovery_and_pair(pub, sub, "test_service")

            logger.info("Initiating 3-way termination from STA side")
            terminate_idp_session(sub.wpas, pub.wpas, paddr, mode=3)

            sessions_pub = get_idp_session_info(pub.wpas)
            sessions_sub = get_idp_session_info(sub.wpas)

            if len(sessions_pub) > 0:
                raise Exception("Session not terminated on publisher")

            if len(sessions_sub) > 0:
                raise Exception("Session not terminated on subscriber")

            logger.info("=== Test Completed Successfully ===")
