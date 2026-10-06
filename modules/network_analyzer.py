"""PCAP / network capture analysis: protocol summary + payload flag hunt."""

from __future__ import annotations

import os

from . import utils


def analyze(filepath: str, outdir: str, ctx: dict) -> list[dict]:
    findings: list[dict] = []
    flag_rx = ctx.get("flag_rx")

    # tshark summary + ascii payload dump (best tool for the job)
    if utils.have_tool("tshark"):
        rc, out, _ = utils.run(
            ["tshark", "-r", filepath, "-q", "-z", "io,phs"], timeout=120)
        if out:
            utils.write_text(os.path.join(outdir, "protocol_hierarchy.txt"), out)

        # dump printable payload bytes across all packets
        rc, out, _ = utils.run(
            ["tshark", "-r", filepath, "-T", "fields", "-e", "data.text",
             "-e", "http.file_data"], timeout=120)
        if out:
            utils.write_text(os.path.join(outdir, "payloads.txt"), out)
            flags = utils.find_flags(out, flag_rx)
            if flags:
                for f in flags:
                    utils.log_hit(f"flag in packet payload: {f}")
                findings.append({
                    "category": "Network payload flag",
                    "detail": "flag found in packet data",
                    "confidence": "high", "flags": flags,
                    "artifacts": ["payloads.txt"]})
        utils.log_info("tshark protocol + payload dump written")
        return findings

    # fallback: scapy
    try:
        from scapy.all import rdpcap, Raw
        packets = rdpcap(filepath)
        payloads = []
        for pkt in packets:
            if Raw in pkt:
                payloads.append(bytes(pkt[Raw].load))
        blob = b"".join(payloads)
        from .binary_analyzer import extract_strings
        text = "\n".join(extract_strings(blob, 4))
        utils.write_text(os.path.join(outdir, "payloads.txt"), text)
        utils.log_info(f"scapy parsed {len(packets)} packets")
        flags = utils.find_flags(text, flag_rx)
        if flags:
            for f in flags:
                utils.log_hit(f"flag in packet payload: {f}")
            findings.append({
                "category": "Network payload flag",
                "detail": "flag in reassembled payloads",
                "confidence": "high", "flags": flags,
                "artifacts": ["payloads.txt"]})
    except Exception as exc:
        utils.log_warn(f"no tshark and scapy failed: {exc}")
    return findings
