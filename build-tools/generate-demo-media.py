#!/usr/bin/env python3
"""
generate-demo-media.py - Generates demo.gif and demo.mp4 for siem-rule-tuner.
Simulates terminal interaction, SIEM alert log clustering, blind-spot verification,
and production child rule synthesis.
Zero external dependencies other than Pillow and local ffmpeg.
"""

import os
import subprocess
import sys
from PIL import Image, ImageDraw, ImageFont

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ASSETS_DIR = os.path.join(BASE_DIR, "assets")
os.makedirs(ASSETS_DIR, exist_ok=True)

WIDTH, HEIGHT = 1000, 620
BG_COLOR = (15, 23, 42)        # Slate-900
HEADER_COLOR = (30, 41, 59)    # Slate-800
BORDER_COLOR = (51, 65, 85)    # Slate-700
TEXT_MAIN = (241, 245, 249)    # Slate-100
TEXT_MUTED = (148, 163, 184)   # Slate-400
TEXT_ACCENT = (56, 189, 248)   # Sky-400
TEXT_GREEN = (74, 222, 128)    # Green-400
TEXT_YELLOW = (250, 204, 21)   # Yellow-400
TEXT_RED = (248, 113, 113)     # Red-400
TEXT_BORDER_COLOR = BORDER_COLOR

try:
    FONT_REGULAR = ImageFont.truetype("consola.ttf", 15)
    FONT_BOLD = ImageFont.truetype("consolab.ttf", 15)
    FONT_TITLE = ImageFont.truetype("consolab.ttf", 16)
except Exception:
    FONT_REGULAR = ImageFont.load_default()
    FONT_BOLD = FONT_REGULAR
    FONT_TITLE = FONT_REGULAR


def draw_window_frame(draw: ImageDraw.ImageDraw, title: str):
    """Draw professional terminal header with control buttons."""
    draw.rectangle([0, 0, WIDTH, HEIGHT], fill=BG_COLOR)
    draw.rectangle([0, 0, WIDTH, 38], fill=HEADER_COLOR)
    draw.line([(0, 38), (WIDTH, 38)], fill=BORDER_COLOR, width=1)

    draw.ellipse([14, 13, 26, 25], fill=(239, 68, 68))   # Red
    draw.ellipse([34, 13, 46, 25], fill=(234, 179, 8))   # Yellow
    draw.ellipse([54, 13, 66, 25], fill=(34, 197, 94))   # Green

    draw.text((WIDTH // 2 - 180, 10), title, font=FONT_TITLE, fill=TEXT_MUTED)


def create_terminal_frames() -> list:
    frames = []

    content_states = [
        # Frame 1: Command prompt
        [
            ("analyst@soc-workstation:~$ ", TEXT_ACCENT),
            ("python3 ./scripts/tune_siem_rule.py --input wazuh_alerts.json --platform wazuh --sanitize", TEXT_MAIN)
        ],
        # Frame 2: Analyzing & Clustering
        [
            ("analyst@soc-workstation:~$ ", TEXT_ACCENT),
            ("python3 ./scripts/tune_siem_rule.py --input wazuh_alerts.json --platform wazuh --sanitize", TEXT_MAIN),
            ("", TEXT_MAIN),
            ("[*] Ingesting 450 false-positive alerts for Wazuh Rule 60103 (Sysmon Event 1)...", TEXT_MUTED),
            ("[*] Applying Rule 4 client-side data sanitization (SHA-256 + RFC 5737)...", TEXT_MUTED),
            ("[+] Primary noisy binary identified: 'VeeamGuestHelper.exe' (450/450 events)", TEXT_GREEN),
            ("[+] Primary parent process identified: 'C:\\Windows\\System32\\services.exe'", TEXT_GREEN)
        ],
        # Frame 3: Blind-Spot Governance Evaluation
        [
            ("analyst@soc-workstation:~$ ", TEXT_ACCENT),
            ("python3 ./scripts/tune_siem_rule.py --input wazuh_alerts.json --platform wazuh --sanitize", TEXT_MAIN),
            ("", TEXT_MAIN),
            ("=======================================================================", TEXT_BORDER_COLOR),
            ("  SIEM FALSE-POSITIVE TUNING & BLIND-SPOT AUDIT REPORT", TEXT_ACCENT),
            ("=======================================================================", TEXT_BORDER_COLOR),
            ("Parent Rule ID     : 60103 (Sysmon Process Creation in System Directory)", TEXT_MAIN),
            ("Tuning Disposition : APPROVED [SURGICAL EXCLUSION VALIDATED]", TEXT_GREEN),
            ("Noise Reduction    : 100.0% (Eliminates 450 false-positive alerts/week)", TEXT_GREEN),
            ("", TEXT_MAIN),
            ("BLIND-SPOT & LOLBIN SECURITY AUDIT:", TEXT_ACCENT),
            ("  - Gate 1 (Multi-Attribute): PASSED (4/4 telemetry anchors bound)", TEXT_GREEN),
            ("  - Gate 2 (LOLBin Safeguard): PASSED (Not an unconstrained LOLBin)", TEXT_GREEN),
            ("  - Gate 3 (Safe Directory) : PASSED (Standard Program Files installation)", TEXT_GREEN),
            ("  - Gate 4 (Parent Kept)    : PASSED (Level 0 child rule with <if_sid>)", TEXT_GREEN)
        ],
        # Frame 4: Code Generation & Validation Tests
        [
            ("analyst@soc-workstation:~$ ", TEXT_ACCENT),
            ("python3 ./scripts/tune_siem_rule.py --input wazuh_alerts.json --platform wazuh --sanitize", TEXT_MAIN),
            ("", TEXT_MAIN),
            ("=======================================================================", TEXT_BORDER_COLOR),
            ("  SYNTHESIZED PRODUCTION RULE: WAZUH XML (level 0 child rule)", TEXT_ACCENT),
            ("=======================================================================", TEXT_BORDER_COLOR),
            ("<group name=\"sysmon,windows,\">", TEXT_MUTED),
            ("  <rule id=\"100101\" level=\"0\">", TEXT_YELLOW),
            ("    <if_sid>60103</if_sid>", TEXT_MAIN),
            ("    <field name=\"win.eventdata.image\">^C:\\\\Program Files\\\\Veeam\\\\Backup\\\\VeeamGuestHelper\\.exe$</field>", TEXT_GREEN),
            ("    <field name=\"win.eventdata.parentImage\">^C:\\\\Windows\\\\System32\\\\services\\.exe$</field>", TEXT_GREEN),
            ("    <field name=\"win.eventdata.user\">^NT AUTHORITY\\\\SYSTEM$</field>", TEXT_GREEN),
            ("    <field name=\"win.eventdata.commandLine\" type=\"pcre2\">(?i)-runAsService</field>", TEXT_GREEN),
            ("    <description>Tuned Exclusion: Exclude legitimate VeeamGuestHelper activity.</description>", TEXT_MUTED),
            ("  </rule>", TEXT_YELLOW),
            ("</group>", TEXT_MUTED),
            ("", TEXT_MAIN),
            ("[TEST VERIFICATION]", TEXT_ACCENT),
            ("Negative Test (FP Suppressed): & \"C:\\Program Files\\Veeam\\...\\VeeamGuestHelper.exe\" -runAsService", TEXT_MUTED),
            ("Positive Test (TP Fires High): Start-Process powershell.exe -Arg \"& $env:TEMP\\VeeamGuestHelper.exe\"", TEXT_MUTED),
            ("=======================================================================", TEXT_BORDER_COLOR),
            ("[SOC STATUS] Production child rule generated with zero blind spots.", TEXT_GREEN)
        ]
    ]

    durations = [1200, 1400, 2500, 4500]

    for state, dur in zip(content_states, durations):
        img = Image.new("RGB", (WIDTH, HEIGHT), BG_COLOR)
        draw = ImageDraw.Draw(img)
        draw_window_frame(draw, "siem-rule-tuner — python3 (wazuh / defender)")

        y = 52
        for line_item in state:
            if isinstance(line_item, tuple):
                text, color = line_item
                draw.text((20, y), text, font=FONT_REGULAR, fill=color)
                y += 22
            else:
                y += 22
        frames.append((img, dur))

    return frames


def build_media():
    print("[*] Generating terminal animation frames...")
    frames = create_terminal_frames()

    gif_path = os.path.join(ASSETS_DIR, "demo.gif")
    mp4_path = os.path.join(ASSETS_DIR, "demo.mp4")

    imgs = [f[0] for f in frames]
    durs = [f[1] for f in frames]

    imgs[0].save(
        gif_path,
        save_all=True,
        append_images=imgs[1:],
        duration=durs,
        loop=0,
        optimize=True
    )
    print(f"[+] Successfully generated GIF: {gif_path} ({os.path.getsize(gif_path) / 1024:.1f} KB)")

    temp_dir = os.path.join(BASE_DIR, "build-tools", "temp_frames")
    os.makedirs(temp_dir, exist_ok=True)

    frame_idx = 0
    fps = 30
    for img, dur in frames:
        count = int((dur / 1000.0) * fps)
        for _ in range(count):
            img.save(os.path.join(temp_dir, f"frame_{frame_idx:05d}.png"))
            frame_idx += 1

    ffmpeg_cmd = [
        "ffmpeg", "-y",
        "-framerate", str(fps),
        "-i", os.path.join(temp_dir, "frame_%05d.png"),
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        "-crf", "18",
        "-preset", "fast",
        mp4_path
    ]

    try:
        subprocess.run(ffmpeg_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[+] Successfully generated MP4: {mp4_path} ({os.path.getsize(mp4_path) / 1024:.1f} KB)")
    except Exception as e:
        print(f"[WARN] ffmpeg conversion failed: {e}")
    finally:
        for f in os.listdir(temp_dir):
            os.remove(os.path.join(temp_dir, f))
        os.rmdir(temp_dir)


if __name__ == "__main__":
    build_media()
