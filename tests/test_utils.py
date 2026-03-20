"""Tests unitaires — utils.py (fmt_uptime, fmt_bps, fmt_pps)."""
import pytest
from utils import fmt_uptime, fmt_bps, fmt_pps


class TestFmtUptime:
    def test_none(self):
        assert fmt_uptime(None) == "N/A"

    def test_zero(self):
        assert fmt_uptime(0) == "0m"

    def test_minutes_only(self):
        # 15 minutes = 15*60*100 ticks
        assert fmt_uptime(15 * 60 * 100) == "15m"

    def test_hours_and_minutes(self):
        # 2h 30m = (2*3600 + 30*60) * 100
        ticks = (2 * 3600 + 30 * 60) * 100
        assert fmt_uptime(ticks) == "02h 30m"

    def test_days_and_hours(self):
        # 3 days, 9 hours = (3*86400 + 9*3600) * 100
        ticks = (3 * 86400 + 9 * 3600) * 100
        assert fmt_uptime(ticks) == "3j 09h"

    def test_string_input(self):
        # ticks can arrive as string from DB
        assert fmt_uptime("6000") == "1m"


class TestFmtBps:
    def test_none(self):
        assert fmt_bps(None) == "N/A"

    def test_bps(self):
        assert fmt_bps(500) == "500 bps"

    def test_kbps(self):
        assert fmt_bps(1500) == "1.5 Kbps"

    def test_mbps(self):
        assert fmt_bps(2_500_000) == "2.50 Mbps"

    def test_gbps(self):
        assert fmt_bps(1_000_000_000) == "1.00 Gbps"

    def test_zero(self):
        assert fmt_bps(0) == "0 bps"


class TestFmtPps:
    def test_none(self):
        assert fmt_pps(None) == "N/A"

    def test_pps(self):
        assert fmt_pps(42) == "42 pps"

    def test_kpps(self):
        assert fmt_pps(1500) == "1.5K pps"

    def test_mpps(self):
        assert fmt_pps(2_000_000) == "2.0M pps"

    def test_zero(self):
        assert fmt_pps(0) == "0 pps"
