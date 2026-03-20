"""Tests d'intégration — metrics.py (/metrics endpoint)."""
import pytest
from unittest.mock import patch, MagicMock


class TestMetricsEndpoint:

    def test_disabled_returns_404(self, client, db_mock):
        db_mock.get_settings.return_value = {"metrics_enabled": "0"}
        resp = client.get("/metrics")
        assert resp.status_code == 404

    def test_enabled_no_token_configured_returns_401(self, client, db_mock):
        db_mock.get_settings.return_value = {
            "metrics_enabled": "1",
            "metrics_token":   "",
        }
        resp = client.get("/metrics")
        assert resp.status_code == 401

    def test_enabled_wrong_token_returns_401(self, client, db_mock):
        db_mock.get_settings.return_value = {
            "metrics_enabled": "1",
            "metrics_token":   "secret123",
        }
        resp = client.get("/metrics",
                          headers={"Authorization": "Bearer wrong"})
        assert resp.status_code == 401

    def test_enabled_correct_token_returns_200(self, client, db_mock):
        db_mock.get_settings.return_value = {
            "metrics_enabled": "1",
            "metrics_token":   "secret123",
        }
        db_mock.get_all_routers.return_value = []
        resp = client.get("/metrics",
                          headers={"Authorization": "Bearer secret123"})
        assert resp.status_code == 200
        assert b"huwa_scrape_time_seconds" in resp.data

    def test_metrics_content_has_router_data(self, client, db_mock):
        db_mock.get_settings.return_value = {
            "metrics_enabled": "1",
            "metrics_token":   "token",
        }
        db_mock.get_all_routers.return_value = [
            {"id": 1, "name": "R1", "ip": "10.0.0.1", "enabled": True}
        ]
        db_mock.get_latest_system.return_value = {
            "cpu_usage": 42.5,
            "mem_usage": 60.0,
            "temperature": 55,
            "sys_uptime": 360000,
        }
        db_mock.get_interfaces_latest.return_value = []
        db_mock.get_events.return_value = []
        db_mock.get_wan_sla_list.return_value = []
        db_mock.get_bps_history.return_value = []

        resp = client.get("/metrics",
                          headers={"Authorization": "Bearer token"})
        assert resp.status_code == 200
        body = resp.data.decode()
        assert "huwa_cpu_usage_percent" in body
        assert "R1" in body
        assert "42.5" in body
