"""Unit tests for server.py helper functions (pure filesystem logic)."""
import json


import core
import server


class TestLoadConfig:
    def test_returns_defaults_when_no_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(core, "CONFIG_PATH", tmp_path / "config.json")
        result = server.load_config()
        assert result["gateway_ip"] == ""
        assert result["gateway_port"] == 3671
        assert result["language"] == "de-DE"
        assert result["connection_type"] == "local"
        assert result["remote_gateway_token"]  # auto-generated UUID4

    def test_reads_existing_file(self, tmp_path, monkeypatch):
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(
            json.dumps({"gateway_ip": "192.168.1.1", "gateway_port": 3671, "language": "en-US"})
        )
        monkeypatch.setattr(core, "CONFIG_PATH", cfg_path)
        result = server.load_config()
        assert result["gateway_ip"] == "192.168.1.1"
        assert result["language"] == "en-US"

    def test_reads_last_project_filename(self, tmp_path, monkeypatch):
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({"gateway_ip": "", "gateway_port": 3671,
                                        "language": "de-DE", "last_project_filename": "home.knxproj"}))
        monkeypatch.setattr(core, "CONFIG_PATH", cfg_path)
        assert server.load_config()["last_project_filename"] == "home.knxproj"


class TestSaveConfig:
    def test_creates_file(self, tmp_path, monkeypatch):
        cfg_path = tmp_path / "config.json"
        monkeypatch.setattr(core, "CONFIG_PATH", cfg_path)
        server.save_config({"gateway_ip": "10.0.0.1", "gateway_port": 3671, "language": "de-DE"})
        assert cfg_path.exists()

    def test_roundtrip(self, tmp_path, monkeypatch):
        cfg_path = tmp_path / "config.json"
        monkeypatch.setattr(core, "CONFIG_PATH", cfg_path)
        token = "test-token-1234"
        data = {"gateway_ip": "10.0.0.1", "gateway_port": 3672, "language": "en-US",
                "connection_type": "local", "remote_gateway_token": token}
        server.save_config(data)
        result = server.load_config()
        assert result["gateway_ip"] == "10.0.0.1"
        assert result["gateway_port"] == 3672
        assert result["language"] == "en-US"
        assert result["remote_gateway_token"] == token

    def test_overwrites_existing(self, tmp_path, monkeypatch):
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps({"gateway_ip": "old"}))
        monkeypatch.setattr(core, "CONFIG_PATH", cfg_path)
        server.save_config({"gateway_ip": "new", "gateway_port": 3671, "language": "de-DE"})
        assert json.loads(cfg_path.read_text())["gateway_ip"] == "new"


class TestLoadLogIntoBuffer:
    def test_empty_when_no_file(self, patched_paths):
        server.load_log_into_buffer()
        assert len(server.state["telegram_buffer"]) == 0
        assert server.state["current_values"] == {}

    def test_parses_valid_lines(self, patched_paths):
        log_path = patched_paths / "knx_bus.log"
        log_path.write_text(
            "2024-01-15 14:32:01.234 | 1.1.5 | Taster EG | 1/2/3 | Licht Küche | Ein\n"
            "2024-01-15 14:33:00.000 | 1.1.6 | Sensor | 2/3/4 | Temperatur | 21.50 °C\n"
        )
        server.load_log_into_buffer()
        entries = list(server.state["telegram_buffer"])
        assert len(entries) == 2
        assert entries[0]["src"] == "1.1.5"
        assert entries[0]["ga"] == "1/2/3"
        assert entries[0]["ga_name"] == "Licht Küche"
        assert entries[0]["value"] == "Ein"
        assert entries[0]["type"] == "telegram"

    def test_skips_malformed_lines(self, patched_paths):
        log_path = patched_paths / "knx_bus.log"
        log_path.write_text(
            "not a valid line\n"
            "only | four | parts | here\n"
            "2024-01-15 14:32:01.234 | 1.1.5 | Gerät | 1/2/3 | GA | Wert\n"
        )
        server.load_log_into_buffer()
        assert len(server.state["telegram_buffer"]) == 1

    def test_updates_current_values(self, patched_paths):
        log_path = patched_paths / "knx_bus.log"
        log_path.write_text(
            "2024-01-15 14:32:00.000 | 1.1.5 | Gerät | 1/2/3 | GA | Aus\n"
            "2024-01-15 14:33:00.000 | 1.1.5 | Gerät | 1/2/3 | GA | Ein\n"
        )
        server.load_log_into_buffer()
        # Last value per GA is stored
        assert server.state["current_values"]["1/2/3"]["value"] == "Ein"

    def test_limits_to_last_500_lines(self, patched_paths):
        log_path = patched_paths / "knx_bus.log"
        lines = [
            f"2024-01-15 14:32:01.234 | 1.1.5 | Gerät | 1/2/{i} | GA | Ein\n"
            for i in range(600)
        ]
        log_path.write_text("".join(lines))
        server.load_log_into_buffer()
        assert len(server.state["telegram_buffer"]) == 500


class TestLoadLastProject:
    def test_does_nothing_when_no_file(self, patched_paths):
        server.load_last_project()
        assert server.state["project_data"] is None
        assert server.state["ga_dpt_map"] == {}

    def test_loads_project_into_state(self, patched_paths):
        project = {
            "group_addresses": {
                "ga1": {"address": "1/2/3", "dpt": {"main": 9, "sub": 1}},
            },
            "devices": {},
        }
        (patched_paths / "last_project.json").write_text(json.dumps(project))
        server.load_last_project()
        assert server.state["project_data"] is not None
        assert server.state["project_data"]["group_addresses"]["ga1"]["address"] == "1/2/3"

    def test_builds_ga_dpt_map(self, patched_paths):
        project = {
            "group_addresses": {
                "ga1": {"address": "1/2/3", "dpt": {"main": 9, "sub": 1}},
                "ga2": {"address": "2/3/4", "dpt": None},
                "ga3": {},  # no address — must be excluded
            }
        }
        (patched_paths / "last_project.json").write_text(json.dumps(project))
        server.load_last_project()
        assert "1/2/3" in server.state["ga_dpt_map"]
        assert "2/3/4" in server.state["ga_dpt_map"]
        assert len(server.state["ga_dpt_map"]) == 2  # ga3 excluded

    def test_handles_corrupt_json(self, patched_paths):
        (patched_paths / "last_project.json").write_text("{ not valid json }")
        # Must not raise — error is logged and state stays clean
        server.load_last_project()
        assert server.state["project_data"] is None
