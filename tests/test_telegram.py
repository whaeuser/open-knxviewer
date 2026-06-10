"""Unit tests for _process_telegram — value formatting and state updates."""

import core
import server


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

class _Payload:
    def __init__(self, value=None):
        self.value = value

    def __str__(self):
        return f"DPTBinary({self.value})"


class _Transcoder:
    def __init__(self, unit="", main=None, sub=None):
        self.unit = unit
        self.dpt_main_number = main
        self.dpt_sub_number = sub


class _DecodedData:
    def __init__(self, value, transcoder):
        self.value = value
        self.transcoder = transcoder


class _Telegram:
    def __init__(self, src="1.1.1", ga="1/2/3", payload_value=None, decoded_data=None):
        self.source_address = src
        self.destination_address = ga
        self.payload = _Payload(payload_value)
        self.decoded_data = decoded_data


def _make_decoded(value, unit="", main=None, sub=None):
    return _DecodedData(value, _Transcoder(unit=unit, main=main, sub=sub))


# ---------------------------------------------------------------------------
# Value formatting — decoded (DPT-aware)
# ---------------------------------------------------------------------------

async def test_bool_true_formatted_as_ein():
    telegram = _Telegram(
        payload_value=1,
        decoded_data=_make_decoded(True, main=1, sub=1),
    )
    await server._process_telegram(telegram)
    assert server.state["current_values"]["1/2/3"]["value"] == "Ein"


async def test_bool_false_formatted_as_aus():
    telegram = _Telegram(
        payload_value=0,
        decoded_data=_make_decoded(False, main=1, sub=1),
    )
    await server._process_telegram(telegram)
    assert server.state["current_values"]["1/2/3"]["value"] == "Aus"


async def test_float_formatted_two_decimal_places():
    telegram = _Telegram(
        payload_value=None,
        decoded_data=_make_decoded(21.5, unit="°C", main=9, sub=1),
    )
    await server._process_telegram(telegram)
    assert server.state["current_values"]["1/2/3"]["value"] == "21.50 °C"


async def test_float_without_unit():
    telegram = _Telegram(
        payload_value=None,
        decoded_data=_make_decoded(5.0, unit="", main=9, sub=2),
    )
    await server._process_telegram(telegram)
    assert server.state["current_values"]["1/2/3"]["value"] == "5.00"


async def test_float_with_percent_unit():
    telegram = _Telegram(
        payload_value=None,
        decoded_data=_make_decoded(75.0, unit="%", main=5, sub=1),
    )
    await server._process_telegram(telegram)
    assert server.state["current_values"]["1/2/3"]["value"] == "75.00 %"


async def test_integer_value_with_unit():
    telegram = _Telegram(
        payload_value=None,
        decoded_data=_make_decoded(3, unit="lx", main=7, sub=1),
    )
    await server._process_telegram(telegram)
    assert server.state["current_values"]["1/2/3"]["value"] == "3 lx"


async def test_integer_value_without_unit():
    telegram = _Telegram(
        payload_value=None,
        decoded_data=_make_decoded(42, unit="", main=7, sub=None),
    )
    await server._process_telegram(telegram)
    assert server.state["current_values"]["1/2/3"]["value"] == "42"


# ---------------------------------------------------------------------------
# Value fallback — no DPT (raw)
# ---------------------------------------------------------------------------

async def test_no_decoded_data_uses_raw_payload():
    telegram = _Telegram(payload_value=(0x0c, 0x1a), decoded_data=None)
    await server._process_telegram(telegram)
    value = server.state["current_values"]["1/2/3"]["value"]
    # Raw value is whatever str(payload.value) produces
    assert "(12, 26)" in value or "0x0c" in value or "12" in value


async def test_no_payload_value_falls_back_to_str_payload():
    """When payload.value is None, falls back to str(payload)."""
    telegram = _Telegram(payload_value=None, decoded_data=None)
    await server._process_telegram(telegram)
    # str(payload) is called — should not raise
    assert "1/2/3" in server.state["current_values"]


# ---------------------------------------------------------------------------
# DPT string formatting
# ---------------------------------------------------------------------------

async def test_dpt_string_main_and_sub():
    telegram = _Telegram(
        payload_value=None,
        decoded_data=_make_decoded(21.5, unit="°C", main=9, sub=1),
    )
    await server._process_telegram(telegram)
    entry = list(server.state["telegram_buffer"])[-1]
    assert entry["dpt"] == "9.001"


async def test_dpt_string_main_only():
    telegram = _Telegram(
        payload_value=None,
        decoded_data=_make_decoded(1, unit="", main=1, sub=None),
    )
    await server._process_telegram(telegram)
    entry = list(server.state["telegram_buffer"])[-1]
    assert entry["dpt"] == "1"


async def test_dpt_empty_when_no_decoded_data():
    telegram = _Telegram(payload_value=1, decoded_data=None)
    await server._process_telegram(telegram)
    entry = list(server.state["telegram_buffer"])[-1]
    assert entry["dpt"] == ""


# ---------------------------------------------------------------------------
# State updates
# ---------------------------------------------------------------------------

async def test_telegram_added_to_buffer():
    telegram = _Telegram(decoded_data=_make_decoded(True, main=1, sub=1))
    await server._process_telegram(telegram)
    assert len(server.state["telegram_buffer"]) == 1


async def test_current_values_updated():
    telegram = _Telegram(ga="3/4/5", decoded_data=_make_decoded(False, main=1, sub=1))
    await server._process_telegram(telegram)
    assert "3/4/5" in server.state["current_values"]
    assert server.state["current_values"]["3/4/5"]["value"] == "Aus"


async def test_current_values_overwritten_by_latest():
    telegram1 = _Telegram(ga="1/0/0", decoded_data=_make_decoded(False, main=1, sub=1))
    telegram2 = _Telegram(ga="1/0/0", decoded_data=_make_decoded(True, main=1, sub=1))
    await server._process_telegram(telegram1)
    await server._process_telegram(telegram2)
    assert server.state["current_values"]["1/0/0"]["value"] == "Ein"


async def test_entry_contains_timestamp():
    telegram = _Telegram(decoded_data=_make_decoded(True, main=1, sub=1))
    await server._process_telegram(telegram)
    entry = list(server.state["telegram_buffer"])[0]
    assert "ts" in entry
    assert len(entry["ts"]) > 10  # "2024-01-15 14:32:01.234"


async def test_entry_contains_raw_field():
    telegram = _Telegram(payload_value=(0x0C,), decoded_data=_make_decoded(True, main=1, sub=1))
    await server._process_telegram(telegram)
    entry = list(server.state["telegram_buffer"])[0]
    assert "raw" in entry


# ---------------------------------------------------------------------------
# Name lookup from project_data
# ---------------------------------------------------------------------------

async def test_device_name_lookup():
    server.state["project_data"] = {
        "devices": {"1.1.1": {"name": "Taster Flur"}},
        "group_addresses": {},
    }
    telegram = _Telegram(src="1.1.1", ga="9/9/9", decoded_data=_make_decoded(True, main=1, sub=1))
    await server._process_telegram(telegram)
    entry = list(server.state["telegram_buffer"])[0]
    assert entry["device"] == "Taster Flur"


async def test_ga_name_lookup():
    core.set_project_data({
        "devices": {},
        "group_addresses": {
            "ga1": {"address": "1/2/3", "name": "Licht Küche"},
        },
    })
    telegram = _Telegram(src="1.1.5", ga="1/2/3", decoded_data=_make_decoded(True, main=1, sub=1))
    await server._process_telegram(telegram)
    entry = list(server.state["telegram_buffer"])[0]
    assert entry["ga_name"] == "Licht Küche"


async def test_unknown_device_gives_empty_name():
    server.state["project_data"] = {"devices": {}, "group_addresses": {}}
    telegram = _Telegram(src="9.9.9", decoded_data=_make_decoded(True, main=1, sub=1))
    await server._process_telegram(telegram)
    entry = list(server.state["telegram_buffer"])[0]
    assert entry["device"] == ""


async def test_no_project_data_gives_empty_names():
    server.state["project_data"] = None
    telegram = _Telegram(decoded_data=_make_decoded(True, main=1, sub=1))
    await server._process_telegram(telegram)
    entry = list(server.state["telegram_buffer"])[0]
    assert entry["device"] == ""
    assert entry["ga_name"] == ""
