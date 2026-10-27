"""IP and ASN modules against mocked providers."""

from __future__ import annotations

import httpx
import pytest

from spyglass_lite import InvalidTarget, Spyglass


@pytest.fixture
def ip_network(monkeypatch):
    async def reverse(ip, *, timeout=4.0):
        return "one.one.one.one"

    async def whois(ip, *, timeout=12.0):
        return {"netname": "APNIC-LABS", "country": "AU"}

    async def a(host, *, timeout=4.0):
        return ["1.1.1.1"]

    monkeypatch.setattr("spyglass_lite._dns.reverse", reverse)
    monkeypatch.setattr("spyglass_lite._whois.address", whois)
    monkeypatch.setattr("spyglass_lite._dns.a", a)
    return None


def _geo_payload():
    return {
        "success": True,
        "country": "Australia",
        "region": "Queensland",
        "city": "Brisbane",
        "isp": "Cloudflare",
        "connection": {"asn": 13335, "org": "Cloudflare, Inc."},
        "latitude": -27.4766,
        "longitude": 153.0166,
        "timezone": {"id": "Australia/Brisbane"},
    }


def _internetdb_payload():
    return {
        "ip": "1.1.1.1",
        "ports": [443, 80, 53],
        "hostnames": ["one.one.one.one"],
        "cpes": ["cpe:/a:cloudflare:cloudflare"],
        "tags": ["cdn"],
    }


async def test_ip_lookup(ip_network, respx_mock):
    respx_mock.get("https://ipwho.is/1.1.1.1").mock(
        return_value=httpx.Response(200, json=_geo_payload())
    )
    respx_mock.get("https://internetdb.shodan.io/1.1.1.1").mock(
        return_value=httpx.Response(200, json=_internetdb_payload())
    )

    result = await Spyglass().aip("1.1.1.1")

    assert result.ip == "1.1.1.1"
    assert result.geo is not None
    assert result.geo.city == "Brisbane"
    assert result.geo.asn == "AS13335"
    assert result.geo.source == "ipwho.is"
    assert result.hostname == "one.one.one.one"
    assert result.ports == [53, 80, 443]
    assert result.whois["netname"] == "APNIC-LABS"
    assert result.cpes == ["cpe:/a:cloudflare:cloudflare"]


async def test_ipv6_lookup(ip_network, respx_mock):
    target = "2001:4860:4860::8888"
    respx_mock.get(url__startswith="https://ipwho.is/2001:4860").mock(
        return_value=httpx.Response(
            200,
            json={
                "success": True,
                "country": "United States",
                "city": "Mountain View",
                "connection": {"asn": 15169, "org": "Google LLC"},
            },
        )
    )
    respx_mock.get(url__startswith="https://internetdb.shodan.io/2001:4860").mock(
        return_value=httpx.Response(200, json={"ports": [443]})
    )

    result = await Spyglass().aip(target)

    assert result.ip == target
    assert result.geo is not None
    assert result.geo.asn == "AS15169"
    assert result.ports == [443]


async def test_unresolvable_host_raises(monkeypatch):
    async def none(host, *, timeout=4.0):
        return []

    monkeypatch.setattr("spyglass_lite._dns.a", none)

    with pytest.raises(InvalidTarget, match="could not resolve"):
        await Spyglass().aip("does-not-exist.invalid")


async def test_ip_geolocation_falls_back(ip_network, respx_mock):
    respx_mock.get("https://ipwho.is/1.1.1.1").mock(
        return_value=httpx.Response(200, json={"success": False})
    )
    respx_mock.get(url__startswith="http://ip-api.com/json/1.1.1.1").mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "success",
                "country": "Australia",
                "regionName": "Queensland",
                "city": "Brisbane",
                "isp": "Cloudflare",
                "as": "AS13335 Cloudflare",
                "lat": -27.4,
                "lon": 153.0,
                "timezone": "Australia/Brisbane",
            },
        )
    )
    respx_mock.get("https://internetdb.shodan.io/1.1.1.1").mock(
        return_value=httpx.Response(200, json={"detail": "No information available"})
    )

    result = await Spyglass().aip("1.1.1.1")

    assert result.geo is not None
    assert result.geo.source == "ip-api.com (fallback)"
    assert result.ports == []
    assert any("internetdb" in error for error in result.errors)


async def test_hostname_target_is_resolved(ip_network, respx_mock):
    respx_mock.get("https://ipwho.is/1.1.1.1").mock(
        return_value=httpx.Response(200, json=_geo_payload())
    )
    respx_mock.get("https://internetdb.shodan.io/1.1.1.1").mock(
        return_value=httpx.Response(200, json=_internetdb_payload())
    )

    result = await Spyglass().aip("one.one.one.one")

    assert result.ip == "1.1.1.1"
    assert result.a_records == ["1.1.1.1"]


async def test_geo_failure_is_reported_not_raised(ip_network, respx_mock):
    respx_mock.get("https://ipwho.is/1.1.1.1").mock(return_value=httpx.Response(500))
    respx_mock.get(url__startswith="http://ip-api.com/json/").mock(return_value=httpx.Response(500))
    respx_mock.get("https://internetdb.shodan.io/1.1.1.1").mock(return_value=httpx.Response(404))

    result = await Spyglass().aip("1.1.1.1")

    assert result.geo is None
    assert "geolocation unavailable" in result.errors


@pytest.mark.parametrize("target", ["", "not an ip or host", "999.1.1.1"])
async def test_invalid_ip_targets_raise(target):
    with pytest.raises(InvalidTarget):
        await Spyglass().aip(target)


# ─── ASN ──────────────────────────────────────────────────


def _mock_ripeatstat(respx_mock, *, rpki_status="valid", announced=True):
    respx_mock.get(url__startswith="https://stat.ripe.net/data/prefix-overview/").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "resource": "1.1.1.1",
                    "prefixes": [
                        {
                            "prefix": "1.1.1.0/24",
                            "asns": [{"asn": 13335, "holder": "CLOUDFLARENET"}],
                        }
                    ],
                }
            },
        )
    )
    respx_mock.get(url__startswith="https://stat.ripe.net/data/as-overview/").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "resource": "AS13335",
                    "holder": "CLOUDFLARENET, US",
                    "announced": announced,
                }
            },
        )
    )
    respx_mock.get(url__startswith="https://stat.ripe.net/data/rpki-validation/").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "prefix": "1.1.1.0/24",
                    "status": rpki_status,
                    "description": "test",
                }
            },
        )
    )


async def test_asn_for_address(respx_mock):
    _mock_ripeatstat(respx_mock)

    result = await Spyglass().aasn("1.1.1.1")

    assert result.query_type == "address"
    assert result.prefix == "1.1.1.0/24"
    assert result.origin_asn == "AS13335"
    assert result.holder == "CLOUDFLARENET, US"
    assert result.announced is True
    assert result.rpki[0].state == "valid"
    assert result.worst_rpki == "valid"


async def test_asn_for_prefix(respx_mock):
    _mock_ripeatstat(respx_mock)

    result = await Spyglass().aasn("1.1.1.0/24")

    assert result.query_type == "prefix"
    assert result.prefix == "1.1.1.0/24"


async def test_asn_for_prefix_uses_the_prefix_response_shape(respx_mock):
    """RIPEStat answers a prefix query with ``resource``/``asns``, not ``prefixes``.

    Reading only the address shape made a prefix query report no origin AS at
    all, which the shared fixture never caught because it mocked an address
    response for every resource.
    """
    respx_mock.get(url__startswith="https://stat.ripe.net/data/prefix-overview/").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "resource": "1.1.1.0/24",
                    "announced": True,
                    "asns": [{"asn": 13335, "holder": "CLOUDFLARENET"}],
                }
            },
        )
    )
    respx_mock.get(url__startswith="https://stat.ripe.net/data/as-overview/").mock(
        return_value=httpx.Response(
            200, json={"data": {"holder": "CLOUDFLARENET, US", "announced": True}}
        )
    )
    respx_mock.get(url__startswith="https://stat.ripe.net/data/rpki-validation/").mock(
        return_value=httpx.Response(200, json={"data": {"prefix": "1.1.1.0/24", "status": "valid"}})
    )

    result = await Spyglass().aasn("1.1.1.0/24")

    assert result.prefix == "1.1.1.0/24"
    assert result.origin_asn == "AS13335"
    assert result.holder == "CLOUDFLARENET, US"


async def test_asn_for_as(respx_mock):
    respx_mock.get(url__startswith="https://stat.ripe.net/data/as-overview/").mock(
        return_value=httpx.Response(
            200,
            json={"data": {"holder": "CLOUDFLARENET, US", "announced": True}},
        )
    )

    result = await Spyglass().aasn("AS13335")

    assert result.query_type == "asn"
    assert result.origin_asn == "AS13335"
    assert result.holder == "CLOUDFLARENET, US"
    assert result.rpki[0].state == "unknown"
    assert "no prefix" in result.rpki[0].description


async def test_asn_requires_the_as_prefix(respx_mock):
    """A bare number is ambiguous with an IP fragment, so it is rejected."""
    with pytest.raises(InvalidTarget):
        await Spyglass().aasn("15169")


async def test_invalid_rpki_is_preserved(respx_mock):
    _mock_ripeatstat(respx_mock, rpki_status="invalid")

    result = await Spyglass().aasn("1.1.1.1")

    assert result.rpki[0].state == "invalid"
    assert result.worst_rpki == "invalid"


@pytest.mark.parametrize("target", ["", "AS", "1.1.1.1/99", "example.com"])
async def test_invalid_asn_targets_raise(target):
    with pytest.raises(InvalidTarget):
        await Spyglass().aasn(target)
