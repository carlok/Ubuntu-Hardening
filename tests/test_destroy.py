"""
Unit tests for destroy.py helper (lookup) functions.

The destroy() and main() functions require live Hetzner API access and
interactive confirmation — those are integration concerns, not unit tested here.
"""
import pytest
from unittest.mock import MagicMock

from destroy import (
    find_server,
    find_attached_firewalls,
    find_orphaned_prov_keys,
    find_floating_ips,
)


# ─────────────────────────────────────────────────────────────
# find_server
# ─────────────────────────────────────────────────────────────

class TestFindServer:
    def test_finds_by_name(self):
        client = MagicMock()
        srv = MagicMock()
        client.servers.get_by_name.return_value = srv
        assert find_server(client, "my-server") is srv

    def test_name_lookup_skips_ip_scan(self):
        client = MagicMock()
        client.servers.get_by_name.return_value = MagicMock()
        find_server(client, "my-server")
        client.servers.get_all.assert_not_called()

    def test_falls_back_to_ip_scan_when_name_missing(self):
        client = MagicMock()
        client.servers.get_by_name.return_value = None
        srv = MagicMock()
        srv.public_net.ipv4.ip = "1.2.3.4"
        client.servers.get_all.return_value = [srv]
        assert find_server(client, "1.2.3.4") is srv

    def test_returns_none_when_ip_not_found(self):
        client = MagicMock()
        client.servers.get_by_name.return_value = None
        srv = MagicMock()
        srv.public_net.ipv4.ip = "9.9.9.9"
        client.servers.get_all.return_value = [srv]
        assert find_server(client, "1.2.3.4") is None

    def test_returns_none_when_server_list_empty(self):
        client = MagicMock()
        client.servers.get_by_name.return_value = None
        client.servers.get_all.return_value = []
        assert find_server(client, "1.2.3.4") is None

    def test_ip_scan_returns_first_matching_server(self):
        client = MagicMock()
        client.servers.get_by_name.return_value = None
        s1 = MagicMock(); s1.public_net.ipv4.ip = "1.1.1.1"
        s2 = MagicMock(); s2.public_net.ipv4.ip = "2.2.2.2"
        client.servers.get_all.return_value = [s1, s2]
        assert find_server(client, "2.2.2.2") is s2


# ─────────────────────────────────────────────────────────────
# find_attached_firewalls
# ─────────────────────────────────────────────────────────────

class TestFindAttachedFirewalls:
    def test_returns_empty_when_no_firewalls(self):
        client = MagicMock()
        server = MagicMock()
        server.public_net.firewalls = []
        assert find_attached_firewalls(client, server) == []

    def test_returns_empty_when_firewalls_is_none(self):
        client = MagicMock()
        server = MagicMock()
        server.public_net.firewalls = None
        assert find_attached_firewalls(client, server) == []

    def test_fetches_firewall_by_id(self):
        client = MagicMock()
        ref = MagicMock(); ref.firewall.id = 42
        server = MagicMock(); server.public_net.firewalls = [ref]
        fw = MagicMock()
        client.firewalls.get_by_id.return_value = fw
        result = find_attached_firewalls(client, server)
        assert fw in result
        client.firewalls.get_by_id.assert_called_with(42)

    def test_returns_multiple_firewalls(self):
        client = MagicMock()
        ref1 = MagicMock(); ref1.firewall.id = 1
        ref2 = MagicMock(); ref2.firewall.id = 2
        server = MagicMock(); server.public_net.firewalls = [ref1, ref2]
        fw1, fw2 = MagicMock(), MagicMock()
        client.firewalls.get_by_id.side_effect = [fw1, fw2]
        result = find_attached_firewalls(client, server)
        assert fw1 in result and fw2 in result


# ─────────────────────────────────────────────────────────────
# find_orphaned_prov_keys
# ─────────────────────────────────────────────────────────────

class TestFindOrphanedProvKeys:
    def test_filters_by_prov_key_prefix(self):
        client = MagicMock()
        k1 = MagicMock(); k1.name = "prov-key-abc123"
        k2 = MagicMock(); k2.name = "user-personal-key"
        k3 = MagicMock(); k3.name = "prov-key-xyz789"
        client.ssh_keys.get_all.return_value = [k1, k2, k3]
        result = find_orphaned_prov_keys(client)
        assert k1 in result and k3 in result
        assert k2 not in result

    def test_returns_empty_when_no_prov_keys(self):
        client = MagicMock()
        k = MagicMock(); k.name = "deploy-key"
        client.ssh_keys.get_all.return_value = [k]
        assert find_orphaned_prov_keys(client) == []

    def test_returns_empty_when_key_list_empty(self):
        client = MagicMock()
        client.ssh_keys.get_all.return_value = []
        assert find_orphaned_prov_keys(client) == []

    def test_does_not_match_partial_prefix(self):
        """Keys named 'myprov-key-*' should not be matched."""
        client = MagicMock()
        k = MagicMock(); k.name = "myprov-key-abc"
        client.ssh_keys.get_all.return_value = [k]
        assert find_orphaned_prov_keys(client) == []


# ─────────────────────────────────────────────────────────────
# find_floating_ips
# ─────────────────────────────────────────────────────────────

class TestFindFloatingIps:
    def _server(self, server_id=100):
        s = MagicMock(); s.id = server_id
        return s

    def test_returns_ips_assigned_to_server(self):
        client = MagicMock()
        server = self._server(100)
        fip1 = MagicMock(); fip1.server = MagicMock(); fip1.server.id = 100
        fip2 = MagicMock(); fip2.server = MagicMock(); fip2.server.id = 999
        client.floating_ips.get_all.return_value = [fip1, fip2]
        result = find_floating_ips(client, server)
        assert fip1 in result and fip2 not in result

    def test_returns_empty_when_no_floating_ips(self):
        client = MagicMock()
        client.floating_ips.get_all.return_value = []
        assert find_floating_ips(client, self._server()) == []

    def test_skips_unassigned_floating_ips(self):
        client = MagicMock()
        fip = MagicMock(); fip.server = None
        client.floating_ips.get_all.return_value = [fip]
        assert find_floating_ips(client, self._server()) == []

    def test_returns_multiple_ips_for_same_server(self):
        client = MagicMock()
        server = self._server(100)
        fip1 = MagicMock(); fip1.server = MagicMock(); fip1.server.id = 100
        fip2 = MagicMock(); fip2.server = MagicMock(); fip2.server.id = 100
        client.floating_ips.get_all.return_value = [fip1, fip2]
        result = find_floating_ips(client, server)
        assert len(result) == 2
