"""Small, legacy-REST GLPI reader used by the explicit asset-import command.

Only GET requests are implemented.  The adapter cannot create, update, or
delete GLPI records.
"""
from __future__ import annotations

import json
import ipaddress
import socket
from dataclasses import dataclass, replace
from http.client import HTTPSConnection
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPSHandler, Request, build_opener


class GlpiApiError(Exception):
    pass


class IPv4HTTPSConnection(HTTPSConnection):
    """HTTPS connection that resolves the GLPI hostname over IPv4 only.

    Cloudflare Access is intentionally narrowed to the portal host's IPv4
    address.  Letting the standard client choose IPv6 would bypass that
    explicit policy expectation and produces an Access denial instead of a
    GLPI API response.
    """

    def connect(self):
        last_error = None
        for family, socktype, proto, _, address in socket.getaddrinfo(
            self.host, self.port, socket.AF_INET, socket.SOCK_STREAM
        ):
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(self.timeout)
                if self.source_address:
                    sock.bind(self.source_address)
                sock.connect(address)
                self.sock = sock
                break
            except OSError as error:
                last_error = error
                sock.close()
        else:
            raise last_error or OSError("No IPv4 address was available for GLPI")

        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class IPv4HTTPSHandler(HTTPSHandler):
    def https_open(self, request):
        return self.do_open(IPv4HTTPSConnection, request)


_IPV4_OPENER = build_opener(IPv4HTTPSHandler())


def open_ipv4_https(request, timeout=20):
    return _IPV4_OPENER.open(request, timeout=timeout)


@dataclass(frozen=True)
class GlpiComputer:
    external_id: str
    name: str
    serial_number: str = ""
    manufacturer: str = ""
    model: str = ""
    operating_system: str = ""
    location_name: str = ""
    entity_name: str = ""
    primary_ip: str = ""
    fqdn: str = ""
    status: str = "unknown"
    network_interfaces: tuple = ()


@dataclass(frozen=True)
class GlpiNetworkInterface:
    external_id: str
    name: str = ""
    mac_address: str = ""
    network_name: str = ""
    ip_addresses: tuple = ()


class GlpiReadOnlyAdapter:
    def __init__(self, base_url, credentials, opener=None):
        self.api_url = base_url.rstrip("/")
        if not self.api_url.endswith("/apirest.php"):
            self.api_url += "/apirest.php"
        self.credentials = credentials
        self.opener = opener or open_ipv4_https
        self.session_token = None
        self.access_headers = {}
        if credentials.get("cf_access_client_id"):
            self.access_headers = {
                "CF-Access-Client-Id": credentials["cf_access_client_id"],
                "CF-Access-Client-Secret": credentials["cf_access_client_secret"],
            }

    def _request(self, path, *, headers=None, query=None):
        url = f"{self.api_url}/{path.lstrip('/')}"
        if query:
            url += "?" + urlencode(query, doseq=True)
        request_headers = {
            "Content-Type": "application/json",
            "User-Agent": "LSMON-GLPI-ReadOnly/1.0",
            "App-Token": self.credentials["app_token"],
            **self.access_headers,
        }
        if headers:
            request_headers.update(headers)
        try:
            with self.opener(Request(url, headers=request_headers, method="GET"), timeout=20) as response:
                payload = response.read().decode("utf-8")
        except HTTPError as error:
            raise GlpiApiError(f"GLPI HTTP {error.code}") from error
        except URLError as error:
            raise GlpiApiError("GLPI connection failed") from error
        except OSError as error:
            raise GlpiApiError("GLPI connection failed") from error
        try:
            return json.loads(payload)
        except json.JSONDecodeError as error:
            raise GlpiApiError("GLPI returned invalid JSON") from error

    def open(self):
        payload = self._request("initSession", headers={"Authorization": f"user_token {self.credentials['user_token']}"})
        token = payload.get("session_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise GlpiApiError("GLPI did not return a session token")
        self.session_token = token

    def close(self):
        if not self.session_token:
            return
        try:
            self._request("killSession", headers={"Session-Token": self.session_token})
        finally:
            self.session_token = None

    @staticmethod
    def _text(value):
        # GLPI's expand_dropdowns makes values strings, while a restricted
        # response may retain numeric IDs. IDs are not useful as customer labels.
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, dict):
            return GlpiReadOnlyAdapter._text(value.get("name") or value.get("value"))
        return ""

    @classmethod
    def _computer(cls, item):
        if not isinstance(item, dict):
            return None
        external_id = str(item.get("id", "")).strip()
        name = cls._text(item.get("name"))
        if not external_id or not name:
            return None
        candidate_ip = cls._text(item.get("ip") or item.get("primary_ip"))
        try:
            primary_ip = str(ipaddress.ip_address(candidate_ip)) if candidate_ip else ""
        except ValueError:
            primary_ip = ""
        return GlpiComputer(
            external_id=external_id,
            name=name,
            serial_number=cls._text(item.get("serial")),
            manufacturer=cls._text(item.get("manufacturers_id")),
            model=cls._text(item.get("computermodels_id")),
            operating_system=cls._text(item.get("operatingsystems_id")),
            location_name=cls._text(item.get("locations_id")),
            entity_name=cls._text(item.get("entities_id")),
            primary_ip=primary_ip,
            fqdn=cls._text(item.get("fqdn")),
            status=cls._text(item.get("states_id")) or "unknown",
        )

    def _computer_detail(self, computer):
        """Read a single Computer record to obtain values omitted from list APIs."""
        item = self._request(
            f"Computer/{computer.external_id}",
            headers={"Session-Token": self.session_token},
            query={"expand_dropdowns": "true"},
        )
        detailed = self._computer(item)
        if detailed is None or detailed.external_id != computer.external_id:
            raise GlpiApiError("GLPI Computer detail response has an unexpected format")
        return detailed

    def get_computer(self, external_id):
        """Return one GLPI Computer by its ID using a GET-only request.

        This supports a narrow post-enrollment routing check without listing
        other customer assets or altering GLPI or portal state.
        """
        if not self.session_token:
            raise GlpiApiError("GLPI session is not open")
        item = self._request(
            f"Computer/{str(external_id).strip()}",
            headers={"Session-Token": self.session_token},
            query={"expand_dropdowns": "true"},
        )
        computer = self._computer(item)
        if computer is None or computer.external_id != str(external_id).strip():
            raise GlpiApiError("GLPI Computer response has an unexpected format")
        return computer

    def list_computers(self, limit=None):
        if not self.session_token:
            raise GlpiApiError("GLPI session is not open")
        all_computers, offset, page_size = [], 0, 100
        while limit is None or len(all_computers) < limit:
            end = offset + page_size - 1
            payload = self._request(
                "Computer/", headers={"Session-Token": self.session_token},
                query={"range": f"{offset}-{end}", "expand_dropdowns": "true"},
            )
            if not isinstance(payload, list):
                raise GlpiApiError("GLPI Computer response has an unexpected format")
            batch = [computer for item in payload if (computer := self._computer(item))]
            all_computers.extend(batch)
            if len(payload) < page_size:
                break
            offset += page_size
        return all_computers[:limit]

    def list_computers_full(self, limit=None):
        """Return detailed computer records and their installed software.

        All requests remain GET-only.  Software is intentionally read only in
        this explicit full mode so a routine identity refresh stays small.
        """
        computers = []
        for computer in self.list_computers(limit=limit):
            detailed = self._computer_detail(computer)
            operating_system = self._operating_system_for_computer(detailed.external_id)
            network_interfaces = self._network_interfaces_for_computer(detailed)
            primary_ip = detailed.primary_ip or next(
                (address for interface in network_interfaces for address in interface.ip_addresses), ""
            )
            # The normal Computer response from this GLPI instance omits OS
            # inventory data.  Preserve the detailed response unless the
            # dedicated, GET-only association actually returned an OS label.
            computers.append(replace(
                detailed,
                operating_system=operating_system or detailed.operating_system,
                primary_ip=primary_ip,
                network_interfaces=network_interfaces,
            ))
        software_names = self._software_version_names()
        software_by_computer = {
            computer.external_id: self._software_for_computer(computer.external_id, software_names)
            for computer in computers
        }
        return computers, software_by_computer

    def _network_interfaces_for_computer(self, computer):
        """Read only NIC names, MACs, network labels, and valid IPs from GLPI."""
        interfaces = []
        for port in self._paged(f"Computer/{computer.external_id}/NetworkPort"):
            if not isinstance(port, dict) or not port.get("id"):
                continue
            port_id = str(port["id"])
            network_names, addresses = [], []
            for network_name in self._paged(f"NetworkPort/{port_id}/NetworkName"):
                if not isinstance(network_name, dict) or not network_name.get("id"):
                    continue
                name = self._text(network_name.get("name"))
                if name and name not in network_names:
                    network_names.append(name)
                for ip_record in self._paged(f"NetworkName/{network_name['id']}/IPAddress"):
                    if not isinstance(ip_record, dict):
                        continue
                    candidate = self._text(ip_record.get("name"))
                    try:
                        address = str(ipaddress.ip_address(candidate))
                    except ValueError:
                        continue
                    if address not in addresses:
                        addresses.append(address)
            interfaces.append(GlpiNetworkInterface(
                external_id=port_id,
                name=self._text(port.get("name")),
                mac_address=self._text(port.get("mac")).lower(),
                network_name=", ".join(network_names)[:255],
                ip_addresses=tuple(addresses),
            ))
        return tuple(interfaces)

    def _operating_system_for_computer(self, computer_id):
        """Return a safe customer-facing OS label from GLPI inventory data.

        GLPI keeps inventory OS details in Item_OperatingSystem rather than in
        the Computer record returned by this deployment.  Read only its public
        OS/version/build labels; deliberately ignore licence and owner fields.
        """
        payload = self._request(
            f"Computer/{computer_id}/Item_OperatingSystem",
            headers={"Session-Token": self.session_token},
            query={"range": "0-0", "expand_dropdowns": "true"},
        )
        if not isinstance(payload, list) or not payload:
            return ""
        item = payload[0]
        if not isinstance(item, dict):
            return ""
        name = self._text(item.get("operatingsystems_id"))
        version = self._text(item.get("operatingsystemversions_id"))
        build = self._text(item.get("operatingsystemservicepacks_id"))
        values = [name]
        if version and version.lower() not in name.lower():
            values.append(version)
        if build and build.lower() not in " ".join(values).lower():
            values.append(f"build {build}")
        return " ".join(value for value in values if value)[:160]

    def _paged(self, path, *, expand_dropdowns=True):
        values, offset, page_size = [], 0, 100
        while True:
            query = {"range": f"{offset}-{offset + page_size - 1}"}
            if expand_dropdowns:
                query["expand_dropdowns"] = "true"
            payload = self._request(
                path,
                headers={"Session-Token": self.session_token},
                query=query,
            )
            if not isinstance(payload, list):
                raise GlpiApiError(f"GLPI {path} response has an unexpected format")
            values.extend(payload)
            if len(payload) < page_size:
                return values
            offset += page_size

    def _software_version_names(self):
        products = {}
        for item in self._paged("Software/"):
            if not isinstance(item, dict) or not item.get("id"):
                continue
            name = self._text(item.get("name"))
            if name:
                products[str(item["id"])] = name

        names = {}
        for item in self._paged("SoftwareVersion/"):
            if not isinstance(item, dict) or not item.get("id"):
                continue
            # GLPI installations often return a numeric softwares_id even when
            # expand_dropdowns is requested.  Resolve it through the read-only
            # Software catalogue; never treat the numeric ID as a customer label.
            software_id = str(item.get("softwares_id", "")).strip()
            name = self._text(item.get("softwares_id")) or products.get(software_id, "")
            if name:
                names[str(item["id"])] = (name, self._text(item.get("name")))
        return names

    def _software_for_computer(self, computer_id, software_names):
        values = []
        # Keep this relationship's IDs numeric.  With expand_dropdowns GLPI
        # substitutes display labels, which cannot be joined to SoftwareVersion.
        for item in self._paged(f"Computer/{computer_id}/Item_SoftwareVersion", expand_dropdowns=False):
            if not isinstance(item, dict):
                continue
            software = software_names.get(str(item.get("softwareversions_id", "")))
            if software and software not in values:
                values.append(software)
        return values
