"""Support for Proxmox VE."""
from __future__ import annotations

from proxmoxer import AuthenticationError, ProxmoxAPI
from proxmoxer.core import ResourceException
from requests.exceptions import (
    ConnectionError as connError,
    ConnectTimeout,
    RetryError,
    SSLError,
)
import voluptuous as vol

from homeassistant.backports.enum import StrEnum
from homeassistant.config_entries import SOURCE_IMPORT, ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    Platform,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import device_registry as dr
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.issue_registry import (
    IssueSeverity,
    async_create_issue,
    async_delete_issue,
)
from homeassistant.helpers.typing import ConfigType

from .const import (
    CONF_CONTAINERS,
    CONF_LXC,
    CONF_NODE,
    CONF_NODES,
    CONF_QEMU,
    CONF_REALM,
    CONF_VMS,
    COORDINATORS,
    DEFAULT_PORT,
    DEFAULT_REALM,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    LOGGER,
    PROXMOX_CLIENT,
    VERSION_REMOVE_YAML,
)
from .coordinator import (
    ProxmoxLXCCoordinator,
    ProxmoxNodeCoordinator,
    ProxmoxQEMUCoordinator,
)

PLATFORMS = [Platform.BINARY_SENSOR]

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.All(
            cv.ensure_list,
            [
                vol.Schema(
                    {
                        vol.Required(CONF_HOST): cv.string,
                        vol.Required(CONF_USERNAME): cv.string,
                        vol.Required(CONF_PASSWORD): cv.string,
                        vol.Optional(CONF_PORT, default=DEFAULT_PORT): cv.port,
                        vol.Optional(CONF_REALM, default=DEFAULT_REALM): cv.string,
                        vol.Optional(
                            CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL
                        ): cv.boolean,
                        vol.Required(CONF_NODES): vol.All(
                            cv.ensure_list,
                            [
                                vol.Schema(
                                    {
                                        vol.Required(CONF_NODE): cv.string,
                                        vol.Optional(CONF_VMS, default=[]): [
                                            cv.positive_int
                                        ],
                                        vol.Optional(CONF_CONTAINERS, default=[]): [
                                            cv.positive_int
                                        ],
                                    }
                                )
                            ],
                        ),
                    }
                )
            ],
        )
    },
    extra=vol.ALLOW_EXTRA,
)


class ProxmoxType(StrEnum):
    """Proxmox type of information."""

    Proxmox = "proxmox"
    Node = "node"
    QEMU = "qemu"
    LXC = "lxc"


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the platform."""

    # import to config flow
    if DOMAIN in config:
        LOGGER.warning(
            # Proxmox VE config flow added and should be removed.
            "Configuration of the Proxmox in YAML is deprecated and should "
            "be removed in %s. Resolve the import issues and remove the "
            "YAML configuration from your configuration.yaml file",
            VERSION_REMOVE_YAML,
        )
        async_create_issue(
            hass,
            DOMAIN,
            "yaml_deprecated",
            breaks_in_ha_version=VERSION_REMOVE_YAML,
            is_fixable=False,
            severity=IssueSeverity.WARNING,
            translation_key="yaml_deprecated",
            translation_placeholders={
                "integration": "Proxmox VE",
                "platform": DOMAIN,
                "version": VERSION_REMOVE_YAML,
            },
        )
        for conf in config[DOMAIN]:
            if conf.get(CONF_PORT) > 65535 or conf.get(CONF_PORT) <= 0:
                async_create_issue(
                    hass,
                    DOMAIN,
                    f"{conf.get[CONF_HOST]}_{conf.get[CONF_PORT]}_import_invalid_port",
                    is_fixable=False,
                    severity=IssueSeverity.ERROR,
                    translation_key="import_invalid_port",
                    translation_placeholders={
                        "integration": "Proxmox VE",
                        "platform": DOMAIN,
                        "host": conf.get[CONF_HOST],
                        "port": conf.get[CONF_PORT],
                    },
                )
            else:
                hass.async_create_task(
                    hass.config_entries.flow.async_init(
                        DOMAIN,
                        context={"source": SOURCE_IMPORT},
                        data=conf,
                    )
                )
    return True


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up the platform."""

    hass.data.setdefault(DOMAIN, {})
    entry_data = config_entry.data

    host = entry_data[CONF_HOST]
    port = entry_data[CONF_PORT]
    user = entry_data[CONF_USERNAME]
    realm = entry_data[CONF_REALM]
    password = entry_data[CONF_PASSWORD]
    verify_ssl = entry_data[CONF_VERIFY_SSL]

    # Construct an API client with the given data for the given host
    proxmox_client = ProxmoxClient(
        host=host,
        port=port,
        user=user,
        realm=realm,
        password=password,
        verify_ssl=verify_ssl,
    )
    try:
        await hass.async_add_executor_job(proxmox_client.build_client)
    except AuthenticationError as error:
        raise ConfigEntryAuthFailed from error
    except SSLError as error:
        raise ConfigEntryNotReady(
            "Unable to verify proxmox server SSL. Try using 'verify_ssl: false' "
            f"for proxmox instance {host}:{port}"
        ) from error
    except ConnectTimeout as error:
        raise ConfigEntryNotReady(
            f"Connection to host {host} timed out during setup"
        ) from error
    except RetryError as error:
        raise ConfigEntryNotReady(
            f"Connection is unreachable to host {host}"
        ) from error
    except connError as error:
        raise ConfigEntryNotReady(
            f"Connection is unreachable to host {host}"
        ) from error
    except ResourceException as error:
        raise ConfigEntryNotReady from error

    proxmox = await hass.async_add_executor_job(proxmox_client.get_api_client)

    coordinators: dict[
        str | int,
        ProxmoxNodeCoordinator | ProxmoxQEMUCoordinator | ProxmoxLXCCoordinator,
    ] = {}
    nodes_add_device = []

    resources = await hass.async_add_executor_job(proxmox.cluster.resources.get)
    LOGGER.debug("API Response - Resources: %s", resources)

    for node in config_entry.data[CONF_NODES]:
        if node in [
            node_proxmox["node"]
            for node_proxmox in await hass.async_add_executor_job(proxmox.nodes().get)
        ]:
            async_delete_issue(
                hass,
                DOMAIN,
                f"{config_entry.entry_id}_{node}_resource_nonexistent",
            )
            coordinator_node = ProxmoxNodeCoordinator(
                hass=hass,
                proxmox=proxmox,
                host_name=config_entry.data[CONF_HOST],
                node_name=node,
            )
            await coordinator_node.async_refresh()
            coordinators[node] = coordinator_node
            if coordinator_node.data is not None:
                nodes_add_device.append(node)
        else:
            async_create_issue(
                hass,
                DOMAIN,
                f"{config_entry.entry_id}_{node}_resource_nonexistent",
                is_fixable=False,
                severity=IssueSeverity.ERROR,
                translation_key="resource_nonexistent",
                translation_placeholders={
                    "integration": "Proxmox VE",
                    "platform": DOMAIN,
                    "host": config_entry.data[CONF_HOST],
                    "port": config_entry.data[CONF_PORT],
                    "resource_type": "Node",
                    "resource": node,
                },
            )

    for vm_id in config_entry.data[CONF_QEMU]:
        if int(vm_id) in [
            (int(resource["vmid"]) if "vmid" in resource else None)
            for resource in resources
        ]:
            async_delete_issue(
                hass,
                DOMAIN,
                f"{config_entry.entry_id}_{vm_id}_resource_nonexistent",
            )
            coordinator_qemu = ProxmoxQEMUCoordinator(
                hass=hass,
                proxmox=proxmox,
                host_name=config_entry.data[CONF_HOST],
                qemu_id=vm_id,
            )
            await coordinator_qemu.async_refresh()
            coordinators[vm_id] = coordinator_qemu
        else:
            async_create_issue(
                hass,
                DOMAIN,
                f"{config_entry.entry_id}_{vm_id}_resource_nonexistent",
                is_fixable=False,
                severity=IssueSeverity.ERROR,
                translation_key="resource_nonexistent",
                translation_placeholders={
                    "integration": "Proxmox VE",
                    "platform": DOMAIN,
                    "host": config_entry.data[CONF_HOST],
                    "port": config_entry.data[CONF_PORT],
                    "resource_type": "QEMU",
                    "resource": vm_id,
                },
            )

    for container_id in config_entry.data[CONF_LXC]:
        if int(container_id) in [
            (int(resource["vmid"]) if "vmid" in resource else None)
            for resource in resources
        ]:
            async_delete_issue(
                hass,
                DOMAIN,
                f"{config_entry.entry_id}_{container_id}_resource_nonexistent",
            )
            coordinator_lxc = ProxmoxLXCCoordinator(
                hass=hass,
                proxmox=proxmox,
                host_name=config_entry.data[CONF_HOST],
                container_id=container_id,
            )
            await coordinator_lxc.async_refresh()
            coordinators[container_id] = coordinator_lxc
        else:
            async_create_issue(
                hass,
                DOMAIN,
                f"{config_entry.entry_id}_{container_id}_resource_nonexistent",
                is_fixable=False,
                severity=IssueSeverity.ERROR,
                translation_key="resource_nonexistent",
                translation_placeholders={
                    "integration": "Proxmox VE",
                    "platform": DOMAIN,
                    "host": config_entry.data[CONF_HOST],
                    "port": config_entry.data[CONF_PORT],
                    "resource_type": "LXC",
                    "resource": container_id,
                },
            )

    hass.data[DOMAIN][config_entry.entry_id] = {
        PROXMOX_CLIENT: proxmox_client,
        COORDINATORS: coordinators,
    }

    for node in nodes_add_device:
        device_info(
            hass=hass,
            config_entry=config_entry,
            api_category=ProxmoxType.Node,
            node=node,
            create=True,
        )

    for platform in PLATFORMS:
        hass.async_create_task(
            hass.config_entries.async_forward_entry_setup(config_entry, platform)
        )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        hass.data[DOMAIN].pop(entry.entry_id)
    return unload_ok


async def update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    await hass.config_entries.async_reload(entry.entry_id)


def device_info(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    api_category: ProxmoxType,
    node: str | None = None,
    vm_id: int | None = None,
    create: bool | None = False,
):
    """Return the Device Info."""

    coordinators = hass.data[DOMAIN][config_entry.entry_id][COORDINATORS]

    host = config_entry.data[CONF_HOST]
    port = config_entry.data[CONF_PORT]

    proxmox_version = None
    if api_category in (ProxmoxType.QEMU, ProxmoxType.LXC):
        coordinator = coordinators[vm_id]
        if (coordinator_data := coordinator.data) is not None:
            vm_name = coordinator_data.name
            node = coordinator_data.node

        name = f"{api_category.upper()} {vm_name} ({vm_id})"
        host_port_node_vm = f"{host}_{port}_{vm_id}"
        url = f"https://{host}:{port}/#v1:0:={api_category}/{vm_id}"
        via_device = (DOMAIN, f"{host}_{port}_{node}")
        default_model = api_category.upper()

    elif api_category is ProxmoxType.Node:
        coordinator = coordinators[node]
        if (coordinator_data := coordinator.data) is not None:
            model_processor = coordinator_data.model
            proxmox_version = f"Proxmox {coordinator_data.version}"

        name = f"Node {node}"
        host_port_node_vm = f"{host}_{port}_{node}"
        url = f"https://{host}:{port}/#v1:0:=node/{node}"
        via_device = ("", "")
        default_model = model_processor

    if create:
        device_registry = dr.async_get(hass)
        return device_registry.async_get_or_create(
            config_entry_id=config_entry.entry_id,
            entry_type=dr.DeviceEntryType.SERVICE,
            configuration_url=url,
            identifiers={(DOMAIN, host_port_node_vm)},
            default_manufacturer="Proxmox VE",
            name=name,
            default_model=default_model,
            sw_version=proxmox_version,
            hw_version=None,
            via_device=via_device,
        )
    return DeviceInfo(
        entry_type=dr.DeviceEntryType.SERVICE,
        configuration_url=url,
        identifiers={(DOMAIN, host_port_node_vm)},
        default_manufacturer="Proxmox VE",
        name=name,
        default_model=default_model,
        sw_version=proxmox_version,
        hw_version=None,
        via_device=via_device,
    )


class ProxmoxClient:
    """A wrapper for the proxmoxer ProxmoxAPI client."""

    _proxmox: ProxmoxAPI

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        port: int | None = DEFAULT_PORT,
        realm: str | None = DEFAULT_REALM,
        verify_ssl: bool | None = DEFAULT_VERIFY_SSL,
    ) -> None:
        """Initialize the ProxmoxClient."""

        self._host = host
        self._port = port
        self._user = user
        self._realm = realm
        self._password = password
        self._verify_ssl = verify_ssl

    def build_client(self) -> None:
        """Construct the ProxmoxAPI client.

        Allows inserting the realm within the `user` value.
        """

        if "@" in self._user:
            user_id = self._user
        else:
            user_id = f"{self._user}@{self._realm}"

        self._proxmox = ProxmoxAPI(
            self._host,
            port=self._port,
            user=user_id,
            password=self._password,
            verify_ssl=self._verify_ssl,
        )

    def get_api_client(self) -> ProxmoxAPI:
        """Return the ProxmoxAPI client."""
        return self._proxmox
