"""Config Flow for ProxmoxVE."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import proxmoxer
from requests.exceptions import ConnectTimeout, SSLError
import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import (
    CONF_BASE,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import async_get_hass, callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import device_registry as dr
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.issue_registry import (
    IssueSeverity,
    async_create_issue,
    async_delete_issue,
)

from . import ProxmoxClient
from .const import (
    CONF_CONTAINERS,
    CONF_LXC,
    CONF_NODE,
    CONF_NODES,
    CONF_QEMU,
    CONF_REALM,
    CONF_VMS,
    DEFAULT_PORT,
    DEFAULT_REALM,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    LOGGER,
)

SCHEMA_HOST_BASE: vol.Schema = vol.Schema(
    {
        vol.Required(CONF_HOST): str,
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): int,
    }
)
SCHEMA_HOST_SSL: vol.Schema = vol.Schema(
    {
        vol.Required(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
    }
)
SCHEMA_HOST_AUTH: vol.Schema = vol.Schema(
    {
        vol.Required(CONF_USERNAME): str,
        vol.Required(CONF_PASSWORD): str,
        vol.Optional(CONF_REALM, default=DEFAULT_REALM): str,
    }
)
SCHEMA_HOST_FULL: vol.Schema = SCHEMA_HOST_BASE.extend(SCHEMA_HOST_SSL.schema).extend(
    SCHEMA_HOST_AUTH.schema
)


class ProxmoxOptionsFlowHandler(config_entries.OptionsFlow):
    """Config flow options for ProxmoxVE."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize ProxmoxVE options flow."""
        self.config_entry = config_entry
        self._proxmox_client: ProxmoxClient
        self._nodes: dict[str, Any] = {}
        self._host: str | None = None

    async def async_step_init(self, user_input: dict[str, Any]) -> FlowResult:
        """Manage the options."""
        return self.async_show_menu(
            step_id="menu",
            menu_options=[
                "host_auth",
                "add_node",
                "change_selection_qemu_lxc",
                "remove_node",
            ],
        )

    async def async_step_host_auth(self, user_input: dict[str, Any]) -> FlowResult:
        """Manage the host options step for proxmoxve config flow."""
        errors = {}

        if user_input is not None:
            host: str = str(self.config_entry.data[CONF_HOST])
            port: int = int(str(self.config_entry.data[CONF_PORT]))
            user: str = str(user_input.get(CONF_USERNAME))
            realm: str = str(user_input.get(CONF_REALM))
            password: str = str(user_input.get(CONF_PASSWORD))
            verify_ssl = user_input.get(CONF_VERIFY_SSL)

            try:
                self._proxmox_client = ProxmoxClient(
                    host=host,
                    port=port,
                    user=user,
                    realm=realm,
                    password=password,
                    verify_ssl=verify_ssl,
                )

                await self.hass.async_add_executor_job(
                    self._proxmox_client.build_client
                )

            except proxmoxer.AuthenticationError:
                errors[CONF_USERNAME] = "auth_error"
            except SSLError:
                errors[CONF_VERIFY_SSL] = "ssl_rejection"
            except ConnectTimeout:
                errors[CONF_HOST] = "cant_connect"
            except Exception:  # pylint: disable=broad-except
                errors[CONF_BASE] = "general_error"

            else:
                config_data: dict[str, Any] = (
                    self.config_entry.data.copy()
                    if self.config_entry.data is not None
                    else {}
                )
                config_data[CONF_USERNAME] = user_input.get(CONF_USERNAME)
                config_data[CONF_PASSWORD] = user_input.get(CONF_PASSWORD)
                config_data[CONF_REALM] = user_input.get(CONF_REALM)
                config_data[CONF_VERIFY_SSL] = user_input.get(CONF_VERIFY_SSL)

                self.hass.config_entries.async_update_entry(
                    self.config_entry,
                    data=config_data,
                )

                return self.async_abort(reason="changes_successful")

        return self.async_show_form(
            step_id="host_auth",
            data_schema=self.add_suggested_values_to_schema(
                (SCHEMA_HOST_AUTH.extend(SCHEMA_HOST_SSL.schema)),
                self.config_entry.data or user_input,
            ),
            errors=errors,
        )

    async def async_step_add_node(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> FlowResult:
        """Handle the node selection step."""

        errors: dict[str, str] = {}

        current_nodes = []
        for node in self.config_entry.data[CONF_NODES]:
            current_nodes.append(node)

        if user_input:
            node = user_input.get(CONF_NODE)
            if node in current_nodes:
                return self.async_abort(reason="node_already_exists")

            return await self.async_step_selection_qemu_lxc(node=node)

        host = self.config_entry.data[CONF_HOST]
        port = self.config_entry.data[CONF_PORT]
        user = self.config_entry.data[CONF_USERNAME]
        realm = self.config_entry.data[CONF_REALM]
        password = self.config_entry.data[CONF_PASSWORD]
        verify_ssl = self.config_entry.data[CONF_VERIFY_SSL]

        try:
            self._proxmox_client = ProxmoxClient(
                host=host,
                port=port,
                user=user,
                realm=realm,
                password=password,
                verify_ssl=verify_ssl,
            )

            await self.hass.async_add_executor_job(self._proxmox_client.build_client)

        except (
            proxmoxer.AuthenticationError,
            SSLError,
            ConnectTimeout,
            Exception,
        ) as err:
            raise (err)

        proxmox = self._proxmox_client.get_api_client()

        nodes = []

        if (proxmox_cliente := self._proxmox_client) is not None:
            if proxmox := (proxmox_cliente.get_api_client()):
                proxmox_nodes = await self.hass.async_add_executor_job(
                    proxmox.nodes.get
                )

                for node in proxmox_nodes:
                    nodes.append(node[CONF_NODE])

                for current_node in current_nodes:
                    if current_node in nodes:
                        nodes.remove(current_node)

                if len(nodes) == 0:
                    return self.async_abort(reason="no_nodes_to_add")

                if len(nodes) == 1:
                    for node in nodes:
                        return await self.async_step_selection_qemu_lxc(node=node)

                return self.async_show_form(
                    step_id="add_node",
                    data_schema=vol.Schema(
                        {
                            vol.Required(CONF_NODE): vol.In(nodes),
                        }
                    ),
                    errors=errors,
                )

        return self.async_abort(reason="no_nodes")

    async def async_step_change_selection_qemu_lxc(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> FlowResult:
        """Handle the QEMU/LXC selection step."""

        errors: dict[str, str] = {}

        if user_input:
            return await self.async_step_selection_qemu_lxc(
                node=user_input.get(CONF_NODE)
            )

        if len(self.config_entry.data[CONF_NODES]) == 1:
            return await self.async_step_selection_qemu_lxc(
                node=list(self.config_entry.data[CONF_NODES].keys())[0]
            )

        nodes = []
        for node in self.config_entry.data[CONF_NODES]:
            nodes.append(node)

        return self.async_show_form(
            step_id="change_selection_qemu_lxc",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_NODE): vol.In(nodes),
                }
            ),
            errors=errors,
        )

    async def async_step_selection_qemu_lxc(
        self,
        user_input: dict[str, Any] | None = None,
        node: str | None = None,
    ) -> FlowResult:
        """Handle the QEMU/LXC selection step."""

        if user_input is None:
            if node not in self.config_entry.data[CONF_NODES]:
                self.config_entry.data[CONF_NODES][node] = {}

            old_qemu = []

            if CONF_QEMU not in self.config_entry.data[CONF_NODES][node]:
                self.config_entry.data[CONF_NODES][node][CONF_QEMU] = []

            for qemu in self.config_entry.data[CONF_NODES][node][CONF_QEMU]:
                old_qemu.append(str(qemu))

            old_lxc = []

            if CONF_LXC not in self.config_entry.data[CONF_NODES][node]:
                self.config_entry.data[CONF_NODES][node][CONF_LXC] = []

            for lxc in self.config_entry.data[CONF_NODES][node][CONF_LXC]:
                old_lxc.append(str(lxc))

            host = self.config_entry.data[CONF_HOST]
            port = self.config_entry.data[CONF_PORT]
            user = self.config_entry.data[CONF_USERNAME]
            realm = self.config_entry.data[CONF_REALM]
            password = self.config_entry.data[CONF_PASSWORD]
            verify_ssl = self.config_entry.data[CONF_VERIFY_SSL]

            try:
                self._proxmox_client = ProxmoxClient(
                    host=host,
                    port=port,
                    user=user,
                    realm=realm,
                    password=password,
                    verify_ssl=verify_ssl,
                )

                await self.hass.async_add_executor_job(
                    self._proxmox_client.build_client
                )

            except (
                proxmoxer.AuthenticationError,
                SSLError,
                ConnectTimeout,
            ) as err:
                raise (err)

            proxmox = self._proxmox_client.get_api_client()

            return self.async_show_form(
                step_id="selection_qemu_lxc",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_NODE): node,
                        vol.Optional(CONF_QEMU, default=old_qemu): cv.multi_select(
                            {
                                **dict.fromkeys(old_qemu),
                                **{
                                    str(
                                        qemu["vmid"]
                                    ): f"{qemu['vmid']} {qemu['name'] if 'name' in qemu else None}"
                                    for qemu in await self.hass.async_add_executor_job(
                                        proxmox.nodes(node).qemu.get
                                    )
                                },
                            }
                        ),
                        vol.Optional(CONF_LXC, default=old_lxc): cv.multi_select(
                            {
                                **dict.fromkeys(old_lxc),
                                **{
                                    str(
                                        lxc["vmid"]
                                    ): f"{lxc['vmid']} {lxc['name'] if 'name' in lxc else None}"
                                    for lxc in await self.hass.async_add_executor_job(
                                        proxmox.nodes(node).lxc.get
                                    )
                                },
                            }
                        ),
                    }
                ),
            )

        node = user_input.get(CONF_NODE)

        qemu_selecition = []
        if (
            CONF_QEMU in user_input
            and (qemu_user := user_input.get(CONF_QEMU)) is not None
        ):
            for qemu in qemu_user:
                qemu_selecition.append(qemu)

        for qemu_id in self.config_entry.data[CONF_NODES][node][CONF_QEMU]:
            if qemu_id not in qemu_selecition:
                # Remove device
                host_port_node_vm = (
                    f"{self.config_entry.data[CONF_HOST]}_"
                    f"{self.config_entry.data[CONF_PORT]}_"
                    f"{node}_{qemu_id}"
                )
                await self.async_remove_device(
                    entry_id=self.config_entry.entry_id,
                    device_identifier=host_port_node_vm,
                )
                async_delete_issue(
                    async_get_hass(),
                    DOMAIN,
                    f"vm_id_nonexistent_{DOMAIN}_{self.config_entry.data[CONF_HOST]}_{self.config_entry.data[CONF_PORT]}_{node}_{qemu_id}",
                )
        self.config_entry.data[CONF_NODES][node][CONF_QEMU] = user_input.get(CONF_QEMU)

        lxc_selecition = []
        if (
            CONF_QEMU in user_input
            and (lxc_user := user_input.get(CONF_LXC)) is not None
        ):
            for qemu in lxc_user:
                lxc_selecition.append(qemu)

        for lxc_id in self.config_entry.data[CONF_NODES][node][CONF_LXC]:
            if lxc_id not in lxc_selecition:
                # Remove device
                host_port_node_vm = (
                    f"{self.config_entry.data[CONF_HOST]}_"
                    f"{self.config_entry.data[CONF_PORT]}_"
                    f"{node}_{lxc_id}"
                )
                await self.async_remove_device(
                    entry_id=self.config_entry.entry_id,
                    device_identifier=host_port_node_vm,
                )
                async_delete_issue(
                    async_get_hass(),
                    DOMAIN,
                    f"vm_id_nonexistent_{DOMAIN}_{self.config_entry.data[CONF_HOST]}_{self.config_entry.data[CONF_PORT]}_{node}_{lxc_id}",
                )
        self.config_entry.data[CONF_NODES][node][CONF_LXC] = user_input.get(CONF_LXC)

        self.hass.config_entries.async_update_entry(
            self.config_entry, data=self.config_entry.data
        )

        await self.hass.config_entries.async_reload(self.config_entry.entry_id)

        return self.async_abort(reason="changes_successful")

    async def async_step_remove_node(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> FlowResult:
        """Handle the QEMU/LXC selection step."""

        errors: dict[str, str] = {}

        if user_input:
            return await self.async_step_remove_node_confirm(
                node=user_input.get(CONF_NODE)
            )

        nodes = []
        for node in self.config_entry.data[CONF_NODES]:
            nodes.append(node)

        return self.async_show_form(
            step_id="remove_node",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_NODE): vol.In(nodes),
                }
            ),
            errors=errors,
        )

    async def async_step_remove_node_confirm(
        self,
        user_input: dict[str, Any] | None = None,
        node: str | None = None,
    ) -> FlowResult:
        """Handle the QEMU/LXC selection step."""
        errors = {}
        if user_input is not None:
            node = user_input.get(CONF_NODE)
            if user_input.get("confirm_remove") is False:
                errors["confirm_remove"] = "confirm_remove_false"
            else:
                for vm_id in (
                    *self.config_entry.data[CONF_NODES][node][CONF_QEMU],
                    *self.config_entry.data[CONF_NODES][node][CONF_LXC],
                ):
                    # Remove device QEMU and LXC
                    host_port_node_vm = (
                        f"{self.config_entry.data[CONF_HOST]}_"
                        f"{self.config_entry.data[CONF_PORT]}_"
                        f"{node}_{vm_id}"
                    )
                    await self.async_remove_device(
                        entry_id=self.config_entry.entry_id,
                        device_identifier=host_port_node_vm,
                    )
                    async_delete_issue(
                        async_get_hass(),
                        DOMAIN,
                        f"vm_id_nonexistent_{DOMAIN}_{self.config_entry.data[CONF_HOST]}_{self.config_entry.data[CONF_PORT]}_{node}_{vm_id}",
                    )

                config_data: dict[str, Any] = self.config_entry.data.copy()
                config_data[CONF_NODES].pop(node)
                self.hass.config_entries.async_update_entry(
                    self.config_entry, data=config_data
                )

                # Remove device node
                host_port_node_vm = (
                    f"{self.config_entry.data[CONF_HOST]}_"
                    f"{self.config_entry.data[CONF_PORT]}_"
                    f"{node}"
                )
                await self.async_remove_device(
                    entry_id=self.config_entry.entry_id,
                    device_identifier=host_port_node_vm,
                )

                async_delete_issue(
                    async_get_hass(),
                    DOMAIN,
                    f"node_nonexistent_{DOMAIN}_{self.config_entry.data[CONF_HOST]}_{self.config_entry.data[CONF_PORT]}_{node}",
                )

                await self.hass.config_entries.async_reload(self.config_entry.entry_id)

                return self.async_abort(reason="changes_successful")

        return self.async_show_form(
            step_id="remove_node_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_NODE): node,
                    vol.Required("confirm_remove"): bool,
                }
            ),
            errors=errors,
        )

    async def async_remove_device(
        self,
        entry_id: str,
        device_identifier: str,
    ) -> bool:
        """Remove device."""
        device_identifiers = {(DOMAIN, device_identifier)}
        dev_reg = dr.async_get(self.hass)
        device = dev_reg.async_get_or_create(
            config_entry_id=entry_id,
            identifiers=device_identifiers,
        )

        dev_reg.async_update_device(
            device_id=device.id,
            remove_config_entry_id=entry_id,
        )
        LOGGER.debug("Device %s (%s) removed", device.name, device.id)
        return True


class ProxmoxVEConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """ProxmoxVE Config Flow class."""

    VERSION = 1
    _reauth_entry: config_entries.ConfigEntry | None = None

    def __init__(self) -> None:
        """Init for ProxmoxVE config flow."""
        super().__init__()

        self._config: dict[str, Any] = {}
        self._nodes: dict[str, Any] = {}
        self._host: str
        self._proxmox_client: ProxmoxClient | None = None

    async def async_step_import(self, import_config: dict[str, Any]) -> FlowResult:
        """Import existing configuration."""

        errors = {}

        if f"{import_config.get(CONF_HOST)}_{import_config.get(CONF_PORT)}" in [
            f"{entry.data.get(CONF_HOST)}_{entry.data.get(CONF_PORT)}"
            for entry in self._async_current_entries()
        ]:
            async_create_issue(
                async_get_hass(),
                DOMAIN,
                f"import_already_configured_{DOMAIN}_{import_config.get(CONF_HOST)}_{import_config.get(CONF_PORT)}",
                breaks_in_ha_version="2023.8.0",
                is_fixable=False,
                severity=IssueSeverity.WARNING,
                translation_key="import_already_configured",
                translation_placeholders={
                    "integration": "Proxmox VE",
                    "platform": DOMAIN,
                    "host": str(import_config.get(CONF_HOST)),
                    "port": str(import_config.get(CONF_PORT)),
                },
            )
            return self.async_abort(reason="import_failed")

        host: str = str(import_config.get(CONF_HOST))
        port: int = int(str(import_config.get(CONF_PORT)))
        user: str = str(import_config.get(CONF_USERNAME))
        realm: str = str(import_config.get(CONF_REALM))
        password: str = str(import_config.get(CONF_PASSWORD))
        verify_ssl = import_config.get(CONF_VERIFY_SSL)

        proxmox_client = ProxmoxClient(
            host=host,
            port=port,
            user=user,
            realm=realm,
            password=password,
            verify_ssl=verify_ssl,
        )

        try:
            await self.hass.async_add_executor_job(proxmox_client.build_client)
        except proxmoxer.backends.https.AuthenticationError:
            errors[CONF_USERNAME] = "auth_error"
            async_create_issue(
                async_get_hass(),
                DOMAIN,
                f"import_auth_error_{DOMAIN}_{import_config.get(CONF_HOST)}_{import_config.get(CONF_PORT)}",
                breaks_in_ha_version="2023.8.0",
                is_fixable=False,
                severity=IssueSeverity.ERROR,
                translation_key="import_auth_error",
                translation_placeholders={
                    "integration": "Proxmox VE",
                    "platform": DOMAIN,
                    "host": str(import_config.get(CONF_HOST)),
                    "port": str(import_config.get(CONF_PORT)),
                },
            )
        except SSLError:
            errors[CONF_VERIFY_SSL] = "ssl_rejection"
            async_create_issue(
                async_get_hass(),
                DOMAIN,
                f"import_ssl_rejection_{DOMAIN}_{import_config.get(CONF_HOST)}_{import_config.get(CONF_PORT)}",
                breaks_in_ha_version="2023.8.0",
                is_fixable=False,
                severity=IssueSeverity.ERROR,
                translation_key="import_ssl_rejection",
                translation_placeholders={
                    "integration": "Proxmox VE",
                    "platform": DOMAIN,
                    "host": str(import_config.get(CONF_HOST)),
                    "port": str(import_config.get(CONF_PORT)),
                },
            )
        except ConnectTimeout:
            errors[CONF_HOST] = "cant_connect"
            async_create_issue(
                async_get_hass(),
                DOMAIN,
                f"import_cant_connect_{DOMAIN}_{import_config.get(CONF_HOST)}_{import_config.get(CONF_PORT)}",
                breaks_in_ha_version="2023.8.0",
                is_fixable=False,
                severity=IssueSeverity.ERROR,
                translation_key="import_cant_connect",
                translation_placeholders={
                    "integration": "Proxmox VE",
                    "platform": DOMAIN,
                    "host": str(import_config.get(CONF_HOST)),
                    "port": str(import_config.get(CONF_PORT)),
                },
            )
        except Exception:  # pylint: disable=broad-except
            errors[CONF_BASE] = "general_error"
            async_create_issue(
                async_get_hass(),
                DOMAIN,
                f"import_general_error_{DOMAIN}_{import_config.get(CONF_HOST)}_{import_config.get(CONF_PORT)}",
                breaks_in_ha_version="2023.8.0",
                is_fixable=False,
                severity=IssueSeverity.ERROR,
                translation_key="import_general_error",
                translation_placeholders={
                    "integration": "Proxmox VE",
                    "platform": DOMAIN,
                    "host": str(import_config.get(CONF_HOST)),
                    "port": str(import_config.get(CONF_PORT)),
                },
            )

        if errors:
            return self.async_abort(reason="import_failed")

        proxmox_nodes_host = []
        if proxmox := (proxmox_client.get_api_client()):
            proxmox_nodes = await self.hass.async_add_executor_job(proxmox.nodes.get)

            for node in proxmox_nodes:
                proxmox_nodes_host.append(node[CONF_NODE])

        if (
            CONF_NODES in import_config
            and (import_nodes := import_config.get(CONF_NODES)) is not None
        ):
            import_config[CONF_NODES] = {}
            for node_data in import_nodes:
                node = node_data[CONF_NODE]
                if node in proxmox_nodes_host:
                    import_config[CONF_NODES][node] = {}
                    import_config[CONF_NODES][node][CONF_QEMU] = node_data[CONF_VMS]
                    import_config[CONF_NODES][node][CONF_LXC] = node_data[
                        CONF_CONTAINERS
                    ]
                else:
                    async_create_issue(
                        async_get_hass(),
                        DOMAIN,
                        f"import_node_not_exist_{DOMAIN}_{import_config.get(CONF_HOST)}_{import_config.get(CONF_PORT)}_{import_config.get(CONF_NODE)}",
                        breaks_in_ha_version="2023.8.0",
                        is_fixable=False,
                        severity=IssueSeverity.WARNING,
                        translation_key="import_node_not_exist",
                        translation_placeholders={
                            "integration": "Proxmox VE",
                            "platform": DOMAIN,
                            "host": str(import_config.get(CONF_HOST)),
                            "port": str(import_config.get(CONF_PORT)),
                            "node": str(node),
                        },
                    )

        async_create_issue(
            async_get_hass(),
            DOMAIN,
            f"import_success_{DOMAIN}_{import_config.get(CONF_HOST)}_{import_config.get(CONF_PORT)}",
            breaks_in_ha_version="2023.8.0",
            is_fixable=False,
            severity=IssueSeverity.WARNING,
            translation_key="import_success",
            translation_placeholders={
                "integration": "Proxmox VE",
                "platform": DOMAIN,
                "host": str(import_config.get(CONF_HOST)),
                "port": str(import_config.get(CONF_PORT)),
            },
        )

        return self.async_create_entry(
            title=(f"{import_config.get(CONF_HOST)}:{import_config.get(CONF_PORT)}"),
            data=import_config,
        )

    async def async_step_reauth(self, data: Mapping[str, Any]) -> FlowResult:
        """Handle a reauthorization flow request."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Confirm reauth dialog."""
        errors = {}
        assert self._reauth_entry
        if user_input is not None:
            host: str = str(self._reauth_entry.data[CONF_HOST])
            port: int = int(str(self._reauth_entry.data[CONF_PORT]))
            verify_ssl: bool = bool(self._reauth_entry.data[CONF_VERIFY_SSL])
            user: str = str(user_input.get(CONF_USERNAME))
            realm: str = str(user_input.get(CONF_REALM))
            password: str = str(user_input.get(CONF_PASSWORD))

            try:
                self._proxmox_client = ProxmoxClient(
                    host,
                    port=port,
                    user=user,
                    realm=realm,
                    password=password,
                    verify_ssl=verify_ssl,
                )

                await self.hass.async_add_executor_job(
                    self._proxmox_client.build_client
                )

            except proxmoxer.backends.https.AuthenticationError:
                errors[CONF_USERNAME] = "auth_error"
            except SSLError:
                errors[CONF_BASE] = "ssl_rejection"
            except ConnectTimeout:
                errors[CONF_BASE] = "cant_connect"
            except Exception:  # pylint: disable=broad-except
                errors[CONF_BASE] = "general_error"

            else:
                if CONF_HOST in self._reauth_entry.data:
                    user_input[CONF_HOST] = self._reauth_entry.data[CONF_HOST]
                if CONF_PORT in self._reauth_entry.data:
                    user_input[CONF_PORT] = self._reauth_entry.data[CONF_PORT]
                if CONF_VERIFY_SSL in self._reauth_entry.data:
                    user_input[CONF_VERIFY_SSL] = self._reauth_entry.data[
                        CONF_VERIFY_SSL
                    ]
                if CONF_NODE in self._reauth_entry.data:
                    user_input[CONF_NODE] = self._reauth_entry.data[CONF_NODE]
                if CONF_QEMU in self._reauth_entry.data:
                    user_input[CONF_QEMU] = self._reauth_entry.data[CONF_QEMU]
                if CONF_LXC in self._reauth_entry.data:
                    user_input[CONF_LXC] = self._reauth_entry.data[CONF_LXC]
                self.hass.config_entries.async_update_entry(
                    self._reauth_entry, data=user_input
                )
                await self.hass.config_entries.async_reload(self._reauth_entry.entry_id)
                return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=self.add_suggested_values_to_schema(
                SCHEMA_HOST_AUTH, self._reauth_entry.data
            ),
            errors=errors,
        )

    async def async_step_user(self, user_input=None) -> FlowResult:
        """Manual user configuration."""
        return await self.async_step_init(user_input)

    async def async_step_init(self, user_input) -> FlowResult:
        """Async step user for proxmoxve config flow."""
        return await self.async_step_host(user_input)

    async def async_step_host(self, user_input) -> FlowResult:
        """Async step of host config flow for proxmoxve."""
        errors = {}

        if user_input:
            host = user_input.get(CONF_HOST, "")
            port = user_input.get(CONF_PORT, DEFAULT_PORT)
            username = user_input.get(CONF_USERNAME, "")
            password = user_input.get(CONF_PASSWORD, "")
            realm = user_input.get(CONF_REALM, DEFAULT_REALM)
            verify_ssl = user_input.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)

            self._host = host

            if port > 65535 or port <= 0:
                errors[CONF_PORT] = "invalid_port"

            if not errors:
                try:
                    self._proxmox_client = ProxmoxClient(
                        host,
                        port=port,
                        user=username,
                        realm=realm,
                        password=password,
                        verify_ssl=verify_ssl,
                    )

                    await self.hass.async_add_executor_job(
                        self._proxmox_client.build_client
                    )

                except proxmoxer.backends.https.AuthenticationError:
                    errors[CONF_USERNAME] = "auth_error"
                except SSLError:
                    errors[CONF_VERIFY_SSL] = "ssl_rejection"
                except ConnectTimeout:
                    errors[CONF_HOST] = "cant_connect"
                except Exception:  # pylint: disable=broad-except
                    errors[CONF_BASE] = "general_error"

                else:
                    self._config[CONF_HOST] = host
                    self._config[CONF_PORT] = port
                    self._config[CONF_USERNAME] = username
                    self._config[CONF_PASSWORD] = password
                    self._config[CONF_REALM] = realm
                    self._config[CONF_VERIFY_SSL] = verify_ssl

                    return await self.async_step_node()

        return self.async_show_form(
            step_id="host",
            data_schema=self.add_suggested_values_to_schema(
                SCHEMA_HOST_FULL, user_input
            ),
            errors=errors,
        )

    async def async_step_node(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> FlowResult:
        """Handle the node selection step."""

        errors: dict[str, str] = {}

        if user_input:
            if (
                f"{self._config[CONF_HOST]}_{self._config[CONF_PORT]}_{user_input.get(CONF_NODE)}"
                in [
                    f"{entry.data.get(CONF_HOST)}_{entry.data.get(CONF_PORT)}_{entry.data.get(CONF_NODE)}"
                    for entry in self._async_current_entries()
                ]
            ):
                return self.async_abort(reason="already_configured")

            self._config[CONF_NODES] = {}
            node = user_input.get(CONF_NODE)
            self._config[CONF_NODES][node] = {}
            return await self.async_step_selection_qemu_lxc(node=node)

        nodes = []
        if (proxmox_cliente := self._proxmox_client) is not None:
            if proxmox := (proxmox_cliente.get_api_client()):
                proxmox_nodes = await self.hass.async_add_executor_job(
                    proxmox.nodes.get
                )

                for node in proxmox_nodes:
                    nodes.append(node[CONF_NODE])

        return self.async_show_form(
            step_id="node",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_NODE): vol.In(nodes),
                }
            ),
            errors=errors,
        )

    async def async_step_selection_qemu_lxc(
        self,
        user_input: dict[str, Any] | None = None,
        node: str | None = None,
    ) -> FlowResult:
        """Handle the QEMU/LXC selection step."""

        if user_input is None:
            if (proxmox_cliente := self._proxmox_client) is not None:
                proxmox = proxmox_cliente.get_api_client()

            return self.async_show_form(
                step_id="selection_qemu_lxc",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_NODE): node,
                        vol.Optional(CONF_QEMU): cv.multi_select(
                            {
                                str(qemu["vmid"]): (
                                    f"{qemu['vmid']} "
                                    f"{qemu['name'] if 'name' in qemu else None}"
                                )
                                for qemu in await self.hass.async_add_executor_job(
                                    proxmox.nodes(node).qemu.get
                                )
                            }
                        ),
                        vol.Optional(CONF_LXC): cv.multi_select(
                            {
                                str(
                                    lxc["vmid"]
                                ): f"{lxc['vmid']} {lxc['name'] if 'name' in lxc else None}"
                                for lxc in await self.hass.async_add_executor_job(
                                    proxmox.nodes(node).lxc.get
                                )
                            }
                        ),
                    }
                ),
            )

        node = str(user_input.get(CONF_NODE))
        if CONF_QEMU not in self._config[CONF_NODES][node]:
            self._config[CONF_NODES][node][CONF_QEMU] = []
        if (
            CONF_QEMU in user_input
            and (qemu_user := user_input.get(CONF_QEMU)) is not None
        ):
            for qemu_selection in qemu_user:
                self._config[CONF_NODES][node][CONF_QEMU].append(qemu_selection)

        if CONF_LXC not in self._config[CONF_NODES][node]:
            self._config[CONF_NODES][node][CONF_LXC] = []
        if (
            CONF_LXC in user_input
            and (lxc_user := user_input.get(CONF_LXC)) is not None
        ):
            for lxc_selection in lxc_user:
                self._config[CONF_NODES][node][CONF_LXC].append(lxc_selection)

        return self.async_create_entry(
            title=(f"{node} - {self._config[CONF_HOST]}:" f"{self._config[CONF_PORT]}"),
            data=self._config,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Options callback for Proxmox."""
        return ProxmoxOptionsFlowHandler(config_entry)
