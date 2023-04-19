"""DataUpdateCoordinators for the Proxmox VE integration."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from proxmoxer import AuthenticationError, ProxmoxAPI
from proxmoxer.core import ResourceException
from requests.exceptions import ConnectTimeout, SSLError

from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.typing import UNDEFINED, UndefinedType
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import CONF_NODE, DOMAIN, LOGGER, UPDATE_INTERVAL
from .models import ProxmoxNodeData, ProxmoxVMData


class ProxmoxCoordinator(DataUpdateCoordinator[ProxmoxNodeData | ProxmoxVMData]):
    """Proxmox VE data update coordinator."""


class ProxmoxNodeCoordinator(ProxmoxCoordinator):
    """Proxmox VE Node data update coordinator."""

    def __init__(
        self,
        hass: HomeAssistant,
        proxmox: ProxmoxAPI,
        host_name: str,
        node_name: str,
    ) -> None:
        """Initialize the Proxmox Node coordinator."""

        super().__init__(
            hass,
            LOGGER,
            name=f"proxmox_coordinator_{host_name}_{node_name}",
            update_interval=timedelta(seconds=UPDATE_INTERVAL),
        )

        self.hass = hass
        self.proxmox = proxmox
        self.node_name = node_name

    async def _async_update_data(self) -> ProxmoxNodeData:
        """Update data  for Proxmox QEMU."""

        def poll_api() -> dict[str, Any] | None:
            """Return data from the Proxmox QEMU API."""
            try:
                api_status = self.proxmox.nodes(self.node_name).status.get()
                if nodes_api := self.proxmox.nodes.get():
                    for node_api in nodes_api:
                        if node_api[CONF_NODE] == self.node_name:
                            api_status["status"] = node_api["status"]
                            api_status["cpu"] = node_api["cpu"]
                            api_status["disk_max"] = node_api["maxdisk"]
                            api_status["disk_use"] = node_api["disk"]
                            break
                api_status["version"] = self.proxmox.nodes(self.node_name).version.get()

            except (
                AuthenticationError,
                SSLError,
                ConnectTimeout,
                ResourceException,
            ) as error:
                raise UpdateFailed from error
            LOGGER.debug("API Response - Node: %s", api_status)
            return api_status

        api_status = await self.hass.async_add_executor_job(poll_api)
        if api_status is None:
            raise UpdateFailed(
                f"Node {self.node_name} unable to be found in host {self.proxmox}"
            )

        return ProxmoxNodeData(
            model=api_status["cpuinfo"]["model"],
            status=api_status["status"],
            version=api_status["version"]["version"],
        )


class ProxmoxQEMUCoordinator(ProxmoxCoordinator):
    """Proxmox VE QEMU data update coordinator."""

    def __init__(
        self,
        hass: HomeAssistant,
        proxmox: ProxmoxAPI,
        host_name: str,
        qemu_id: int,
    ) -> None:
        """Initialize the Proxmox QEMU coordinator."""

        super().__init__(
            hass,
            LOGGER,
            name=f"proxmox_coordinator_{host_name}_{qemu_id}",
            update_interval=timedelta(seconds=UPDATE_INTERVAL),
        )

        self.hass = hass
        self.proxmox = proxmox
        self.node_name: str
        self.vm_id = qemu_id

    async def _async_update_data(self) -> ProxmoxVMData:
        """Update data  for Proxmox QEMU."""

        def poll_api() -> dict[str, Any] | None:
            """Return data from the Proxmox QEMU API."""
            node_name = None
            try:
                api_status = None

                resources = self.proxmox.cluster.resources.get()
                LOGGER.debug("API Response - Resources: %s", resources)

                for resource in resources:
                    if "vmid" in resource:
                        if int(resource["vmid"]) == int(self.vm_id):
                            node_name = resource["node"]

                self.node_name = str(node_name)
                if self.node_name is not None:
                    api_status = (
                        self.proxmox.nodes(self.node_name)
                        .qemu(self.vm_id)
                        .status.current.get()
                    )

            except (
                AuthenticationError,
                SSLError,
                ConnectTimeout,
                ResourceException,
            ) as error:
                raise UpdateFailed from error
            LOGGER.debug("API Response - QEMU: %s", api_status)
            return api_status

        api_status = await self.hass.async_add_executor_job(poll_api)
        if api_status is None:
            raise UpdateFailed(f"Vm/Container {self.vm_id} unable to be found")

        update_device_via(self)

        return ProxmoxVMData(
            status=api_status["status"],
            name=api_status["name"],
            node=self.node_name,
        )


class ProxmoxLXCCoordinator(ProxmoxCoordinator):
    """Proxmox VE LXC data update coordinator."""

    def __init__(
        self,
        hass: HomeAssistant,
        proxmox: ProxmoxAPI,
        host_name: str,
        container_id: int,
    ) -> None:
        """Initialize the Proxmox LXC coordinator."""

        super().__init__(
            hass,
            LOGGER,
            name=f"proxmox_coordinator_{host_name}_{container_id}",
            update_interval=timedelta(seconds=UPDATE_INTERVAL),
        )

        self.hass = hass
        self.proxmox = proxmox
        self.vm_id = container_id
        self.node_name: str

    async def _async_update_data(self) -> ProxmoxVMData:
        """Update data  for Proxmox LXC."""

        def poll_api() -> dict[str, Any] | None:
            """Return data from the Proxmox LXC API."""
            node_name = None
            try:
                api_status = None

                resources = self.proxmox.cluster.resources.get()
                LOGGER.debug("API Response - Resources: %s", resources)

                for resource in resources:
                    if "vmid" in resource:
                        if int(resource["vmid"]) == int(self.vm_id):
                            node_name = resource["node"]

                self.node_name = str(node_name)
                if node_name is not None:
                    api_status = (
                        self.proxmox.nodes(self.node_name)
                        .lxc(self.vm_id)
                        .status.current.get()
                    )

            except (
                AuthenticationError,
                SSLError,
                ConnectTimeout,
                ResourceException,
            ) as error:
                raise UpdateFailed from error
            LOGGER.debug("API Response - LXC: %s", api_status)
            return api_status

        api_status = await self.hass.async_add_executor_job(poll_api)

        if api_status is None:
            raise UpdateFailed(f"Vm/Container {self.vm_id} unable to be found")

        update_device_via(self)

        return ProxmoxVMData(
            status=api_status["status"],
            name=api_status["name"],
            node=self.node_name,
        )


def update_device_via(self) -> None:
    """Return the Device Info."""
    dev_reg = dr.async_get(self.hass)
    device = dev_reg.async_get_or_create(
        config_entry_id=self.config_entry.entry_id,
        identifiers={
            (
                DOMAIN,
                f"{self.config_entry.data[CONF_HOST]}_"
                f"{self.config_entry.data[CONF_PORT]}_"
                f"{self.vm_id}",
            )
        },
    )
    via_device = dev_reg.async_get_device(
        {
            (
                DOMAIN,
                f"{self.config_entry.data[CONF_HOST]}_"
                f"{self.config_entry.data[CONF_PORT]}_"
                f"{self.node_name}",
            )
        }
    )
    via_device_id: str | UndefinedType = via_device.id if via_device else UNDEFINED
    if device.via_device_id is not via_device_id:
        LOGGER.debug(
            "Update device %s - connected via device: old=%s, new=%s",
            self.vm_id,
            device.via_device_id,
            via_device_id,
        )
        dev_reg.async_update_device(
            device.id,
            via_device_id=via_device_id,
            entry_type=dr.DeviceEntryType.SERVICE,
        )
