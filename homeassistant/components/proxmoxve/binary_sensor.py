"""Binary sensor to read Proxmox VE data."""

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from . import COORDINATORS, DOMAIN, ProxmoxType, device_info
from .const import CONF_LXC, CONF_NODES, CONF_QEMU
from .entity import ProxmoxEntity


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up binary sensors."""

    sensors = []
    coordinators = hass.data[DOMAIN][config_entry.entry_id][COORDINATORS]

    for node in config_entry.data[CONF_NODES]:
        if node in hass.data[DOMAIN][config_entry.entry_id][COORDINATORS]:
            for vm_id in config_entry.data[CONF_NODES][node][CONF_QEMU]:
                if vm_id in hass.data[DOMAIN][config_entry.entry_id][COORDINATORS]:
                    coordinator = coordinators[vm_id]

                    # unfound vm case
                    if coordinator.data is None:
                        continue

                    vm_sensor = create_binary_sensor(
                        coordinator=coordinator,
                        vm_id=vm_id,
                        key="status",
                        name="Status",
                        config_entry=config_entry,
                        info_device=device_info(
                            hass=hass,
                            config_entry=config_entry,
                            api_category=ProxmoxType.QEMU,
                            node=node,
                            vm_id=vm_id,
                        ),
                    )
                    sensors.append(vm_sensor)

            for container_id in config_entry.data[CONF_NODES][node][CONF_LXC]:
                if (
                    container_id
                    in hass.data[DOMAIN][config_entry.entry_id][COORDINATORS]
                ):
                    coordinator = coordinators[container_id]

                    # unfound container case
                    if coordinator.data is None:
                        continue

                    container_sensor = create_binary_sensor(
                        coordinator=coordinator,
                        vm_id=container_id,
                        key="status",
                        name="Status",
                        config_entry=config_entry,
                        info_device=device_info(
                            hass=hass,
                            config_entry=config_entry,
                            api_category=ProxmoxType.LXC,
                            node=node,
                            vm_id=container_id,
                        ),
                    )
                    sensors.append(container_sensor)

    async_add_entities(sensors)


class ProxmoxBinarySensor(ProxmoxEntity, BinarySensorEntity):
    """A binary sensor for reading Proxmox VE data."""

    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: DataUpdateCoordinator,
        unique_id: str,
        name: str,
        icon: str,
        device_class,
        info_device,
    ) -> None:
        """Create the binary sensor for vms or containers."""
        super().__init__(coordinator, unique_id, name, icon)

        self._attr_device_class = device_class
        self._attr_device_info = info_device

    @property
    def is_on(self) -> bool | None:
        """Return the state of the binary sensor."""
        if (data := self.coordinator.data) is None:
            return None

        return data.status == "running"

    @property
    def available(self) -> bool:
        """Return sensor availability."""

        return super().available and self.coordinator.data is not None


def create_binary_sensor(
    coordinator,
    vm_id: int,
    key: str,
    name: str,
    config_entry,
    info_device,
) -> ProxmoxBinarySensor:
    """Create a binary sensor based on the given data."""
    return ProxmoxBinarySensor(
        coordinator=coordinator,
        unique_id=f"{config_entry.entry_id}_{vm_id}_{key}",
        name=name,
        icon="",
        device_class=BinarySensorDeviceClass.RUNNING,
        info_device=info_device,
    )
