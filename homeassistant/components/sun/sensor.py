"""Sensor platform for Sun integration."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    DOMAIN as SENSOR_DOMAIN,
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import DEGREE, EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceEntryType
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import StateType

from . import (
    ELEVATION_ABOVE,
    STATE_ABOVE_HORIZON,
    STATE_ATTR_AZIMUTH,
    STATE_ATTR_ELEVATION,
    STATE_ATTR_NEXT_DAWN,
    STATE_ATTR_NEXT_DUSK,
    STATE_ATTR_NEXT_MIDNIGHT,
    STATE_ATTR_NEXT_NOON,
    STATE_ATTR_NEXT_RISING,
    STATE_ATTR_NEXT_SETTING,
    STATE_ATTR_RISING,
    STATE_BELOW_HORIZON,
    Sun,
)
from .const import DOMAIN

ENTITY_ID_SENSOR_FORMAT = SENSOR_DOMAIN + ".sun{}"


@dataclass
class SunEntityDescriptionMixin:
    """Mixin for required Sun base description keys."""

    value_fn: Callable[[Sun], StateType | datetime]


@dataclass
class SunSensorEntityDescription(SensorEntityDescription, SunEntityDescriptionMixin):
    """Describes Sun sensor entity."""


SENSOR_TYPES: tuple[SunSensorEntityDescription, ...] = (
    SunSensorEntityDescription(
        key="sun",
        name=None,
        translation_key="sun",
        icon="mdi:theme-light-dark",
        value_fn=lambda data: STATE_ABOVE_HORIZON
        if data.solar_elevation > ELEVATION_ABOVE
        else STATE_BELOW_HORIZON,
    ),
    SunSensorEntityDescription(
        key="next_dawn",
        device_class=SensorDeviceClass.TIMESTAMP,
        translation_key="next_dawn",
        icon="mdi:sun-clock",
        value_fn=lambda data: data.next_dawn,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SunSensorEntityDescription(
        key="next_dusk",
        device_class=SensorDeviceClass.TIMESTAMP,
        translation_key="next_dusk",
        icon="mdi:sun-clock",
        value_fn=lambda data: data.next_dusk,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SunSensorEntityDescription(
        key="next_midnight",
        device_class=SensorDeviceClass.TIMESTAMP,
        translation_key="next_midnight",
        icon="mdi:sun-clock",
        value_fn=lambda data: data.next_midnight,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SunSensorEntityDescription(
        key="next_noon",
        device_class=SensorDeviceClass.TIMESTAMP,
        translation_key="next_noon",
        icon="mdi:sun-clock",
        value_fn=lambda data: data.next_noon,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SunSensorEntityDescription(
        key="next_rising",
        device_class=SensorDeviceClass.TIMESTAMP,
        translation_key="next_rising",
        icon="mdi:sun-clock",
        value_fn=lambda data: data.next_rising,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SunSensorEntityDescription(
        key="next_setting",
        device_class=SensorDeviceClass.TIMESTAMP,
        translation_key="next_setting",
        icon="mdi:sun-clock",
        value_fn=lambda data: data.next_setting,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SunSensorEntityDescription(
        key="solar_elevation",
        translation_key="solar_elevation",
        icon="mdi:theme-light-dark",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.solar_elevation,
        entity_registry_enabled_default=False,
        native_unit_of_measurement=DEGREE,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
    SunSensorEntityDescription(
        key="solar_azimuth",
        translation_key="solar_azimuth",
        icon="mdi:sun-angle",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.solar_azimuth,
        entity_registry_enabled_default=False,
        native_unit_of_measurement=DEGREE,
        entity_category=EntityCategory.DIAGNOSTIC,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Set up Sun sensor platform."""

    sun: Sun = hass.data[DOMAIN]

    async_add_entities(
        [SunSensor(sun, description, entry.entry_id) for description in SENSOR_TYPES]
    )


class SunSensor(SensorEntity):
    """Representation of a Sun Sensor."""

    _attr_has_entity_name = True
    entity_description: SunSensorEntityDescription

    def __init__(
        self, sun: Sun, entity_description: SunSensorEntityDescription, entry_id: str
    ) -> None:
        """Initiate Sun Sensor."""
        self.entity_description = entity_description
        self._attr_unique_id = f"{entry_id}-{entity_description.key}"
        self.sun = sun

        self._attr_device_info = DeviceInfo(
            name="Sun",
            identifiers={(DOMAIN, entry_id)},
            entry_type=DeviceEntryType.SERVICE,
        )

    @property
    def native_value(self) -> StateType | datetime:
        """Return value of sensor."""
        state = self.entity_description.value_fn(self.sun)
        return state

    @property
    def icon(self) -> str | None:
        """Return the icon of the sensor sun."""
        if self.entity_description.key == "sun":
            # 0.8333 is the same value as astral uses
            if self.sun.solar_elevation > ELEVATION_ABOVE:
                return "mdi:white-balance-sunny"
            return "mdi:weather-night"
        return self.entity_description.icon

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return the state attributes of the sensor sun."""
        if self.entity_description.key == "sun":
            return {
                STATE_ATTR_NEXT_DAWN: self.sun.next_dawn.isoformat(),
                STATE_ATTR_NEXT_DUSK: self.sun.next_dusk.isoformat(),
                STATE_ATTR_NEXT_MIDNIGHT: self.sun.next_midnight.isoformat(),
                STATE_ATTR_NEXT_NOON: self.sun.next_noon.isoformat(),
                STATE_ATTR_NEXT_RISING: self.sun.next_rising.isoformat(),
                STATE_ATTR_NEXT_SETTING: self.sun.next_setting.isoformat(),
                STATE_ATTR_ELEVATION: self.sun.solar_elevation,
                STATE_ATTR_AZIMUTH: self.sun.solar_azimuth,
                STATE_ATTR_RISING: self.sun.rising,
            }
        return {}
