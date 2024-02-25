"""The tests for the Sun sensor platform."""
from datetime import datetime, timedelta

from astral import LocationInfo
import astral.sun
from freezegun.api import FrozenDateTimeFactory
import pytest

from homeassistant.components import sun
from homeassistant.components.sensor import SensorDeviceClass
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
import homeassistant.helpers.entity_registry as er
from homeassistant.setup import async_setup_component
import homeassistant.util.dt as dt_util


async def test_setting_rising(
    hass: HomeAssistant,
    freezer: FrozenDateTimeFactory,
    entity_registry_enabled_by_default: None,
) -> None:
    """Test retrieving sun setting and rising."""
    utc_now = datetime(2016, 11, 1, 8, 0, 0, tzinfo=dt_util.UTC)
    freezer.move_to(utc_now)
    await async_setup_component(hass, sun.DOMAIN, {sun.DOMAIN: {}})
    await hass.async_block_till_done()

    utc_today = utc_now.date()

    location = LocationInfo(
        latitude=hass.config.latitude, longitude=hass.config.longitude
    )

    mod = -1
    while True:
        next_dawn = astral.sun.dawn(
            location.observer, date=utc_today + timedelta(days=mod)
        )
        if next_dawn > utc_now:
            break
        mod += 1

    mod = -1
    while True:
        next_dusk = astral.sun.dusk(
            location.observer, date=utc_today + timedelta(days=mod)
        )
        if next_dusk > utc_now:
            break
        mod += 1

    mod = -1
    while True:
        next_midnight = astral.sun.midnight(
            location.observer, date=utc_today + timedelta(days=mod)
        )
        if next_midnight > utc_now:
            break
        mod += 1

    mod = -1
    while True:
        next_noon = astral.sun.noon(
            location.observer, date=utc_today + timedelta(days=mod)
        )
        if next_noon > utc_now:
            break
        mod += 1

    mod = -1
    while True:
        next_rising = astral.sun.sunrise(
            location.observer, date=utc_today + timedelta(days=mod)
        )
        if next_rising > utc_now:
            break
        mod += 1

    mod = -1
    while True:
        next_setting = astral.sun.sunset(
            location.observer, date=utc_today + timedelta(days=mod)
        )
        if next_setting > utc_now:
            break
        mod += 1

    expected_solar_elevation = astral.sun.elevation(location.observer, utc_now)
    expected_solar_azimuth = astral.sun.azimuth(location.observer, utc_now)

    state1 = hass.states.get("sensor.sun_next_dawn")
    state2 = hass.states.get("sensor.sun_next_dusk")
    state3 = hass.states.get("sensor.sun_next_midnight")
    state4 = hass.states.get("sensor.sun_next_noon")
    state5 = hass.states.get("sensor.sun_next_rising")
    state6 = hass.states.get("sensor.sun_next_setting")
    assert next_dawn.replace(microsecond=0) == dt_util.parse_datetime(state1.state)
    assert next_dusk.replace(microsecond=0) == dt_util.parse_datetime(state2.state)
    assert next_midnight.replace(microsecond=0) == dt_util.parse_datetime(state3.state)
    assert next_noon.replace(microsecond=0) == dt_util.parse_datetime(state4.state)
    assert next_rising.replace(microsecond=0) == dt_util.parse_datetime(state5.state)
    assert next_setting.replace(microsecond=0) == dt_util.parse_datetime(state6.state)
    solar_elevation_state = hass.states.get("sensor.sun_solar_elevation")
    assert float(solar_elevation_state.state) == pytest.approx(
        expected_solar_elevation, 0.1
    )
    solar_azimuth_state = hass.states.get("sensor.sun_solar_azimuth")
    assert float(solar_azimuth_state.state) == pytest.approx(
        expected_solar_azimuth, 0.1
    )

    entry_ids = hass.config_entries.async_entries("sun")

    entity_reg = er.async_get(hass)
    entity = entity_reg.async_get("sensor.sun_next_dawn")

    assert entity
    assert entity.entity_category is EntityCategory.DIAGNOSTIC
    assert entity.unique_id == f"{entry_ids[0].entry_id}-next_dawn"

    freezer.tick(timedelta(hours=24))
    # Block once for Sun to update
    await hass.async_block_till_done()
    # Block another time for the sensors to update
    await hass.async_block_till_done()

    # Make sure all the signals work
    assert state1.state != hass.states.get("sensor.sun_next_dawn").state
    assert state2.state != hass.states.get("sensor.sun_next_dusk").state
    assert state3.state != hass.states.get("sensor.sun_next_midnight").state
    assert state4.state != hass.states.get("sensor.sun_next_noon").state
    assert state5.state != hass.states.get("sensor.sun_next_rising").state
    assert state6.state != hass.states.get("sensor.sun_next_setting").state
    assert (
        solar_elevation_state.state
        != hass.states.get("sensor.sun_solar_elevation").state
    )
    assert (
        solar_azimuth_state.state != hass.states.get("sensor.sun_solar_azimuth").state
    )

    entity = entity_reg.async_get("sensor.sun_next_dusk")
    assert entity
    assert entity.entity_category is EntityCategory.DIAGNOSTIC
    assert entity.unique_id == f"{entry_ids[0].entry_id}-next_dusk"

    entity = entity_reg.async_get("sensor.sun_next_midnight")
    assert entity
    assert entity.entity_category is EntityCategory.DIAGNOSTIC
    assert entity.unique_id == f"{entry_ids[0].entry_id}-next_midnight"

    entity = entity_reg.async_get("sensor.sun_next_noon")
    assert entity
    assert entity.entity_category is EntityCategory.DIAGNOSTIC
    assert entity.unique_id == f"{entry_ids[0].entry_id}-next_noon"

    entity = entity_reg.async_get("sensor.sun_next_rising")
    assert entity
    assert entity.entity_category is EntityCategory.DIAGNOSTIC
    assert entity.unique_id == f"{entry_ids[0].entry_id}-next_rising"

    entity = entity_reg.async_get("sensor.sun_next_setting")
    assert entity
    assert entity.entity_category is EntityCategory.DIAGNOSTIC
    assert entity.unique_id == f"{entry_ids[0].entry_id}-next_setting"

    entity = entity_reg.async_get("sensor.sun_solar_elevation")
    assert entity
    assert entity.entity_category is EntityCategory.DIAGNOSTIC
    assert entity.unique_id == f"{entry_ids[0].entry_id}-solar_elevation"

    entity = entity_reg.async_get("sensor.sun_solar_azimuth")
    assert entity
    assert entity.entity_category is EntityCategory.DIAGNOSTIC
    assert entity.unique_id == f"{entry_ids[0].entry_id}-solar_azimuth"

    entity = entity_reg.async_get("sensor.sun_solar_rising")
    assert entity
    assert entity.entity_category is EntityCategory.DIAGNOSTIC
    assert entity.unique_id == f"{entry_ids[0].entry_id}-solar_rising"


async def test_sensor_sun(
    hass: HomeAssistant,
    freezer: FrozenDateTimeFactory,
    entity_registry_enabled_by_default: None,
) -> None:
    """Test retrieving sun entity."""
    utc_now = datetime(2016, 11, 1, 0, 0, 0, tzinfo=dt_util.UTC)
    freezer.move_to(utc_now)
    await async_setup_component(hass, sun.DOMAIN, {sun.DOMAIN: {}})
    await hass.async_block_till_done()

    entry_ids = hass.config_entries.async_entries("sun")

    entity_reg = er.async_get(hass)
    entity = entity_reg.async_get("sensor.sun")

    assert entity
    assert entity.original_device_class is SensorDeviceClass.ENUM
    assert entity.unique_id == f"{entry_ids[0].entry_id}-sun"
    assert entity.translation_key == "sun"

    assert entity.device_id
    device_registry = dr.async_get(hass)
    device_entry = device_registry.async_get(entity.device_id)
    assert device_entry
    assert device_entry.name == "Sun"
    assert device_entry.entry_type is dr.DeviceEntryType.SERVICE

    state = hass.states.get("sensor.sun")
    assert state.state == sun.STATE_BELOW_HORIZON

    assert (
        state.attributes.get(sun.STATE_ATTR_NEXT_DAWN)
        == hass.states.get("sensor.sun_next_dawn").state
    )
    assert (
        state.attributes.get(sun.STATE_ATTR_NEXT_DUSK)
        == hass.states.get("sensor.sun_next_dusk").state
    )
    assert (
        state.attributes.get(sun.STATE_ATTR_NEXT_MIDNIGHT)
        == hass.states.get("sensor.sun_next_midnight").state
    )
    assert (
        state.attributes.get(sun.STATE_ATTR_NEXT_NOON)
        == hass.states.get("sensor.sun_next_noon").state
    )
    assert (
        state.attributes.get(sun.STATE_ATTR_NEXT_RISING)
        == hass.states.get("sensor.sun_next_rising").state
    )
    assert (
        state.attributes.get(sun.STATE_ATTR_NEXT_SETTING)
        == hass.states.get("sensor.sun_next_setting").state
    )
    assert state.attributes.get(sun.STATE_ATTR_SOLAR_AZIMUTH) == float(
        hass.states.get("sensor.sun_solar_azimuth").state
    )
    assert state.attributes.get(sun.STATE_ATTR_SOLAR_ELEVATION) == float(
        hass.states.get("sensor.sun_solar_elevation").state
    )
    assert state.attributes.get(sun.STATE_ATTR_RISING) == bool(
        hass.states.get("sensor.sun_solar_rising").state
    )

    freezer.tick(timedelta(hours=36))
    # Block once for Sun to update
    await hass.async_block_till_done()
    # Block another time for the sensors to update
    await hass.async_block_till_done()

    state_2 = hass.states.get("sensor.sun")
    assert state_2.state == sun.STATE_ABOVE_HORIZON

    assert (
        state_2.attributes.get(sun.STATE_ATTR_NEXT_DAWN)
        == hass.states.get("sensor.sun_next_dawn").state
    )
    assert (
        state_2.attributes.get(sun.STATE_ATTR_NEXT_DUSK)
        == hass.states.get("sensor.sun_next_dusk").state
    )
    assert (
        state_2.attributes.get(sun.STATE_ATTR_NEXT_MIDNIGHT)
        == hass.states.get("sensor.sun_next_midnight").state
    )
    assert (
        state_2.attributes.get(sun.STATE_ATTR_NEXT_NOON)
        == hass.states.get("sensor.sun_next_noon").state
    )
    assert (
        state_2.attributes.get(sun.STATE_ATTR_NEXT_RISING)
        == hass.states.get("sensor.sun_next_rising").state
    )
    assert (
        state_2.attributes.get(sun.STATE_ATTR_NEXT_SETTING)
        == hass.states.get("sensor.sun_next_setting").state
    )
    assert state_2.attributes.get(sun.STATE_ATTR_SOLAR_AZIMUTH) == float(
        hass.states.get("sensor.sun_solar_azimuth").state
    )
    assert state_2.attributes.get(sun.STATE_ATTR_SOLAR_ELEVATION) == float(
        hass.states.get("sensor.sun_solar_elevation").state
    )
    assert state_2.attributes.get(sun.STATE_ATTR_RISING) == bool(
        hass.states.get("sensor.sun_solar_rising").state
    )
