"""Provide common tests tools for tts."""
from __future__ import annotations

from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import voluptuous as vol

from homeassistant.components import media_source
from homeassistant.components.tts import (
    CONF_LANG,
    DOMAIN as TTS_DOMAIN,
    PLATFORM_SCHEMA,
    Provider,
    TextToSpeechEntity,
    TtsAudioType,
    Voice,
    _get_cache_files,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType
from homeassistant.setup import async_setup_component

from tests.common import (
    MockConfigEntry,
    MockModule,
    MockPlatform,
    mock_integration,
    mock_platform,
)

DEFAULT_LANG = "en_US"
SUPPORT_LANGUAGES = ["de_CH", "de_DE", "en_GB", "en_US"]
TEST_DOMAIN = "test"


def mock_tts_get_cache_files_fixture_helper():
    """Mock the list TTS cache function."""
    with patch(
        "homeassistant.components.tts._get_cache_files", return_value={}
    ) as mock_cache_files:
        yield mock_cache_files


def mock_tts_init_cache_dir_fixture_helper(
    init_tts_cache_dir_side_effect: Any,
) -> Generator[MagicMock, None, None]:
    """Mock the TTS cache dir in memory."""
    with patch(
        "homeassistant.components.tts._init_tts_cache_dir",
        side_effect=init_tts_cache_dir_side_effect,
    ) as mock_cache_dir:
        yield mock_cache_dir


def init_tts_cache_dir_side_effect_fixture_helper() -> Any:
    """Return the cache dir."""
    return None


def mock_tts_cache_dir_fixture_helper(
    tmp_path, mock_tts_init_cache_dir, mock_tts_get_cache_files, request
):
    """Mock the TTS cache dir with empty dir."""
    mock_tts_init_cache_dir.return_value = str(tmp_path)

    # Restore original get cache files behavior, we're working with a real dir.
    mock_tts_get_cache_files.side_effect = _get_cache_files

    yield tmp_path

    if not hasattr(request.node, "rep_call") or request.node.rep_call.passed:
        return

    # Print contents of dir if failed
    print("Content of dir for", request.node.nodeid)  # noqa: T201
    for fil in tmp_path.iterdir():
        print(fil.relative_to(tmp_path))  # noqa: T201

    # To show the log.
    pytest.fail("Test failed, see log for details")


def tts_mutagen_mock_fixture_helper():
    """Mock writing tags."""
    with patch(
        "homeassistant.components.tts.SpeechManager.write_tags",
        side_effect=lambda *args: args[1],
    ) as mock_write_tags:
        yield mock_write_tags


async def get_media_source_url(hass: HomeAssistant, media_content_id: str) -> str:
    """Get the media source url."""
    if media_source.DOMAIN not in hass.config.components:
        assert await async_setup_component(hass, media_source.DOMAIN, {})

    resolved = await media_source.async_resolve_media(hass, media_content_id, None)
    return resolved.url


class BaseProvider:
    """Test speech API provider."""

    def __init__(self, lang: str) -> None:
        """Initialize test provider."""
        self._lang = lang

    @property
    def default_language(self) -> str:
        """Return the default language."""
        return self._lang

    @property
    def supported_languages(self) -> list[str]:
        """Return list of supported languages."""
        return SUPPORT_LANGUAGES

    @callback
    def async_get_supported_voices(self, language: str) -> list[Voice] | None:
        """Return list of supported languages."""
        if language == "en-US":
            return [
                Voice("james_earl_jones", "James Earl Jones"),
                Voice("fran_drescher", "Fran Drescher"),
            ]
        return None

    @property
    def supported_options(self) -> list[str]:
        """Return list of supported options like voice, emotions."""
        return ["voice", "age"]

    def get_tts_audio(
        self, message: str, language: str, options: dict[str, Any]
    ) -> TtsAudioType:
        """Load TTS dat."""
        return ("mp3", b"")


class MockProvider(BaseProvider, Provider):
    """Test speech API provider."""

    def __init__(self, lang: str) -> None:
        """Initialize test provider."""
        super().__init__(lang)
        self.name = "Test"


class MockTTSEntity(BaseProvider, TextToSpeechEntity):
    """Test speech API provider."""

    @property
    def name(self) -> str:
        """Return the name of the entity."""
        return "Test"


class MockTTS(MockPlatform):
    """A mock TTS platform."""

    PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
        {vol.Optional(CONF_LANG, default=DEFAULT_LANG): vol.In(SUPPORT_LANGUAGES)}
    )

    def __init__(self, provider: MockProvider, **kwargs: Any) -> None:
        """Initialize."""
        super().__init__(**kwargs)
        self._provider = provider

    async def async_get_engine(
        self,
        hass: HomeAssistant,
        config: ConfigType,
        discovery_info: DiscoveryInfoType | None = None,
    ) -> Provider | None:
        """Set up a mock speech component."""
        return self._provider


async def mock_setup(
    hass: HomeAssistant,
    mock_provider: MockProvider,
) -> None:
    """Set up a test provider."""
    mock_integration(hass, MockModule(domain=TEST_DOMAIN))
    mock_platform(hass, f"{TEST_DOMAIN}.{TTS_DOMAIN}", MockTTS(mock_provider))

    await async_setup_component(
        hass, TTS_DOMAIN, {TTS_DOMAIN: {"platform": TEST_DOMAIN}}
    )
    await hass.async_block_till_done()


async def mock_config_entry_setup(
    hass: HomeAssistant, tts_entity: MockTTSEntity
) -> MockConfigEntry:
    """Set up a test tts platform via config entry."""

    async def async_setup_entry_init(
        hass: HomeAssistant, config_entry: ConfigEntry
    ) -> bool:
        """Set up test config entry."""
        await hass.config_entries.async_forward_entry_setup(config_entry, TTS_DOMAIN)
        return True

    async def async_unload_entry_init(
        hass: HomeAssistant, config_entry: ConfigEntry
    ) -> bool:
        """Unload up test config entry."""
        await hass.config_entries.async_forward_entry_unload(config_entry, TTS_DOMAIN)
        return True

    mock_integration(
        hass,
        MockModule(
            TEST_DOMAIN,
            async_setup_entry=async_setup_entry_init,
            async_unload_entry=async_unload_entry_init,
        ),
    )

    async def async_setup_entry_platform(
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        async_add_entities: AddEntitiesCallback,
    ) -> None:
        """Set up test tts platform via config entry."""
        async_add_entities([tts_entity])

    loaded_platform = MockPlatform(async_setup_entry=async_setup_entry_platform)
    mock_platform(hass, f"{TEST_DOMAIN}.{TTS_DOMAIN}", loaded_platform)

    config_entry = MockConfigEntry(domain=TEST_DOMAIN)
    config_entry.add_to_hass(hass)
    assert await hass.config_entries.async_setup(config_entry.entry_id)
    await hass.async_block_till_done()

    return config_entry
