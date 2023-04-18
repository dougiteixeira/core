"""Models for Proxmox VE integration."""

import dataclasses


@dataclasses.dataclass
class ProxmoxNodeData:
    """Data parsed from the Proxmox API for Node."""

    model: str
    status: str
    version: str


@dataclasses.dataclass
class ProxmoxVMData:
    """Data parsed from the Proxmox API for QEMU and LXC."""

    name: str
    status: str
