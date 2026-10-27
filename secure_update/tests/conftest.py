import pytest

from secure_update.testbed import UpdateBed


@pytest.fixture
def bed():
    """一套全新的仓库 + ECU（出厂镜像 1.5.0 / A-RX-06，secure_version 2，release counter 5）。密钥在这里临时生成。"""
    return UpdateBed()
