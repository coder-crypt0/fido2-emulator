import pytest
from usbip_client import TestRig


@pytest.fixture
def rig():
    instance = TestRig()
    try:
        yield instance
    finally:
        instance.close()
