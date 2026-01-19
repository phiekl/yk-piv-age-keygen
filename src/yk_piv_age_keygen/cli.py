#!/usr/bin/env python3
#
# Copyright 2026 Philip Eklöf
#
# SPDX-License-Identifier: MIT
#
# ruff: noqa: TRY400 # Use `logging.exception` instead of `logging.error`

"""yubikey-age-keygen module."""

import argparse
import datetime
import enum
import hashlib
import logging
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING

import click
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from ykman._cli.piv import _update_chuid as yk_update_chuid
from ykman._cli.util import prompt_timeout as yk_prompt_timeout
from ykman.device import _UsbCompositeDevice as YubiKeyUsbCompositeDevice
from ykman.device import list_all_devices as yk_list_all_devices
from ykman.piv import derive_management_key as yk_derive_management_key
from ykman.piv import get_pivman_data as yk_get_pivman_data
from ykman.piv import get_pivman_protected_data as yk_get_pivman_protected_data
from ykman.piv import sign_certificate_builder as yk_sign_certificate_builder
from ykman.scripting import ScriptingDevice as YubiKeyScriptingDevice
from yubikit.core import InvalidPinError as YubiKeyInvalidPinError
from yubikit.core.smartcard import SW as YUBIKEY_STATUS_WORD
from yubikit.core.smartcard import ApduError as YubiKeyApduError
from yubikit.management import DeviceInfo as YubiKeyDeviceInfo
from yubikit.piv import DEFAULT_MANAGEMENT_KEY as YUBIKEY_DEFAULT_MANAGEMENT_KEY
from yubikit.piv import KEY_TYPE as YUBIKEY_KEY_TYPE
from yubikit.piv import SLOT as YUBIKEY_SLOT
from yubikit.piv import PivSession as YubiKeyPivSession
from yubikit.support import get_name as yk_get_name

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey


def arg_parse() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase the verbosity level",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=False,
        help="decrease log level to WARNING",
    )
    parser.add_argument(
        "-S",
        "--serial",
        type=int,
        help="use the YubiKey with this serial (required with multiple devices)",
        metavar="<num>",
    )
    parser.add_argument(
        "-s",
        "--slot",
        type=int,
        required=True,
        help="generate a key and certificate in this retired slot",
        metavar="{1..20}",
    )
    parser.add_argument(
        "-p",
        "--pin",
        help="PIN code (requested interactively if not specified)",
        metavar="<pin>",
    )
    parser.add_argument(
        "-m",
        "--mgmt-key",
        help="management key (required if key is not PIN derived/protected)",
        metavar="<key>",
    )
    parser.add_argument(
        "-P",
        "--pin-policy",
        choices=["never", "once", "always"],
        default="once",
        help="new PIN policy for slot (default: once)",
    )
    parser.add_argument(
        "-T",
        "--touch-policy",
        choices=["never", "always", "cached"],
        default="always",
        help="new touch policy for slot (default: always)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="force replacement of currently existing key/certificate in slot",
    )

    return parser.parse_args()


class PinPolicy(enum.IntEnum):
    """PIV PIN policy values as used by yubikit/ykman."""

    NEVER = 0x01
    ONCE = 0x02
    ALWAYS = 0x03


class TouchPolicy(enum.IntEnum):
    """PIV touch policy values as used by yubikit/ykman."""

    NEVER = 0x01
    ALWAYS = 0x02
    CACHED = 0x03


def get_devices_output(
    devices: Sequence[tuple[YubiKeyUsbCompositeDevice, YubiKeyDeviceInfo]],
) -> str:
    """Format a human-readable list of detected YubiKeys."""
    lines = ["Devices detected:"]
    for dev, dev_info in devices:
        line = "- "
        line += yk_get_name(dev_info, dev.pid.yubikey_type)
        if dev_info.version:
            line += f" ({dev_info.version})"
        if dev_info.serial:
            line += f" (serial: {dev_info.serial})"
        lines.append(line)
    lines.append("")
    return "\n".join(lines)


def slotnum(slot: int) -> int:
    """Convert a PIV slot number to a RETIRED 1..20 slot number."""
    return slot - YUBIKEY_SLOT.RETIRED1 + 1


class KeygenError(Exception):
    """Base exception raised in most cases."""


class KeygenDeviceSelectionError(KeygenError):
    """Raised when e.g. multiple devices available and no serial provided."""

    def __init__(
        self,
        msg: str,
        devices: Sequence[tuple[YubiKeyUsbCompositeDevice, YubiKeyDeviceInfo]],
    ) -> None:
        """Store msg and devices."""
        self.msg = msg
        self.devices = devices

    def __str__(self) -> str:
        """Return msg as string."""
        return self.msg


class Keygen:
    """Generate a age-plugin-yubikey compatible key in a RETIRED PIV slot."""

    def __init__(  # noqa: C901,PLR0912,PLR0913,PLR0915 # too many everything
        self,
        serial: int | None = None,
        slot: int = 1,
        pin: str | None = None,
        mgmt_key: str | None = None,
        pin_policy: str = "cached",
        touch_policy: str = "always",
        force: bool = False,  # noqa: FBT001,FBT002 # booelan in function definition
    ) -> None:
        """Initialize options for key generation."""
        if not isinstance(force, bool):
            msg = "Non-bool force option provided."
            raise KeygenError(msg)
        self.force = force

        if pin is not None:
            if not isinstance(pin, str):
                msg = "Non-string PIN provided."
                raise KeygenError(msg)
            if not pin:
                msg = "Empty PIN provided."
                raise KeygenError(msg)
        self.pin = pin

        if not isinstance(pin_policy, str):
            msg = f"PIN policy {pin_policy!r} is not a string."
            raise KeygenError(msg)
        if not pin_policy:
            msg = "Empty PIN policy provided."
            raise KeygenError(msg)
        match pin_policy:
            case "always":
                self.pin_policy: PinPolicy = PinPolicy.ALWAYS
            case "once":
                self.pin_policy: PinPolicy = PinPolicy.ONCE
            case "never":
                self.pin_policy: PinPolicy = PinPolicy.NEVER
            case _:
                msg = f"Unknown PIN policy {pin_policy!r}."
                raise KeygenError(msg)

        self.mgmt_key: bytes | None = None
        if mgmt_key is not None:
            if not isinstance(mgmt_key, str):
                msg = "Management key is not a string."
                raise KeygenError(msg)
            if not mgmt_key:
                msg = "Management key is empty."
                raise KeygenError(msg)
            try:
                self.mgmt_key = bytes.fromhex(mgmt_key)
            except ValueError as e:
                msg = f"Management key {mgmt_key!r} is not a valid hex string."
                raise KeygenError(msg) from e

        self.serial: int | None = None
        if serial is not None:
            if not isinstance(serial, int):
                msg = f"Serial {serial!r} is not an integer."
                raise KeygenError(msg)
            if serial < 0:
                msg = f"Serial {serial!r} is < 0."
                raise KeygenError(msg)
            self.serial = serial

        if not isinstance(slot, int):
            msg = f"Slot {slot!r} is not an integer."
            raise KeygenError(msg)
        if slot < 1 or slot > 20:  # noqa: PLR2004 # Magic value used in comparison
            msg = f"Slot {slot!r} is not in the range 1-20."
            raise KeygenError(msg)
        self.slot: int = YUBIKEY_SLOT.RETIRED1 + slot - 1

        if not isinstance(touch_policy, str):
            msg = f"Touch policy {touch_policy!r} is not a string."
            raise KeygenError(msg)
        if not touch_policy:
            msg = "Empty touch policy provided."
            raise KeygenError(msg)
        match touch_policy:
            case "always":
                self.touch_policy: TouchPolicy = TouchPolicy.ALWAYS
            case "cached":
                self.touch_policy: TouchPolicy = TouchPolicy.CACHED
            case "never":
                self.touch_policy: TouchPolicy = TouchPolicy.NEVER
            case _:
                msg = f"Unknown touch policy {touch_policy!r}."
                raise KeygenError(msg)

        self.authenticated: bool = False
        self.crt: x509.Certificate | None = None
        self.device: YubiKeyScriptingDevice | None = None
        self.key_type = YUBIKEY_KEY_TYPE.ECCP256
        self.log = logging.getLogger(__name__)
        self.pubkey: EllipticCurvePublicKey | None = None
        self.session: YubiKeyPivSession | None = None

    # https://github.com/str4d/age-plugin-yubikey/blob/631f4426e1a5657b71420c4bb8e82676c6fb09c8/src/piv_p256/recipient.rs#L35
    def _pubkey_tag(self) -> str:
        """Compute the tag used in the certificate CN from the public key."""
        if self.pubkey is None:
            msg = "_pubkey_tag: Key not generated."
            raise KeygenError(msg)

        nums = self.pubkey.public_numbers()
        prefix = b"\x02" if (nums.y % 2 == 0) else b"\x03"
        h = hashlib.new("sha256")
        h.update(prefix + nums.x.to_bytes(32, "big"))
        return h.hexdigest()[0:8]

    def authenticate_piv(self) -> None:  # noqa: C901 # too complex
        """Verify PIN, resolve/derive management key, and authenticate to PIV."""
        if self.session is None:
            msg = "authenticate_piv: No session exists."
            raise KeygenError(msg)

        self.authenticated = False

        pivman_data = yk_get_pivman_data(self.session)

        if self.mgmt_key is not None:
            if pivman_data.has_protected_key:
                msg = "Management key is PIN protected and should not be provided."
                raise KeygenError(msg)
            if pivman_data.has_derived_key:
                msg = "Management key is PIN derived and should not be provided."
                raise KeygenError(msg)

        if not self.pin:
            self.pin = click.prompt(
                f"Enter PIN for YubiKey with serial '{self.serial}' (default: 123456)",
                hide_input=True,
            )
        self.session.verify_pin(self.pin)

        if pivman_data.has_derived_key:
            try:
                self.mgmt_key = yk_derive_management_key(self.pin, pivman_data.salt)
            except Exception as e:
                msg = "Failed to get PIN derived management key."
                raise KeygenError(msg) from e
            self.log.info("Management key derived from PIN.")
        elif pivman_data.has_stored_key:
            try:
                pivman_protected_data = yk_get_pivman_protected_data(self.session)
            except Exception as e:
                msg = "Failed to get PIN protected management key."
                raise KeygenError(msg) from e
            self.mgmt_key = pivman_protected_data.key
            self.log.info("Management key fetched from data protected by PIN.")
        elif not self.mgmt_key:
            try:
                mgmt_key_default = YUBIKEY_DEFAULT_MANAGEMENT_KEY.hex()

                self.mgmt_key = bytes.fromhex(
                    click.prompt(
                        f"Enter management key (default: {mgmt_key_default})",
                        hide_input=True,
                    ),
                )
            except ValueError as e:
                msg = "Management key is not a valid hex string."
                raise KeygenError(msg) from e

        self.log.info("Authenticating ...")
        with yk_prompt_timeout():
            self.session.authenticate(self.mgmt_key)
        self.log.info("Successfully authenticated.")

        # PIN verification should apparently be done after authentication as well...?
        self.session.verify_pin(self.pin)
        self.authenticated = True

    def check_slot_empty(self) -> None:
        """Ensure the slot does not contain a certificate already (unless forced)."""
        if self.session is None:
            msg = "check_slot_empty: No session exists."
            raise KeygenError(msg)

        try:
            self.session.get_certificate(self.slot)
            if not self.force:
                msg = (
                    f"PIV slot {self.slot:X} (RETIRED{slotnum(self.slot)})"
                    " already contains a key+certificate."
                )
                raise KeygenError(msg)
            self.log.info(
                "Existing key and certificate in PIV slot %X"
                " (RETIRED%d) will be replaced.",
                self.slot,
                slotnum(self.slot),
            )
        except YubiKeyApduError as e:
            if e.sw == YUBIKEY_STATUS_WORD.FILE_NOT_FOUND:
                self.log.info(
                    "No existing certificate found in PIV slot %X (RETIRED%d).",
                    self.slot,
                    slotnum(self.slot),
                )
            else:
                msg = f"Failed reading certificate: {e.sw}"
                raise KeygenError(msg) from e

    def get_device(self) -> None:
        """Select a YubiKey device (by serial, or the only connected device)."""
        if self.device is not None:
            msg = "get_device: Device already selected."
            raise KeygenError(msg)

        devices = yk_list_all_devices()
        if not devices:
            msg = "No YubiKey detected."
            raise KeygenError(msg)

        if self.serial:
            for _dev, dev_info in devices:
                if dev_info.serial == self.serial:
                    dev = _dev
                    break
            else:
                msg = f"Unable to find YubiKeys matching serial '{self.serial}'."
                raise KeygenDeviceSelectionError(msg, devices)
        elif len(devices) == 1:
            dev, dev_info = next(iter(devices))
        else:
            msg = "Multiple YubiKeys detected, serial needs to be specified."
            raise KeygenDeviceSelectionError(
                msg,
                devices,
            )

        self.device = YubiKeyScriptingDevice(dev, dev_info)
        if not self.serial:
            self.serial = dev_info.serial

        self.log.info("Found YubiKey with serial '%d'.", self.serial)

    def generate_certificate(self) -> None:
        """Create and store a certificate with age-plugin-yubikey metadata."""
        if self.pubkey is None:
            msg = "generate_certificate: Key not generated."
            raise KeygenError(msg)

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "age-plugin-yubikey"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "0.5.0"),
                x509.NameAttribute(
                    NameOID.COMMON_NAME,
                    f"age identity {self._pubkey_tag()}",
                ),
            ],
        )

        ext = x509.UnrecognizedExtension(
            ObjectIdentifier("1.3.6.1.4.1.41482.3.8"),
            bytes([self.pin_policy, self.touch_policy]),
        )

        builder = (
            x509.CertificateBuilder()
            .issuer_name(subject)  # same as subject_name = self-signed
            .subject_name(subject)
            .not_valid_before(datetime.datetime.now(datetime.UTC))
            .not_valid_after(
                datetime.datetime(9999, 12, 31, 23, 59, 59, tzinfo=datetime.UTC),
            )
            .serial_number(x509.random_serial_number())
            .public_key(self.pubkey)
            .add_extension(ext, critical=False)
        )

        timeout = None
        if self.touch_policy in (TouchPolicy.ALWAYS, TouchPolicy.CACHED):
            timeout = 0.0

        self.log.info("Generating certificate ...")
        with yk_prompt_timeout(timeout):
            self.crt = yk_sign_certificate_builder(
                self.session,
                self.slot,
                self.key_type,
                builder,
            )

        self.session.put_certificate(self.slot, self.crt)
        yk_update_chuid(self.session)

    def generate_key(self) -> None:
        """Create a new key in the selected PIV slot."""
        if not self.authenticated:
            msg = "generate_key: Not authenticated."
            raise KeygenError(msg)

        self.log.info(
            "Generating %s key in slot %X (RETIRED%d) ...",
            self.key_type.name,
            self.slot,
            slotnum(self.slot),
        )
        self.pubkey = self.session.generate_key(
            self.slot,
            self.key_type,
            self.pin_policy,
            self.touch_policy,
        )

    def get_session(self) -> None:
        """Open a PIV session against the selected YubiKey smartcard interface."""
        if self.device is None:
            msg = "get_session: Device not selected."
            raise KeygenError(msg)
        if self.session is not None:
            msg = "get_session: Session already exists."
            raise KeygenError(msg)

        self.session = YubiKeyPivSession(self.device.smart_card())

    def main(self) -> None:
        """Execute the main workflow."""
        try:
            self.get_device()
            self.get_session()
            self.check_slot_empty()
            self.authenticate_piv()
            self.generate_key()
            self.generate_certificate()
        except YubiKeyInvalidPinError as e:
            raise KeygenError(e) from e
        except YubiKeyApduError as e:
            msg = f"APDU: {YUBIKEY_STATUS_WORD(e.sw).name}"
            raise KeygenError(msg) from e


def main() -> None:
    """CLI entrypoint."""
    opts = arg_parse()

    if opts.quiet:
        log_level = logging.WARNING
    elif opts.verbose > 0:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    logging.basicConfig(format="%(levelname)s: %(message)s", level=log_level)
    logger = logging.getLogger(__name__)

    try:
        Keygen(
            opts.serial,
            opts.slot,
            opts.pin,
            opts.mgmt_key,
            opts.pin_policy,
            opts.touch_policy,
            opts.force,
        ).main()
        raise SystemExit
    except KeygenDeviceSelectionError as e:
        print(get_devices_output(e.devices), file=sys.stderr)  # noqa: T201
        logger.error(e)
    except KeygenError as e:
        logger.error(e)
    except click.exceptions.Abort:
        logger.error("Aborted.")

    raise SystemExit(1)


if __name__ == "__main__":
    main()
