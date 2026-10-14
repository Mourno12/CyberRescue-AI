"""Shipped detection rules. Order is irrelevant: the registry sorts by rule id."""

from cyberrescue.detection.correlation import HostChain, UncorroboratedAlert
from cyberrescue.detection.rules.auth import FailedThenSuccess, RepeatedFailures
from cyberrescue.detection.rules.exfil import SensitiveAssetExfiltration
from cyberrescue.detection.rules.lateral import RemoteAuthToMultipleHosts
from cyberrescue.detection.rules.network import (
    KnownMaliciousHash,
    MaliciousInfrastructureContact,
    PeriodicOutbound,
)
from cyberrescue.detection.rules.persistence import AutostartToUserWritable
from cyberrescue.detection.rules.privilege import NewPrivilegedAccount
from cyberrescue.detection.rules.process import (
    RecoveryInhibition,
    SuspiciousInterpreter,
    UserWritableExecution,
)
from cyberrescue.detection.rules.ransomware import MassEncryption

ALL_RULES: list[type] = [
    FailedThenSuccess, RepeatedFailures,
    RemoteAuthToMultipleHosts,
    UserWritableExecution, SuspiciousInterpreter, RecoveryInhibition,
    AutostartToUserWritable,
    NewPrivilegedAccount,
    KnownMaliciousHash, MaliciousInfrastructureContact, PeriodicOutbound,
    SensitiveAssetExfiltration,
    MassEncryption,
    # Layer 2
    HostChain, UncorroboratedAlert,
]
