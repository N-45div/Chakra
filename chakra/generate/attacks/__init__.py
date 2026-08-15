"""Attack families.

Every family is an AttackFamily: it exposes a parameter space (the knobs a real
fraudster controls — amounts, timing, ratios) and an `emit` method that turns a
parameter vector into raw events injected into a population. Families never
import chakra.schema.features and never write a feature value. A test enforces
this; it is the guarantee that the detector learns fraud, not the author's rules.
"""

from chakra.generate.attacks.base import AttackFamily, AttackParams, ParamSpec
from chakra.generate.attacks.f11_enumeration import F11Enumeration
from chakra.generate.attacks.f5_upi_deception import F5UpiDeception
from chakra.generate.attacks.f6_mule_network import F6MuleNetwork

ATTACK_FAMILIES: dict[str, AttackFamily] = {
    "F11": F11Enumeration(),
    "F5": F5UpiDeception(),
    "F6": F6MuleNetwork(),
}

__all__ = [
    "AttackFamily",
    "AttackParams",
    "ParamSpec",
    "ATTACK_FAMILIES",
    "F11Enumeration",
    "F5UpiDeception",
    "F6MuleNetwork",
]
