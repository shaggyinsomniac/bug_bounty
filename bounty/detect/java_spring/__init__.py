"""
bounty.detect.java_spring — Spring Boot / Java framework detection modules.

Re-exports all Spring-specific detection classes.
"""

from __future__ import annotations

from bounty.detect.java_spring.actuator import (
    ActuatorEnv,
    ActuatorExposed,
    ActuatorHeapdump,
    ActuatorLoggers,
)
from bounty.detect.java_spring.h2console import H2Console

__all__ = [
    "ActuatorExposed",
    "ActuatorEnv",
    "ActuatorHeapdump",
    "ActuatorLoggers",
    "H2Console",
]

