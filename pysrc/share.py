from dataclasses import dataclass

from . import kyber

@dataclass
class PriShare:
	I: int          # Index of the private share
	V: kyber.Scalar # Value of the private share
