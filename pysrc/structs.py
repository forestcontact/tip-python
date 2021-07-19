from typing import List
from dataclasses import dataclass, field

from typing import NewType

uint64 = NewType('uint64', int)

@dataclass
class Justification:
	share_index: int #uint32
	share:       bytes #kyber.Scalar

@dataclass
class JustificationBundle:
	dealer_index:    int #uint32
	justifications: List[Justification]
	# SessionID of the current run
	session_id: bytes
	# Signature over the hash of the whole bundle
	signature: bytes

# Response holds the Response from another participant as well as the index of
# the target Dealer.
@dataclass
class Response:
	# Index of the Dealer for which this response is for
	dealer_index: int = 0 # uint32
	status:      bool = False


# ResponseBundle is the struct sent out by share holder containing the status
# for the deals received in the first phase.
@dataclass
class ResponseBundle:
	# Index of the share holder for which these reponses are for
	share_index: int = 0 #uint32
	responses: List[Response] = field(default_factory=list)#[]Response
	# SessionID of the current run
	session_id: bytes = None
	# Signature over the hash of the whole bundle
	signature: bytes = None

# Deal holds the Deal for one participant as well as the index of the issuing
# Dealer.

@dataclass
class Deal:
	# Index of the share holder
	share_index: int #uint32
	# encrypted share issued to the share holder
	encrypted_share: bytes

@dataclass
class Point:
    raw: bytes

@dataclass
class Scalar:
    raw: bytes

# DealBundle is the struct sent out by dealers that contains all the deals and
# the public polynomial.
@dataclass
class DealBundle:
	dealer_index: int = 0 #uint32
	deals: List[Deal] = field(default_factory=list)   #[]Deal
	# Public coefficients of the public polynomial used to create the shares
	public: List[Point] = field(default_factory=list) #[]kyber.Point
	# SessionID of the current run
	session_id: bytes = None # []byte
	# Signature over the hash of the whole bundle
	signature: bytes = None # []byte
