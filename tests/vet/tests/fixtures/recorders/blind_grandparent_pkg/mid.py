"""Middle class of the known-blind inheritance fixture: it adds nothing, it
only stands between the handler and the recorder. Never run."""
from .base import Base


class Mid(Base):
    pass
