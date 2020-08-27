from pydantic import BaseModel, Field
from typing import List
from enum import Enum
from collections import namedtuple


class MState(Enum):
    STATE_DEPLOYING = 0
    STATE_READY = 1


class ATypes(Enum):
    hping3 = 1
    slowhttptest = 2
    hey = 3
    
    def __repr__(self):
        return self.name


class CloudMachine(BaseModel):
    name: str
    ip: str
    state: MState


class AttackEntity(BaseModel):
    id: int
    attack_type: int
    target: str
    binary_options: str
    duration: int
    start_time: int


class Project(BaseModel):
    id: int
    title: str
    is_finished: bool
    machine_list: List[CloudMachine] = None
    attack_list: List[AttackEntity] = None
    start_date: int
    end_date: int = 0


class AttackPattern(BaseModel):
    attack_type: int
    title: str = Field(..., max_length=150)
    bin_opts: str
    is_default: bool
