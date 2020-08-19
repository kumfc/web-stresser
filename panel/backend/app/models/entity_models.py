from pydantic import BaseModel
from typing import List
from enum import Enum


class MState(Enum):
    STATE_DEPLOYING = 0
    STATE_READY = 1


class ATypes(Enum):
    HTTP_FLOOD = 0
    SLOW_HTTP = 1
    BENIS = 2


class CloudMachine(BaseModel):
    ip: str
    state: MState


class AttackEntity(BaseModel):
    attack_type: ATypes
    binary_options: str
    start_time: int
    end_time: int = None


class Project(BaseModel):
    name: str
    machine_list: List[CloudMachine]
    attack_list: List[AttackEntity]
    start_date: int
    end_date: int = None

