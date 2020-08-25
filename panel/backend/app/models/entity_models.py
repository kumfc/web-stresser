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

