from pydantic import BaseModel
from typing import List, Any
from app.models.entity_models import Project, AttackPattern, CloudMachine


class SimpleResponse(BaseModel):
    success: bool

    def __init__(self, status: bool, **args) -> None:
        super().__init__(success=status, **args)


class ErrorResponse(SimpleResponse):
    error: str


class AttackListResponseScheme(SimpleResponse):
    attack_list: List[AttackPattern]


class GetProjectListResponseScheme(SimpleResponse):
    project_list: List[Project]


class GetProjectResponseScheme(SimpleResponse):
    data: Project


class CreateMachinesResponseScheme(SimpleResponse):
    machine_list: List[CloudMachine]


class CreateProjectResponseScheme(SimpleResponse):
    id: int
    title: str
    start_date: int
