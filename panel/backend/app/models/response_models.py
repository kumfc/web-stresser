from pydantic import BaseModel
from typing import List, Any
from app.models.entity_models import Project


class SimpleResponse(BaseModel):
    success: bool

    def __init__(self, status: bool, **args) -> None:
        super().__init__(success=status, **args)


class GetProjectListResponseScheme(SimpleResponse):
    project_list: List[Project]


class GetProjectResponseScheme(SimpleResponse):
    data: Project


class CreateProjectResponseScheme(SimpleResponse):
    id: int
    title: str
    start_date: int
