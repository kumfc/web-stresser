from pydantic import BaseModel, HttpUrl, Field


class CreateProjectScheme(BaseModel):
    title: str = Field(..., max_length=150)


class EditProjectScheme(BaseModel):
    id: int
    title: str = Field(..., max_length=150)


class CreateCloudMachinesScheme(BaseModel):
    project_id: int
    count: int
