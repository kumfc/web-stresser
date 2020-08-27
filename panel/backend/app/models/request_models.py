from pydantic import BaseModel, Field


class CreateProjectScheme(BaseModel):
    title: str = Field(..., max_length=150)


class EditProjectScheme(BaseModel):
    id: int
    title: str = Field(..., max_length=150)


class CreateCloudMachinesScheme(BaseModel):
    project_id: int
    count: int


class CreateAttackScheme(BaseModel):
    project_id: int
    bin_id: int
    bin_opts: str
    duration: int
    bandwidth: int
    target_ip: str
    target_port: int
