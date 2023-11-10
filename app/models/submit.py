from pydantic.main import BaseModel


class Submit(BaseModel):
    uziNumber: str
