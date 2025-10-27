from pydantic import BaseModel


class Usercreate(BaseModel):
    username: str
    password: str

    