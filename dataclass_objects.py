from dataclasses import dataclass, field
from enum import Enum
from csv import DictReader

from resources.logger import logger


@dataclass
class UserMapping:
    email: str
    aid: str

    def __post_init__(self):
        self.email = self.email.replace('"', "").replace("'", "")
        self.aid = self.aid.replace('"', "").replace("'", "")


class Permission(Enum):
    none = 0
    read = 1
    write = 2
    admin = 3

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, Permission):
            return self.value == __o.value
        else:
            return False

    def __gt__(self, __o) -> bool:
        if isinstance(__o, Permission):
            return self.value > __o.value
        else:
            return False


class GlobalPermission(Enum):
    none = 0
    user = 1
    creator = 2
    admin = 3
    sysadmin = 4


class PermissionUtils:
    @staticmethod
    def set_permission(str_input: str | None) -> Permission:
        if str_input in ["PROJECT_ADMIN", "REPO_ADMIN"]:
            return Permission.admin
        elif str_input in ["PROJECT_WRITE", "REPO_WRITE"]:
            return Permission.write
        elif str_input in ["PROJECT_READ", "REPO_READ"]:
            return Permission.read
        else:
            return Permission.none

    @staticmethod
    def convert_global_permisison_to_standard(global_permission: GlobalPermission):
        if global_permission in [GlobalPermission.admin, GlobalPermission.sysadmin]:
            return Permission.admin
        else:
            return Permission.none

    @staticmethod
    def set_global_permission(str_input: str | None) -> GlobalPermission:
        if str_input == "LICENSED_USER":
            return GlobalPermission.user
        elif str_input == "PROJECT_CREATE":
            return GlobalPermission.creator
        elif str_input == "ADMIN":
            return GlobalPermission.admin
        elif str_input == "SYS_ADMIN":
            return GlobalPermission.sysadmin
        else:
            return GlobalPermission.none


@dataclass
class User:
    name: str
    email_address: str
    display_name: str
    slug: str
    permission: Permission
    aid: str = ""

    def __post_init__(self):
        self._hash = hash(self.email_address)

    def __hash__(self) -> int:
        return self._hash

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, User):
            return __o._hash == self._hash
        else:
            return __o == self._hash

    def get_aid(self) -> None:
        with open("./export-users.csv", "r", encoding="utf-8") as mapping_file:
            reader = DictReader(mapping_file)
            for row in reader:
                user = UserMapping(email=row["email"], aid=row["User id"])
                if user.email.lower() == self.email_address.lower():
                    self.aid = user.aid
                    return
            logger.debug(
                f"No email/aid match was found in the export-users.csv file for user {self.email_address}."
            )
            return

    @staticmethod
    def email_valid(name: str, email: str | None) -> bool:
        if email is None or email == "":
            logger.debug(
                f'Skipping user "{name}" as they do not have an email address which will cause issues later.'
            )
            return False
        return True


@dataclass
class GlobalUser(User):
    permission: GlobalPermission = GlobalPermission(0)

    def __hash__(self) -> int:
        return super().__hash__()


@dataclass
class GroupBase:
    name: str
    slug: str

    def __post_init__(self):
        # replaces space characters with escape character and escape
        if self.slug == "":
            self.slug = (
                self.name.replace(" - ", "-")
                .replace(" ", "-")
                .replace("+", "-")
                .lower()
            )
        self._hash = hash(self.name)

    def __hash__(self) -> int:
        return self._hash


@dataclass
class Group(GroupBase):
    members: set[User] = field(default_factory=set)
    used: bool = False

    def __hash__(self) -> int:
        return super().__hash__()


@dataclass
class GroupPermission(GroupBase):
    permission: Permission

    def __hash__(self) -> int:
        return super().__hash__()


@dataclass
class GlobalGroupPermission(GroupBase):
    permission: GlobalPermission

    def __hash__(self) -> int:
        return super().__hash__()


@dataclass
class Repository:
    slug: str
    name: str
    groups: set[GroupPermission] = field(default_factory=set)
    users: set[User] = field(default_factory=set)

    def __hash__(self) -> int:
        return hash(self.slug)


@dataclass
class Project:
    key: str
    name: str
    default_permission: Permission
    groups: set[GroupPermission] = field(default_factory=set)
    users: set[User] = field(default_factory=set)
    repositories: set[Repository] = field(default_factory=set)

    def __hash__(self) -> int:
        return hash(self.key)


@dataclass
class MappingInstance:
    groups: set[Group] = field(default_factory=set)
    global_groups: set[GlobalGroupPermission] = field(default_factory=set)
    global_users: set[GlobalUser] = field(default_factory=set)
    projects: set[Project] = field(default_factory=set)
