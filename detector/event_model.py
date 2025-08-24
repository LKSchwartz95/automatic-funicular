from pydantic import BaseModel, Field, IPvAnyAddress, conint
from typing import Literal, Optional, List, Dict
from datetime import datetime
import hashlib


Severity = Literal["LOW", "MED", "HIGH"]


class Event(BaseModel):
    ts: datetime
    severity: Severity
    rule: str
    src_ip: IPvAnyAddress
    src_port: conint(ge=1, le=65535)
    dst_ip: IPvAnyAddress
    dst_port: conint(ge=1, le=65535)
    host: Optional[str] = None
    context: Dict[str, str] = Field(default_factory=dict)
    snippet_sha256: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    def to_jsonable(self) -> dict:
        d = self.model_dump()
        d["ts"] = self.ts.isoformat().replace("+00:00", "Z")
        return d

    @classmethod
    def create_http_basic_auth(
        cls,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        host: Optional[str] = None,
    ) -> "Event":
        return cls(
            ts=datetime.now(),
            severity="HIGH",
            rule="http.basic_auth",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            host=host,
            context={"protocol": "HTTP"},
        )

    @classmethod
    def create_http_credential_key(
        cls,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        host: Optional[str] = None,
        keys_found: List[str] = None,
        body_snippet: Optional[str] = None,
    ) -> "Event":
        snippet_hash = None
        if body_snippet:
            snippet_hash = hashlib.sha256(body_snippet.encode("utf-8")).hexdigest()

        return cls(
            ts=datetime.now(),
            severity="MED",
            rule="http.credential_key",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            host=host,
            context={"protocol": "HTTP", "keys": ",".join(keys_found or [])},
            snippet_sha256=snippet_hash,
        )

    @classmethod
    def create_smtp_no_starttls(
        cls,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> "Event":
        return cls(
            ts=datetime.now(),
            severity="HIGH",
            rule="smtp.no_starttls",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            context={"protocol": "SMTP", "phase": "AUTH", "pre_tls": "true"},
        )

    @classmethod
    def create_pop3_clear_creds(
        cls,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> "Event":
        return cls(
            ts=datetime.now(),
            severity="HIGH",
            rule="pop3.clear_creds",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            context={"protocol": "POP3"},
        )

    @classmethod
    def create_imap_clear_login(
        cls,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> "Event":
        return cls(
            ts=datetime.now(),
            severity="HIGH",
            rule="imap.clear_login",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            context={"protocol": "IMAP"},
        )

    @classmethod
    def create_ftp_clear_creds(
        cls,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> "Event":
        return cls(
            ts=datetime.now(),
            severity="HIGH",
            rule="ftp.clear_creds",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            context={"protocol": "FTP"},
        )

    @classmethod
    def create_telnet_clear_login(
        cls,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> "Event":
        return cls(
            ts=datetime.now(),
            severity="HIGH",
            rule="telnet.clear_login",
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            context={"protocol": "TELNET"},
        )
