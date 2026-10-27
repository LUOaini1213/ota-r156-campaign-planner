"""测试共用的断言。"""


def last_attack(bed) -> str:
    events = bed.ecu.security_log.read()["events"]
    return events[-1]["attack"] if events else ""


def assert_rejected(bed, before: dict, attack: str) -> None:
    """攻击被拒之后：ECU 的 active 槽、pending、软件标识 / RXSWIN、防回滚计数器都不变，安全日志记下了攻击类型。"""
    assert bed.ecu_state() == before
    assert last_attack(bed) == attack
    assert bed.ecu.journal.read()["state"] == "IDLE"
