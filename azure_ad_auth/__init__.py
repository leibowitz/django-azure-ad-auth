__version_info__ = {
    "major": 1,
    "minor": 5,
    "micro": 28,
    "releaselevel": "final",
    "serial": 12,
}


def get_version(short=False):
    assert __version_info__["releaselevel"] in ("alpha", "beta", "final")  # noqa: S101
    vers = [f"{__version_info__['major']}.{__version_info__['minor']}"]
    if __version_info__["micro"]:
        vers.append(f".{__version_info__['micro']}")
    if __version_info__["releaselevel"] != "final" and not short:
        vers.append(
            f"{__version_info__['releaselevel'][0]}{__version_info__['serial']}",
        )
    return "".join(vers)


__version__ = get_version()
