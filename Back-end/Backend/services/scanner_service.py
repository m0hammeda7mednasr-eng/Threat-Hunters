from scanner.runner import (
    run_scan
)


def start_scan(data):

    target = data.get(
        "target"
    )

    if not target:

        raise ValueError(
            "Target is required"
        )

    scan_mode = data.get(
        "scan_mode",
        "light"
    )

    cookie_header = data.get(
        "cookie_header"
    )

    enable_nuclei = data.get(
        "enable_nuclei",
        False
    )

    nuclei_profile = data.get(
        "nuclei_profile",
        "public-safe-v1"
    )

    modules = data.get(
        "modules"
    )

    result = run_scan(

        target=target,

        scan_mode=scan_mode,

        cookie_header=cookie_header,

        enable_nuclei=enable_nuclei,

        confirm_permission=True,

        nuclei_profile=nuclei_profile,

        modules=modules

    )

    return result