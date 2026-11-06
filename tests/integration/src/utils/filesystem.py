import os

import pytest


def make_link(path, target, *, directory=False):
    if os.name == "nt" and directory:
        from _winapi import CreateJunction

        try:
            CreateJunction(str(target), str(path))
        except OSError as exc:
            if exc.winerror == 5:
                pytest.skip("Windows test environment denied junction creation")
            raise
        return

    try:
        path.symlink_to(target, target_is_directory=directory)
    except OSError as exc:
        if os.name == "nt" and exc.winerror == 1314:
            pytest.skip("Windows file symlinks require Developer Mode or symlink privilege")
        raise
