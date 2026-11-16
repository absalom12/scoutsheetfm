import hashlib
import os
import shutil
import ssl
import subprocess
import sys
import zipfile

import pytest

import updater


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_newer_compares_numerically():
    assert updater.newer("0.4.10", "0.4.9") and updater.newer("0.5.0", "0.4.12")
    assert not updater.newer("0.4.7", "0.4.7") and not updater.newer("0.4.6", "0.4.7")


@pytest.mark.skipif(sys.platform != "darwin", reason="ditto and codesign are macOS tools")
def test_unsigned_download_leaves_current_app_in_place(tmp_path):
    current = tmp_path / "Apps" / "ScoutSheet.app"
    (current / "Contents").mkdir(parents=True)
    (current / "Contents" / "marker").write_text("old")
    fake = tmp_path / "src" / "ScoutSheet.app"
    (fake / "Contents").mkdir(parents=True)
    subprocess.run(["ditto", "-c", "-k", "--keepParent", fake, tmp_path / "u.zip"], check=True)
    with pytest.raises(subprocess.CalledProcessError):  # codesign --verify refuses it
        updater.install(current, (tmp_path / "u.zip").as_uri(), sha(tmp_path / "u.zip"))
    assert (current / "Contents" / "marker").read_text() == "old"
    assert [p.name for p in current.parent.iterdir()] == ["ScoutSheet.app"]  # work folder cleaned up


def windows_zip(tmp_path):
    with zipfile.ZipFile(tmp_path / "u.zip", "w") as z:
        z.writestr("ScoutSheet/ScoutSheet.exe", "new")
    current = tmp_path / "Apps" / "FM26-Scout"
    current.mkdir(parents=True)
    (current / "FM26-Scout.exe").write_text("old")
    return current, tmp_path / "u.zip"


def test_windows_update_is_staged_next_to_the_app(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    current, z = windows_zip(tmp_path)
    new, target, work = updater.install(current, z.as_uri(), sha(z))
    assert (new / "ScoutSheet.exe").read_text() == "new" and (work / "swap.ps1").exists()
    assert target == current.parent / "ScoutSheet" and (current / "FM26-Scout.exe").read_text() == "old"  # swapped after exit


def test_windows_update_with_a_bad_checksum_changes_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    current, z = windows_zip(tmp_path)
    with pytest.raises(ValueError, match="checksum"):
        updater.install(current, z.as_uri(), "0" * 64)
    assert [p.name for p in current.parent.iterdir()] == ["FM26-Scout"]


@pytest.mark.skipif(sys.platform != "win32", reason="the swap script is PowerShell")
def test_windows_swap_replaces_the_folder_once_the_app_exits(tmp_path):
    apps = tmp_path / "Apps"
    current, work = apps / "FM26-Scout", apps / ".work"
    current.mkdir(parents=True)
    new = work / "new" / "ScoutSheet"
    new.mkdir(parents=True)
    shutil.copy(os.path.join(os.environ["SystemRoot"], "System32", "whoami.exe"), new / "ScoutSheet.exe")  # exits at once
    (work / "swap.ps1").write_text(updater.SWAP_PS1, encoding="utf-8")
    app = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"])
    subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", work / "swap.ps1",
                    "-ProcId", str(app.pid), "-Cur", current, "-New", new, "-Target", apps / "ScoutSheet",
                    "-Work", work], check=True, timeout=60)
    assert [p.name for p in apps.iterdir()] == ["ScoutSheet"]
    assert (apps / "ScoutSheet" / "ScoutSheet.exe").exists()


def test_update_downloads_check_certificates_against_certifi():
    # A bundled macOS app has no system root certificates: without certifi's, every download fails.
    assert updater.TLS.cert_store_stats()["x509_ca"] > 100
    assert updater.TLS.verify_mode == ssl.CERT_REQUIRED and updater.TLS.check_hostname


def test_last_failure_reads_the_log_once(tmp_path, monkeypatch):
    monkeypatch.setenv("SCOUTSHEET_DATA_DIR", str(tmp_path))
    assert updater.last_failure() is None  # no log: nothing to say
    log = tmp_path / updater.LOG
    log.write_text("2026-11-16T10:00:00 start: a -> b\n2026-11-16T10:00:20 RESULT failed: the app folder stayed locked: denied\n")
    assert updater.last_failure() == "the app folder stayed locked: denied"
    assert not log.exists() and (tmp_path / "update.log.prev").exists()  # shown once
    log.write_text("2026-11-16T10:00:00 start\n2026-11-16T10:00:01 RESULT ok\n")
    assert updater.last_failure() is None
    log.write_text("2026-11-16T10:00:00 start\n")  # the script died before the end
    assert updater.last_failure() == "the update did not finish"


@pytest.mark.skipif(sys.platform != "win32", reason="the swap script is Windows PowerShell")
@pytest.mark.parametrize("locked", [False, True])
def test_swap_ps1_swaps_or_rolls_back(tmp_path, locked):
    """Runs the real swap.ps1 on a fake app folder (CI windows-latest). A file held open in the current app folder
    stands for antivirus or WebView2: the swap must give up, keep the old app and log why."""
    exe = shutil.which("hostname.exe")
    cur, work = tmp_path / "ScoutSheet", tmp_path / ".scoutsheet-update-x"
    new = work / "new" / "ScoutSheet"
    for d, tag in ((cur, "old"), (new, "new")):
        d.mkdir(parents=True)
        shutil.copy(exe, d / "ScoutSheet.exe")
        (d / "version.txt").write_text(tag)
    (work / "swap.ps1").write_text(updater.SWAP_PS1, encoding="utf-8")
    log = tmp_path / "update.log"
    held = open(cur / "version.txt") if locked else None
    try:
        dying = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(1)"])
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(work / "swap.ps1"),
                        "-ProcId", str(dying.pid), "-Cur", str(cur), "-New", str(new), "-Target", str(cur),
                        "-Work", str(work), "-Log", str(log), "-Tries", "5"], check=True, timeout=120)
    finally:
        if held:
            held.close()
    result = [l for l in log.read_text().splitlines() if " RESULT " in l][-1]
    if locked:
        assert "RESULT failed" in result and (cur / "version.txt").read_text() == "old"
    else:
        assert result.endswith("RESULT ok") and (cur / "version.txt").read_text() == "new"
