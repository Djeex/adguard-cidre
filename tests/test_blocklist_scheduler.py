import pytest

import blocklist_scheduler as bs


def test_backup_first_start_creates_backup_when_missing(tmp_path, monkeypatch):
    adguard_yaml = tmp_path / "AdGuardHome.yaml"
    adguard_yaml.write_text("original: config\n")
    first_backup = tmp_path / "AdGuardHome.yaml.first-start.bak"

    monkeypatch.setattr(bs, "ADGUARD_YAML", adguard_yaml)
    monkeypatch.setattr(bs, "FIRST_BACKUP", first_backup)

    bs.backup_first_start()

    assert first_backup.read_text() == "original: config\n"


def test_backup_first_start_does_not_overwrite_existing_backup(tmp_path, monkeypatch):
    adguard_yaml = tmp_path / "AdGuardHome.yaml"
    adguard_yaml.write_text("new: config\n")
    first_backup = tmp_path / "AdGuardHome.yaml.first-start.bak"
    first_backup.write_text("pristine: original\n")

    monkeypatch.setattr(bs, "ADGUARD_YAML", adguard_yaml)
    monkeypatch.setattr(bs, "FIRST_BACKUP", first_backup)

    bs.backup_first_start()

    assert first_backup.read_text() == "pristine: original\n"


def test_backup_first_start_raises_if_adguard_yaml_missing(tmp_path, monkeypatch):
    adguard_yaml = tmp_path / "AdGuardHome.yaml"
    first_backup = tmp_path / "AdGuardHome.yaml.first-start.bak"

    monkeypatch.setattr(bs, "ADGUARD_YAML", adguard_yaml)
    monkeypatch.setattr(bs, "FIRST_BACKUP", first_backup)

    with pytest.raises(FileNotFoundError):
        bs.backup_first_start()
