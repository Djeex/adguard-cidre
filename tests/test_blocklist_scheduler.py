import pytest
import schedule as schedule_lib

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


# --- schedule_job (schedule) ---

@pytest.fixture(autouse=True)
def clear_schedule():
    yield
    schedule_lib.clear()


def test_schedule_job_daily(monkeypatch):
    monkeypatch.setattr(bs, "BLOCKLIST_CRON_TYPE", "daily")
    monkeypatch.setattr(bs, "BLOCKLIST_CRON_TIME", "06:00")

    bs.schedule_job()

    assert len(schedule_lib.jobs) == 1
    job = schedule_lib.jobs[0]
    assert job.unit == "days"
    assert str(job.at_time) == "06:00:00"
    assert job.job_func.func is bs.update_blocklist


def test_schedule_job_weekly_valid_day(monkeypatch):
    monkeypatch.setattr(bs, "BLOCKLIST_CRON_TYPE", "weekly")
    monkeypatch.setattr(bs, "BLOCKLIST_CRON_TIME", "18:30")
    monkeypatch.setattr(bs, "BLOCKLIST_CRON_DAY", "wed")

    bs.schedule_job()

    job = schedule_lib.jobs[0]
    assert job.unit == "weeks"
    assert job.start_day == "wednesday"
    assert str(job.at_time) == "18:30:00"


def test_schedule_job_weekly_invalid_day_defaults_to_monday(monkeypatch):
    monkeypatch.setattr(bs, "BLOCKLIST_CRON_TYPE", "weekly")
    monkeypatch.setattr(bs, "BLOCKLIST_CRON_DAY", "xxx")

    bs.schedule_job()

    assert schedule_lib.jobs[0].start_day == "monday"


def test_schedule_job_invalid_time_defaults_to_six_am(monkeypatch):
    monkeypatch.setattr(bs, "BLOCKLIST_CRON_TYPE", "daily")
    monkeypatch.setattr(bs, "BLOCKLIST_CRON_TIME", "not-a-time")

    bs.schedule_job()

    assert str(schedule_lib.jobs[0].at_time) == "06:00:00"


def test_schedule_job_invalid_type_defaults_to_daily(monkeypatch):
    monkeypatch.setattr(bs, "BLOCKLIST_CRON_TYPE", "bogus")

    bs.schedule_job()

    assert schedule_lib.jobs[0].unit == "days"
