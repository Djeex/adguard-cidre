import pytest
import schedule as schedule_lib
import yaml

import blocklist_scheduler as bs


class FakeResponse:
    def __init__(self, text="", status_code=200, raise_exc=None):
        self.text = text
        self.status_code = status_code
        self._raise_exc = raise_exc

    def raise_for_status(self):
        if self._raise_exc:
            raise self._raise_exc


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


# --- update_yaml_with_ips (pyyaml) ---


def test_update_yaml_with_ips_writes_disallowed_clients(tmp_path, monkeypatch):
    adguard_yaml = tmp_path / "AdGuardHome.yaml"
    adguard_yaml.write_text("dns:\n  bind_hosts:\n  - 0.0.0.0\n")
    tmp_yaml = tmp_path / "AdGuardHome.yaml.tmp"

    monkeypatch.setattr(bs, "ADGUARD_YAML", adguard_yaml)
    monkeypatch.setattr(bs, "TMP_YAML", tmp_yaml)

    result = bs.update_yaml_with_ips(["1.2.3.0/24", "5.6.7.8"])

    assert result is True
    data = yaml.safe_load(adguard_yaml.read_text())
    assert data["dns"]["disallowed_clients"] == ["1.2.3.0/24", "5.6.7.8"]
    assert not tmp_yaml.exists()


def test_update_yaml_with_ips_missing_file_returns_false(tmp_path, monkeypatch):
    adguard_yaml = tmp_path / "AdGuardHome.yaml"

    monkeypatch.setattr(bs, "ADGUARD_YAML", adguard_yaml)

    assert bs.update_yaml_with_ips(["1.2.3.4"]) is False


def test_update_yaml_with_ips_invalid_yaml_returns_false(tmp_path, monkeypatch):
    adguard_yaml = tmp_path / "AdGuardHome.yaml"
    adguard_yaml.write_text("key: [unclosed\n")

    monkeypatch.setattr(bs, "ADGUARD_YAML", adguard_yaml)

    assert bs.update_yaml_with_ips(["1.2.3.4"]) is False


def test_update_yaml_with_ips_missing_dns_key_raises(tmp_path, monkeypatch):
    adguard_yaml = tmp_path / "AdGuardHome.yaml"
    adguard_yaml.write_text("some_other_key: true\n")

    monkeypatch.setattr(bs, "ADGUARD_YAML", adguard_yaml)

    with pytest.raises(KeyError):
        bs.update_yaml_with_ips(["1.2.3.4"])


# --- fetch_all_country_codes / download_cidr_lists / restart_adguard_container (requests) ---


def test_fetch_all_country_codes_parses_codes(monkeypatch):
    monkeypatch.setattr(
        bs.requests, "get", lambda *a, **k: FakeResponse(text='COUNTRIES = ["FR", "DE", "US"]\n')
    )

    assert bs.fetch_all_country_codes() == {"fr", "de", "us"}


def test_fetch_all_country_codes_returns_empty_set_on_error(monkeypatch):
    def raise_error(*a, **k):
        raise bs.requests.exceptions.ConnectionError("boom")

    monkeypatch.setattr(bs.requests, "get", raise_error)

    assert bs.fetch_all_country_codes() == set()


def test_download_cidr_lists_combines_successful_countries_and_skips_failures(monkeypatch):
    def fake_get(url, timeout=None):
        if "/fr.cidr" in url:
            return FakeResponse(text="1.1.1.0/24\n1.1.2.0/24\n")
        raise bs.requests.exceptions.ConnectionError("boom")

    monkeypatch.setattr(bs.requests, "get", fake_get)

    result = bs.download_cidr_lists(["fr", "de"])

    assert result == ["1.1.1.0/24", "1.1.2.0/24"]


def test_restart_adguard_container_success_does_not_raise(monkeypatch):
    monkeypatch.setattr(bs.requests, "post", lambda *a, **k: FakeResponse(status_code=204))

    bs.restart_adguard_container()


def test_restart_adguard_container_error_status_does_not_raise(monkeypatch):
    monkeypatch.setattr(
        bs.requests, "post", lambda *a, **k: FakeResponse(status_code=500, text="err")
    )

    bs.restart_adguard_container()


def test_restart_adguard_container_network_error_does_not_raise(monkeypatch):
    def raise_error(*a, **k):
        raise bs.requests.exceptions.ConnectionError("boom")

    monkeypatch.setattr(bs.requests, "post", raise_error)

    bs.restart_adguard_container()


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
